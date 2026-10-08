# Host Audit Role Task Specification

> **상태: 뼈대(#119) + Asset Inventory(#120).** [ADR-0009](adr/0009-host-audit-read-only-inspection.md)의 Host Audit 실행 흐름(대상 확정 → 접속 해석 → 호스트별 읽기 전용 수집 → 보고서 모델 → HTML)을 가장 얇게 관통한다. 지금은 식별(Inventory Hostname, FQDN, IP, 환경)과 운영 체제만 수집하고, 보고서는 러너 로컬에만 남긴다. 나머지 Asset Inventory 항목, Configuration Drift, Configuration Vulnerability, Package Vulnerability, Audit Baseline 비교, RustFS 보관, 메일은 [스펙 #115](https://github.com/ppzxc/infra-automation/issues/115)의 후속 티켓이 이 뼈대에 붙인다.

---

## 1. 개요 및 구현 기능 (What)

- **진입점**: `playbooks/host_audit.yml`. 플레이 순서는 아래와 같다.
  1. 대상·실행 메타 확정 (localhost, `tasks/prepare.yml`)
  2. 접속 해석 (`common/resolve_connection.yml` 재사용, Deploy와 같은 관리 계정)
  3. 호스트별 수집 (`tasks/main.yml`)
  4. 임시 키 정리 (`common/cleanup_connection.yml`)
  5. 보고서 (localhost, `tasks/report.yml`)
- **대상**: `host_audit_scope_pattern`(`servers:loadbalancers:overseer`) ∩ `target_hosts`. Host Agents Exclusion 호스트와 CentOS 6/7 호스트도 대상이다. 네트워크 장비(`cisco_switches`)는 범위 밖이며 보고서 표지에 그렇게 적는다.
- **읽기 전용 수집**: 대상 호스트에서는 `ansible.builtin.raw`로 POSIX sh 조회(`roles/host_audit/files/identity_probe.sh`)만 실행한다. Python·모듈·원격 임시 파일이 없고 `gather_facts: false`라 CentOS 6/7도 같은 경로로 수집한다.
- **접속 실패**: 수집 태스크는 `ignore_unreachable: true`라 한 호스트가 실패해도 실행이 계속된다. 접속 실패는 `unreachable`, 수집 실패는 `probe_failed`로 기록된다. 접속 해석 단계에서 실패해 기록이 없는 대상은 보고서 모델이 대상 목록과 비교해 찾아낸다. 셋 모두 보고서에 '점검불가'와 이유로 나온다.
- **보고서 모델**: `filter_plugins/host_audit.py`의 `host_audit_report_model(records, meta)` 하나가 판단·집계·라벨을 모두 정한다. 템플릿 `report.html.j2`는 모델을 그리기만 한다.
- **보고서 레이아웃**: A안(섹션 우선). 구성은 다음과 같다.
  - 표지: ISMS 2.11.2 필수 항목인 점검일시, 점검대상, 점검방법, 점검내용, 비교 기준, 점검 계정, 원본 보관
  - 요약: 점검불가 안내 포함
  - Asset Inventory 표
  - 검토·결재란
- **보고서 인쇄 CSS**: `@page { size: A4 }`, 섹션별 `break-before: page`, `thead` 반복, 시스템 한글 폰트 스택을 쓰고 외부 리소스는 쓰지 않는다.

## 2. 왜 구현해야 하는가? (Why)

ISMS 1.2.1(자산 식별)·2.11.2(정기 취약점 점검)는 자산 목록과 점검 결과를 증적으로 요구한다. 점검이 호스트를 바꾸면 증적으로 쓸 수 없으므로 수집은 조회만 한다(ADR-0009 §1). 후속 섹션이 모두 같은 흐름(수집 JSON → 모델 → 템플릿)에 붙도록 뼈대를 먼저 세운다.

## 3. 무엇을 변경하는가? (What Changes)

- **대상 호스트**: 변경 없음. 로그인과 명령 실행의 흔적(인증 로그, 로그인 기록)만 남는다(CONTEXT.md Host Audit의 허용 범위). molecule Fast Scenario가 실행 전후 `/etc`, `/usr`, 패키지 DB·캐시, cron spool의 체크섬·메타데이터가 같은지 확인한다(`VERIFY-AUD-010`).
- **러너**: `${HOST_AUDIT_OUTPUT_ROOT:-/tmp/host_audit}/<run_id>/` 아래에 파일을 만든다. 디렉터리는 `0700`, 파일은 `0600`이다.

```text
<run_id>/                 # 예: ha-20261008T220005Z (UTC 시작 시각)
├── hosts/<Inventory Hostname>.json   # 호스트별 원본 기록 (§4)
├── run.json                          # 실행 메타 (run_id, run_kind, started_at, target_hosts, output_dir, timezone, targets)
└── report.html                       # A4 인쇄용 보고서
```

## 4. 호스트별 JSON 구조 (schema_version 2)

```json
{
  "schema_version": 2,
  "inventory_hostname": "ns0332",
  "collected_at": "2026-10-08T22:00:07Z",
  "status": "ok",
  "reason": "",
  "declared": {
    "fqdn": "ns0332.nanoit.kr",
    "ip": "10.0.0.32",
    "environment": "production",
    "groups": ["servers"]
  },
  "identity": {
    "hostname": "ns0332",
    "fqdn": "ns0332.nanoit.kr",
    "ips": ["10.0.0.32"],
    "account": "ppzxc"
  },
  "os": {
    "id": "rocky",
    "version_id": "9.6",
    "name": "Rocky Linux 9.6 (Blue Onyx)",
    "redhat_release": "Rocky Linux release 9.6 (Blue Onyx)",
    "kernel": "5.14.0-570.el9.x86_64",
    "arch": "x86_64"
  }
}
```

| 필드 | 의미 |
|---|---|
| `status` | `ok`(수집 완료) · `unreachable`(접속 실패) · `probe_failed`(접속은 됐으나 수집 표식 없음) |
| `reason` | 점검불가 이유(첫 줄, 최대 200자). `ok`이면 빈 문자열 |
| `declared` | 인벤토리 값 (`fqdn`, `ip`, `host_agents_environment`, 그룹). 환경이 비면 보고서에 '미지정' |
| `identity` / `os` | 호스트에서 수집한 값. `status`가 `ok`가 아니면 `null`. `ips`는 루프백·링크 로컬을 뺀 전체 주소, `account`는 점검에 쓴 계정 |
| `os.name` | `/etc/os-release`의 `PRETTY_NAME`, 없으면(CentOS 6) `/etc/redhat-release` 첫 줄 |

후속 티켓은 필드를 추가하고 `schema_version`을 올린다. 기존 필드의 의미는 바꾸지 않는다.

## 5. 변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `host_audit_run_kind` | `on_demand` | `scheduled`(Audit Baseline이 됨) · `on_demand`. Semaphore 템플릿에 고정 |
| `host_audit_run_id` | `ha-<UTC 시작 시각>` | 실행 ID. 보통 지정하지 않음 |
| `host_audit_output_root` | env `HOST_AUDIT_OUTPUT_ROOT` 또는 `/tmp/host_audit` | 러너 출력 상위 경로 |
| `host_audit_scope_pattern` | `servers:loadbalancers:overseer` | 점검 대상 그룹 |
| `host_audit_timezone` | `Asia/Seoul` | 보고서 시각 표기 |
| `target_hosts` | (없음) | 일부 호스트만 점검할 때 Inventory Hostname 패턴 |

## 6. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `AUD-001` | `Assert Host Audit run kind is supported` | `ansible.builtin.assert` | 러너 | 읽기 전용 |
| `AUD-002` | `Fix the run start time once per run` | `ansible.builtin.set_fact` | 러너 | 읽기 전용 (실행당 1회 고정) |
| `AUD-003` | `Fix Host Audit run metadata` | `ansible.builtin.set_fact` | 러너 | 읽기 전용 |
| `AUD-004` | `Select Host Audit targets into the host_audit_targets group` | `ansible.builtin.add_host` | 러너 | 인메모리 그룹, `changed_when: false` |
| `AUD-005` | `Create the runner-local output directory for this run` | `ansible.builtin.file` | 러너 | 실행별 디렉터리 `0700` |
| `AUD-010` | `Probe host identity and OS (raw, read-only)` | `ansible.builtin.raw` | All (CentOS 6 ~ Rocky 10, Ubuntu) | 조회 전용, `changed_when: false`, `check_mode: false`, `ignore_unreachable: true` |
| `AUD-011` | `Build the per-host audit record` | `ansible.builtin.set_fact` | 러너 | `host_audit_host_record` 필터 |
| `AUD-100` | `Probe Asset Inventory (raw, read-only)` | `ansible.builtin.raw` (`become: true`) | All (CentOS 6 ~ Rocky 10, Ubuntu) | 조회 전용, `changed_when: false`, `check_mode: false`, `ignore_unreachable: true` |
| `AUD-101` | `Add Asset Inventory and declared values to the per-host record` | `ansible.builtin.set_fact` | 러너 | `host_audit_inventory_record` 필터 |
| `AUD-012` | `Save the per-host record on the runner` | `ansible.builtin.copy` | 러너 (`delegate_to: localhost`) | 실행별 파일 `0600` |
| `AUD-020` | `Find the per-host records of this run` | `ansible.builtin.find` | 러너 | 읽기 전용 |
| `AUD-021` | `Build the report model from the per-host records` | `ansible.builtin.set_fact` | 러너 | `host_audit_report_model` 필터 |
| `AUD-022` | `Save the run metadata on the runner` | `ansible.builtin.copy` | 러너 | 실행별 파일 `0600` |
| `AUD-023` | `Render the A4 report HTML` | `ansible.builtin.template` | 러너 | 실행별 파일 `0600` |
| `AUD-024` | `Show where the report was written` | `ansible.builtin.debug` | 러너 | 읽기 전용 |

## 7. Asset Inventory (#120)

ISMS 1.2.1 자산 목록. 수집 스크립트는 `roles/host_audit/files/inventory_probe.sh`(POSIX sh, sudo)이고, 판정은 `filter_plugins/host_audit_inventory.py`의 `inventory_section`이 한다. 보고서 모델의 `asset_inventory` 키로 들어가며 템플릿 조각은 `templates/sections/asset_inventory*.html.j2`, 호스트별 부록은 `sections/appendix*.html.j2`다.

| 영역 | 수집 (호스트) | 보고서 |
|---|---|---|
| 식별 | 호스트명, FQDN, IP (AUD-010) | 표 2.1 |
| OS·EOL | os-release / redhat-release, 커널, 아키텍처 | 표 2.2, EOS면 요약 경고 띠 |
| 하드웨어 | CPU 모델·수, 메모리, DMI 제조사·모델·시리얼, 마운트별 디스크 | 표 2.2 요약, 부록 상세 |
| 운영 | 가동 시간, 마지막 부팅, 시간 동기화(chrony / ntpd / timedatectl) | 표 2.2 |
| 패키지 | rpm / dpkg 전체 목록, 마지막 갱신일 | 수·마지막 갱신일·주요 패키지(kernel, openssl, openssh, glibc, sudo, docker) 버전만. **전체 목록은 호스트별 JSON에만** |
| listening 포트 | `ss -tlnp`/`-ulnp`(없으면 `netstat`) | 외부/로컬 수, 부록에 포트·프로세스 |
| 계정 | passwd, shadow(상태 단어만), wheel·sudo·admin 그룹, sudoers 규칙, lastlog(없으면 lastlog2) | 로그인 가능·특수권한 수, 표 2.3 발견 목록, 부록 계정 표 |
| Host Agents | otelcol-contrib·restic·resticprofile 바이너리, 서비스·백업 타이머/cron | 정상 / 일부 이상 / 미설치 / 제외(Host Agents Exclusion) |

**판정 규칙**

- **미지정**: `host_audit_asset`의 용도·관리 부서·책임자(직책)·관리자(직책)·보안등급 중 빈 값.
- **선언 외**: 특수권한자(uid 0, wheel·sudo·admin 그룹 구성원, sudoers 규칙 대상) 중 허용 목록에 없는 계정. 허용 목록은 `accounts`의 sudo 권한 계정(`sudo: true`, 또는 `sudo` 미지정 + `tier: admin`, `state: absent` 제외), `openbao_ssh_allowed_principals`, `host_audit_privileged_extra`, 그리고 root다. sudoers의 `User_Alias` 등 별칭은 펼치지 않는다.
- **장기 미사용**: 로그인 가능한 셸을 가진 계정 중 `lastlog -t 90`에 없는 계정(기록 없음 포함). 점검 계정과 uid 0 계정은 제외하고 표지에 명시한다. uid 0의 직접 로그인은 Configuration Vulnerability(KISA-2026) 항목이 다룬다. lastlog가 없으면 '마지막 로그인 점검불가'로 표시하고 장기 미사용 판정을 하지 않는다.
- **EOL**: `roles/host_audit/vars/main.yml`의 `host_audit_eol_table`(기준일 `reviewed_on`, 무상 표준 지원 종료일). 실행 시작일 기준 지난 날짜면 지원 종료(EOS), 180일 이내면 EOL 임박, 표에 없으면 확인 불가.
- **점검불가**: Asset Inventory 수집이 실패하면 '점검불가(수집 실패)', /etc/shadow를 읽지 못하면 '계정 잠금 상태 점검불가'.

**보안**: 비밀번호 해시는 호스트에서 `set`/`locked`/`empty`로 줄여서만 넘어온다. 선언 값에는 사람 이름이 아니라 직책을 적는다.

**읽기 전용**: 스크립트는 sudo로 돌지만 rpm 조회만은 `nobody`로 낮춰 실행한다(`setpriv`, 없으면 `su`). root로 `rpm -qa`를 돌리면 rpm이 DB를 쓰기 모드로 열어 EL9의 `rpmdb.sqlite-shm` 수정 시각(EL6/7은 Berkeley DB 환경 파일)이 바뀌기 때문이다. molecule `VERIFY-AUD-010`과 pytest의 `centos:6`/`centos:7` 컨테이너 시험이 관리 영역의 메타데이터까지 같은지 확인한다.

**선언 예시** (`inventory/host_vars/<Inventory Hostname>.yml`)

```yaml
host_audit_asset:
  purpose: "웹 서비스"
  department: "인프라팀"
  owner_role: "인프라팀장"
  admin_role: "시스템 관리자"
  security_grade: "2등급"
```

**호스트별 JSON 추가 필드 (schema_version 2)**: `declared.asset`(위 5개 + `privileged_allowlist`)과 `inventory`가 붙는다. 식별이 실패한 호스트는 `inventory: null`.

```json
"inventory": {
  "status": "ok", "reason": "",
  "hardware": {"cpu_model": "...", "cpu_count": 4, "mem_total_kb": 16266740,
               "dmi": {"vendor": "Dell Inc.", "product": "PowerEdge R640", "serial": "ABC1234"},
               "disks": [{"mount": "/", "fstype": "xfs", "size_kb": 52403200, "used_kb": 10485760}]},
  "operation": {"probe_epoch": 1791496805, "uptime_s": 864000, "boot_epoch": 1790632805,
                "timesync": {"tools": ["chrony"], "synced": true}},
  "packages": {"manager": "rpm", "count": 512, "last_update_epoch": 1791000000,
               "key": {"kernel": ["5.14.0-570.el9"], "openssl": [], "openssh": [], "glibc": [], "sudo": [], "docker": []},
               "all": [{"name": "glibc", "version": "2.34-168.el9", "arch": "x86_64"}]},
  "ports": [{"proto": "tcp", "address": "0.0.0.0", "port": 22, "process": "sshd"}],
  "accounts": {"users": [{"name": "ppzxc", "uid": 1000, "gid": 1000, "shell": "/bin/bash", "login": true,
                          "password": "set", "last_login": "pts/0 10.0.0.5 Thu Oct 8 ...", "recent_login": true}],
               "privileged": [{"name": "ppzxc", "via": ["group wheel"], "nopasswd": true}],
               "shadow_readable": true, "lastlog_available": true},
  "host_agents": {"otelcol": {"installed": true, "active": true},
                  "backup": {"installed": true, "scheduled": true}}
}
```

| 변수 | 기본값 | 설명 |
|---|---|---|
| `host_audit_asset` | `{}` | 선언 값 (위 예시) |
| `host_audit_privileged_extra` | `[]` | 특수권한 허용 목록에 더할 이름 |

## 8. 검증

- **pytest** `tests/test_host_audit.py`는 다음을 검증한다.
  - 기록과 보고서 모델: 접속 실패, 기록 없음, 미지정, FQDN 불일치, KST 표기
  - 프로브 스크립트 출력 형식
  - 템플릿의 인쇄 CSS와 외부 리소스 부재
- **pytest** `tests/test_host_audit_inventory.py`는 Asset Inventory를 검증한다.
  - 수집 결과 해석: 8개 영역, 특수권한 근거, 비밀번호 해시 미포함, CentOS 6 출력(netstat, epoch 없는 rpm)
  - 보고서 모델: 미지정·선언 외·90일 장기 미사용(점검 계정·uid 0 제외)·EOS/임박/미확인·전체 패키지 목록 미포함·수집 실패 점검불가
  - 수집 스크립트를 이 머신과 `centos:6`·`centos:7` 컨테이너(이미지가 로컬에 있을 때)에서 실제로 실행
- **molecule Fast Scenario** `molecule/fast/verify.yml`:
  - `VERIFY-AUD-010`: 수집(식별 + Asset Inventory) 전후 관리 영역의 체크섬·메타데이터가 같은지 확인한다.
  - `VERIFY-AUD-012`: 러너에 저장된 JSON 구조를 확인한다.
  - `VERIFY-AUD-100`: Asset Inventory 기록의 영역별 구조와 값(패키지 수, root 계정, sshd 포트 등)을 확인한다.

## 9. Package Vulnerability (#123)

설치 패키지 버전이 CVE·벤더 권고에 해당하는지 판정한다(ISMS 2.10.8 · 2.11.2). Vuls는 PoC(#112)에서 기각했고(CentOS 7 CVE 69건 누락, EOL 경고 없음, DB 13.6 GB), Trivy를 SBOM 입력으로 쓴다.

- **호스트(읽기 전용)**: `files/package_probe.sh`를 `raw`로 실행해 릴리스 파일과 패키지 DB만 읽는다(`rpm -qa --queryformat` / `dpkg-query -W`). 아무것도 설치하지 않고 원격 파일도 만들지 않는다. CentOS 6/7도 같은 경로다. 식별 수집(AUD-010)이 `ok`인 호스트만 수집한다. root로 접속한 경우 rpm은 `nobody`로 조회한다(root로 열면 EL9 `rpmdb.sqlite-shm`이 바뀜, #120과 같은 방식). Asset Inventory의 패키지 목록(#120)과 별도로 읽는 이유는 Trivy 판정에 소스 패키지(rpm `SOURCERPM`, deb `source:Package`·`source:Version`)와 EL8+ 모듈 레이블이 필요하기 때문이다.
- **러너**: 패키지 기록 → CycloneDX 1.5 SBOM(`host_audit_sbom`) → `trivy sbom --offline-scan --skip-db-update`(호스트마다 순차) → 분류(`host_audit_package_findings`) → 섹션 모델(`host_audit_package_section`). 판정·분류·집계는 모두 `filter_plugins/host_audit_packages.py`가 하고 템플릿(`templates/sections/package_vulnerability.html.j2`)은 그리기만 한다.
- **Trivy 고정**: `vars/trivy.yml`의 버전·SHA256(직접 계산한 값, upstream checksums.txt를 기준으로 쓰지 않음)과 맞는 릴리스만 `get_url checksum`으로 받아 러너 캐시(`host_audit_cache_dir`)에 풀고 실행한다. restic(BAK-075)과 같은 방식이고 커스텀 Semaphore 이미지가 필요 없다. 버전을 올릴 때는 sigstore 번들을 `cosign verify-blob`으로 검증한 뒤 sha256을 직접 계산해 넣는다(절차는 파일 머리말). 2026-03 공급망 사고(GHSA-69fq-xp46-6x23)의 v0.69.4는 쓰지 않는다. 현재 v0.75.0(amd64·arm64 모두 cosign 검증 통과, 2026-10-08).
- **취약점 DB**: 매 실행 `trivy image --download-db-only`로 갱신한다(`host_audit_trivy_db_repository`로 미러 지정 가능). 갱신에 실패하면 캐시 DB의 `UpdatedAt`이 7일(`host_audit_trivy_db_max_age_days`) 이내일 때만 그 캐시로 판정하고, 넘었거나 캐시가 없으면 섹션 전체를 '점검불가'로 표시한다(실행은 계속). DB 생성 시각과 갱신 여부는 표지의 '취약점 DB'에 찍힌다. 캐시가 실행 사이에 남으려면 러너의 `HOME`(또는 `host_audit_cache_dir`)이 유지돼야 한다.
- **OS 인식 검사**: Trivy가 결과의 `Metadata.OS`를 수집한 OS 계열·버전과 다르게 인식하면 그 호스트를 '점검불가(OS 인식 불일치)'로 표시한다. OS를 인식하지 못하면 0건이 조용히 나오기 때문이다(PoC 함정).
- **분류** (건수는 (CVE, 패키지) 쌍 기준, Audit Baseline 동일성 키는 `CVE|패키지`):

| 분류 | 조건 |
|---|---|
| 업데이트 가능 | Trivy `fixed`이고, CentOS 6/7이면 수정 버전이 CentOS vault 최종판 이하 |
| CentOS용 수정본 없음 | CentOS 6/7에서 수정 버전이 vault 최종판보다 높음(RHEL ELS 전용 수정) 또는 vault에 없는 패키지 |
| 수정 안 함 (will not fix) | Red Hat `will_not_fix`. 상세 표에서 빼고 건수만 따로 센다 |
| 벤더 미수정 | `affected`, `fix_deferred`, `under_investigation`, `end_of_life` 등 수정 버전이 없음 |

- **CentOS vault 최종판 표**: `files/centos_vault_final/centos-{6,7}.tsv`(패키지 이름 → `vault.centos.org/{6.10,7.9.2009}/{os,updates}/x86_64/Packages/`의 최대 version-release). 파일 이름에 epoch가 없으므로 비교는 epoch를 빼고 한다. CentOS 6/7은 동결됐으므로 다시 만들 필요가 없다.
- **보고서**: 위험도별 inline SVG 막대, 분류별 건수, 호스트별 건수(EOS 표시), 긴급·높음 상세(will-not-fix 제외, 최대 `host_audit_package_detail_limit`행). 전체 패키지 목록과 전체 발견은 러너 파일에만 남는다.

```text
<run_id>/
├── packages/<Inventory Hostname>.json   # 패키지 기록 (아래)
├── sbom/<Inventory Hostname>.cdx.json   # Trivy 입력 SBOM
├── trivy/<Inventory Hostname>.json      # Trivy 원본 결과
└── package_vulnerability.json           # 섹션 모델 (DB 상태, 호스트별 건수, 상세)
```

패키지 기록(`schema_version` 1): `inventory_hostname`, `collected_at`, `status`(`ok` · `unreachable` · `probe_failed` · `unsupported`), `reason`, `os`(`family` = Trivy OS 계열, `version`, `major`, `name`, `arch`), `format`(`rpm` · `deb`), `packages`(각 `name`, `epoch`, `version`, `release`, `arch`, `src_name`, `src_epoch`, `src_version`, `src_release`, `modularitylabel`).

**SBOM 변환 검증**: `tests/fixtures/host_audit_packages`는 Rocky 8/9, CentOS 6/7, Ubuntu 22.04, Debian 13 공식 이미지에서 `package_probe.sh`를 실행한 출력과, 같은 이미지의 `trivy image` 결과((CVE, 패키지, 설치 버전, 상태, 수정 버전) 쌍)다. 변환한 SBOM을 `trivy sbom`으로 판정한 결과가 6개 OS 모두 `trivy image`와 같았고(차이 0, 2026-10-08, Trivy 0.75.0), 그 SBOM의 sha256을 `sbom_equivalence.json`에 고정했다. 변환기 출력이 바뀌면 pytest가 실패한다. 그때는 같은 비교(이미지에서 프로브 실행 → SBOM → `trivy sbom`과 `trivy image`의 쌍 비교)를 다시 돌려 차이 0을 확인한 뒤 픽스처를 갱신한다.

| 변수 | 기본값 | 설명 |
|---|---|---|
| `host_audit_packages_enabled` | `true` | false면 패키지 수집·판정을 건너뛴다 |
| `host_audit_cache_dir` | `$HOME/.cache/host-audit` | Trivy 바이너리·DB 캐시 |
| `host_audit_trivy_db_max_age_days` | `7` | 갱신 실패 시 허용하는 캐시 DB 나이 |
| `host_audit_trivy_db_repository` | (Trivy 기본값) | 취약점 DB 미러 |
| `host_audit_trivy_db_timeout` | `300` | DB 갱신 최대 시간(초). 넘으면 갱신 실패로 보고 캐시 규칙 적용 |
| `host_audit_package_detail_limit` | `300` | 긴급·높음 상세 최대 행 수 |

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `AUD-300` | `Ensure the runner-local package record directory exists` | `ansible.builtin.file` | 러너 (`delegate_to: localhost`) | 실행별 디렉터리 `0700` |
| `AUD-301` | `Probe installed packages and release (raw, read-only)` | `ansible.builtin.raw` | All (CentOS 6 ~ Rocky 10, Ubuntu/Debian) | 조회 전용, `changed_when: false`, `check_mode: false`, `ignore_unreachable: true` |
| `AUD-302` | `Save the per-host package record on the runner` | `ansible.builtin.copy` | 러너 (`delegate_to: localhost`) | 실행별 파일 `0600` |
| `AUD-310` | `Find the per-host package records of this run` | `ansible.builtin.find` | 러너 | 읽기 전용 |
| `AUD-311` | `Load the pinned Trivy version table` | `ansible.builtin.include_vars` | 러너 | 읽기 전용 |
| `AUD-312` | `Detect the runner architecture for the pinned Trivy` | `ansible.builtin.command` | 러너 | `changed_when: false` |
| `AUD-313` | `Assert the runner architecture is in the pinned Trivy table` | `ansible.builtin.assert` | 러너 | 읽기 전용 |
| `AUD-314` | `Ensure the runner Trivy cache and this run's scan directories exist` | `ansible.builtin.file` | 러너 | 디렉터리 `0700` |
| `AUD-315` | `Download the pinned Trivy release on the runner and verify SHA256` | `ansible.builtin.get_url` | 러너 | `checksum: sha256:` (불일치 시 실패) |
| `AUD-316` | `Extract the verified Trivy binary into the runner cache` | `ansible.builtin.unarchive` | 러너 | `creates` |
| `AUD-317` | `Fix the runner Trivy command line` | `ansible.builtin.set_fact` | 러너 | 읽기 전용 |
| `AUD-318` | `Refresh the Trivy vulnerability DB (download only)` | `ansible.builtin.command` | 러너 | `changed_when: false`, `failed_when: false`, `timeout`으로 시간 제한(실패는 AUD-319가 판정) |
| `AUD-319` | `Decide whether the Trivy DB may be used for this run` | `ansible.builtin.set_fact` | 러너 | `host_audit_trivy_db_state` 필터 |
| `AUD-320` | `Write the CycloneDX SBOM of each collected host` | `ansible.builtin.copy` | 러너 | 실행별 파일 `0600` |
| `AUD-321` | `Judge each SBOM with Trivy (offline, one host at a time)` | `ansible.builtin.command` | 러너 | `changed_when: false`, 결과 파일 없으면 호스트 '점검불가' |
| `AUD-322` | `Classify the Trivy findings of each host` | `ansible.builtin.set_fact` | 러너 | `host_audit_package_findings` 필터 |
| `AUD-323` | `Build the Package Vulnerability section model` | `ansible.builtin.set_fact` | 러너 | `host_audit_package_section` 필터 |
| `AUD-324` | `Save the Package Vulnerability section on the runner` | `ansible.builtin.copy` | 러너 | 실행별 파일 `0600` |

검증: pytest `tests/test_host_audit_packages.py`(기록 파싱, SBOM 동등성 고정, DB 7일 규칙, CentOS 수정본 없음·will-not-fix 분류, 섹션·보고서 모델, 템플릿, Trivy 고정). molecule Fast Scenario는 패키지 프로브를 포함한 수집 전후 관리 영역이 같은지(`VERIFY-AUD-010`)와 패키지 기록 구조(`VERIFY-AUD-302`)를 확인한다. Trivy 판정 자체는 molecule 범위 밖이다(스펙 #115 테스트 결정 ②).

## 10. Configuration Vulnerability (KISA-2026, #121)

- **기준**: KISA 「2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」 Unix 서버 항목. 항목 코드는 판을 붙여 `KISA-2026:U-NN`으로 적는다(2021판과 번호가 다르다). CIS RHEL 9 Benchmark v2.0.0 규칙 번호는 참조 열로만 둔다. 근거: `docs/research/host-audit-configuration-vulnerability-baseline.md`(#102, `research/host-audit-configuration-vulnerability-baseline` 브랜치).
- **구현 범위**: 계정 관리 분류 U-01~U-13. 나머지 분류(파일 및 디렉토리 관리 U-14~U-33, 서비스 관리 U-34~U-63, 패치 관리 U-64, 로그 관리 U-65~U-67)는 같은 틀에 항목 스크립트와 `ITEMS` 항목을 더해 붙인다.
- **실행**: `roles/host_audit/files/kisa/`의 `_lib.sh` + `U-NN.sh`(이름순) + `_end.sh`를 이어 붙여 `ansible.builtin.raw`로 `sh -s`에 넣는다. 호스트에 파일을 남기지 않고 Python이 필요 없어 CentOS 6 ~ Rocky 10, Ubuntu에서 같은 경로로 돈다. `/etc/shadow`와 `sshd -T`를 읽어야 해서 이 태스크만 root로 승격한다. 식별 수집(`AUD-010`)에 실패한 호스트는 건너뛴다.
- **출력 규약**: 표식(`__HOST_AUDIT_KISA_BEGIN__`/`__HOST_AUDIT_KISA_END__`) 사이에 항목마다 `U-NN|<GOOD·VULN·NA·MANUAL>|증적` 한 줄. 증적은 설정 값·계정 이름·개수만 담고 비밀번호 해시 같은 비밀값은 싣지 않는다. 스크립트는 `KISA_ROOT`로 점검할 루트를 바꿀 수 있어 pytest가 가짜 `/etc`로 판정을 검증한다.
- **판정 5종**: 양호 · 취약 · 예외(승인) · 해당없음 · 점검불가(수동). 스크립트가 결과를 내지 않은 항목은 양호로 두지 않고 점검불가(수동)로 둔다. 판정과 예외 적용은 `filter_plugins/host_audit_kisa.py`의 `host_audit_kisa_result`가 한다.
- **예외 레지스터**: `host_audit_kisa_exceptions`(role defaults, Git). 항목마다 `code`, 적용 범위(`hosts`/`groups`, 비우면 전체), `reason`(사유), `risk`(위험성), `mitigation`(보완대책), `approver`(직책), `approved_on`, `expires_on`을 둔다(ISMS 2.11.2 "사유·위험성·보완대책 보고", 결함사례 2 "승인 이력").

  | 레지스터 상태 | 조건 | 판정에 미치는 영향 |
  |---|---|---|
  | 유효 | 필수 항목·승인자·승인일이 있고 만료일이 실행일(KST) 이후 | 취약·점검불가(수동) → 예외(승인) |
  | 만료 | 만료일이 실행일보다 앞 | 취약·점검불가(수동) → 취약 |
  | 승인 대기 | 승인자 또는 승인일이 없음 | 바꾸지 않음(보고서에 '승인 대기' 표시) |
  | 형식 오류 | 사유·위험성·보완대책 중 빠진 것이 있거나 만료일이 날짜가 아님 | 바꾸지 않음 |

  양호·해당없음은 예외가 있어도 바뀌지 않는다. 첫 항목은 Docker 구간의 `KISA-2026:U-28`(접속 IP 및 포트 제한)이며 승인 전이라 '승인 대기'다. U-28 점검이 구현되면 그때부터 판정에 적용된다.
- **보고서**: "4. Configuration Vulnerability" 섹션에 항목별 판정 건수, 양호 외 항목(취약·점검불가(수동)·예외(승인), 항목·판정별로 호스트 묶음), 예외 레지스터를 싣는다. 양호 항목과 증적은 호스트별 부록(`sections/appendix_config_vulnerability.html.j2`)에 싣는다. 섹션 모델은 `host_audit_report_model`이 `host_audit_kisa_section`을 불러 `config_vulnerability` 키로 넣고, 예외 레지스터는 실행 메타의 `kisa_exceptions`로 넘어간다. 점검이 돌지 못한 호스트는 요약의 점검불가 표에 'Configuration Vulnerability'로 나온다.

### 10.1 구현 항목 (계정 관리)

| 코드 | 항목 (중요도) | 자동 판정 방법 | CIS 참조 |
|---|---|---|---|
| `KISA-2026:U-01` | root 계정 원격 접속 제한 (상) | `sshd -T`(실패 시 `sshd_config`)의 `PermitRootLogin`이 `no`이고 telnet(23/tcp) listening이 없으면 양호 | 5.1.20 |
| `KISA-2026:U-02` | 비밀번호 관리정책 설정 (상) | `PASS_MAX_DAYS` ≤ 90, `PASS_MIN_DAYS` ≥ 1, 문자 종류 3종+8자 또는 2종+10자(pwquality·PAM 인자) | 5.3.3.2.2, 5.3.3.2.3, 5.4.1.1, 5.4.1.2 |
| `KISA-2026:U-03` | 계정 잠금 임계값 설정 (상) | auth 스택 pam_faillock·pam_tally2·pam_tally의 `deny`(없으면 faillock.conf, 기본 3)가 1~10 | 5.3.3.1.1 |
| `KISA-2026:U-04` | 비밀번호 파일 보호 (상) | `/etc/passwd` 비밀번호 필드가 모두 `x`(잠금 표시 허용)이고 `/etc/shadow` 존재 | 7.2.1 |
| `KISA-2026:U-05` | root 이외의 UID가 '0' 금지 (상) | UID 0 계정이 root뿐 | 5.4.2.1 |
| `KISA-2026:U-06` | 사용자 계정 su 기능 제한 (상) | `/etc/pam.d/su`의 pam_wheel.so, 또는 su가 root 외 그룹 소유·other 실행 불가. su 없으면 해당없음 | 5.2.7 |
| `KISA-2026:U-07` | 불필요한 계정 제거 (하) | 점검불가(수동) — 로그인 가능 계정 목록을 증적으로 | - |
| `KISA-2026:U-08` | 관리자 그룹에 최소한의 계정 포함 (중) | 점검불가(수동) — GID 0 그룹·기본 그룹 GID 0 계정·wheel/sudo/admin 구성원을 증적으로 | 5.4.2.2, 5.4.2.3 |
| `KISA-2026:U-09` | 계정이 존재하지 않는 GID 금지 (하) | 모든 계정의 기본 GID가 `/etc/group`에 있음 | 7.2.3 |
| `KISA-2026:U-10` | 동일한 UID 금지 (중) | 중복 UID 없음 | 7.2.4 |
| `KISA-2026:U-11` | 사용자 shell 점검 (하) | 가이드가 나열한 시스템 계정(daemon, bin, sys, adm, listen, nobody, nobody4, noaccess, diag, operator, games, gopher)의 셸이 nologin/false | 5.4.2.7 |
| `KISA-2026:U-12` | 세션 종료 시간 설정 (하) | 전역 sh 프로필의 `TMOUT`이 1~600초(여러 곳이면 가장 큰 값) | 5.4.3.2 |
| `KISA-2026:U-13` | 안전한 비밀번호 암호화 알고리즘 사용 (중) | `/etc/shadow`에 MD5·Blowfish·DES 해시가 없고 `ENCRYPT_METHOD`·pam_unix 설정이 약한 알고리즘이 아님 | 5.3.3.4.3, 5.4.1.4 |

항목명·중요도·판단 기준 문장은 `9u4a/kisa-infra-audit`(MIT, 2026판 기준)가 가이드에서 인용한 항목 설명을 따랐고, 873쪽 PDF 원문과 직접 대조하지는 않았다. 판정 스크립트는 그 설명을 참고해 새로 작성했다(코드 차용 없음).

### 10.2 호스트별 JSON 추가 필드

```json
"config_vulnerability": {
  "edition": "KISA-2026",
  "status": "ok",
  "reason": "",
  "results": [
    {"code": "KISA-2026:U-02", "result": "VULN", "verdict": "예외(승인)",
     "evidence": "PASS_MAX_DAYS=99999 PASS_MIN_DAYS=0 ...",
     "exception": {"state": "유효", "reason": "...", "risk": "...", "mitigation": "...",
                   "approver": "정보보호 책임자", "approved_on": "2026-09-01", "expires_on": "2026-12-31"}}
  ]
}
```

`result`는 스크립트 원판정(`GOOD`·`VULN`·`NA`·`MANUAL`, 출력이 없으면 `NONE`), `verdict`는 예외 레지스터를 적용한 최종 판정이다. 점검이 돌지 못하면 `status`가 `failed`이고 `results`는 비어 있다. 식별 수집에 실패한 호스트에는 이 필드가 없다.

### 10.3 태스크 매트릭스

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `AUD-200` | `Run KISA-2026 Unix checks (raw, read-only)` | `ansible.builtin.raw` | All (CentOS 6 ~ Rocky 10, Ubuntu) | 조회 전용, `changed_when: false`, `check_mode: false`, `ignore_unreachable: true`, root 승격 |
| `AUD-201` | `Add KISA-2026 verdicts to the per-host audit record` | `ansible.builtin.set_fact` | 러너 | `host_audit_kisa_result` 필터 |

검증: pytest `tests/test_host_audit_kisa.py`(판정 5종, 예외 유효·만료·승인 대기·범위, 보고서 섹션·부록, 가짜 루트에서의 스크립트 판정과 해시 미노출), molecule Fast `VERIFY-AUD-200`·`VERIFY-AUD-201`(점검 실행·판정 기록). 읽기 전용은 `VERIFY-AUD-010` 스냅샷 사이에서 함께 확인된다.
