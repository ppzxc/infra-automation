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
- **구현 범위**: Unix U-01~U-67 전 항목. 계정 관리 U-01~U-13(#121), 파일 및 디렉토리 관리 U-14~U-33, 서비스 관리 U-34~U-63, 패치 관리 U-64, 로그 관리 U-65~U-67(#122). 자동 판정할 수 없는 항목은 점검불가(수동)로 두고 판단에 쓸 목록을 증적으로 남긴다(§10.1·§10.4).
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

  양호·해당없음은 예외가 있어도 바뀌지 않는다. 첫 항목은 Docker 구간의 `KISA-2026:U-28`(접속 IP 및 포트 제한)이며 승인 전이라 '승인 대기'다. U-28은 Docker가 도는 호스트(`dockerd` 실행 또는 `docker0`)를 점검불가(수동)로 내므로, 승인자·승인일·만료일을 채우면 그 호스트들이 예외(승인)가 된다. 레지스터는 항목 코드 단위라, Docker 호스트에 방화벽 제한이 전혀 없어 취약으로 나온 경우에도 같은 예외가 적용된다는 점에 유의한다(증적에 `docker=yes`와 "no IP/port restriction"이 함께 남는다).
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

항목명·중요도·판단 기준 문장은 `9u4a/kisa-infra-audit`(MIT, 2026판 기준)가 가이드에서 인용한 항목 설명을 따랐고, 873쪽 PDF 원문과 직접 대조하지는 않았다. 판정 스크립트는 그 설명을 참고해 새로 작성했다(코드 차용 없음). §10.4도 같다.

### 10.4 구현 항목 (파일 및 디렉토리·서비스·패치·로그 관리, #122)

공통 규칙:
- **서비스 사용 여부**: 프로세스 이름(`ps -e -o comm=`), systemd unit active(`systemctl is-active`), (x)inetd 항목(`/etc/xinetd.d/NAME`의 `disable = yes` 아님, `inetd.conf`의 주석 아닌 줄), 필요한 경우 TCP listening(`ss`·`netstat`) 중 하나라도 있으면 사용 중으로 본다. 서비스를 쓰지 않아 기준이 성립하지 않는 항목은 해당없음이다.
- **파일 탐색**: U-15·U-23·U-25는 루트(/)와 로컬 디스크 파일시스템(ext2/3/4·xfs·btrfs) 마운트를 `find -xdev`로 뒤진다(가상·네트워크 파일시스템 제외). 각 탐색은 120초 제한이며, 넘으면 점검불가(수동)다.
- **읽기 전용**: 커널 모듈을 올릴 수 있는 방화벽 조회(`nft`, 레거시 `iptables`)는 해당 모듈이 이미 올라와 있을 때만 한다. sendmail 버전은 실행하지 않고 `sendmail.cf`의 `DZ` 줄로 읽는다. rpm은 조회하지 않는다.
- **비밀값**: SNMP community는 길이·문자 종류만 판정하고 값은 증적에 싣지 않는다.

| 코드 | 항목 (중요도) | 자동 판정 방법 | CIS 참조 |
|---|---|---|---|
| `KISA-2026:U-14` | root 홈, 패스 디렉터리 권한 및 패스 설정 (상) | 전역 프로필·`/etc/environment`·root 시작 파일의 `PATH=` 값에 `.` 또는 빈 항목이 맨 뒤가 아닌 위치에 없음 | - |
| `KISA-2026:U-15` | 파일 및 디렉터리 소유자 설정 (상) | `-nouser`·`-nogroup` 파일 없음 | 7.1.12 |
| `KISA-2026:U-16` | /etc/passwd 파일 소유자 및 권한 설정 (상) | root, 644 이하 | 7.1.1 |
| `KISA-2026:U-17` | 시스템 시작 스크립트 권한 설정 (상) | `/etc/rc.d/init.d`·`/etc/init.d`·`/etc/systemd/system` 일반 파일이 root 소유, 그룹·기타 쓰기 없음(755 이하). 파일이 없으면 해당없음 | - |
| `KISA-2026:U-18` | /etc/shadow 파일 소유자 및 권한 설정 (상) | root, 400 이하 | 7.1.5 |
| `KISA-2026:U-19` | /etc/hosts 파일 소유자 및 권한 설정 (상) | root, 644 이하 | - |
| `KISA-2026:U-20` | /etc/(x)inetd.conf 파일 소유자 및 권한 설정 (상) | root, 600 이하. 둘 다 없으면 해당없음 | - |
| `KISA-2026:U-21` | /etc/(r)syslog.conf 파일 소유자 및 권한 설정 (상) | root·bin·sys, 640 이하. 둘 다 없으면 해당없음 | - |
| `KISA-2026:U-22` | /etc/services 파일 소유자 및 권한 설정 (상) | root·bin·sys, 644 이하 | - |
| `KISA-2026:U-23` | SUID, SGID, Sticky bit 설정 파일 점검 (상) | 점검불가(수동) — SUID/SGID 파일 목록(최대 40개)을 증적으로. 없으면 양호 | 7.1.13 |
| `KISA-2026:U-24` | 사용자, 시스템 환경변수 파일 소유자 및 권한 설정 (상) | 로그인 계정 홈의 `.profile`·`.bashrc` 등이 root 또는 해당 계정 소유, 그룹·기타 쓰기 없음 | 7.2.10 |
| `KISA-2026:U-25` | world writable 파일 점검 (상) | 없으면 양호, 있으면 점검불가(수동) — 목록(최대 30개)을 증적으로 | 7.1.11 |
| `KISA-2026:U-26` | /dev에 존재하지 않는 device 파일 점검 (상) | `/dev` 아래 일반 파일 없음(`/dev/shm`·`/dev/mqueue`·`/dev/hugepages` 제외) | - |
| `KISA-2026:U-27` | $HOME/.rhosts, hosts.equiv 사용 금지 (상) | 파일이 없거나, 있으면 root/해당 계정 소유·600 이하·`+` 없음 | - |
| `KISA-2026:U-28` | 접속 IP 및 포트 제한 (상) | firewalld 기본 zone target이 ACCEPT 아님, ufw active, nftables input drop 정책·`saddr` 규칙, 레거시 iptables INPUT DROP·`-s` 규칙, `hosts.deny` `ALL: ALL` 중 하나. Docker 호스트는 점검불가(수동) | 4.1.2 |
| `KISA-2026:U-29` | hosts.lpd 파일 소유자 및 권한 설정 (하) | 없거나, root·600 이하 | - |
| `KISA-2026:U-30` | UMASK 설정 관리 (중) | 전역 프로필·`login.defs`의 모든 umask 값이 022 비트를 포함. 지정이 없으면 취약 | 5.4.3.3 |
| `KISA-2026:U-31` | 홈디렉토리 소유자 및 권한 설정 (중) | 로그인 계정 홈이 해당 계정 소유, 기타 쓰기 없음 | 7.2.9 |
| `KISA-2026:U-32` | 홈 디렉토리로 지정한 디렉토리의 존재 관리 (중) | 로그인 계정의 홈 디렉터리가 모두 존재 | 7.2.9 |
| `KISA-2026:U-33` | 숨겨진 파일 및 디렉토리 검색 및 제거 (하) | 점검불가(수동) — 로그인 홈·`/tmp`·`/var/tmp`·`/dev`의 숨김 항목 중 통상 항목(`.ssh`, `.bashrc` 등) 외 목록. 없으면 양호 | - |
| `KISA-2026:U-34` | Finger 서비스 비활성화 (상) | finger 서비스·79/tcp 없음 | - |
| `KISA-2026:U-35` | 공유 서비스에 대한 익명 접근 제한 설정 (상) | vsftpd `anonymous_enable=YES`, proftpd `<Anonymous>`, exports `no_root_squash`·`anonuid=0`, Samba `guest ok = yes`가 없음 | - |
| `KISA-2026:U-36` | r 계열 서비스 비활성화 (상) | rlogin·rsh·rexec 서비스·512~514/tcp 없음 | - |
| `KISA-2026:U-37` | crontab 설정파일 권한 설정 미흡 (상) | `/usr/bin/crontab`·`/usr/bin/at` 750 이하, `/etc/crontab`·`cron.allow/deny`·`at.allow/deny` root·640 이하. 모두 없으면 해당없음 | 2.4.1.2~2.4.1.8, 2.4.2.1 |
| `KISA-2026:U-38` | DoS 공격에 취약한 서비스 비활성화 (상) | echo·discard·daytime·chargen (x)inetd 항목·7/9/13/19 tcp 없음 | - |
| `KISA-2026:U-39` | 불필요한 NFS 서비스 비활성화 (상) | NFS 서버(nfsd·nfs-server) 없음. 필요하면 예외 레지스터 | - |
| `KISA-2026:U-40` | NFS 접근 통제 (상) | 모든 export가 허용 호스트 지정(`*`·호스트 없음 아님), `/etc/exports` root·644 이하. NFS 서버 없으면 해당없음 | - |
| `KISA-2026:U-41` | 불필요한 automountd 제거 (상) | automount(autofs) 없음 | - |
| `KISA-2026:U-42` | 불필요한 RPC 서비스 비활성화 (상) | 가이드 목록(rpc.cmsd, rpc.ttdbserverd, sadmind, rusersd, walld, sprayd, rstatd, rpc.nisd, rexd, rpc.pcnfsd, rpc.statd, rpc.ypupdated, rpc.rquotad, kcms_server, cachefsd) 없음 | - |
| `KISA-2026:U-43` | NIS, NIS+ 점검 (상) | ypserv·ypbind·ypxfrd·yppasswdd 없음 | - |
| `KISA-2026:U-44` | tftp, talk 서비스 비활성화 (상) | tftp·talk·ntalk 없음 | - |
| `KISA-2026:U-45` | 메일 서비스 버전 점검 (상) | 점검불가(수동) — 사용 중인 MTA와 버전(postfix `mail_version`, sendmail.cf `DZ`, `exim -bV`). 알려진 취약 버전은 Package Vulnerability. MTA 없으면 해당없음 | - |
| `KISA-2026:U-46` | 일반 사용자의 메일 서비스 실행 방지 (상) | sendmail `PrivacyOptions`에 `restrictqrun`, postfix `postsuper`·exim `exiqgrep`에 기타 실행 권한 없음 | - |
| `KISA-2026:U-47` | 스팸 메일 릴레이 제한 (상) | postfix relay·recipient restrictions에 `reject_`/`defer_unauth_destination`, sendmail `promiscuous_relay` 없음. exim은 점검불가(수동) | - |
| `KISA-2026:U-48` | expn, vrfy 명령어 제한 (중) | postfix `disable_vrfy_command = yes`, sendmail `noexpn`+`novrfy` 또는 `goaway`. exim은 점검불가(수동) | - |
| `KISA-2026:U-49` | DNS 보안 버전 패치 (상) | 점검불가(수동) — `named -v`. named 없으면 해당없음 | - |
| `KISA-2026:U-50` | DNS ZoneTransfer 설정 (상) | named 설정(+include 1단계)에 `allow-transfer`가 있고 `any`가 아님 | - |
| `KISA-2026:U-51` | DNS 서비스의 취약한 동적 업데이트 설정 금지 (중) | `allow-update`가 없거나 `any`가 아님 | - |
| `KISA-2026:U-52` | Telnet 서비스 비활성화 (중) | telnet 서비스·`telnet.socket`·23/tcp 없음 | - |
| `KISA-2026:U-53` | FTP 서비스 정보 노출 제한 (하) | vsftpd `ftpd_banner` 지정, proftpd `ServerIdent` 제한. pure-ftpd는 점검불가(수동). FTP 없으면 해당없음 | - |
| `KISA-2026:U-54` | 암호화되지 않는 FTP 서비스 비활성화 (중) | FTP 데몬·21/tcp 없음, 또는 vsftpd `ssl_enable=YES`이고 SSL 강제를 끄지 않음 | - |
| `KISA-2026:U-55` | FTP 계정 shell 제한 (중) | `ftp` 계정 셸이 nologin/false. 계정 없으면 해당없음 | - |
| `KISA-2026:U-56` | FTP 서비스 접근 제어 설정 (하) | TCP Wrapper에 FTP 데몬(또는 ALL) 항목, proftpd `<Limit LOGIN>`. FTP 없으면 해당없음 | - |
| `KISA-2026:U-57` | Ftpusers 파일 설정 (중) | `ftpusers`·vsftpd `user_list`에 root, proftpd `RootLogin on` 아님. FTP 없으면 해당없음 | - |
| `KISA-2026:U-58` | 불필요한 SNMP 서비스 구동 점검 (중) | snmpd 없음. 필요하면 예외 레지스터 | - |
| `KISA-2026:U-59` | 안전한 SNMP 버전 사용 (상) | snmpd.conf에 v1/v2c(`rocommunity`·`rwcommunity`·`com2sec`) 없음. snmpd 없으면 해당없음 | - |
| `KISA-2026:U-60` | SNMP Community String 복잡성 설정 (중) | 모든 community가 public·private 아니고 영문+숫자 10자 이상 또는 영문+숫자+특수 8자 이상(값 비노출). v3 전용은 점검불가(수동) | - |
| `KISA-2026:U-61` | SNMP Access Control 설정 (상) | community 항목마다 source가 default가 아님. v3 전용은 점검불가(수동) | - |
| `KISA-2026:U-62` | 로그인 시 경고 메시지 설정 (하) | `/etc/motd` 또는 `/etc/issue`에 OS 이름·escape 외 문구가 있고, sshd `Banner` 지정, telnet 사용 시 `/etc/issue.net` | 1.7.1~1.7.3, 5.1.5 |
| `KISA-2026:U-63` | sudo 명령어 접근 관리 (중) | `/etc/sudoers` root·640 이하. 없으면 해당없음 | - |
| `KISA-2026:U-64` | 주기적 보안 패치 및 벤더 권고사항 적용 (상) | 점검불가(수동) — OS·커널을 증적으로. 미적용 보안 패치는 같은 보고서의 Package Vulnerability가 판정 | - |
| `KISA-2026:U-65` | NTP 및 시각 동기화 설정 (중) | chronyd·ntpd가 돌고 `server`/`pool` 지정, 또는 systemd-timesyncd active | 2.3.1 |
| `KISA-2026:U-66` | 정책에 따른 시스템 로깅 설정 (중) | rsyslogd·syslog-ng·syslogd가 돌고 auth/authpriv 규칙이 있음(로그 정책은 ADR-0006 Host Agents) | - |
| `KISA-2026:U-67` | 로그 디렉터리 소유자 및 권한 설정 (중) | `/var/log` 바로 아래 파일이 root 소유·644 이하 | 6.2.4.1 |

OS별 판정 확인: 같은 스크립트를 root로 `centos:6`, `centos:7`, `rockylinux:8`, `rockylinux:9`, `ubuntu:22.04`, `debian:13` 컨테이너에서 돌려 67개 항목 모두 판정(양호·취약·해당없음·점검불가(수동))이 나오는 것을 확인했다. Rocky 10은 로컬 이미지가 없어 컨테이너로 돌리지 않았다(같은 POSIX sh·coreutils 경로).

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

검증: pytest `tests/test_host_audit_kisa.py`(판정 5종, 예외 유효·만료·승인 대기·범위, 보고서 섹션·부록, 가짜 루트에서의 스크립트 판정과 해시 미노출, #122: U-01~U-67 카탈로그·스크립트 1:1, 프로비저닝된 서버·취약 서버 가짜 루트의 항목별 판정, postfix 메일 항목, U-28 Docker 구간과 예외 레지스터, SNMP community 비노출, dash·`bash --posix`·bash 결과 일치). 프로세스·unit·listening 포트는 `ps`·`systemctl`·`ss` 스텁으로 고정해 pytest가 실행 머신에 좌우되지 않는다. molecule Fast `VERIFY-AUD-200`·`VERIFY-AUD-201`(점검 실행·판정 기록). 읽기 전용은 `VERIFY-AUD-010` 스냅샷 사이에서 함께 확인된다.

## 11. 보관과 Audit Baseline (#125)

실행마다 러너의 실행 디렉터리 전체를 RustFS **Host Audit 전용 버킷**(기본 `host-audit`)에 올리고, 직전 정기 실행(Audit Baseline)과 비교해 모든 섹션의 발견을 표시한다. 모든 동작은 러너 localhost의 보고서 단계에서 일어나고 대상 호스트에는 아무것도 하지 않는다. check 모드에서는 조회·업로드를 하지 않는다.

### 11.1 버킷 레이아웃

| 키 | 내용 | 쓰는 실행 |
|---|---|---|
| `<YYYY-MM>/<run_id>/report.html` | A4 보고서 | 모든 실행 |
| `<YYYY-MM>/<run_id>/run.json` | 실행 메타(`run_kind` 포함) | 모든 실행 |
| `<YYYY-MM>/<run_id>/findings.json` | 섹션별 발견 색인 `{section: {hosts, ids: {host: [id]}}}`, `resolved`, `baseline_run_id` | 모든 실행 |
| `<YYYY-MM>/<run_id>/hosts/*.json` 등 | 호스트별 JSON, 패키지 목록·SBOM·Trivy 원본, `package_vulnerability.json`, `pointer.json` | 모든 실행 |
| `baseline/<run_id>.json` | 포인터 `{run_id, run_kind, started_at, findings_key, resolved}` | **정기 실행만**, 모든 업로드 성공 후 |

`<YYYY-MM>`은 보고서 시간대(`host_audit_timezone`) 기준 실행 시작 월이다. 수시 실행은 보관하되 포인터를 쓰지 않으므로 Audit Baseline이 되지 않는다.

**기준선 찾기**: `baseline/` 목록 1회(ListObjectsV2) → 지난 12개월(+1일) 안에 수정된 포인터만 Get → 이번 실행보다 먼저 시작한 정기 실행 중 가장 최근 것이 Audit Baseline → 그 `findings_key`를 Get. 재발 판정은 같은 포인터들의 `resolved` 목록(정기 실행이 해소로 표시한 항목)을 쓴다. 포인터 목록은 1,000개(월 1회 기준 80년 이상)까지 한 번에 읽는다.

### 11.2 상태 판정

동일성 키는 (Inventory Hostname, 섹션, 항목 식별자)다. 항목 식별자: Configuration Vulnerability는 `KISA-2026:U-NN`(판정이 취약·예외(승인)일 때만 발견, 점검불가(수동)는 제외), Package Vulnerability는 `CVE|패키지`, Asset Inventory는 `account:<이름>`·`port:<proto>/<port>`·`privileged:<이름>`.

| 상태 | 뜻 |
|---|---|
| 신규 | 기준선에 없음 |
| 지속 | 기준선에도 있음 |
| 재발 | 기준선에 없고, 지난 12개월 정기 실행이 해소로 표시했던 항목 |
| 해소 | 기준선에 있었고 이번에 없음(그 호스트·섹션을 이번에 점검함) — 정기 실행만 재발 이력에 남긴다 |
| 확인 불가 | 기준선에 있었지만 이번에 그 호스트·섹션을 점검하지 못함 |
| 첫 실행 | 기준선(이전 정기 실행)이 없음 |

Asset Inventory 항목은 발견이 아니라 변경이다: 기준선 대비 **신규**·**삭제**만 표시하고, 이번에 처음 점검한 호스트의 항목은 변경으로 세지 않는다. 보고서에는 Configuration Vulnerability '양호 외 항목'의 호스트 옆, Package Vulnerability '긴급·높음 상세'의 CVE 옆에 상태 배지가 붙고, 'Audit Baseline 대비 변경' 섹션에 섹션별 건수·재발·해소·확인 불가·Asset Inventory 변경이 나온다. 표지의 '비교 기준'에 Audit Baseline 실행 ID, '원본 보관'에 버킷 경로가 찍힌다.

**새 섹션의 참여 방법**: 섹션 모델에 `baseline_findings: {hosts: [점검한 호스트], findings: [{host, id, label}]}`를 넣으면 같은 규칙으로 비교된다(예: Configuration Drift). 보고서 모델 빌더에서 Audit Baseline은 마지막에 적용된다.

### 11.3 실패 처리

- 자격증명·입력 누락: 업로드하지 않는다. 보고서는 만들고(비교 기준 '조회 실패') 실행은 실패로 끝난다(`AUD-516`).
- Audit Baseline 조회 실패(목록·포인터·findings.json): 비교 없이 보고서를 만들고 원본은 올린 뒤 실행을 실패로 끝낸다.
- 업로드 실패(파일 하나라도): 실행을 실패로 끝낸다. 정기 실행이면 포인터를 올리지 않아 이 실행은 다음 달 비교 기준이 되지 않는다.

### 11.4 입력 (OpenBao KV v2, Git에는 시크릿 없음)

| 경로 | 키 | 필수 | 설명 |
|---|---|---|---|
| `agents/host_audit` | `storage_access_key`, `storage_secret_key` | ● | Host Audit 전용 키(Put·Get·List). 백업·유지보수 키 재사용 금지 |
| `agents/host_audit` | `storage_bucket` | | 기본 `host-audit` |
| `agents/host_audit` | `storage_endpoint` | | 비우면 `agents/rustfs.rustfs_endpoint` |
| `agents/host_audit` | `storage_region` | | 기본 `us-east-1` |

로그인은 Host Agents와 같은 AppRole(`VAULT_ROLE_ID`/`VAULT_SECRET_ID`) 또는 `VAULT_TOKEN`이다. AppRole 정책에 `agents/host_audit`, `agents/rustfs` 읽기가 있어야 한다. 시험할 때는 Extra variables `host_audit_storage`(endpoint·bucket·access_key·secret_key·region)로 OpenBao를 건너뛸 수 있고, 보관 없이 돌리려면 `host_audit_storage_enabled=false`를 준다.

| 변수 | 기본값 | 설명 |
|---|---|---|
| `host_audit_storage_enabled` | `true` | false면 러너 로컬만, 비교 안 함 |
| `host_audit_storage_bucket` | `host-audit` | 버킷 기본값 |
| `host_audit_storage` | `{}` | 보관 대상 직접 지정(시험용, Extra variables) |
| `host_audit_storage_validate_certs` · `host_audit_storage_ca_file` | `true` · `""` | RustFS TLS 검증 · 사설 CA(러너 경로) |
| `host_audit_storage_timeout` | `60` | S3 요청 하나의 최대 시간(초) |

S3 요청은 `ansible.builtin.uri`에 AWS Signature V4 헤더(`host_audit_s3_request`, 표준 라이브러리만 사용)를 붙여 보낸다 — 러너 이미지에 boto3·aws-cli를 추가하지 않는다. 업로드 본문의 SHA-256을 서명에 넣는다.

### 11.5 버킷 준비 (운영자, 1회)

설정 파일은 `roles/host_audit/files/storage/`에 있다. RustFS 1.0.1 컨테이너에 아래 절차를 그대로 적용해 확인했다(2026-10-08).

```bash
export AWS_ACCESS_KEY_ID=<RustFS 관리자 키> AWS_SECRET_ACCESS_KEY=<…> AWS_DEFAULT_REGION=us-east-1
S3="aws --endpoint-url https://<rustfs>:9000 s3api"
# 1) Object Lock을 켠 버킷(버저닝 자동 활성) — 생성 시에만 켤 수 있다
$S3 create-bucket --bucket host-audit --object-lock-enabled-for-bucket
# 2) 기본 보존 GOVERNANCE 1095일(3년)
$S3 put-object-lock-configuration --bucket host-audit --object-lock-configuration file://host-audit-object-lock.json
# 3) 수명주기 3년: 1095일 뒤 만료, 이전 버전은 다음 날 삭제
$S3 put-bucket-lifecycle-configuration --bucket host-audit --lifecycle-configuration file://host-audit-lifecycle.json
```

전용 키: 정책 `host-audit-putget-policy.json`(`s3:PutObject`·`s3:GetObject` on `host-audit/*`, `s3:ListBucket` on `host-audit`, Delete 없음)을 만들고 Host Audit 전용 사용자에 붙인 뒤 키를 OpenBao `agents/host_audit`에 넣는다. RustFS 콘솔(Identity → Policies/Users) 또는 `rc admin`(MinIO 호환 관리 API `/rustfs/admin/v3/add-canned-policy`, `add-user`, `idp/builtin/policy/attach`)으로 한다. 확인 결과: 이 키로 Put·Get·List는 성공, Delete·다른 버킷 쓰기·수명주기 변경은 `AccessDenied`.

**Object Lock (RustFS 1.0.1 확인)**: 생성 시 Object Lock을 켜면 버저닝이 함께 켜지고, 기본 보존과 객체별 보존(`x-amz-object-lock-mode`)이 적용되며, 보존 중인 버전 삭제는 `AccessDenied`로 거부된다(COMPLIANCE로 확인). **GOVERNANCE**를 권장한다 — 개인정보나 시크릿이 잘못 올라갔을 때 관리자가 우회 권한으로 지울 수 있어야 하고, 전용 키에는 Delete도 우회 권한도 없으므로 점검 원본은 그대로 보호된다. 같은 키로 덮어쓰면 새 버전이 생길 뿐 이전 버전은 보존된다. Host Agents의 restic 버킷은 Object Lock을 끈다(ADR-0006) — 이 버킷과 다르다.

### 11.6 태스크 매트릭스

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `AUD-500` | `Log in to OpenBao with AppRole for the Host Audit storage key` | `ansible.builtin.uri` | 러너 | 읽기 전용, `no_log` |
| `AUD-501` | `Fetch the Host Audit storage KV from OpenBao (agents/host_audit, agents/rustfs)` | `ansible.builtin.uri` | 러너 | 읽기 전용, `no_log` |
| `AUD-502` | `Resolve the Host Audit storage target and dedicated key` | `ansible.builtin.set_fact` | 러너 | 누락 항목은 이름만, `no_log` |
| `AUD-503` | `List the Audit Baseline pointers of scheduled runs` | `ansible.builtin.uri` (S3 ListObjectsV2) | 러너 | 읽기 전용, `no_log` |
| `AUD-504` | `Get the pointers of scheduled runs within the 12-month window` | `ansible.builtin.uri` (S3 GetObject) | 러너 | 읽기 전용, `no_log` |
| `AUD-505` | `Get the findings of the Audit Baseline run` | `ansible.builtin.uri` (S3 GetObject) | 러너 | 읽기 전용, `no_log` |
| `AUD-506` | `Decide the Audit Baseline state of this run` | `ansible.builtin.set_fact` | 러너 | `ok`·`failed`·`disabled` |
| `AUD-510` | `Save the findings index of this run on the runner` | `ansible.builtin.copy` | 러너 | 실행별 파일 `0600` |
| `AUD-511` | `Save the Audit Baseline pointer of a scheduled run on the runner` | `ansible.builtin.copy` | 러너 | 정기 실행만, `0600` |
| `AUD-512` | `Find every file of this run to keep` | `ansible.builtin.find` | 러너 | 읽기 전용 |
| `AUD-513` | `Compute the SHA-256 of every file to keep` | `ansible.builtin.stat` | 러너 | 읽기 전용 |
| `AUD-514` | `Upload this run to the Host Audit bucket (<YYYY-MM>/<run_id>/)` | `ansible.builtin.uri` (S3 PutObject) | 러너 | 실행 ID별 새 키, `no_log` |
| `AUD-515` | `Upload the Audit Baseline pointer of a scheduled run` | `ansible.builtin.uri` (S3 PutObject) | 러너 | 정기 실행·전체 업로드 성공 시만, `no_log` |
| `AUD-516` | `Fail the run when the Audit Baseline lookup or keeping the originals failed` | `ansible.builtin.assert` | 러너 | 파일 이름·상태만 표시 |

검증: pytest `tests/test_host_audit_baseline.py`(AWS SigV4 공개 예제 서명 일치, 경로·포트·키 인코딩, 목록 XML, KST 월 경계, 12개월 창, 기준선 선택(수시 실행 제외), 신규·지속·재발·해소·확인 불가·첫 실행, Asset Inventory 신규·삭제, 배지·표지·저장 문서, 정책·수명주기·보존 설정, 포인터 업로드 조건). RustFS 1.0.1 컨테이너로 서명 요청의 Put·Get·List, 전용 정책의 거부 동작, Object Lock, 위 버킷 준비 절차를 수동으로 확인했다. molecule은 보고서 단계를 돌리지 않으므로 이 절의 태스크는 molecule 검증 대상이 아니다.
## 12. Configuration Drift (#124)

Git에 선언된 상태(프로비저닝 `site.yml`, Host Agents Config)와 호스트 실제 상태의 차이(CONTEXT.md Configuration Drift, ADR-0009 §1). 직전 Host Audit과의 차이는 Drift가 아니다(Audit Baseline 비교, #125).

- **방식**: 보고서 플레이(러너 localhost)가 두 플레이북을 `--check --diff`로 하위 실행한다(`tasks/drift.yml`, `tasks/drift_subrun.yml`). `ansible.posix.json` 콜백 결과에서 선언 플레이의 `changed` 태스크를 호스트별 행(SPEC-ID, 태스크 이름, 요약)으로 만든다. check 모드는 관리 상태를 바꾸지 않는다(#117, `tests/test_check_mode_read_only.py`).

  | 하위 실행 | 명령 | 대상(감사 대상과의 교집합) | 행을 만드는 플레이 |
  |---|---|---|---|
  | 프로비저닝 | `site.yml --check --diff` | `host_audit_drift_site_pattern` (`servers:loadbalancers`) | `Provision Baseline On-Premise Target Hosts` |
  | Host Agents Config | `host_agents.yml --tags agents_config --check --diff` | `host_audit_drift_agents_pattern` (`servers:!host_agents_excluded`) | `Apply Host Agents` |

- **인증**: 하위 실행은 평소 Semaphore 실행과 같은 경로로 접속한다. 각 플레이북이 자기 `resolve_connection`·`cleanup_connection` 플레이를 돌리고, 같은 인벤토리 소스(`ansible_inventory_sources`를 `-i`로)와 같은 OpenBao 자격증명을 쓴다. 자격증명(`VAULT_ROLE_ID`·`VAULT_SECRET_ID`·`VAULT_TOKEN`·`VAULT_ADDR`·`VAULT_NAMESPACE`·`VAULT_MOUNT`)은 이번 실행의 변수(Semaphore Secret extra var) 또는 환경 변수에서 읽어 **하위 프로세스 환경 변수로만** 넘긴다. 명령줄과 파일에는 남기지 않고 태스크는 `no_log`다. 그래서 Host Audit 템플릿의 AppRole 정책은 Deploy·Config와 같은 KV 경로(`hosts/<host>`, `users/*`, `hosts/<host>/agents`, `agents/*`)를 읽을 수 있어야 한다. 비밀이 아닌 실행 변수는 `host_audit_drift_forward_vars`(기본 `bootstrap_user`, `target_admin_users`)에 정의돼 있으면 넘기고, 더 필요한 값은 `host_audit_drift_extra_vars`로 준다.
- **diff 원문 미보관**: 콜백 출력에는 diff 원문(파일 내용)이 있어 비밀값이 있을 수 있다. 러너 임시 파일(실행 디렉터리 밖, `0600`)에 받아 해석한 뒤 `always`에서 지운다. 행 요약에는 경로, 추가·삭제 줄 수, 바뀌는 속성 이름, 반복 항목 수만 남는다. `no_log` 태스크는 '비공개(no_log)'로만 나온다. 핸들러 결과는 바뀐 태스크의 결과일 뿐이라 행을 만들지 않는다.
- **점검불가**:
  - Raw Provisioning Path 호스트(CentOS 6/7, 인벤토리 `raw_provisioning_path`가 우선)는 하위 실행에 넣지 않고 '점검불가'와 이유(raw 태스크는 `--check`에서 스킵, ADR-0005)로 표시한다.
  - Host Audit 수집 단계에서 점검불가였던 호스트는 하위 실행에서 뺀다(이유는 이미 요약의 점검불가 표에 있다).
  - 하위 실행 안에서 접속 실패·태스크 실패·결과 없음인 호스트는 그 하위 실행에 대해 '점검불가'와 이유로 표시한다. 실패한 태스크 뒤의 태스크는 판정되지 않았다는 뜻이다.
  - 하위 실행이 통째로 실패하면(시간 초과 `host_audit_drift_timeout`, JSON 해석 불가) 그 하위 실행 부분만 점검불가로 표시하고 Host Audit 실행은 계속된다.
- **보고서**: 3장 Configuration Drift — 하위 실행별 결과, Drift 항목 표(호스트·SPEC-ID·태스크·요약·**판단(수기)** 칸), 제외 목록. 판단 칸에는 조치(선언대로 복원) / 선언 수정 / 승인된 변경 중 하나를 적는다(ISMS 2.9.1 변경관리 증적). 호스트별 부록에 Drift 건수와 점검불가 이유가 나온다.
- **Audit Baseline(§11)**: 섹션 모델의 `baseline_findings`로 참여한다. 항목 식별자는 `<하위 실행>:<SPEC-ID>`(SPEC-ID가 없으면 `<하위 실행>:task:<태스크 이름>`)이다. 계획된 하위 실행이 모두 그 호스트를 판정한 경우에만 '점검한 호스트'로 넣어, 하위 실행 실패·시간 초과·호스트 점검불가가 직전 Drift를 '해소'로 바꾸지 않게 한다(그 경우 '확인 불가'). 노이즈로 제외한 행은 발견이 아니다.
- **check 모드 노이즈**: 수렴된 호스트에서도 `--check`에서 매번 `changed`로 나오는 태스크는 Drift가 아니다. 고치는 것이 원칙이고, 고칠 수 없을 때만 `host_audit_drift_ignore`에 `spec_id`(또는 SPEC-ID 없는 태스크의 `task` 이름)와 `reason`을 올린다. 일치하는 행은 Drift 표에서 빠지고 '제외(check 모드 노이즈)' 표에 사유·호스트 수로 남는다.

- **노이즈 점검 결과(molecule Fast, Rocky 8·9·Ubuntu 22.04, 2026-10-08)**: 수렴(converge) 직후 같은 역할(common·security·access_security)을 `--check --diff`로 다시 돌려 남는 `changed`를 찾았다. 노이즈로 제외할 태스크는 없었고, 아래는 고쳤다.
  - `COMMON-017`: `/etc/systemd/journald.conf.d`가 기본 설치에 없어 복사가 실패했고 `failed_when: false`가 이를 가려 보존 설정이 한 번도 써지지 않았다(실제 미준수). `COMMON-017-DIR`이 디렉터리를 먼저 만들고, `VERIFY-COMMON-017`은 파일 존재를 단언한다.
  - `SEC-006-PROBE`: check 모드에서 스킵돼 `firewalld_module_usable`이 기본값 true가 되고, CLI 폴백이 필요한 호스트(Rocky 8 테스트 이미지)에서 `SEC-006-IFACE`가 check 모드에서만 실패했다. 조회 전용이라 `check_mode: false`로 check 모드에서도 실행한다.
  - `SEC-012`(테스트 컨테이너): audit 패키지가 없어 `/etc/audit/rules.d`가 없고 템플릿이 매번 '새 파일'로 나온다. 실제 호스트에는 auditd가 있으므로 노이즈로 제외하지 않았다. 운영 호스트에서 나오면 실제 미준수다.
  - 한계: firewall-cmd CLI 폴백 태스크(`command`)는 check 모드에서 스킵되므로 그 호스트의 방화벽 규칙 Drift는 판정되지 않는다.

| 변수 | 기본값 | 설명 |
|---|---|---|
| `host_audit_drift_enabled` | `true` | false면 하위 실행을 건너뛴다 |
| `host_audit_drift_site_pattern` | `servers:loadbalancers` | site.yml 하위 실행 대상 |
| `host_audit_drift_agents_pattern` | `servers:!host_agents_excluded` | Host Agents Config 하위 실행 대상 |
| `host_audit_drift_timeout` | `3600` | 하위 실행 하나의 최대 시간(초) |
| `host_audit_drift_forward_vars` | `[bootstrap_user, target_admin_users]` | 정의돼 있으면 하위 실행에 넘길 실행 변수 이름 |
| `host_audit_drift_extra_vars` | `{}` | 하위 실행에 더 넘길 비밀 아닌 변수 |
| `host_audit_drift_ignore` | `[]` | check 모드 노이즈 제외 표식 (`spec_id` 또는 `task`, `reason`) |

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `AUD-400` | `Plan which hosts each Drift sub-run checks` | `ansible.builtin.set_fact` | 러너 | `host_audit_drift_plan` 필터 |
| `AUD-401` | `Fix the Drift sub-run definitions` | `ansible.builtin.set_fact` | 러너 | 읽기 전용 |
| `AUD-402` | `Create a runner temp file for the callback output (outside the run directory)` | `ansible.builtin.tempfile` | 러너 | 실행마다 새 임시 파일, `always`에서 삭제(AUD-407) |
| `AUD-403` | `Run the playbook in --check --diff with the JSON callback` | `ansible.builtin.shell` | 러너 (대상 호스트에는 `--check`) | `changed_when: false`, `failed_when: false`, `timeout`으로 시간 제한, `no_log` |
| `AUD-404` | `Read the sub-run stderr tail for the report reason` | `ansible.builtin.command` | 러너 | `changed_when: false` |
| `AUD-405` | `Parse the sub-run result into per-host Drift rows` | `ansible.builtin.set_fact` | 러너 | `host_audit_drift_parse` 필터 |
| `AUD-406` | `Build the Configuration Drift section model` | `ansible.builtin.set_fact` | 러너 | `host_audit_drift_section` 필터 |
| `AUD-407` | `Remove the callback output (holds raw diff text)` | `ansible.builtin.file` | 러너 | `state: absent` |

검증: pytest `tests/test_host_audit_drift.py` — 실제 `ansible.posix.json` `--check --diff` 출력(`tests/fixtures/host_audit_drift/check_callback.json`, 로컬 호스트 대상 check 실행으로 생성)에서 SPEC-ID 행, 준수·스킵 태스크 제외, diff 원문·no_log 내용 미포함, 실패·접속 실패 호스트, 선언 플레이만 행 생성, 핸들러 제외, 노이즈 제외 표식, Raw 경로·수집 실패 호스트 계획, 하위 실행 실패 시 부분 점검불가, 보고서 모델·템플릿(판단 칸). 하위 실행은 OpenBao 접속이 필요해 molecule 범위 밖이다.
