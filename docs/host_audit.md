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
