# Host Audit Role Task Specification

> **상태: 뼈대 구현(#119).** [ADR-0009](adr/0009-host-audit-read-only-inspection.md)의 Host Audit 실행 흐름(대상 확정 → 접속 해석 → 호스트별 읽기 전용 수집 → 보고서 모델 → HTML)을 가장 얇게 관통한다. 지금은 식별(Inventory Hostname, FQDN, IP, 환경)과 운영 체제만 수집하고, 보고서는 러너 로컬에만 남긴다. 나머지 Asset Inventory 항목, Configuration Drift, Configuration Vulnerability, Package Vulnerability, Audit Baseline 비교, RustFS 보관, 메일은 [스펙 #115](https://github.com/ppzxc/infra-automation/issues/115)의 후속 티켓이 이 뼈대에 붙인다.

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

## 4. 호스트별 JSON 구조 (schema_version 1)

```json
{
  "schema_version": 1,
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
| `AUD-012` | `Save the per-host record on the runner` | `ansible.builtin.copy` | 러너 (`delegate_to: localhost`) | 실행별 파일 `0600` |
| `AUD-020` | `Find the per-host records of this run` | `ansible.builtin.find` | 러너 | 읽기 전용 |
| `AUD-021` | `Build the report model from the per-host records` | `ansible.builtin.set_fact` | 러너 | `host_audit_report_model` 필터 |
| `AUD-022` | `Save the run metadata on the runner` | `ansible.builtin.copy` | 러너 | 실행별 파일 `0600` |
| `AUD-023` | `Render the A4 report HTML` | `ansible.builtin.template` | 러너 | 실행별 파일 `0600` |
| `AUD-024` | `Show where the report was written` | `ansible.builtin.debug` | 러너 | 읽기 전용 |

## 7. 검증

- **pytest** `tests/test_host_audit.py`는 다음을 검증한다.
  - 기록과 보고서 모델: 접속 실패, 기록 없음, 미지정, FQDN 불일치, KST 표기
  - 프로브 스크립트 출력 형식
  - 템플릿의 인쇄 CSS와 외부 리소스 부재
- **molecule Fast Scenario** `molecule/fast/verify.yml`:
  - `VERIFY-AUD-010`: 수집 전후 관리 영역의 체크섬·메타데이터가 같은지 확인한다.
  - `VERIFY-AUD-012`: 러너에 저장된 JSON 구조를 확인한다.
