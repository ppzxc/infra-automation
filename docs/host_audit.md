# Host Audit Role Task Specification

> **상태: 구현 완료(#119~#126), 첫 운영 실행 대기(#127).** [ADR-0009](adr/0009-host-audit-read-only-inspection.md)의 Host Audit — 대상 확정 → 접속 해석 → 호스트별 읽기 전용 수집(Asset Inventory, Configuration Vulnerability KISA-2026 U-01~U-67, Package Vulnerability) → Configuration Drift 하위 실행 → 보고서 모델 → A4 HTML → RustFS 보관·Audit Baseline 비교 → 메일. Semaphore 템플릿·스케줄·첫 실행 순서는 [semaphore-setup.md §5~§7](semaphore-setup.md#5-task-template).

---

## 1. 개요 및 구현 기능 (What)

- **진입점**: `playbooks/host_audit.yml`. 플레이 순서는 아래와 같다.
  1. 대상·실행 메타 확정 (localhost, `tasks/prepare.yml`)
  2. 접속 해석 (`common/resolve_connection.yml` 재사용, Deploy와 같은 관리 계정)
  3. 호스트별 수집 (`tasks/main.yml`)
  4. 임시 키 정리 (`common/cleanup_connection.yml`)
  5. 보고서 (localhost, `tasks/report.yml`)
- **대상**: `host_audit_scope_pattern`(`servers:loadbalancers:overseer:!host_audit_excluded`) ∩ `target_hosts`. Host Agents Exclusion 호스트와 CentOS 6/7 호스트도 대상이다. Semaphore 인벤토리의 `host_audit_excluded` 그룹(러너에서 접속할 수 없는 호스트 등)은 대상이 아니며 보고서에도 나오지 않는다. 네트워크 장비(`cisco_switches`)는 범위 밖이며 보고서 표지에 그렇게 적는다.
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
├── xlsx/host-audit-<run_id>-<Inventory Hostname>.xlsx   # 호스트별 Remediation Plan (§17)
├── xlsx/host-audit-<run_id>-total.xlsx                  # 모든 호스트를 한 시트에 모은 합계 (§17)
└── report.html                       # A4 인쇄용 보고서
```

## 4. 호스트별 JSON 구조 (schema_version 2)

```json
{
  "schema_version": 2,
  "inventory_hostname": "ns0331",
  "collected_at": "2026-10-08T22:00:07Z",
  "status": "ok",
  "reason": "",
  "declared": {
    "fqdn": "ns0331.nanoit.kr",
    "ip": "10.0.0.32",
    "environment": "production",
    "groups": ["servers"]
  },
  "identity": {
    "hostname": "ns0331",
    "fqdn": "ns0331.nanoit.kr",
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
| `declared` | 인벤토리 값 (`fqdn`, `ip`, 그룹)과 환경(`host_audit_environment`, 공용 `deployment_environment`(`playbooks/group_vars/all.yml`, 기본 `production`)를 따른다). 허용 값만 받는다(AUD-001) |
| `identity` / `os` | 호스트에서 수집한 값. `status`가 `ok`가 아니면 `null`. `ips`는 루프백·링크 로컬을 뺀 전체 주소, `account`는 점검에 쓴 계정 |
| `os.name` | `/etc/os-release`의 `PRETTY_NAME`, 없으면(CentOS 6) `/etc/redhat-release` 첫 줄 |

후속 티켓은 필드를 추가하고 `schema_version`을 올린다. 기존 필드의 의미는 바꾸지 않는다.

## 5. 변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `host_audit_run_kind` | `on_demand` | `scheduled`(Audit Baseline이 됨) · `on_demand`. Semaphore 템플릿에 고정 |
| `host_audit_run_id` | `ha-<UTC 시작 시각>` | 실행 ID. 보통 지정하지 않음 |
| `host_audit_output_root` | env `HOST_AUDIT_OUTPUT_ROOT` 또는 `/tmp/host_audit` | 러너 출력 상위 경로 |
| `host_audit_output_retention_days` | `7` | 출력 상위 경로 아래에서 이 일수가 지난 실행 디렉터리를 다음 실행 초기에 지움(#157, §14) |
| `host_audit_scope_pattern` | `servers:loadbalancers:overseer:!host_audit_excluded` | 점검 대상 그룹 |
| `host_audit_timezone` | `Asia/Seoul` | 보고서 시각 표기 |
| `target_hosts` | (없음) | 일부 호스트만 점검할 때 Inventory Hostname 패턴 |
| `host_audit_kisa_alert_enabled` | `true` | 정기 실행의 KISA 월간 악화 알림(§15, #331). false면 알리지 않음 |
| `host_audit_alert_validate_certs` | `true` | 알림 webhook TLS 검증. 주소는 OpenBao `secrets/services/alert/notify`의 `url`(과 선택 `token`·`auth_header`)이고 실행 변수로 덮어쓰지 않는다 |
| `host_audit_environment` | 공용 `deployment_environment`(`playbooks/group_vars/all.yml`, `production`) | 점검 기록의 환경(`declared.environment`). 모든 호스트가 같은 값이라 인벤토리 변수가 아니라 공용 값이고, Host Agents(`host_agents_environment`)와 한 곳에서 정한다. 역할만 따로 돌리는 시험·molecule은 `deployment_environment`를 직접 준다. `-e`로 덮어쓸 수 있다 |
| `host_audit_log_review_enabled` | `false` | 수시 실행에서도 Log Review Report를 만든다(§18). 정기 실행은 이 값과 무관하게 만든다 |
| `host_audit_log_review_timeout` · `host_audit_log_review_validate_certs` | `120` · `true` | OpenObserve `_search` 한 번의 최대 시간(초)과 TLS 검증. 주소·조직은 `inventory/services/openobserve`, 계정은 `secrets/services/openobserve/readonly`이고 실행 변수로 덮어쓰지 않는다 |
| `host_audit_log_review_collect_hosts` · `host_audit_log_review_devices` | 수집 로스터(`o2c_roster('collect')`) · `fortigate_firewalls` 그룹 + `host_audit_log_review_switch_syslog_devices`(`o2c_switch_syslog_roster`와 같은 목록) | 3부 수집 공백의 수집 대상(§18) |
| `host_audit_log_review_business_hours` · `host_audit_log_review_holidays` · `host_audit_log_review_failure_threshold` · `host_audit_log_review_failure_window_minutes` | `{start: 8, end: 20}` · 연도별 공휴일(2026) · `5` · `10` | 1부 1~5번 판정 기준(§18.2). 업무시간은 평일 정시 구간(끝 미포함) KST이고 정시가 아니면 3·4번이 판정 오류가 된다. 공휴일은 `"YYYY": ["YYYY-MM-DD", ...]`이고 점검 달의 연도가 없으면 보고서가 '공휴일 목록 없음'으로 적는다 |
| `host_audit_regression_enabled` | `true` | Security Regression(§16) 전체 스위치. false면 수집·판정을 건너뛴다(롤백) |
| `host_audit_regression_expect` | `{}` | 호스트별 기대치 선언(§16.2의 선언 키). 비면 그 호스트는 대상이 아님. 값은 비공개 인벤토리·Environment로 준다 |
| `host_audit_regression_backup_enabled` · `host_audit_rustfs_policy_snapshot_file` | `false` · env `HOST_AUDIT_RUSTFS_POLICY_SNAPSHOT` | 백업 정책 항목(`EXP-BAK-*`) 판정 켜기 · 수집기 스냅샷 파일(러너 경로, 없으면 BAK-2/3 점검불가) |
| `host_audit_backup_policy_file` · `host_audit_backup_policy_prefix` | `roles/backup/files/host-key-policy.json` · `backup-prod-` | 기대 정책 · 호스트 서비스 계정 이름 접두어 |

## 6. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `AUD-001` | `Assert Host Audit run kind is supported` | `ansible.builtin.assert` | 러너 | 읽기 전용 |
| `AUD-002` | `Fix the run start time once per run` | `ansible.builtin.set_fact` | 러너 | 읽기 전용 (실행당 1회 고정) |
| `AUD-003` | `Fix Host Audit run metadata` | `ansible.builtin.set_fact` | 러너 | 읽기 전용 |
| `AUD-004` | `Select Host Audit targets into the host_audit_targets group` | `ansible.builtin.add_host` | 러너 | 인메모리 그룹, `changed_when: false` |
| `AUD-005` | `Create the runner-local output directory for this run` | `ansible.builtin.file` | 러너 | 실행별 디렉터리 `0700` |
| `AUD-006` | `Find the run directories older than the retention days` | `ansible.builtin.find` | 러너 | 읽기 전용, 출력 상위 경로 바로 아래의 디렉터리만, 이름이 run_id 규칙(`[A-Za-z0-9][A-Za-z0-9._-]*`, `AUD-630`과 같음)에 맞는 것만, `resend-*` 제외, check 모드 건너뜀 |
| `AUD-007` | `Remove the run directories older than the retention days` | `ansible.builtin.file` | 러너 | `state: absent`, 이번 실행 디렉터리 제외, check 모드 건너뜀 |
| `AUD-010` | `Probe host identity and OS (raw, read-only)` | `ansible.builtin.raw` | All (CentOS 6 ~ Rocky 10, Ubuntu) | 조회 전용, `changed_when: false`, `check_mode: false`, `ignore_unreachable: true` |
| `AUD-011` | `Build the per-host audit record` | `ansible.builtin.set_fact` | 러너 | `host_audit_host_record` 필터 |
| `AUD-100` | `Probe Asset Inventory (raw, read-only)` | `ansible.builtin.raw` (`become: true`) | All (CentOS 6 ~ Rocky 10, Ubuntu) | 조회 전용, `changed_when: false`, `check_mode: false`, `ignore_unreachable: true` |
| `AUD-101` | `Add Asset Inventory and declared values to the per-host record` | `ansible.builtin.set_fact` | 러너 | `host_audit_inventory_record`·`host_audit_asset_declaration` 필터. 선언 값은 `resolve_connection`이 이미 읽은 Asset 문서(`_asset_doc`)의 `description`과 `isms` 절에서 다섯 값만 고른다(OpenBao 재조회 없음) |
| `AUD-012` | `Save the per-host record on the runner` | `ansible.builtin.copy` | 러너 (`delegate_to: localhost`) | 실행별 파일 `0600` |
| `AUD-020` | `Find the per-host records of this run` | `ansible.builtin.find` | 러너 | 읽기 전용 |
| `AUD-021` | `Build the report model from the per-host records` | `ansible.builtin.set_fact` | 러너 | `host_audit_report_model` 필터. Package 발견은 넘기지 않고 `package_findings_dir`(파일 디렉터리)만 넘긴다(#155) |
| `AUD-022` | `Save the run metadata on the runner` | `ansible.builtin.copy` | 러너 | 실행별 파일 `0600` |
| `AUD-023` | `Render the A4 report HTML` | `ansible.builtin.template` | 러너 | 실행별 파일 `0600` |
| `AUD-024` | `Show where the report was written` | `ansible.builtin.debug` | 러너 | 읽기 전용 |

호스트별 Remediation Plan xlsx와 합계 xlsx를 쓰는 `AUD-025`는 §17.1에 있다.

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
| Host Agents | otelcol-contrib·restic·resticprofile 바이너리, 서비스·백업 타이머/cron | 정상 / 정상(백업 전용) / 일부 이상 / 미설치 / 제외(Host Agents Exclusion). `host_agents_backup_only` 호스트는 otelcol 없이 백업이 설치·예약돼 있으면 정상(백업 전용) |

**판정 규칙**

- **선언 값 출처**: ISMS 자산대장의 사본인 OpenBao Asset 문서 `inventory/assets/<Inventory Hostname>`다. `resolve_connection`이 접속 해석 때 이미 읽어 `_asset_doc`으로 발행한 문서에서 다섯 값만 고르고(같은 문서에 접속 절(`access`)이 있어 통째로 기록·보고서에 넘기지 않는다) OpenBao를 다시 조회하지 않는다. 값은 용도=최상위 `description`(끝의 `[그룹자산명]`도 그대로 표시), `isms` 절의 `department`(관리 부서), `owner_role`(책임자 직책), `admin_role`(관리자 직책), `asset_importance`(자산중요도, H/M/L)다. `isms`의 나머지 키(`target`·`group_asset_name`·`personal_info_system`)는 이 역할이 읽지 않는다(자산대장 스크립트의 몫). 스키마(`schemas/openbao/inventory/asset.schema.json`)의 이름이 읽는 키와 같다.
- **조회 실패**: 다음 둘 중 하나면 다섯 칸 모두 '조회 실패'로 표시한다. (1) `_asset_doc`이 발행되지 않았다(`resolve_connection`은 Asset 문서가 없으면 그 호스트를 실패시키므로, 접속 해석을 거치지 않은 실행에서만 생긴다). (2) 발행됐지만 문서가 비어 있다. 접속 절만 있고 선언 값이 없는 문서는 비어 있지 않으므로 '미지정'이다. 값이 정말 없는 것('미지정')과 구분하며 메일 요약도 '선언 미지정 호스트'와 '선언 조회 실패 호스트'를 따로 센다.
- **미지정**: 조회는 됐는데 다섯 값 중 빈 값. Asset 문서에 `isms` 절이 없는 서버와 `isms.target=false` 서버도 별도 상태 없이 '미지정'이다.
- **잘못된 값**: 자산중요도가 H/M/L이 아니면 `잘못된 값 (<원래 값>)`으로 표시한다(원래 값은 20자까지, 넘으면 `…`). 비교는 대문자 H/M/L 정확 일치이고 정규화하지 않는다(자산대장 표기 그대로라는 용어 정의를 따른다. 소문자·다른 표기는 사본 오류로 보고 고치게 한다). 표시 문구는 원래 값만 덧붙이고 허용 값(H·M·L)을 칸마다 되풀이하지 않는다: 스펙이 '원래 값과 함께 잘못된 값'으로 정했고 허용 값은 용어 정의(Asset Importance)와 이 절에 있다.
- **선언 값 처리 결정**
  - 저장 값은 자산대장 사본 그대로다(증적). 앞뒤 공백만 자른다. 상한은 값 하나 500자이고 넘으면 `…`로 끝낸다. 실제 용도(끝의 `[그룹자산명]` 포함)는 그보다 훨씬 짧아 잘리지 않으며, 상한은 엉뚱한 긴 덩어리가 기록에 들어가는 것만 막는다. 문자열이 아닌 값(dict·list·bool·숫자)은 빈 값으로 저장하되 `declared.asset.malformed`에 키를 남기고 보고서에는 '잘못된 값 (값이 문자열이 아님)'으로 보인다('미지정'이 아니다).
  - Asset 문서 텍스트에 `{{ }}` 같은 템플릿 문법이 있어도 평가되지 않는다. 필터가 값을 unsafe로 표시하므로(2.19 이전 버전에 필요하고 2.19 이상에서는 기본 동작과 같다) 러너 버전과 무관하게 템플릿으로 해석되지 않는다. `tests/test_host_audit_inventory.py`가 실제 `[AUD-101]` 태스크를 `ansible-playbook`으로 돌려 확인한다. 그래서 값을 고쳐 저장하지 않는다. 태스크는 입력에 Asset 문서 전체(접속 절 포함)가 있어 `no_log`다(실패하면 내용이 가려지므로 필터 동작은 pytest가 직접 검증한다).
  - Asset 문서를 읽는 곳이 `resolve_connection` 하나라(변수 이름 `_asset_doc`은 `tests/test_host_audit_inventory.py`가 고정한다) 같은 결과를 거기서 받아 쓰고, 그 변수가 없거나 비어 있으면 조회 실패다. 원인(403·404·타임아웃)은 기록하지 않는다(문서가 없거나 못 읽으면 `resolve_connection`이 그 호스트를 실패시킨다).
  - 태그 색: '미지정'·'조회 실패'는 회색, '잘못된 값'만 빨강이다. 조회 실패는 값을 알 수 없다는 뜻이지 발견이 아니므로 지원 종료·선언 외(빨강)와 구분하고, 메일 요약은 조회 실패 호스트 수를 경고(WARN)로 센다. 치명(CRIT)으로 올리지 않는 이유는, 상태 코드를 기록하지 않아 문서 없음(404)과 장애(403·타임아웃)를 구분할 수 없는 채로 전체 실패를 장애로 단정하면 `--limit` 실행이나 신규 호스트에서 오경보가 나기 때문이다. 세 상태 호스트 수(`미지정`·`조회 실패`·`잘못된 값`)는 각각 따로 세므로 한 호스트가 둘 이상에 들어갈 수 있다.
  - 호스트별 JSON `schema_version`은 2로 둔다. `declared.asset`은 `security_grade`가 `asset_importance`로 바뀌고 `lookup`이 더해졌다. 이 필드는 Audit Baseline 비교에 쓰이지 않고 보고서 모델을 만들 때 실행 안에서 읽힌다. 이 변경 전에 저장한 기록의 `security_grade`는 자산중요도 칸에 '잘못된 값 (<원래 값>)'으로 보인다. Git 호스트 변수에 남은 옛 선언은 더 이상 읽지 않으므로(경고 없음), 호스트 변수의 옛 선언은 지우고 자산대장 사본(OpenBao Asset 문서의 `isms` 절)에 값을 등록한다.
- **선언 외**: 특수권한자(uid 0, wheel·sudo·admin 그룹 구성원, sudoers 규칙 대상) 중 허용 목록에 없는 계정. 허용 목록은 `accounts`의 sudo 권한 계정(`sudo: true`, 또는 `sudo` 미지정 + `tier: admin`, `state: absent` 제외), `openbao_ssh_allowed_principals`, `host_audit_privileged_extra`, 그리고 root다. sudoers의 `User_Alias` 등 별칭은 펼치지 않는다.
- **장기 미사용**: 로그인 가능한 셸을 가진 계정 중 `lastlog -t 90`에 없는 계정(기록 없음 포함). 점검 계정과 uid 0 계정은 제외하고 표지에 명시한다. uid 0의 직접 로그인은 Configuration Vulnerability(KISA-2026) 항목이 다룬다. lastlog가 없으면 '마지막 로그인 점검불가'로 표시하고 장기 미사용 판정을 하지 않는다.
- **EOL**: `roles/host_audit/vars/main.yml`의 `host_audit_eol_table`(기준일 `reviewed_on`, 무상 표준 지원 종료일). 실행 시작일 기준 지난 날짜면 지원 종료(EOS), 180일 이내면 EOL 임박, 표에 없으면 확인 불가.
- **점검불가**: Asset Inventory 수집이 실패하면 '점검불가(수집 실패)', /etc/shadow를 읽지 못하면 '계정 잠금 상태 점검불가'.

**보안**: 비밀번호 해시는 호스트에서 `set`/`locked`/`empty`로 줄여서만 넘어온다. 선언 값은 ISMS 자산대장에 적힌 표기 그대로 넣는다. Asset 문서의 다섯 값 외(접속 절 등)는 기록·보고서·메일에 넘어가지 않는다.

**읽기 전용**: 스크립트는 sudo로 돌지만 rpm 조회만은 `nobody`로 낮춰 실행한다(`setpriv`, 없으면 `su`). root로 `rpm -qa`를 돌리면 rpm이 DB를 쓰기 모드로 열어 EL9의 `rpmdb.sqlite-shm` 수정 시각(EL6/7은 Berkeley DB 환경 파일)이 바뀌기 때문이다. molecule `VERIFY-AUD-010`과 pytest의 `centos:6`/`centos:7` 컨테이너 시험이 관리 영역의 메타데이터까지 같은지 확인한다.

**선언 예시** (OpenBao Asset 문서 `inventory/assets/<Inventory Hostname>`의 `description`과 `isms` 절. 자산대장 표기 그대로 적는다)

```yaml
description: "웹 서비스 [그룹자산명]"
isms:
  department: "인프라팀"
  owner_role: "인프라팀장"
  admin_role: "시스템 관리자"
  asset_importance: "M"
```

**호스트별 JSON 추가 필드 (schema_version 2)**: `declared.asset`(위 5개 + `lookup`(`ok`/`failed`) + `privileged_allowlist` + 문자열이 아닌 값이 있을 때만 `malformed`(그 키 목록))과 `inventory`가 붙는다. 식별이 실패한 호스트는 `inventory: null`.

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
| `host_audit_privileged_extra` | `[]` | 특수권한 허용 목록에 더할 이름 |

## 8. 검증

- **pytest** `tests/test_host_audit.py`는 다음을 검증한다.
  - 기록과 보고서 모델: 접속 실패, 기록 없음, 미지정, FQDN 불일치, KST 표기
  - 프로브 스크립트 출력 형식
  - 템플릿의 인쇄 CSS와 외부 리소스 부재
- **pytest** `tests/test_host_audit_inventory.py`는 Asset Inventory를 검증한다.
  - 수집 결과 해석: 8개 영역, 특수권한 근거, 비밀번호 해시 미포함, CentOS 6 출력(netstat, epoch 없는 rpm)
  - 보고서 모델: 미지정·조회 실패·잘못된 값(Asset 문서에서 다섯 값만 읽음, 접속 정보 미포함)·선언 외·90일 장기 미사용(점검 계정·uid 0 제외)·EOS/임박/미확인·전체 패키지 목록 미포함·수집 실패 점검불가
  - 수집 스크립트를 이 머신과 `centos:6`·`centos:7` 컨테이너(이미지가 로컬에 있을 때)에서 실제로 실행
- **molecule Fast Scenario** `molecule/fast/verify.yml`:
  - `VERIFY-AUD-010`: 수집(식별 + Asset Inventory) 전후 관리 영역의 체크섬·메타데이터가 같은지 확인한다.
  - `VERIFY-AUD-012`: 러너에 저장된 JSON 구조를 확인한다.
  - `VERIFY-AUD-100`: Asset Inventory 기록의 영역별 구조와 값(패키지 수, root 계정, sshd 포트 등)을 확인한다.

### 8.1 러너 메모리·시간 harness (#153, Spec #148)

Host Audit 러너(Semaphore 컨테이너)가 발견을 변수로 들고 다니면서 OOM으로 죽은 일(task 265, 287)을 숫자로
재현하고, 이후 개선(#148의 Ticket 3·4·6)의 효과를 비교하기 위한 측정 도구다. 역할 밖 플레이북이라 role의 `library/`·`module_utils/`를 `ANSIBLE_LIBRARY`·`ANSIBLE_MODULE_UTILS`로 지정한다(#155). `scripts/host_audit_memory_harness.py`.

- **입력**: 호스트 수와 호스트당 CVE 수. 합성 실행 디렉터리(`hosts/`, `packages/`, `trivy/`)와 이전 정기 실행의
  findings(Audit Baseline)를 만든다. 이전 findings는 현재 발견의 80%가 그대로이고 20%만큼은 해소된 것으로 만든다.
- **범위**: 실제 태스크를 `ansible-playbook`으로 돌린다. Package Vulnerability 분류·섹션(AUD-322~324),
  보고서 모델(AUD-021), findings 인덱스 저장(AUD-510), Audit Baseline 비교. 태스크는 role의 YAML에서 ID로
  뽑아 쓰므로 태스크가 바뀌면 harness도 바뀐 태스크를 잰다. Trivy 판정(AUD-321)은 합성 결과 파일로 대신한다.
- **지표**: `ansible-playbook` 프로세스 트리 전체(자식 포함)의 RSS 합계 최대값과 소요 시간. 러너 컨테이너의 OOM은
  cgroup 단위라 본 프로세스만 재면 일을 서브프로세스로 옮겼을 때 좋아진 것처럼 보일 수 있다. 본 프로세스 최대값은 참고로만
  함께 출력한다. 0.1초 간격 샘플링이고 부모·자식이 공유하는 페이지를 중복 집계하므로 약간 크게 나온다.
- **실행**:
  - `python3 scripts/host_audit_memory_harness.py --hosts 24 --cves 23000` (결과는 JSON으로 출력)
  - `pytest -m heavy_harness -s tests/test_host_audit_memory_harness.py` (같은 실운영 규모)
  - 기본 `pytest`는 무거운 실행을 제외하고, 작은 규모(3대 × 20건)로 harness가 끝까지 도는지만 확인한다.
- **현재 기준값(2026-10-13, 개선 전, 비교 기준)**:

| 항목 | 값 |
|---|---|
| 규모 | 24대 × 호스트당 23,000건 = 552,000건 |
| 프로세스 트리 최대 RSS | 3,765 MB |
| `ansible-playbook` 본 프로세스 최대 RSS | 1,845 MB |
| 소요 시간 합계 | 220.5초 (AUD-322 104초, AUD-323 65초, AUD-021 27초, AUD-510 5초) |
| 조건 | 개발 머신(WSL2, 32 CPU, 24GB), ansible-core 2.21.4, Python 3.14.4, forks=1, 러너 컨테이너 한도 없음 |

- **#155 적용 후 측정(2026-10-13, 같은 머신·같은 조건, 같은 날 개선 전 재측정 포함)**: 발견을 파일로 돌리고(§9) AUD-322를 모듈로 바꾼 결과다.

| 항목 | 개선 전(#155 이전) | 개선 후 | 변화 |
|---|---|---|---|
| 프로세스 트리 최대 RSS | 3,736 MB (기준값 3,765 MB) | 2,175 MB | -42% |
| `ansible-playbook` 본 프로세스 최대 RSS | 1,827 MB (기준값 1,845 MB) | 1,235 MB | -32% |
| 소요 시간 합계 | 211.2초 | 31.5초 | -85% |
| 단계별 | AUD-322 80초, AUD-323 77초, AUD-021 30초, AUD-510 4.4초 | AUD-322 9.2초, AUD-323 0.5초, AUD-021 5.3초, AUD-510 1.9초 | |

  남은 1.2 GB는 #155가 줄이는 대상이 아니었고 #156이 줄였다(아래). harness가 이전 실행의 findings(Audit Baseline, 약 44만 건 id)를 플레이북 변수로 싣는 비용이고, 태스크를 하나도 돌리지 않고 변수만 싣는 플레이북이 이미 본 프로세스 1,259 MB, 트리 2,186 MB를 쓴다(트리는 태스크 워커가 fork로 복사돼 두 배로 집계됨). 실운영에서는 AUD-505의 `uri` 결과가 같은 크기의 변수가 된다(Audit Baseline 쪽 개선은 별도 티켓). 그 고정 비용을 뺀 #155 몫의 최대 증가분은 개선 전 약 570 MB(본 프로세스)에서 개선 후 0(변수만 실은 상태보다 낮음)이 됐다. 합성 Trivy 파일은 호스트당 약 5 MB로 실제(200~250 MB)보다 작아서 파싱 피크는 harness에 거의 드러나지 않는다. 실제 크기에서는 그 피크가 `ansible-playbook`이 아니라 호스트마다 끝나는 모듈 프로세스에서만 생긴다.

- **#156 적용 후 측정(2026-10-13, 같은 머신·같은 조건, 직전 #155 반영본과 같은 날 비교)**: 이전 실행의 `findings.json`을 변수가 아니라 러너 파일로 받고(AUD-505), 별도 프로세스 모듈이 Package id를 호스트별 파일로 나눠(AUD-508) 비교가 호스트 하나씩 읽게 했다(§11.2). harness도 같은 태스크(AUD-507·508·506)를 돈다. 이전 findings는 `package_findings/previous_findings.json`에 미리 놓아 S3 다운로드를 대신한다.

| 항목 | #155 반영본(개선 전) | 개선 후 | 변화 |
|---|---|---|---|
| 프로세스 트리 최대 RSS | 2,171 MB | 285 MB | -87% |
| `ansible-playbook` 본 프로세스 최대 RSS | 1,236 MB | 91 MB | -93% |
| 소요 시간 합계 | 26.3초 | 17.2초 | -35% |

  처음 측정값(3,765 MB, #153 기준값)과 비교하면 프로세스 트리 최대 RSS가 약 92% 줄었다(3,765 → 285 MB). 남은 피크는 AUD-508 모듈이 이전 `findings.json`(약 44만 건 id)을 한 번 읽어 나누는 별도 프로세스(수백 MB, 끝나면 반환)다.

  **측정 한계(주의)**: 위 "개선 전"(#155 반영본) harness는 이전 findings의 id 약 44만 건을 플레이북 변수로 싣는 방식이라, 그 변수 자체가 본 프로세스 약 1.2 GB, 트리 약 2.2 GB의 고정 비용이었다. 이 비용은 harness가 만든 것이고 실운영의 전 단계와 같다고 볼 수 없다(실운영은 AUD-505 `uri` 결과가 같은 크기의 변수가 되므로 비슷하긴 하지만 harness의 변수 주입과 똑같지는 않다). 그래서 #156의 -87%(트리)·-93%(본 프로세스)는 harness 기준이고, 실운영에서 #156 하나로 줄어드는 양은 이 표보다 작을 가능성이 높다. 개선 효과의 근거로는 "이전 findings 때문에 늘어나던 변수 비용이 없어졌다"는 구조 변화를 쓰고, 실운영 수치는 실제 정기 실행에서 다시 재야 한다. harness는 `psutil`(`pip install psutil`)이 필요하고, 없으면 안내 메시지를 내고 끝난다(테스트는 건너뜀). `scripts/measure_trivy_concurrency.py`도 같다.

  실운영 러너의 한도는 4G다(1G에서 task 287이 AUD-021에서 죽었다). 트리 최대치 3.8GB는 그 한도에 거의 닿는다.
  절대값은 머신과 버전에 따라 달라지므로 개선 효과는 같은 머신에서 전후를 비교한다.

## 9. Package Vulnerability (#123)

설치 패키지 버전이 CVE·벤더 권고에 해당하는지 판정한다(ISMS 2.10.8 · 2.11.2). Vuls는 PoC(#112)에서 기각했고(CentOS 7 CVE 69건 누락, EOL 경고 없음, DB 13.6 GB), Trivy를 SBOM 입력으로 쓴다.

- **호스트(읽기 전용)**: `files/package_probe.sh`를 `raw`로 실행해 릴리스 파일과 패키지 DB만 읽는다(`rpm -qa --queryformat` / `dpkg-query -W`). 아무것도 설치하지 않고 원격 파일도 만들지 않는다. CentOS 6/7도 같은 경로다. 식별 수집(AUD-010)이 `ok`인 호스트만 수집한다. root로 접속한 경우 rpm은 `nobody`로 조회한다(root로 열면 EL9 `rpmdb.sqlite-shm`이 바뀜, #120과 같은 방식). Asset Inventory의 패키지 목록(#120)과 별도로 읽는 이유는 Trivy 판정에 소스 패키지(rpm `SOURCERPM`, deb `source:Package`·`source:Version`)와 EL8+ 모듈 레이블이 필요하기 때문이다.
- **러너**: 패키지 기록 → CycloneDX 1.5 SBOM(`host_audit_sbom`) → `trivy sbom --offline-scan --skip-db-update`(호스트마다 순차) → 분류(`host_audit_package_findings`) → 섹션 모델(`host_audit_package_section`). 판정·분류·집계 규칙은 모두 `filter_plugins/host_audit_packages.py`에 있고 템플릿(`templates/sections/package_vulnerability.html.j2`)은 그리기만 한다. 호스트별 분류(AUD-322)는 그 규칙을 쓰는 커스텀 모듈이 한다(아래 '발견은 파일로, 요약만 변수로').
- **Trivy 고정**: `vars/trivy.yml`의 버전·SHA256(직접 계산한 값, upstream checksums.txt를 기준으로 쓰지 않음)과 맞는 릴리스만 `get_url checksum`으로 받아 러너 캐시(`host_audit_cache_dir`)에 풀고 실행한다. restic(BAK-075)과 같은 방식이고 커스텀 Semaphore 이미지가 필요 없다. 버전을 올릴 때는 sigstore 번들을 `cosign verify-blob`으로 검증한 뒤 sha256을 직접 계산해 넣는다(절차는 파일 머리말). 2026-03 공급망 사고(GHSA-69fq-xp46-6x23)의 v0.69.4는 쓰지 않는다. 현재 v0.75.0(amd64·arm64 모두 cosign 검증 통과, 2026-10-08).
- **취약점 DB**: 매 실행 `trivy image --download-db-only`로 갱신한다(`host_audit_trivy_db_repository`로 미러 지정 가능). 갱신에 실패하면 캐시 DB의 `UpdatedAt`이 7일(`host_audit_trivy_db_max_age_days`) 이내일 때만 그 캐시로 판정하고, 넘었거나 캐시가 없으면 섹션 전체를 '점검불가'로 표시한다(실행은 계속). DB 생성 시각과 갱신 여부는 표지의 '취약점 DB'에 찍힌다. 캐시가 실행 사이에 남으려면 러너의 `HOME`(또는 `host_audit_cache_dir`)이 유지돼야 한다.
- **Trivy 실패 처리 (#154)**: AUD-321이 `failed_when: false`로 계속 진행한 뒤 AUD-322가 호스트마다 다음을 '점검불가'(`scan_failed`)로 표시한다. 사유에 Trivy의 rc가 들어가고 137(또는 Ansible이 시그널 종료로 보고하는 -9)이면 'OOM-kill 추정'이 붙는다. 다른 호스트의 판정과 실행은 계속된다. 순서는 rc → 결과 파일 → 내용이다(rc≠0이면 파일이 유효해 보여도 신뢰하지 않는다).
  - rc≠0
  - 출력이 비어 있음(0바이트)
  - 잘린 JSON(쓰는 도중 종료). 원문 파싱은 필터가 하므로 한 호스트의 손상이 AUD-322 전체를 멈추지 않는다.
  - 결과 파일 없음
- **발견은 파일로, 요약만 변수로 (#155)**: 발견 약 55만 건이 `set_fact`·보고서 모델·템플릿 평가를 거치며 메모리에 오르던 두 경로(AUD-322/323의 호스트별 결과, AUD-021 `package_results` → findings 색인)를 파일 기반으로 바꿨다.
  - **커스텀 모듈을 쓴 이유**: 필터는 `ansible-playbook` 프로세스 안에서 돌아 Trivy 결과 파싱 같은 일시적 피크가 그대로 최대 메모리로 남는다. 모듈은 별도 프로세스라 끝나면 메모리를 돌려준다. 이 저장소의 첫 커스텀 모듈이다(#156에서 `host_audit_baseline_load.py`가 추가돼 모두 셋): `roles/host_audit/library/host_audit_package_scan.py`(AUD-322), `host_audit_findings_write.py`(AUD-510).
  - **FQCN 예외**: 세 모듈(`host_audit_package_scan`, `host_audit_findings_write`, `host_audit_baseline_load`)은 역할 안(`library/`)의 로컬 모듈이라 컬렉션 FQCN이 없다(스펙 #155가 role `library/`를 지정). 다른 태스크 모듈은 그대로 FQCN이다.
  - **회귀 확인**: 변경 전 코드(b1665bb)의 필터로 같은 합성 입력의 섹션 모델·Audit Baseline 결과·`findings.json`을 따로 기록해(`tests/fixtures/host_audit_packages/golden_before_155.json`) 변경 후 결과가 같음을 비교한다.
  - **규칙은 한 벌**: 모듈은 `roles/host_audit/module_utils/host_audit_packages.py`로 `filter_plugins/host_audit_packages.py`를 심볼릭 링크해 같은 분류·실패 판정을 쓴다(필터와 갈라지지 않게). 역할 밖 플레이북(harness·pytest)은 `ANSIBLE_LIBRARY`·`ANSIBLE_MODULE_UTILS`로 이 디렉터리를 가리킨다.
  - **AUD-322**: 호스트마다 모듈이 기록과 Trivy 결과를 읽어 분류하고 `package_findings/<호스트>.json`에 발견 전체를 쓴다. 돌려주는 값은 요약(심각도·분류별 건수, 긴급·높음 상세 후보 최대 `host_audit_package_detail_limit`행과 총수, 파일 경로)이다. 상세 후보 상위 N행의 합집합에 전체 상위 N행이 들어 있으므로 요약만으로 섹션 모델이 같아진다. Trivy 실패 판정(rc → 파일 → 내용, 4경우)은 #154 그대로다.
  - **AUD-323**: 요약만 모아 `host_audit_package_section`으로 섹션 모델을 만든다. `_host_audit_package_results` 사실은 더 없다.
  - **AUD-021 / Audit Baseline**: 메타에서 `package_results`를 빼고 `package_findings_dir`를 넘긴다. 비교는 호스트 파일을 하나씩 읽어 하고(호스트 단위 집합), 상태는 보고서가 그리는 상세 행의 키만 남기며 건수·재발·해소·확인 불가는 따로 센다. 보고서 결과(섹션 건수, 상세, 부록, Audit Baseline 배지)는 이전과 같다(pytest가 같은 합성 입력으로 이전 방식의 결과와 비교).
  - **AUD-510**: `findings.json`의 Package 섹션(`hosts`, 호스트별 정렬·중복 제거한 `ids`)은 모델 대신 파일에서 호스트 하나씩 읽어 쓴다. 모델의 `baseline.document`에는 이 섹션이 없고 `baseline.package_index`(`dir`, 점검된 `hosts`)가 대신 있다. 저장되는 `findings.json`의 형식은 그대로다(Audit Baseline 비교가 다음 달에 그대로 읽는다).
  - **보관(AUD-512~513) 결정**: `package_findings/`는 **보관하지 않는다**. 호스트당 수 MB(약 23,000건 기준)이고, 같은 내용을 보관되는 `sbom/<호스트>.cdx.json`을 Trivy로 다시 판정해 뽑을 수 있으며(CentOS는 vault 표 포함, §11.1 재판정), 발견 id는 보관되는 `findings.json`에 들어 있다. 다만 재판정은 **그 시점의 취약점 DB**를 쓰므로 판정 당시와 결과가 다를 수 있다 — 판정 당시 기록은 `findings.json`과 `package_vulnerability.json`이다. 3년 잠금 버킷에 중복 용량을 얹지 않는다. 그래서 AUD-513의 대상에서 뺀다(AUD-512 find 결과를 거른다, `trivy/`와 함께). 보관 실패로 디렉터리가 남을 때(#157)는 이 파일도 함께 남는다. 보관이 성공하면 디렉터리와 함께 정리된다.
  - **이전 실행의 findings.json (#156)**: Audit Baseline 조회(AUD-505)로 받은 지난 실행의 `findings.json`도 변수로 오르지 않는다. 러너 파일(`package_findings/previous_findings.json`)로 받아 AUD-508 모듈이 Package id를 `package_findings/previous/<호스트>.json`으로 나누고, `host_audit_baseline_history.baseline`에는 나머지 작은 섹션과 그 디렉터리 위치만 남는다. 상세는 §11.2·§11.6.
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
├── sbom/<Inventory Hostname>.cdx.json   # Trivy 입력 SBOM (압축 없이 보관, §11.1)
├── trivy/<Inventory Hostname>.json      # Trivy 원본 결과. 러너 전용, 보관하지 않음 (#159, §11.1)
├── trivy_version.json                   # 판정에 쓴 Trivy 버전·DB 메타데이터 (보관, AUD-326)
├── package_findings/<Inventory Hostname>.json  # 호스트별 분류 결과(발견 전체). 러너 전용, 보관하지 않음 (#155)
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
| `AUD-321` | `Judge each SBOM with Trivy (offline, one host at a time)` | `ansible.builtin.command` | 러너 | `changed_when: false`, `failed_when: false`(실패 판정은 AUD-322가 rc로 한다) |
| `AUD-322` | `Classify the Trivy findings of each host` | `host_audit_package_scan` (role `library/` 커스텀 모듈) | 러너 | 호스트마다 별도 프로세스가 패키지 기록·`trivy/<호스트>.json`을 직접 읽어 분류하고 발견 전체를 `package_findings/<호스트>.json`(`0600`)에 쓴다. 돌려주는 값은 요약(건수·상세 후보·파일 경로)뿐이고 `set_fact`로 만들지 않는다(#155). AUD-321의 호스트별 rc와 결과 파일로 rc≠0·빈 출력·잘린 JSON·파일 없음을 호스트 '점검불가'로 판정한다(#154). 호스트별 결과는 `register`로만 모은다(리스트 누적 금지 — 메모리가 호스트 수의 제곱) |
| `AUD-323` | `Build the Package Vulnerability section model` | `ansible.builtin.set_fact` | 러너 | AUD-322의 요약을 한 번에 모아 `host_audit_package_section` 필터(발견 전체는 메모리에 없다) |
| `AUD-324` | `Save the Package Vulnerability section on the runner` | `ansible.builtin.copy` | 러너 | 실행별 파일 `0600` |
| `AUD-325` | `Read the Trivy version and vulnerability DB metadata` | `ansible.builtin.command` | 러너 | `trivy version --format json`(`timeout 60`), `changed_when: false`, `failed_when: false` (실패는 AUD-326이 대체값으로 처리) |
| `AUD-326` | `Save the Trivy version and DB record of this run on the runner` | `ansible.builtin.copy` | 러너 | `trivy_version.json` `0600`, `host_audit_trivy_provenance` 필터, DB를 못 써도 기록, 보관 대상 (#159) |

검증: pytest `tests/test_host_audit_packages.py`(기록 파싱, SBOM 동등성 고정, DB 7일 규칙, CentOS 수정본 없음·will-not-fix 분류, 섹션·보고서 모델, 템플릿, Trivy 고정, Trivy 실패 4경우 점검불가·나머지 호스트 계속). molecule Fast Scenario는 패키지 프로브를 포함한 수집 전후 관리 영역이 같은지(`VERIFY-AUD-010`)와 패키지 기록 구조(`VERIFY-AUD-302`)를 확인한다. Trivy 판정 자체는 molecule 범위 밖이다(스펙 #115 테스트 결정 ②).

## 10. Configuration Vulnerability (KISA-2026, #121)

- **기준**: KISA 「2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」 Unix 서버 항목. 항목 코드는 판을 붙여 `KISA-2026:U-NN`으로 적는다(2021판과 번호가 다르다). CIS RHEL 9 Benchmark v2.0.0 규칙 번호는 참조 열로만 둔다. 근거: `docs/research/host-audit-configuration-vulnerability-baseline.md`(#102, `research/host-audit-configuration-vulnerability-baseline` 브랜치).
- **구현 범위**: Unix U-01~U-67 전 항목. 계정 관리 U-01~U-13(#121), 파일 및 디렉토리 관리 U-14~U-33, 서비스 관리 U-34~U-63, 패치 관리 U-64, 로그 관리 U-65~U-67(#122). 자동 판정할 수 없는 항목은 점검불가(수동)로 두고 판단에 쓸 목록을 증적으로 남긴다(항목별 방법은 YAML `check`, 공통 규칙은 §10.4).
- **항목 목록의 원본은 YAML**: U-01~U-67의 항목 메타데이터는 `filter_plugins/host_audit_kisa_items.yml` 한 파일이 유일한 원본이다(Spec #488). `title`·`severity`·`category`·`criteria`·`cis`에 우리 probe가 보는 것을 한 줄로 쓴 `check`, 가이드를 우리 말로 요약한 `purpose`·`threat`·`remediation`, 조치 영향도·조치 난이도, 가이드 쪽 번호 `guide_page`가 붙는다(필드는 §10.5). `host_audit_kisa.py`는 import 시 이 파일을 읽기만 한다. 항목 표는 문서에 두지 않으니 항목 내용은 YAML을 고친다.
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

### 10.1 항목 목록 (YAML)

항목 목록(코드, 항목명, 중요도, 분류, 판단 기준, CIS 참조, 점검방법)은 `filter_plugins/host_audit_kisa_items.yml`이다. 문서의 항목 표를 지웠으므로 두 곳이 어긋나지 않는다. 항목명·중요도·판단 기준(`criteria`)은 2026판 가이드 PDF 원문과 대조해 원문 문장을 따랐고(그래서 U-09는 "불필요한 그룹이 제거된 경우", U-63은 "권한이 640"이며 우리 probe는 기본 GID 누락과 640 이하를 본다 — 이 차이는 `check`에 있고 본문 표는 `criteria`만 싣는다), 항목마다 `guide_page`(가이드 인쇄 쪽)로 원문을 찾을 수 있다. 처음에는 `9u4a/kisa-infra-audit`(MIT)가 인용한 설명을 따랐으나 #490에서 원문과 대조해 바로잡았다(U-05 따옴표, U-09·U-26·U-63의 판단 기준 등). 판정 스크립트는 가이드를 참고해 새로 작성했다(코드 차용 없음).

### 10.4 파일 및 디렉토리·서비스·패치·로그 관리 항목의 공통 규칙 (#122)

공통 규칙:
- **서비스 사용 여부**: 프로세스 이름(`ps -e -o comm=`), systemd unit active(`systemctl is-active`), (x)inetd 항목(`/etc/xinetd.d/NAME`의 `disable = yes` 아님, `inetd.conf`의 주석 아닌 줄), 필요한 경우 TCP listening(`ss`·`netstat`) 중 하나라도 있으면 사용 중으로 본다. 서비스를 쓰지 않아 기준이 성립하지 않는 항목은 해당없음이다.
- **파일 탐색**: U-15·U-23·U-25는 루트(/)와 로컬 디스크 파일시스템(ext2/3/4·xfs·btrfs) 마운트를 `find -xdev`로 뒤진다(가상·네트워크 파일시스템 제외). 각 탐색은 120초 제한이며, 넘으면 점검불가(수동)다.
- **읽기 전용**: 커널 모듈을 올릴 수 있는 방화벽 조회(`nft`, 레거시 `iptables`)는 해당 모듈이 이미 올라와 있을 때만 한다. sendmail 버전은 실행하지 않고 `sendmail.cf`의 `DZ` 줄로 읽는다. rpm은 조회하지 않는다.
- **file capability (#432, Spec #433)**: U-23의 증적 줄 끝에 file capability가 붙은 파일을 덧붙인다(SUID 밖의 권한 상승 통로). 읽기 전용이고 알림은 없다. 판정(양호·점검불가(수동))은 SUID/SGID만으로 정해지며 capability는 판정을 바꾸지 않는다.
  - 수집: 로컬 디스크 파일시스템(SUID 탐색과 같은 마운트 집합, `-xdev`)의 파일에 `getcap`을 돌린다(`find -xdev -type f -exec getcap {} +`). `getcap -r`은 마운트 경계를 넘어 `/proc`·네트워크 파일시스템까지 걸으므로 쓰지 않는다. 시간 제한(120초)과 목록 길이 제한(최대 40개)은 SUID/SGID 탐색과 같다.
  - 컨테이너 저장소 제외: 역할 변수 `host_audit_kisa_capability_exclude_paths`(기본 `/var/lib/docker`·`/var/lib/containerd`·`/var/lib/containers`·`/home/*/.local/share/containers`·`/root/.local/share/containers`, `find -path` 글롭)와 일치하는 디렉터리는 `getcap` 탐색에서 들어가지 않는다(`-prune`). 항목마다 경로와 그 아래(`경로/*`)를 함께 걸어, 탐색 시작점(마운트)이 제외 경로 안쪽(예: `/var/lib/docker/overlay2`가 별도 마운트)이어도 그 시작점째 건너뛴다. 컨테이너 이미지 레이어(`overlay2` 등)는 호스트 파일이 아니라 이미지 내용이라 걸으면 같은 이미지가 호스트마다 검토 항목으로 쏟아져 노이즈가 되기 때문이다. 이 제외는 capability 목록에만 걸리고 SUID/SGID 판정(양호·점검불가(수동))은 그 경로도 그대로 걷는다. 컨테이너 안의 capability는 이 점검 범위 밖이다(이미지 점검 대상). 목록을 비우면 전부 탐색한다.
  - 구분: 역할 변수 `host_audit_kisa_capability_defaults`(`"<경로> <capability 이름>"`)와 경로·capability 이름 집합이 같으면 배포판 기본이고, 그 밖의 항목만 `file capability review (N): ...`로 검토 대상이 된다. 이름은 순서·중복과 무관한 집합으로 비교한다(`cap_net_admin,cap_net_raw` = `cap_net_raw,cap_net_admin`). 배포판마다 같은 경로의 조합이 다를 수 있으면 같은 경로 줄을 여러 개 둔다(기본값의 ping은 `cap_net_raw`와 `cap_net_admin,cap_net_raw` 두 줄). 플래그(`=ep`, `+p`)와 옛 libcap(CentOS 6/7)의 `경로 = cap+ep` 표기는 비교하지 않는다.
  - 한계: 기본 목록은 배포판 패키지 지식으로 적었고 실제 호스트에서 실측하지 않았다. 첫 보고서에서 기본인데 '검토'로 나온 항목은 호스트에서 확인해 목록에 줄을 더한다.
  - 한계: 경로는 출력에서 첫 ` cap_` 앞까지로 읽으므로 공백이 있는 경로도 통째로 보존한다. 경로 자체에 ` cap_`이 들어 있으면(사실상 없음) 경로와 capability를 가르지 못한다.
  - 소요 시간: U-23은 SUID/SGID 탐색과 `getcap` 탐색을 각각 최대 120초까지, 합쳐 최대 240초 돈다. 점검 태스크(AUD-200)에는 별도 태스크 제한이 없고 `ansible.cfg`의 `timeout = 30`은 SSH 연결 제한이라 실행 시간에 걸리지 않는다. 같은 120초 `find`를 쓰는 U-15·U-17·U-25·U-26(각 1회)과 합쳐 호스트당 최악 6회 × 120초 = 12분이다. 저장소에는 이를 끊는 제한이 없다(Semaphore 쪽 실행 제한은 저장소 밖 설정이라 확인하지 못했다). 각 탐색이 시간을 넘으면 그 항목만 점검불가로 남는다.
  - 증적 문구: `file capability: none`(없음), `file capability: default only (N)`(기본만), `file capability review (N): ...; default: M`(기본 밖 있음), `file capability: 점검불가(...)`(`getcap`이 없거나 실행할 수 없음, 시간 초과).
- **비밀값**: SNMP community는 길이·문자 종류만 판정하고 값은 증적에 싣지 않는다.


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

검증: pytest `tests/test_host_audit_kisa_capability.py`(#432: file capability 세 경우 — 기본만 있음·기본 밖 항목 있음·`getcap` 없음/실행 불가, SUID 판정 불변, 옛·현재 libcap 표기, 길이 제한, 역할 변수 주입)와 `tests/test_host_audit_kisa.py`(판정 5종, 예외 유효·만료·승인 대기·범위, 보고서 섹션·부록, 가짜 루트에서의 스크립트 판정과 해시 미노출, #122: U-01~U-67 카탈로그·스크립트 1:1, 프로비저닝된 서버·취약 서버 가짜 루트의 항목별 판정, postfix 메일 항목, U-28 Docker 구간과 예외 레지스터, SNMP community 비노출, dash·`bash --posix`·bash 결과 일치). 프로세스·unit·listening 포트는 `ps`·`systemctl`·`ss` 스텁으로 고정해 pytest가 실행 머신에 좌우되지 않는다. molecule Fast `VERIFY-AUD-200`·`VERIFY-AUD-201`(점검 실행·판정 기록). 읽기 전용은 `VERIFY-AUD-010` 스냅샷 사이에서 함께 확인된다.

### 10.5 조치방법과 조치 영향도 (Spec #488 / Ticket-2, #490)

보고서 본문의 "양호 외 항목" 표가 항목마다 무엇을 어떻게 고치는지, 고치면 서비스가 얼마나 흔들리는지를 보여 준다. 이 단계에서 호스트는 여전히 바꾸지 않고(읽기 전용), 조치도 이행 추적도 하지 않는다.

- **YAML 필드(항목마다 필수)**: `check`(우리 probe가 보는 것 한 줄), `remediation.summary`(OS 공통 조치 요약, 한 줄 300자 이하, 앞뒤 공백 없음 — 본문 표가 한 줄로 싣는다), `remediation.steps.rhel`·`steps.debian`(계열에 따라 명령·파일이 실제로 다른 항목만, 키는 이 둘뿐), `remediation_impact`·`remediation_effort`(`level` 1~3과 `reason`), `guide_page`, `purpose`·`threat`(각 1~2문장). 가이드 원문은 옮기지 않고 우리 말로 요약하며 설정값·경로 같은 사실만 그대로 둔다. `tests/test_host_audit_kisa_remediation.py`가 67개 전부의 필드와 level 범위, steps 키, 인프라 상세(주소·관리번호·메일)가 없음을 검사한다.
- **조치 영향도(Remediation Impact)**: 조치가 호스트에서 돌고 있는 서비스를 흔드는 정도. 1은 가이드가 영향 없음으로 본 경우(설정·권한 변경 위주이며, 서비스 재기동이 따르는 항목도 있어 구체적인 부수 작업은 항목의 reason을 따른다), 2는 재기동·재로그인이나 특정 연동이 조건부로 영향받는 경우, 3은 접속 불가·서비스 중단·로그인 불능 가능성이 있는 경우다. 가이드 "조치 시 영향"이 "영향 없음"류(정형문 50개와 조건부 U-05·U-50)인 52개는 1이고, 가이드가 개별로 서술한 15개(U-02, 03, 04, 06, 10, 12, 19, 23, 28, 41, 45, 49, 56, 57, 66)만 그 문장을 근거로 2 또는 3이다. 판정 위험(중요도)과 별개다.
- **조치 난이도(Remediation Effort)**: 고치기 어려운 정도. 1은 설정 한 곳이나 명령 한두 개, 2는 여러 파일이나 대상 목록을 하나씩 처리하거나 재기동이 따르는 경우, 3은 패키지 교체·정책 수립·협의·판단이 필요한 대량 검토다. 조치 방법·사례를 근거로 67개 모두 매긴다.
- **값의 근거와 확정**: level과 reason은 2026판 가이드 PDF와 조치 방법을 근거로 쓴 값이며 확정은 PR 검토로 한다(바꿀 때는 reason도 함께 검토한다). 영향도 1인 52개는 가이드 서술에 따라 1로 고정하고, 실제 우려가 있으면(예: U-37 일반 사용자 실행 차단, U-64 서비스 영향 파악) reason에 적어 두며 올릴지는 PR에서 정한다. 이 고정 때문에 reason에 우려가 적힌 1이 정렬에서는 위로 올 수 있다. 개별 서술 15개에는 U-04도 들어 있어 Linux만 보면 영향이 없어도 가이드의 HP-UX 서술을 근거로 2다. 영향도 2·3 항목과 난이도 분포는 PR 본문 표로 보여 준 뒤 사용자가 확정한다.
- **조치 문구와 probe의 범위**: `remediation`은 가이드의 조치 방법이고 `check`는 우리 probe가 보는 범위라 둘이 완전히 겹치지는 않는다(예: 가이드는 xinetd.d·systemd 설정 파일까지 다루고 U-20 probe는 두 파일만 판정한다). 조치 뒤 판정은 다음 실행에서 probe가 확인한다. 알려진 차이: U-57의 vsftpd 조치 문구는 `userlist_deny=yes`일 때만 user_list가 차단 목록이라고 적지만 probe는 `userlist_deny`를 보지 않는다(probe 쪽 보강은 이 티켓 범위 밖이다).
- **파생 값(저장하지 않음)**: 위험도 = 가이드 중요도(상 3, 중 2, 하 1), 우선순위 = 상 1, 중 2, 하 3, 시급성 = 우선순위 1 단기, 2 중기, 3 장기(기한은 정하지 않는다). 판정·호스트와 무관하게 항목마다 같은 값이다. `host_audit_kisa.py`의 `risk_level`·`priority_of`·`urgency_of`·`remediation_view`가 계산한다.
- **본문 표**: "양호 외 항목" 표에 중요도 옆 `조치 영향도` 열(숫자)과 판단 기준 칸 아래 `조치: <remediation.summary>` 한 줄이 붙는다. 호스트별 부록(`appendix_config_vulnerability`)에는 조치 데이터를 싣지 않는다(부록 행은 기본 열만 쓴다). 표 아래에 조치 영향도 설명이 실리고, 가이드 출처 문장("조치방법은 KISA 「2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」를 바탕으로 요약함")은 양호 외 항목이 없어도 보고서 맨 끝(검토 및 결재 뒤)에 한 번 실린다.
- **정렬**: 본문 표는 우선순위(1이 먼저) → 조치 영향도(낮은 것 먼저) → 조치 난이도(쉬운 것 먼저) → 판정(취약 → 점검불가(수동) → 예외(승인)) → 항목 코드 순이다. 앞의 세 키가 우선순위 규칙이고, 세 키가 같은 행끼리(다른 항목 포함)는 판정, 그다음 항목 코드가 순서를 정한다. 이전의 판정 우선 정렬은 이 규칙으로 바뀌었다(Spec #488 결정: 표 정렬은 우선순위 규칙을 따르며 판정은 정렬 키가 아니라 열로 보인다. 그래서 예외(승인) 행이 같은 우선순위의 취약 행보다 위에 올 수 있다). 정렬은 `order_findings`가 한다.
- **호스트별 JSON 불변**: 조치 데이터는 보고서 모델을 만들 때 YAML에서 붙인다. `config_vulnerability`의 `edition`·`status`·`reason`·`results[].{code,result,verdict,evidence,exception}`와 레코드 `schema_version` 2는 바뀌지 않는다(Audit Baseline 비교 호환).
- **조치 안내 부록(`부록 N+1. 조치 안내`, Spec #488 / Ticket-3, #491)**: 호스트별 부록 뒤, 검토 및 결재 앞에 항목 단위 부록이 붙는다. N은 호스트별 부록 수이므로 번호는 그 뒤로 이어진다. 대상은 본문 "양호 외 항목" 표와 같은 항목 집합이고 같은 순서(`order_findings`)다. 한 항목은 판정이 달라도 한 블록이다. 블록(`<section class="rg-block">`)은 머리에 판정별 호스트 목록(`취약: … · 점검불가(수동): … · 예외(승인): …`, 호스트가 없는 판정은 뺀다), 이어서 점검 목적·보안 위협·판단 기준·점검방법(`check`)·조치방법·조치 영향도와 조치 난이도(단계와 이유)·`가이드 p.<guide_page>`를 싣는다. 조치방법은 `summary`와 그 항목에 있는 계열별 `steps` 전부이며 계열 이름(RHEL 계열·Debian 계열)을 붙이고 호스트의 계열로 고르지 않는다(계열이 섞인 호스트 목록을 한 블록으로 처리하기 위해서다. 호스트 계열에 맞춘 단계는 Remediation Plan xlsx가 고른다). steps의 줄바꿈은 `white-space: pre-wrap`으로 살린다. 호스트별 증적은 다시 싣지 않는다. 블록은 `break-inside: avoid`라 쪽 중간에서 잘리지 않고 쪽수 상한은 없다(블록 하나가 한 쪽보다 길면 브라우저가 어쩔 수 없이 나눈다. 호스트 목록이 아주 길어지는 경우도 같다. 스펙이 쪽수 상한을 두지 않기로 했으므로 호스트 목록 상한이나 접기는 두지 않는다. 블록은 항목 전체 코드(`KISA-2026:U-NN`)로 구분하고 카탈로그 조회는 본문 표(`_item_meta`·`remediation_view`)와 같은 규칙이라 다른 판 접두어의 코드도 같은 항목 번호의 카탈로그 문구를 쓰며(알려진 한계, 저장 기록의 판은 항상 `KISA-2026`이다), 카탈로그에 없는 코드도 본문 표와 같은 집합이 되도록 가진 열만으로 블록을 만든다). 양호 외 항목이 없는 실행에서는 부록 제목 아래에 `조치 안내 대상 없음`을 표시해 부록이 빠진 것과 대상이 없는 것을 구분한다. 데이터는 보고서 모델의 `config_vulnerability.remediation_guide`(항목 YAML에서 붙인 값뿐)이고 템플릿은 `sections/remediation_guide.html.j2`다. 검증은 공유 렌더링 테스트 `tests/test_host_audit_remediation_guide.py`(부록 위치·번호, 본문 표와 같은 순서, 판정이 섞인 항목의 호스트 목록, steps 있는 항목·없는 항목, 대상 없음, 이스케이프, `break-inside`)다.
- **범위**: 호스트별 Remediation Plan xlsx는 §17이다. HTML의 조치 요약·조치 영향도·조치 안내 부록은 필터·템플릿 변경이라 SPEC-ID가 없다.

## 11. 보관과 Audit Baseline (#125)

실행마다 러너의 실행 디렉터리 전체를 RustFS **Host Audit 전용 버킷**(기본 `host-audit`)에 올리고, 직전 정기 실행(Audit Baseline)과 비교해 모든 섹션의 발견을 표시한다. 모든 동작은 러너 localhost의 보고서 단계에서 일어나고 대상 호스트에는 아무것도 하지 않는다. check 모드에서는 조회·업로드를 하지 않는다.

### 11.1 버킷 레이아웃

| 키 | 내용 | 쓰는 실행 |
|---|---|---|
| `<YYYY-MM>/<run_id>/report.html` | A4 보고서 | 모든 실행 |
| `<YYYY-MM>/<run_id>/mail_summary.json` | 메일 요약(제목·섹션별 한 줄·첨부 SHA-256, 주소 없음) — 재발송이 읽음 (#126) | 모든 실행 |
| `<YYYY-MM>/<run_id>/run.json` | 실행 메타(`run_kind` 포함) | 모든 실행 |
| `<YYYY-MM>/<run_id>/findings.json` | 섹션별 발견 색인 `{section: {hosts, ids: {host: [id]}}}`, `resolved`, `baseline_run_id` | 모든 실행 |
| `<YYYY-MM>/<run_id>/trivy_version.json` | 판정 당시 Trivy 버전·취약점 DB 메타데이터 `{trivy_version, db_version, db_updated_at, db_downloaded_at, db_next_update, db_status, db_refreshed, source}` (#159) | 모든 실행 |
| `<YYYY-MM>/<run_id>/sbom/<host>.cdx.json` | Trivy 입력 SBOM(CycloneDX), 압축 없이 그대로. 다시 판정하는 입력이다(아래 재판정) (#159) | 모든 실행 |
| `<YYYY-MM>/<run_id>/xlsx/host-audit-<run_id>-total.xlsx` | 모든 호스트의 행을 한 시트에 모은 합계 Remediation Plan(§17). 호스트가 없는 실행에는 없다. 파일마다 `AUD-513` SHA-256, Content-Type 은 호스트별 xlsx와 같다(`AUD-514`) | 모든 실행 |
| `<YYYY-MM>/<run_id>/xlsx/host-audit-<run_id>-<host>.xlsx` | 호스트별 Remediation Plan(§17). 파일마다 `AUD-513` SHA-256, Content-Type `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`(`AUD-514`) (#494) | 모든 실행 |
| `<YYYY-MM>/<run_id>/xlsx/host-audit-<run_id>-xlsx.zip` | 위 xlsx 전부(호스트별과 합계)를 묶은 zip(`AUD-026`). 압축 안의 이름만 폴더를 가진다: 합계는 `total.xlsx`, 호스트별은 `hosts/<Inventory Hostname>.xlsx`(§17.2). 메일의 두 번째 첨부이고 같은 바이트가 여기 보관된다. `AUD-513` SHA-256, Content-Type `application/zip`(`AUD-514`). 재발송이 받아 요약에 기록된 해시와 대조한다(§13.4) (#495) | 모든 실행 |
| `<YYYY-MM>/<run_id>/hosts/*.json` 등 | 호스트별 JSON, 패키지 목록(`packages/`), `package_vulnerability.json`, `pointer.json`. `trivy/`와 `package_findings/`는 올리지 않음(§9) | 모든 실행 |
| `baseline/<run_id>.json` | 포인터 `{run_id, run_kind, started_at, findings_key, resolved}` | **정기 실행만**, 모든 업로드 성공 후 |

`<YYYY-MM>`은 보고서 시간대(`host_audit_timezone`) 기준 실행 시작 월이다. 수시 실행은 보관하되 포인터를 쓰지 않으므로 Audit Baseline이 되지 않는다.

**용량 (#159, #151을 뒤집음)**: 버킷은 GOVERNANCE 3년 보존이라 올린 뒤에는 지울 수 없다. 전체 실행(24대) 1회가 약 3.57 GiB였고 대부분이 `trivy/<host>.json`(호스트당 약 200~250 MB, 대부분이 `References`·`Description`)이다. #151은 이를 gzip해 올리기로 했지만(#147 옵션 2), 그래도 지울 수 없는 용량이 크고 판정 원본은 SBOM에서 다시 만들 수 있어 `trivy/`를 **아예 올리지 않기로 바꿨다**(옵션 1). 실행당 보관 용량은 SBOM 등 약 30 MB다. 그래서 압축 단계(`AUD-517`~`AUD-520`)는 없앴고 `sbom/`도 압축하지 않는다(작아서 이득이 적고, 보관한 파일이 곧 업로드한 파일이다). 보관 해시(`AUD-513` SHA-256)는 올리는 파일 그대로의 값이고, `AUD-512`가 찾은 파일에서 `trivy/`와 `package_findings/`를 뺀다. 러너의 `trivy/`는 정리 정책(§14, #157)이 그대로 다룬다.

**판정 기록과 재판정 (#159)**: 판정 당시 Trivy 버전과 취약점 DB 메타데이터(DB 버전, `UpdatedAt`, `DownloadedAt`, `NextUpdate`)를 `AUD-325`가 `trivy version --format json`으로 읽고 `AUD-326`이 실행 결과 `trivy_version.json`에 적어 함께 보관한다(DB를 못 써도 기록하며, `trivy version`이 실패하면 고정 버전과 DB 메타데이터 파일 값으로 대신하고 `source`에 표시). 상세 증적이 필요하면 보관된 `sbom/<host>.cdx.json`을 내려받아 `trivy_version.json`의 버전과 같은 Trivy로 `trivy sbom --scanners vuln --format json <SBOM>`을 한 번 더 돌린다. **한계**: 재판정은 그 시점의 DB를 쓴다(DB는 보관하지 않는다). 판정 당시와 건수가 다를 수 있고(새 CVE 추가, 수정본 반영), 판정 당시 기록은 `findings.json`·`package_vulnerability.json`뿐이다. `trivy_version.json`의 `db_updated_at`은 당시 DB의 시점을 알려 줄 뿐 그 DB를 복원하지는 못한다. CentOS 6/7 분류(`CentOS용 수정본 없음`)는 재판정 결과에 vault 표(`files/centos_vault_final/`)를 적용해 다시 만든다.

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

**기준선 읽기 (#156)**: 이전 `findings.json`은 형식이 그대로(변경 없음)이고 읽는 방법만 파일 기반이다. AUD-505가 러너 파일로 받고, AUD-508(`host_audit_baseline_load`)이 `sections.package_vulnerability.ids`를 `package_findings/previous/<호스트>.json`으로 나눈다. 비교는 이번 실행의 호스트 파일과 이 파일을 호스트 하나씩 읽어 하므로 판정은 이전과 같다(`tests/test_host_audit_baseline_files.py`가 이전 형식의 기준선으로 확인). 조회 실패(파일 없음·손상, 상태 코드≠200)는 AUD-506이 이전과 같이 `failed`로 판정한다.

Asset Inventory 항목은 발견이 아니라 변경이다: 기준선 대비 **신규**·**삭제**만 표시하고, 이번에 처음 점검한 호스트의 항목은 변경으로 세지 않는다. 보고서에는 Configuration Vulnerability '양호 외 항목'의 호스트 옆, Package Vulnerability '긴급·높음 상세'의 CVE 옆에 상태 배지가 붙고, 'Audit Baseline 대비 변경' 섹션에 섹션별 건수·재발·해소·확인 불가·Asset Inventory 변경이 나온다. 표지의 '비교 기준'에 Audit Baseline 실행 ID, '원본 보관'에 버킷 경로가 찍힌다.

**새 섹션의 참여 방법**: 섹션 모델에 `baseline_findings: {hosts: [점검한 호스트], findings: [{host, id, label}]}`를 넣으면 같은 규칙으로 비교된다(예: Configuration Drift). 보고서 모델 빌더에서 Audit Baseline은 마지막에 적용된다.

### 11.3 실패 처리

- 자격증명·입력 누락: 업로드하지 않는다. 보고서는 만들고(비교 기준 '조회 실패') 실행은 실패로 끝난다(`AUD-516`).
- Audit Baseline 조회 실패(목록·포인터·findings.json): 비교 없이 보고서를 만들고 원본은 올린 뒤 실행을 실패로 끝낸다.
- 업로드 실패(파일 하나라도): 실행을 실패로 끝낸다. 정기 실행이면 포인터를 올리지 않아 이 실행은 다음 달 비교 기준이 되지 않는다.
- 판정 위치(#126): 자격증명은 `storage_credentials.yml`(AUD-501·502, 재발송도 사용), 판정 `AUD-516`은 `storage_result.yml`에 있고 메일 발송(§13) **뒤에** 돈다. 그래서 원본이 다 올라간 실행은 Audit Baseline 조회만 실패했어도 메일이 나가고, 실행은 그 뒤 실패로 끝난다.

### 11.4 입력 (OpenBao, Git에는 시크릿 없음)

읽는 문서와 필수 키는 역할 `vars/main.yml`의 `host_audit_openbao_required` 하나가 선언하고, 입력 검증(`AUD-502`·`AUD-603`)·스키마 `required` 대조 테스트·요청 기록 단언이 같은 선언을 쓴다. 읽기는 공용 읽기 지점(`lookup('openbao_doc', ...)`, [openbao_integration.md](openbao_integration.md))뿐이라 역할에는 네임스페이스·마운트·접두사·로그인 코드가 없다.

| 문서 | 키 | 필수 | 설명 |
|---|---|---|---|
| `secrets/services/rustfs/audit_reports` | `access_key`, `secret_key` | ● | Host Audit 전용 키(Put·Get·List). 백업·유지보수 키 재사용 금지 |
| `inventory/services/rustfs` | `url` | ● | RustFS 주소(비밀 아님) |
| `inventory/services/rustfs` | `region` | | 기본 `us-east-1` |
| `secrets/services/alert/notify` | `url`, 선택 `token`·`auth_header` | ● (악화 알림이 있을 때, url만 필수) | KISA 악화 알림 webhook(§15). `token`이 있을 때만 `auth_header`(기본 `X-NANOIT-ACCESS`) 헤더로 붙인다. 못 읽어도 보관·메일은 막히지 않는다 |
| `inventory/config/host_audit` | `mail_recipients`, `mail_sender`, `mail_sender_display_name` | (필수 키 없음) | 메일 입력(§13.3). 없으면 읽기 실패가 아니라 메일 문제로 남는다 |
| `inventory/services/openobserve` | `url`, 선택 `org`·`ca_file` | ● (Log Review Report를 만들 때) | OpenObserve 주소(비밀 아님, §18). `org` 기본 `default` |
| `secrets/services/openobserve/readonly` | `username`, `password` | ● (Log Review Report를 만들 때) | OpenObserve 조회 전용 용도 계정(정책 `openobserve-readonly`, 읽기만). 서버가 조회 전용을 강제하지 못하므로 역할은 `POST _search`만 부른다(§18). 못 읽으면 보고서 항목이 '조회 실패'이고 실행은 계속된다 |

버킷 이름(`host_audit_storage_bucket`, 기본 `host-audit`)은 공개해도 되는 값이라 역할 기본값이다(전용 키의 정책이 이 버킷으로 범위가 정해져 있다). 주소·키는 대체값도 실행 변수(Extra variables) 덮어쓰기도 없다: 문서나 필수 키가 없으면 대체값 없이 보관 문제가 된다. 읽기 실패(문서 없음·403·연결 불가·인증 정보 없음)와 필수 키 누락은 실행을 여기서 멈추지 않고 `_host_audit_storage_problem`에 문서 경로와 키 이름만(값·원인은 가림) 남기며, 보고서는 비교 없이 만들어지고 `AUD-516`이 실행을 실패로 끝낸다. 보관 없이 돌리려면 `host_audit_storage_enabled=false`를 준다. 인증은 공용 읽기 지점의 AppRole(Semaphore Environment의 `VAULT_ROLE_ID`·`VAULT_SECRET_ID`)이다. 이 역할은 토큰을 따로 받아 두지 않는다(`_vault_token`을 만들지 않음): 읽는 태스크마다 새로 로그인하므로 앞 단계가 토큰 TTL(30분)보다 길어도 만료된 토큰을 쓰지 않는다. `host_audit_environment`는 `production|staging|development|test`만 허용한다(`AUD-001`). `host_audit` AppRole 정책이 위 문서를 읽는다(`openbao/`).

| 변수 | 기본값 | 설명 |
|---|---|---|
| `host_audit_storage_enabled` | `true` | false면 러너 로컬만, 비교 안 함 |
| `host_audit_storage_bucket` | `host-audit` | 버킷 이름 |
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

전용 키: 정책 `host-audit-putget-policy.json`(`s3:PutObject`·`s3:GetObject` on `host-audit/*`, `s3:ListBucket` on `host-audit`, Delete 없음)을 만들고 Host Audit 전용 사용자에 붙인 뒤 키를 OpenBao `secrets/services/rustfs/audit_reports`에 넣는다. RustFS 콘솔(Identity → Policies/Users) 또는 `rc admin`(MinIO 호환 관리 API `/rustfs/admin/v3/add-canned-policy`, `add-user`, `idp/builtin/policy/attach`)으로 한다. 확인 결과: 이 키로 Put·Get·List는 성공, Delete·다른 버킷 쓰기·수명주기 변경은 `AccessDenied`.

**Object Lock (RustFS 1.0.1 확인)**: 생성 시 Object Lock을 켜면 버저닝이 함께 켜지고, 기본 보존과 객체별 보존(`x-amz-object-lock-mode`)이 적용되며, 보존 중인 버전 삭제는 `AccessDenied`로 거부된다(COMPLIANCE로 확인). **GOVERNANCE**를 권장한다 — 개인정보나 시크릿이 잘못 올라갔을 때 관리자가 우회 권한으로 지울 수 있어야 하고, 전용 키에는 Delete도 우회 권한도 없으므로 점검 원본은 그대로 보호된다. 같은 키로 덮어쓰면 새 버전이 생길 뿐 이전 버전은 보존된다. Host Agents의 restic 버킷은 Object Lock을 끈다(ADR-0006) — 이 버킷과 다르다.

### 11.6 태스크 매트릭스

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `AUD-501` | `Read the Host Audit storage documents and the alert document (host_audit_openbao_required)` | `ansible.builtin.set_fact` (`lookup openbao_doc`) | 러너 | 읽기 전용, `no_log`. 문서마다 따로 읽어(`errors='ignore'`) 못 읽은 문서 경로만 보관 문제로 이름 붙이고, 알림 문서는 실패해도 보관을 막지 않음. 읽을 문서는 `host_audit_openbao_*_doc` 선언에서 옴 |
| `AUD-502` | `Resolve the Host Audit storage target and dedicated key` | `ansible.builtin.set_fact` | 러너 | 누락 항목은 문서 경로와 키 이름만(선언 `host_audit_openbao_required` 기준), `no_log` |
| `AUD-503` | `List the Audit Baseline pointers of scheduled runs` | `ansible.builtin.uri` (S3 ListObjectsV2) | 러너 | 읽기 전용, `no_log` |
| `AUD-504` | `Get the pointers of scheduled runs within the 12-month window` | `ansible.builtin.uri` (S3 GetObject) | 러너 | 읽기 전용, `no_log` |
| `AUD-507` | `Make the runner-only directory for the previous findings` | `ansible.builtin.file` | 러너 | `package_findings/`와 `previous/`, `0700` (보관하지 않는 디렉터리, #155·#156) |
| `AUD-505` | `Get the findings of the Audit Baseline run` | `ansible.builtin.uri` (S3 GetObject, `dest`) | 러너 | 읽기 전용, `no_log`. 내용은 변수가 아니라 `package_findings/previous_findings.json`(`0600`)로 받는다 (#156) |
| `AUD-508` | `Split the previous findings into per-host id files` | `host_audit_baseline_load` (role `library/` 커스텀 모듈) | 러너 | `no_log`. Package id를 호스트별 파일(`0600`)로 나누고 나머지만 돌려줌. 파일 없음·손상은 `valid=false` → AUD-506이 조회 실패 |
| `AUD-506` | `Decide the Audit Baseline state of this run` | `ansible.builtin.set_fact` | 러너 | `ok`·`failed`·`disabled` |
| `AUD-510` | `Save the findings index of this run on the runner` | `host_audit_findings_write` (role `library/` 커스텀 모듈) | 러너 | 실행별 파일 `0600`. 다른 섹션은 모델의 document 그대로, Package 발견 id는 `package_findings/<호스트>.json`에서 호스트 하나씩 읽어 쓴다(#155) |
| `AUD-511` | `Save the Audit Baseline pointer of a scheduled run on the runner` | `ansible.builtin.copy` | 러너 | 정기 실행만, `0600` |
| `AUD-512` | `Find every file of this run to keep` | `ansible.builtin.find` | 러너 | 읽기 전용. 실행 디렉터리를 재귀로 찾으므로 `xlsx/`의 호스트별·합계 xlsx(AUD-025)와 그 zip(AUD-026)도 대상이다 |
| `AUD-513` | `Compute the SHA-256 of every file to keep` | `ansible.builtin.stat` | 러너 | 읽기 전용. xlsx와 zip도 파일별로 구한다 |
| `AUD-514` | `Upload this run to the Host Audit bucket (<YYYY-MM>/<run_id>/)` | `ansible.builtin.uri` (S3 PutObject) | 러너 | 실행 ID별 새 키, `no_log`. Content-Type은 `.html` text/html, `.xlsx` OOXML 스프레드시트, `.zip` application/zip, 나머지 application/json. xlsx와 zip은 `<YYYY-MM>/<run_id>/xlsx/`에 올라간다 |
| `AUD-515` | `Upload the Audit Baseline pointer of a scheduled run` | `ansible.builtin.uri` (S3 PutObject) | 러너 | 정기 실행·전체 업로드 성공 시만, `no_log` |
| `AUD-516` | `Fail the run when the Audit Baseline lookup or keeping the originals failed` | `ansible.builtin.assert` | 러너 | 파일 이름·상태만 표시 |

검증: pytest `tests/test_host_audit_baseline.py`(AWS SigV4 공개 예제 서명 일치, 경로·포트·키 인코딩, 목록 XML, KST 월 경계, 12개월 창, 기준선 선택(수시 실행 제외), 신규·지속·재발·해소·확인 불가·첫 실행, Asset Inventory 신규·삭제, 배지·표지·저장 문서, 정책·수명주기·보존 설정, 포인터 업로드 조건, #159: `AUD-512`·`AUD-513`을 러너에서 실제로 돌려 `trivy/`·`package_findings/`가 보관 대상에서 빠지고 `sbom/`·`trivy_version.json`·나머지 파일은 압축·변경 없이 원본 그대로이며 보관 SHA-256이 파일의 값인지, 보관하지 않는 실행은 아무것도 올리지 않는지, 압축 단계(`AUD-517~520`)가 없는지, `AUD-325`·`AUD-326`이 DB 판정 뒤에 조건 없이 도는지). RustFS 1.0.1 컨테이너로 서명 요청의 Put·Get·List, 전용 정책의 거부 동작, Object Lock, 위 버킷 준비 절차를 수동으로 확인했다. molecule은 보고서 단계를 돌리지 않으므로 이 절의 태스크는 molecule 검증 대상이 아니다.
## 12. Configuration Drift (#124)

Git에 선언된 상태(프로비저닝 `site.yml`, Host Agents Config)와 호스트 실제 상태의 차이(CONTEXT.md Configuration Drift, ADR-0009 §1). 직전 Host Audit과의 차이는 Drift가 아니다(Audit Baseline 비교, #125).

- **방식**: 보고서 플레이(러너 localhost)가 두 플레이북을 `--check --diff`로 하위 실행한다(`tasks/drift.yml`, `tasks/drift_subrun.yml`). `ansible.posix.json` 콜백 결과에서 선언 플레이의 `changed` 태스크를 호스트별 행(SPEC-ID, 태스크 이름, 요약)으로 만든다. check 모드는 관리 상태를 바꾸지 않는다(#117, `tests/test_check_mode_read_only.py`).

  | 하위 실행 | 명령 | 대상(감사 대상과의 교집합) | 행을 만드는 플레이 |
  |---|---|---|---|
  | 프로비저닝 | `site.yml --check --diff` | `host_audit_drift_site_pattern` (`servers:loadbalancers`) | `Provision Baseline On-Premise Target Hosts` |
  | Host Agents Config | `host_agents.yml --tags agents_config --check --diff` | `host_audit_drift_agents_pattern` (`servers:!host_agents_excluded`) | `Apply Host Agents` |

- **인증**: 하위 실행은 평소 Semaphore 실행과 같은 경로로 접속한다. 각 플레이북이 자기 `resolve_connection`·`cleanup_connection` 플레이를 돌리고, 같은 인벤토리 소스(`ansible_inventory_sources`를 `-i`로)와 같은 OpenBao 자격증명을 쓴다. 새 구조의 Host Provisioning(`site.yml`, FUNA env 포함)과 Host Agents Config가 읽는 문서(Asset·Endpoint·Credential·Automation Identity·Service·작업 설정)를 하위 실행이 같은 공용 읽기 지점으로 읽어 렌더링하므로, `host_audit` AppRole은 `provision`과 `host_agents`가 읽는 경로를 모두 읽는다(정책 합집합, `openbao/roles.yml`). 하위 프로세스에는 OpenBao 주소와 인증(`VAULT_ADDR`·`VAULT_ROLE_ID`·`VAULT_SECRET_ID`·`VAULT_TOKEN`)을 이번 실행의 변수(Semaphore Secret extra var) 또는 환경 변수에서 읽어 **하위 프로세스 환경 변수로만** 넘긴다(네임스페이스·마운트는 읽기 지점이 정하므로 넘기지 않는다). 명령줄과 파일에는 남기지 않고 태스크는 `no_log`다. 비밀이 아닌 실행 변수는 `host_audit_drift_forward_vars`(기본 `target_removed_users`: 계정 입력 중 실행 변수로 남은 유일한 값, 저장된 사실은 Asset 문서의 `access` 절이 준다)에 정의돼 있으면 넘기고, 더 필요한 값은 `host_audit_drift_extra_vars`로 준다.
- **diff 원문 미보관**: 콜백 출력에는 diff 원문(파일 내용)이 있어 비밀값이 있을 수 있다. 러너 임시 파일(실행 디렉터리 밖, `0600`)에 받아 해석한 뒤 `always`에서 지운다. 행 요약에는 경로, 추가·삭제 줄 수, 바뀌는 속성 이름, 반복 항목 수만 남는다. `no_log` 태스크는 '비공개(no_log)'로만 나온다. 핸들러 결과는 바뀐 태스크의 결과일 뿐이라 행을 만들지 않는다.
- **비대상(점검불가 아님)**: Raw Provisioning Path 호스트(CentOS 6/7, 인벤토리 `raw_provisioning_path`가 우선)는 하위 실행에 넣지 않는다. raw 태스크는 `--check`에서 스킵되어(ADR-0005) Drift를 볼 수 없는 것이 설계다. 조치할 항목이 아니므로 점검불가 숫자·표에 넣지 않고, 섹션 모델의 `not_applicable`(호스트·이유)로 모아 보고서 요약과 메일 본문에 'Configuration Drift 비대상 N대 — raw 태스크가 --check에서 스킵됨' 한 줄로 따로 보인다(호스트별 부록에는 '비대상'과 이유가 나온다).
- **점검불가**(실제 확인이 필요한 것):
  - Host Audit 수집 단계에서 점검불가였던 호스트는 하위 실행에서 뺀다(이유는 이미 요약의 점검불가 표에 있다).
  - 하위 실행 안에서 접속 실패·태스크 실패·결과 없음인 호스트는 그 하위 실행에 대해 '점검불가'와 이유로 표시한다. 실패한 태스크 뒤의 태스크는 판정되지 않았다는 뜻이다.
  - 하위 실행이 통째로 실패하면(시간 초과 `host_audit_drift_timeout`, JSON 해석 불가) 그 하위 실행 부분만 점검불가로 표시하고 Host Audit 실행은 계속된다.
- **보고서**: 3장 Configuration Drift — 하위 실행별 결과, Drift 항목 표(호스트·SPEC-ID·태스크·요약·**판단(수기)** 칸), 제외 목록. 판단 칸에는 조치(선언대로 복원) / 선언 수정 / 승인된 변경 중 하나를 적는다(ISMS 2.9.1 변경관리 증적). 호스트별 부록에 Drift 건수와 점검불가 이유가 나온다.
- **Audit Baseline(§11)**: 섹션 모델의 `baseline_findings`로 참여한다. 항목 식별자는 `<하위 실행>:<SPEC-ID>`(SPEC-ID가 없으면 `<하위 실행>:task:<태스크 이름>`)이다. 계획된 하위 실행이 모두 그 호스트를 판정한 경우에만 '점검한 호스트'로 넣어, 하위 실행 실패·시간 초과·호스트 점검불가가 직전 Drift를 '해소'로 바꾸지 않게 한다(그 경우 '확인 불가'). 노이즈로 제외한 행은 발견이 아니다.
- **감사 규칙 적재 drift (#424)**: `security` 역할의 `SEC-083`은 `auditctl -l`과 렌더링한 규칙을 비교하는 조회 전용 태스크(`check_mode: false`)다. 커널에 적재된 규칙이 선언과 다르면 `--check`에서도 `changed`로 나와 이 표의 행이 된다(규칙 파일은 같고 적재만 낡은 호스트, 예: `exec_log` 잔존·적재 0개). 적재 자체는 적용 실행의 `Restart auditd` 핸들러가 한다. audit 도구가 없는 호스트와 Raw Provisioning Path 호스트는 행이 나오지 않는다(후자는 점검불가). 비교 기준은 `docs/security.md`의 '비교 기준(근사)'.
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
| `host_audit_drift_forward_vars` | `[target_removed_users]` | 정의돼 있으면 하위 실행에 넘길 실행 변수 이름 |
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

검증: pytest `tests/test_host_audit_drift.py` — 실제 `ansible.posix.json` `--check --diff` 출력(`tests/fixtures/host_audit_drift/check_callback.json`, 로컬 호스트 대상 check 실행으로 생성)에서 SPEC-ID 행, 준수·스킵 태스크 제외, diff 원문·no_log 내용 미포함, 실패·접속 실패 호스트, 선언 플레이만 행 생성, 핸들러 제외, 노이즈 제외 표식, Raw 경로·수집 실패 호스트 계획, 하위 실행 실패 시 부분 점검불가, 보고서 모델·템플릿(판단 칸). 하위 실행은 OpenBao 접속이 필요해 molecule 범위 밖이다. 하위 실행 정의(site.yml·host_agents.yml `--tags agents_config`, `--check`)와 넘기는 환경(주소·인증뿐, 네임스페이스·마운트 없음)은 `tests/test_host_audit_openbao.py`가 정적으로 고정한다.

## 13. 메일 발송 (#126)

원본 보관(§11)이 끝난 보고서를 Google Workspace SMTP relay로 보낸다. 러너 localhost의 보고서 단계에서만 동작하고 대상 호스트에는 아무것도 하지 않는다. check 모드에서는 보내지 않는다.

### 13.1 순서와 실패 처리

```text
report.yml
  AUD-025 호스트별·합계 xlsx → AUD-026 xlsx zip → AUD-611·615 보고서·zip SHA-256 → AUD-612·613 메일 요약(mail_summary.json, 주소 없음, zip 해시 포함)
  storage_upload.yml   AUD-510~515 원본(요약 포함, trivy/·package_findings/ 제외) 업로드
  AUD-614              보관 성공 판정 — 업로드가 하나라도 실패하면 보내지 않음
  mail.yml             AUD-600~609 수신자 해석 → 수신자마다 1통 발송 → 결과(주소 없이)
  storage_result.yml   AUD-516 보관 판정 (실패면 여기서 끝남)
  mail_result.yml      AUD-610 메일 판정 (실패면 여기서 끝남)
```

| 상황 | 메일 | 실행 결과 |
|---|---|---|
| 업로드 실패·보관 자격증명 없음 | 보내지 않음 | 실패(AUD-516) |
| 원본은 다 올라가고 Audit Baseline 조회만 실패 | 보냄(표지에 '조회 실패') | 실패(AUD-516) |
| 메일 실패(접속·STARTTLS·수신자 거부) | 일부 또는 전부 안 감 | 실패(AUD-610), 원본은 버킷에 그대로 — 재발송(§13.4) |
| 수신자·발신자 없음 또는 형식 오류 | 보내지 않음 | 실패(AUD-610), 키 이름과 건수만 표시 |
| `host_audit_mail_enabled=false`·check 모드 | 보내지 않음 | 성공 |
| `host_audit_storage_enabled=false`(시험) | 러너 원본을 보냄(본문에 '보관 안 함') | 메일 결과대로 |

### 13.2 메일 형태

- 제목: `[Host Audit] <정기|수시> 점검 보고서 <시작일> — 취약 n · 긴급/높음 n · 점검불가 n`. 제목의 점검불가 n은 본문 '점검불가' 줄(`n건 (호스트·항목)`)·보고서 요약 '점검불가 항목 n건 (호스트·항목)'·본문 점검불가 표 행 수와 같은 숫자(`model['unavailable']`의 행 수)다. 설계상 비대상(Drift raw 경로)은 이 숫자에 들지 않는다.
- **점검불가 숫자의 정의(#488 후속)**: 두 가지가 있고 라벨이 다르다. (1) 호스트 수 카드 '점검불가 호스트 (수집 단계)' — Host Audit 수집이 접속 실패·수집 실패·접속 준비 실패로 끝난 호스트(`summary.hosts_unavailable`). 점검 대상 = 점검 완료 + 점검불가 호스트가 성립한다. (2) 호스트·항목 건수 '점검불가 n건 (호스트·항목)' — 점검불가 표의 행 수로, 위 (1)의 호스트에 더해 점검 중 오류·결과 없음·하위 실행 실패·Package Vulnerability·Asset Inventory 등 항목 단위 점검불가를 센다. 설계상 비대상은 둘 다에 들지 않고 'Configuration Drift 비대상 N대' 한 줄로만 나온다.
  - 결정: 점검 중 오류(수집은 끝났으나 Drift 하위 실행에서 판정이 빈 호스트)는 호스트 카드에 넣지 않는 현재 동작을 유지한다. 근거: 그 호스트는 수집·KISA·패키지 등 나머지 섹션 판정이 정상이라 '점검 완료'에 들며, 카드에 더하면 점검 완료와 점검불가가 겹쳐 합이 대상 수와 어긋난다. 대신 호스트 이름과 이유가 점검불가 표(2)에 남아 건수에 잡힌다. 바꾸면 '점검 완료'의 정의(수집 성공)와 Audit Baseline의 '점검한 호스트' 기준이 달라지므로 바꾸지 않았다.
- 본문: `<table>` 레이아웃과 `style=""` 인라인만 쓴다(`<style>`·이미지·SVG·data URI 없음 — Gmail·Outlook이 지운다). 호스트 수 3칸(점검 대상 호스트·점검 완료·점검불가 호스트 (수집 단계)), 섹션별 한 줄 요약(점검불가, Asset Inventory, Configuration Vulnerability, Package Vulnerability, Configuration Drift, Configuration Drift 비대상(있을 때만), Audit Baseline), EOS 호스트, 비교 기준, 첨부 파일명·**SHA-256**·**원본 보관 경로**.
- 첨부: 보고서 `host-audit-<run_id>.html`과 합계·호스트별 Remediation Plan xlsx를 묶은 `host-audit-<run_id>-xlsx.zip`(압축 안은 `total.xlsx`와 `hosts/<Inventory Hostname>.xlsx`), 모두 ASCII 파일명이다(한글 파일명은 RFC 2231 인코딩이 클라이언트마다 깨진다). 첨부 바이트는 버킷의 `report.html`·`xlsx/…-xlsx.zip`과 같다. 본문에 zip 파일명·**zip SHA-256**·보관 경로가 한 줄씩 더 실린다(보고서 해시 줄과 같은 형태).
- 머리글: `X-Host-Audit-Run-Id`, `X-Host-Audit-Report-SHA256`, `X-Host-Audit-Xlsx-Zip-SHA256`(zip을 붙인 메일만).
- **수신자마다 1통**을 보낸다. 받는 사람은 다른 수신자의 주소를 보지 않는다. 또 한 통에 여러 명을 넣으면 일부 거부 시 `community.general.mail`이 거부된 주소를 경고로 찍는데, 모듈 경고는 `no_log`로 가려지지 않는다(실측).

### 13.3 입력 (OpenBao, Git에는 주소 없음)

| 문서 | 키 | 필수 | 설명 |
|---|---|---|---|
| `inventory/config/host_audit` | `mail_recipients` | ● (보낼 때) | 받는 사람 목록. 중복은 대소문자 무시로 하나만(문자열 하나나 `,`·`;`·공백 구분 문자열도 받는다) |
| `inventory/config/host_audit` | `mail_sender` | ● (보낼 때) | 보내는 주소 1개. Workspace relay가 허용한 도메인의 역할 주소 |
| `inventory/config/host_audit` | `mail_sender_display_name` | | 보내는 사람 표시 이름. 없으면 주소만 보낸다 |

수신자·발신자·표시 이름을 덮어쓰는 Extra variables는 없다(값의 출처는 이 문서 하나). 문서가 없으면(404) 수신자 없음 문제로, 못 읽으면(403·연결 불가·인증 정보 없음) 읽기 실패 문제로 남고(문서 경로만, 원인은 가림) 보내지 않으며 `AUD-610`이 실행을 실패로 끝낸다. 표시 이름은 선택이다.

| 변수 | 기본값 | 설명 |
|---|---|---|
| `host_audit_mail_enabled` | `true` | false면 보내지 않음 |
| 표시 이름 | (문서 값) | 이름은 RFC 2047로 인코딩해 `From:` 헤더에만 넣고 봉투 발신자(릴레이가 보는 값)는 주소 그대로다. CR/LF 같은 제어 문자나 `<>"@`가 있거나 공백뿐이거나 길면(영문 64자, 한글 등 비ASCII 15자 초과; 인코딩된 한 단어가 75자 안에 들게 한다) 이름을 버리고 주소만 보낸다(메일을 막지 않는다). 쉼표·세미콜론은 따옴표로 감싸 그대로 쓴다. 이름은 결과 판정의 가림 대상에도 들어간다(원문 일치만 가리며, 짧은 이름은 오류 문구의 같은 글자도 가린다) |
| `host_audit_mail_host` · `host_audit_mail_port` | `smtp-relay.gmail.com` · `587` | 운영값. 시험용 SMTP를 쓸 때만 덮어씀 |
| `host_audit_mail_secure` | `starttls` | STARTTLS를 못 하면 보내지 않음. 시험용 평문은 `never` |
| `host_audit_mail_ehlohost` | `""` | relay 설정이 HELO 도메인을 요구할 때 그 이름 |
| `host_audit_mail_timeout` | `30` | SMTP 접속 제한 시간(초) |

주소는 개인정보다. 주소를 다루는 태스크(AUD-602·603, 606, 608)는 모두 `no_log`이고, 오류 문구는 `host_audit_mail_redact`로 주소를 `<수신자>`로 바꾼 뒤에만 보여 준다. 보고서·호스트별 JSON·`run.json`·`mail_summary.json`에는 주소가 들어가지 않는다. 발송 태스크는 `ignore_errors`가 아니라 `failed_when: false`다 — ansible-core는 무시된 모듈 오류의 메시지("Failed to send mail to '<주소>'")를 `no_log`와 상관없이 찍는다(실측). 성공 여부는 `rc`와 모듈의 성공 메시지로 판정한다.

알려진 한계: `community.general.mail`의 STARTTLS는 서버 인증서를 검증하지 않는다(파이썬 `smtplib.starttls()` 기본 컨텍스트). relay 구간은 암호화되지만 중간자 공격을 막지 못한다 — 러너에서 relay까지의 경로는 사내망과 Google 사이 인터넷 구간이다.

### 13.4 재발송

`playbooks/host_audit_resend.yml`(Semaphore 템플릿 Host Audit — Resend)은 다시 점검하지 않는다. 버킷 `<YYYY-MM>/<run_id>/`에서 `report.html`과 `mail_summary.json`을 받아 SHA-256을 비교하고(다르면 보내지 않음), 요약이 xlsx zip을 기록했으면 `xlsx/host-audit-<run_id>-xlsx.zip`도 받아(`AUD-629`) 기록된 해시와 대조한다(`AUD-633`: 받지 못함·이름 불일치·해시 불일치면 하나도 보내지 않고 멈춘다). 같은 첨부 둘·같은 요약에 제목 앞 `[재발송]`을 붙여 지금의 수신자에게 보낸다. 받은 보고서와 zip은 보낸 뒤 러너에서 지운다(`AUD-628`). zip의 받을 이름은 요약의 값이 아니라 실행 ID에서 정한다(요약은 버킷에서 받은 값이라 경로 문자를 믿지 않는다).

- `host_audit_resend_run_id`: 보관된 실행 ID(필수, 영문·숫자·`._-`).
- `host_audit_resend_month`: 기본 형식(`ha-<UTC 시작 시각>`)이 아닌 실행 ID일 때 `YYYY-MM`(보고서 시간대 기준 실행 시작 월). 기본 형식이면 ID에서 계산한다(예: `ha-20261031T220000Z` → KST 11월 1일 → `2026-11/`).
- `mail_summary.json`이 없는 실행은 최소 요약(첨부·SHA-256·보관 경로)으로 보낸다. 요약에 `xlsx_zip` 기록이 없는 옛 실행(zip이 생기기 전)은 보고서만 보낸다.

### 13.5 태스크 매트릭스

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `AUD-600` | `Decide whether this run sends the report mail` | `ansible.builtin.set_fact` | 러너 | 비활성·check 모드·보관 실패면 보내지 않음 |
| `AUD-602` | `Read the Host Audit mail settings from OpenBao (inventory/config/host_audit)` | `ansible.builtin.set_fact` (`lookup openbao_doc`) | 러너 | 읽기 전용, `no_log`. 문서가 없으면 `{}`, 못 읽으면 값 없음(AUD-603이 문제로 남김) |
| `AUD-603` | `Resolve the mail recipients and sender` | `ansible.builtin.set_fact` | 러너 | 수신자·발신자 주소와 선택 표시 이름(`From:` 헤더 값)을 해석, 문제는 키 이름·건수만, `no_log` |
| `AUD-604` | `Create a private temporary directory for the attachment` | `ansible.builtin.tempfile` | 러너 | 실행마다 새 디렉터리, AUD-607이 삭제 |
| `AUD-605` | `Copy the report, the xlsx zip and the Log Review Report under their ASCII attachment names` | `ansible.builtin.copy` | 러너 | 임시 디렉터리, `0600`. 보고서 1개와 (요약에 `xlsx_zip`이 있고 호출자가 경로를 준 때만) xlsx zip 1개, (요약에 `log_review`가 있고 경로를 준 때만) Log Review Report 1개(18절) |
| `AUD-606` | `Send the summary, the A4 report, the xlsx zip and the Log Review Report (community.general.mail)` | `community.general.mail` | 러너 | 수신자마다 1통(첨부 최대 셋, 머리글 `X-Host-Audit-Log-Review-SHA256`), `failed_when: false`, `no_log` |
| `AUD-607` | `Remove the temporary attachment directory` | `ansible.builtin.file` | 러너 | `always`, `state: absent` |
| `AUD-608` | `Judge the mail outcome without any address` | `ansible.builtin.set_fact` | 러너 | `host_audit_mail_outcome` 필터, `no_log` |
| `AUD-609` | `Show the mail outcome (counts only)` | `ansible.builtin.debug` | 러너 | 수신자 수·첨부명·SHA-256만 |
| `AUD-610` | `Fail the run when the report mail was not delivered` | `ansible.builtin.assert` | 러너 | 보관 판정 뒤, 주소 없는 문구 |
| `AUD-611` | `Compute the SHA-256 of the report to attach` | `ansible.builtin.stat` | 러너 | 읽기 전용 |
| `AUD-612` | `Build the mail summary of this run` | `ansible.builtin.set_fact` | 러너 | `host_audit_mail_summary` 필터(보고서·xlsx zip의 파일명·SHA-256·크기·보관 경로) |
| `AUD-613` | `Save the mail summary on the runner` | `ansible.builtin.copy` | 러너 | 실행별 파일 `0600`, 원본과 함께 보관 |
| `AUD-615` | `Compute the SHA-256 of the xlsx zip to attach` | `ansible.builtin.stat` | 러너 | 읽기 전용. 메일 요약(AUD-612)이 싣는 zip 해시 |
| `AUD-614` | `Decide whether the originals were kept` | `ansible.builtin.set_fact` | 러너 | 업로드 상태 코드만 |
| `AUD-620` | `Fix the resend metadata and the archived run location` | `ansible.builtin.set_fact` | 러너 | `host_audit_mail_resend_prefix` 필터 |
| `AUD-621` | `Create the runner-local directory for the downloaded report` | `ansible.builtin.file` | 러너 | `0700` |
| `AUD-622` | `Assert the Host Audit storage key is available for the resend` | `ansible.builtin.assert` | 러너 | 읽기 전용 |
| `AUD-623` | `Get the archived report` | `ansible.builtin.uri` (S3 GetObject) | 러너 | 읽기 전용, `no_log` |
| `AUD-624` | `Get the archived mail summary` | `ansible.builtin.uri` (S3 GetObject) | 러너 | 읽기 전용, `no_log` |
| `AUD-625` | `Compute the SHA-256 of the downloaded report` | `ansible.builtin.stat` | 러너 | 읽기 전용 |
| `AUD-626` | `Assert the archived report exists and matches its recorded SHA-256` | `ansible.builtin.assert` | 러너 | 해시 불일치면 보내지 않음 |
| `AUD-629` | `Get the archived xlsx zip` | `ansible.builtin.uri` (S3 GetObject) | 러너 | 읽기 전용, `no_log`. 요약이 xlsx zip을 기록한 실행만 |
| `AUD-633` | `Assert the archived xlsx zip exists and matches its recorded SHA-256` | `ansible.builtin.assert` | 러너 | 받지 못함·이름 불일치·해시 불일치면 보내지 않음. 번호는 `AUD-630`(정리 판정)이 이미 쓰여 633이다 |
| `AUD-627` | `Prepare the resend summary and attachments` | `ansible.builtin.set_fact` | 러너 | `host_audit_mail_resend_summary` 필터 |
| `AUD-628` | `Remove the downloaded report, xlsx zip and Log Review Report from the runner` | `ansible.builtin.file` | 러너 | `state: absent`(재발송 실행 디렉터리 통째로) |

재발송의 `Read the xlsx zip record of the archived summary`(요약에서 zip 기록을 읽는 `set_fact`), `Compute the SHA-256 of the downloaded xlsx zip`(받은 zip의 `stat`), `Say that the xlsx zip is not resent without its recorded hash`(요약이 없을 때 알리는 `debug`)는 AUD-629·633의 보조 태스크라 SPEC-ID를 두지 않는다(스펙이 재발송 zip에 정한 번호는 둘뿐이다). 메일 첨부 경로는 AUD-605의 `copy` 결과(`dest`)를 AUD-606이 그대로 쓴다.

## 14. 러너 디렉터리 정리 (#157)

러너의 `<host_audit_output_root>/<run_id>`는 실행당 약 3.6GB다. 두 곳에서 정리한다.

### 14.1 이번 실행분 (`cleanup.yml`, 보고서 단계의 `always`)

AUD-516·AUD-610은 assert로 실행을 끝낸다. 그래서 정리는 보관·메일·두 판정을 묶은 block의 `always`에서 돈다 — 실행이 실패로 끝나도 정책대로 처리된다. 지우는 것은 이번 실행의 `output_dir` 하나이고 `host_audit_output_root`는 지우지 않는다.

| 상황 | 동작 |
|---|---|
| Remediation Plan xlsx 쓰기·zip 묶기·이전 시도 xlsx 정리 실패(보관 여부·메일 결과와 무관) | 남긴다. 맨 끝 판정(`Fail the run when a Remediation Plan xlsx could not be written`)이 실패한 대상과 함께 실행을 실패로 끝내고 `AUD-632`가 이유(`xlsx 산출물 실패(<대상>)`)를 보여 준다(§17). 아래 행들보다 먼저 판정한다. |
| xlsx 판정 사실(`_host_audit_xlsx_problem`)이 없음(그 앞 단계에서 멈춤) | 남긴다. 값이 없는 것을 '실패 없음'으로 읽지 않고, 이유는 '앞 단계에서 멈춰 xlsx 판정이 없음'이다. |
| 보관 성공(xlsx 산출물 실패 없음) | 지운다. 메일 결과와 관계없다(재발송은 버킷에서 한다). |
| 보관 꺼짐(`host_audit_storage_enabled=false`), 메일 발송 성공 | 지운다. |
| 보관 꺼짐, 메일 실패 또는 미발송 | 남긴다. 러너 사본이 유일하다. |
| 보관 실패(업로드 실패, 보관 입력 누락) | 남긴다. AUD-516 메시지가 이 디렉터리를 가리킨다. |
| check 모드 | 지우지 않는다. |

"보관 성공"은 AUD-516이 통과하는 조건과 같다: 보관 입력 이상 없음, 업로드 전부 200, 정기 실행은 포인터 업로드 200, Audit Baseline 조회가 `failed`가 아님. Audit Baseline 조회만 실패한 실행은 AUD-516이 실패로 끝내고 메시지가 러너 디렉터리를 가리키므로 남긴다. 판정에 쓸 값이 없으면(앞 단계가 일찍 끝남) 남긴다. 남긴 경우 실행 로그에 경로와 이유를 보여 준다(`AUD-632`). 이유는 보관 단계 실패뿐 아니라 그 앞 단계(AUD-025 Remediation Plan 생성·쓰기)의 실패도 가리킨다.

**경로 검증**: `output_dir`이 정확히 `<host_audit_output_root>/<run_id>`(출력 상위 경로 바로 아래 한 단계)이고, `run_id`가 `[A-Za-z0-9][A-Za-z0-9._-]*`이며 `resend-`로 시작하지 않을 때만 지운다. 하나라도 어긋나면 지우지 않고 이유를 보여 준다.

### 14.2 오래된 실행 디렉터리 (`prepare.yml`)

OOM 등으로 중간에 죽은 실행은 정리 단계에 가지 못한다. 실행 초기(`AUD-005` 뒤)에 출력 상위 경로 바로 아래 디렉터리 중 이름이 run_id 규칙(`[A-Za-z0-9][A-Za-z0-9._-]*`, `AUD-630`의 검증과 같은 식)에 맞고 `host_audit_output_retention_days`(기본 **7일**, 수정 시각 기준)가 지난 것만 지운다. 규칙에 맞지 않는 이름(`.`·`_`·`-`로 시작, 공백 포함 등)은 이 역할이 만든 것이 아니므로 건드리지 않는다. 이번 실행 디렉터리, 재발송용 `resend-*` 디렉터리, 디렉터리가 아닌 항목은 건드리지 않는다. check 모드에서는 지우지 않는다.

### 14.3 태스크 매트릭스

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `AUD-630` | `Decide whether to remove this run's output directory` | `ansible.builtin.set_fact` | 러너 | 읽기 전용 판정, 경로 검증 포함 |
| `AUD-631` | `Remove this run's output directory` | `ansible.builtin.file` | 러너 | `state: absent`, 이번 실행 `output_dir`만, check 모드 건너뜀 |
| `AUD-632` | `Show where the kept run directory is and why` | `ansible.builtin.debug` | 러너 | 남긴 경우만, 경로와 이유 |
(AUD-006·007은 §6 매트릭스)

검증: pytest `tests/test_host_audit_cleanup.py` — report.yml의 실제 마지막 block(AUD-516·AUD-610·정리)을 러너에서 돌려 위 표의 각 상황(AUD-610 실패·AUD-516 실패 포함)과 경로 검증(출력 상위 경로 자체, 밖, 하위, `resend-*`)을, `prepare.yml`의 AUD-005~007을 실제 디렉터리 수정 시각으로 돌려 N일 규칙을 확인한다.

### 13.6 검증

- pytest `tests/test_host_audit_mail.py`: 수신자 정규화(목록·구분 문자열·중복·형식 오류는 건수만), 오류 문구의 주소 가림, 수신자별 발송 결과 판정(일부 실패·`failed_when` 재작성 대비), ASCII 첨부명, 실제 보고서 모델에서 만든 요약(주소 없음), 본문 템플릿(표·인라인만, `<style>`·이미지·SVG 없음, 50KB 미만, 이스케이프), 재발송 위치(KST 월 경계·형식 검사), 태스크 순서(보관 → 메일 → 보관 판정 → 메일 판정)와 `no_log`, 요약·본문의 zip SHA-256 줄. `tests/test_host_audit_xlsx_zip_report.py`(통합, 임시 SMTP·S3 서버): `report.yml`이 `xlsx/host-audit-<run_id>-xlsx.zip`을 같은 바이트로 만들고 보관 목록에 해시와 함께 올리며 요약에 zip 해시를 싣는지, 메일에 첨부 둘이 가는지, 재발송이 해시가 같으면 둘 다 보내고 다르거나 zip이 없으면 아무것도 보내지 않는지(zip 기록이 없는 옛 실행은 보고서만). `tests/test_host_audit_zip_write.py`: zip 모듈의 구성·순서·고정 시각·같은 바이트.
- 수동 E2E(2026-10-08, 러너 로컬, 옛 OpenBao 구조 당시의 기록): mailpit(STARTTLS 필수, 자체 서명 인증서, 수신자 허용 규칙) + RustFS + OpenBao dev(namespace `infra/prod/host`)로 실제 report 단계를 돌렸다 — 수신자 3명에게 1통씩 도착, 첨부 SHA-256 = 버킷 `report.html` SHA-256, 재발송 첨부도 같은 해시, 업로드 실패 시 메일 0통·실행 실패, 메일 실패(닫힌 포트·전원 거부·일부 거부) 시 원본 유지·실행 실패, 수신자 없음 시 키 이름만 표시하고 실패, OpenBao `mail_to`(`;` 구분 문자열) 조회. 모든 경우 실행 로그에서 주소 0건. mailpit HTML 검사(caniemail 기준) 본문 지원율 95.5% — 미지원은 classic Outlook의 `max-width`(표 `width="640"` 속성으로 대체)뿐.
- 운영 확인(운영자, #105 이후): 실제 relay 발송, Gmail·Outlook(웹·classic) 표시, `.html` 첨부 차단 여부. #495부터는 Gmail이 zip 안의 xlsx를 막지 않는지도 첫 실제 실행에서 확인한다(압축 안 한 zip이라 내용 검사를 받는다).

## 15. KISA 월간 악화 알림 (Spec #322 / Ticket-9, #331)

월간(정기) Host Audit의 Configuration Vulnerability(KISA) 결과에서 **지난 정기 점검(Audit Baseline)에 취약이 아니던 항목이 이번에 취약이면** 사내 알림 webhook으로 알린다. 보고서의 신규·지속 표시는 그대로이고, 이 알림은 악화만 따로 골라 운영자가 보고서를 열기 전에 알게 한다.

- **항목 단위 비교**: 실패 개수가 아니라 (호스트, `KISA-2026:U-NN`) 단위다. 지난달 U-01이 실패했고 이번 달 U-02가 실패하면 실패는 하나씩으로 같지만 U-02는 악화로 알린다(`host_audit_kisa_worsened`, `filter_plugins/host_audit_baseline.py`). 취약만 센다: 점검불가(수동)·예외(승인)·해당없음·양호는 대상이 아니다. 지난달에도 취약이던 항목은 알리지 않는다.
- **지난 결과가 없는 호스트는 알리지 않는다**: 이번에 처음 점검한 호스트(Audit Baseline이 그 호스트를 점검하지 않음)와 Audit Baseline 자체가 없는 첫 정기 실행은 비교 대상이 없어 알리지 않는다. Audit Baseline 조회가 실패한 실행도 알리지 않는다(비교하지 않음).
- **한계**: 지난달 예외(승인)였던 항목이 예외 만료로 이번에 취약이 된 경우는 Audit Baseline 색인(`findings.json`)이 취약과 예외를 구분해 담지 않아 지속으로 보이고 이 알림에 잡히지 않는다. 보고서의 예외 만료 표시를 본다.
- **언제 보내나**: 정기 실행(`host_audit_run_kind=scheduled`)만 보낸다. 수시 실행은 Audit Baseline이 되지 않으므로 알리지 않고, check 모드도 보내지 않는다(`AUD-640`). 보관·메일 뒤에 한 번 보낸다.
- **본문**: 악화된 항목 목록(`• <호스트>: KISA-2026:U-NN <항목 이름>`)과 비교한 두 실행 ID, 조치 안내가 text/plain으로 들어간다. 플랫폼 한도(5000자)에 맞춰 자르고 남은 건수를 `… 외 N건`으로 적는다. 주소·시크릿은 없다.
- **webhook 입력**: OpenBao `secrets/services/alert/notify`의 `url`(text/plain 경로)이고, 인증이 필요하면 `token`(선택, 비밀)과 `auth_header`(선택, 헤더 이름, 기본 `X-NANOIT-ACCESS`)를 더한다(`AUD-641`은 `token`이 있을 때만 헤더를 붙인다). 실행 변수로 덮어쓰지 않는다(`AUD-501`·`AUD-502`가 보관 입력과 함께 읽는다). 값은 모든 태스크에서 `no_log`이고 보고서·로그에 남지 않는다. `host_audit` AppRole 정책에 `alert-notify`(이 문서 읽기)가 필요하다. 못 읽어도 보관·메일은 막히지 않고 악화 항목이 있을 때만 `AUD-642`가 실패시킨다.
- **전달 실패는 실행 실패로 드러난다**: 악화 항목이 있는데 webhook이 없거나 전송이 거부되면(`AUD-642`) 보관·메일 판정이 모두 끝난 뒤 마지막에 실행을 실패로 끝낸다(보고서와 보관은 이미 끝남). 알림 실패가 다른 판정을 가리지 않는다.

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `AUD-640` | `Decide whether this run notifies KISA worsening` | `ansible.builtin.set_fact` | 러너 | 읽기 전용 판정 (`host_audit_kisa_alert`: 정기 실행·악화 항목 있음·check 모드 아님), `no_log` |
| `AUD-641` | `Send the KISA worsening notification to the alert webhook` | `ansible.builtin.uri` | 러너 | 악화 항목이 있을 때만 text/plain POST, `no_log`, 전송 결과는 실패시키지 않고 AUD-642가 판정 |
| `AUD-642` | `Fail the run when a KISA worsening notification could not be delivered` | `ansible.builtin.assert` | 러너 | 읽기 전용 (webhook 없음·응답이 2xx가 아님이면 실패, 다른 판정 뒤에 마지막으로) |

검증: pytest `tests/test_host_audit_kisa_worsened.py` — 개수가 같아도 항목이 바뀌면 악화로 잡히는 것, 지난 결과가 없는 호스트·첫 실행·취약이 아닌 판정은 잡히지 않는 것, 통지 본문의 항목 목록·길이 한도, 로컬 HTTP 서버로 받은 실제 요청(text/plain, 인증 헤더 없음, 본문), 수시 실행·check 모드·비활성에서 보내지 않는 것, 전달 실패 시 실행 실패, 판정이 다른 판정 뒤에 오는 배선.

## 16. Security Regression (Spec #364 / Ticket-10, #377)

정기 점검이 스펙 #364의 기대치(관리 웹 접점 루프백 바인드, 수신 접점·원격 접속 출발지 제한, 탐지 동작과 로그 보존, 백업 정책의 삭제 불가, 시크릿 파일 권한)를 계속 확인하고, 퇴행하면 알린다. 점검은 읽기 전용이다(ADR-0009 §1). 결과는 **항목 ID와 판정(통과·실패·해당없음·점검불가)뿐**이고 주소·포트·경로·시크릿 값은 호스트 기록, 보고서, 알림 어디에도 들어가지 않는다. 기대치의 출처는 `docs/runbooks/`의 각 런북(mgmt-web-loopback-bind, receiver-source-restriction, ssh-source-restriction, detection-recovery, backup-host-key-scope, secret-file-permissions)이고 점검 절차와 기준선 연계는 [docs/runbooks/host-audit-regression.md](runbooks/host-audit-regression.md)에 있다.

### 16.1 대상 선언과 판정

- **선언 기반**: 이 기대치는 강화한 핵심 서버에만 해당한다. 호스트별 선언 `host_audit_regression_expect`(§5)가 비어 있으면 그 호스트는 이 섹션 대상이 아니고 어떤 항목도 실패하지 않는다. 선언의 값(포트, 설정 파일 경로, 허용 출발지)은 공개 저장소에 두지 않고 Semaphore 인벤토리·Environment로 준다(Semaphore 인벤토리는 static이라 저장소 `group_vars`는 적용되지 않는다).
- **판정 4종**: 통과 · 실패 · 해당없음(선언하지 않은 항목) · 점검불가(선언했는데 조회 도구가 없거나 답이 없음). **점검불가는 통과로 세지 않는다.** 점검불가는 보고서에 따로 표시되고 합계에 남는다.
- **퇴행 알림**: 실패 항목은 Audit Baseline의 발견(`security_regression` 섹션)이라 신규·지속·재발·해소가 표시된다. 지난 정기 점검에 실패가 아니던 항목이 이번에 실패하면 기존 KISA 악화 알림(§15, `AUD-640`~`AUD-642`)이 같은 본문에 항목 ID로 함께 알린다(같은 webhook, 정기 실행만, 호스트별 비교 기준 없으면 알리지 않음). 새 알림 경로를 만들지 않았고 전달 실패 판정(`AUD-642`)도 그대로다.

### 16.2 점검 항목과 합격 기준

선언 키는 `host_audit_regression_expect`의 키다.

| 항목 | 기대치 출처 | 선언 키 | 합격 기준 |
|---|---|---|---|
| `EXP-MGMT-1` | mgmt-web-loopback-bind | `mgmt_web_ports` | 선언한 관리 웹 접점이 루프백 밖 주소에 열려 있지 않다(소켓과 컨테이너 게시 포트 모두) |
| `EXP-MGMT-2` | mgmt-web-loopback-bind | `mgmt_wildcard_allowed` | 모든 주소에서 청취하는 접점이 허용 목록(프록시 경로 등 설계된 예외) 안에 있다 |
| `EXP-MGMT-3` | mgmt-web-loopback-bind | `mgmt_removed_ports`, `mgmt_removed_names` | 제거 목록의 포트·컨테이너·서비스가 없다 |
| `EXP-RECV-1` | receiver-source-restriction 8절 | `recv_syslog_conf` | 로그 수신 설정(Telegraf)의 `[[inputs.socket_listener]]`에 비어 있지 않은 `allowed_sources` 허용 목록이 있다. 트랩 수신기(옛 `EXP-RECV-2`·`EXP-RECV-3`)는 LibreNMS 폐기로 없다(2026-11-16) |
| `EXP-SSH-1` | ssh-source-restriction 6절 | `ssh_restricted` | `sshd_config`에 관리형 Match 블록과 `DenyUsers *`가 있다 |
| `EXP-SSH-2` | ssh-source-restriction 6절 | `ssh_restricted`, `ssh_denied_addr` | `sshd -T -C`로 평가한 허용 밖 출발지(기본 문서용 주소)가 거부된다 |
| `EXP-SSH-3` | ssh-source-restriction 6절 | `ssh_restricted`, `ssh_allowed_addrs` | 루프백과 선언한 허용 출발지가 거부되지 않는다 |
| `EXP-SSH-4` | ssh-source-restriction 6절 | `ssh_restricted` | 허용 목록이 비어 있지 않다(Match 블록에 루프백 외 제외 항목이 있다) |
| `EXP-DET-1` | detection-recovery | `det_journald` | journald가 영구 저장이고 영구 저널 디렉터리가 있다 |
| `EXP-DET-2` | detection-recovery | `det_fail2ban` | fail2ban sshd jail이 동작한다 |
| `EXP-DET-3` | detection-recovery | `det_fail2ban_no_firewall` | sshd jail 동작이 `dummy`뿐이다(방화벽 비관리 호스트) |
| `EXP-DET-4` | detection-recovery | `det_auditd` | 적재된 감사 규칙에 identity, auth_config, sudo_config, sshd_config 키가 있다 |
| `EXP-DET-5` | detection-recovery | `det_auditd` | 적재된 규칙이 있고 전체 execve 추적 규칙이 없다 |
| `EXP-DET-6` | detection-recovery | `det_audit_secret` | 적재된 규칙에 secret_access 키가 있다 |
| `EXP-DET-7` | detection-recovery | `det_log_agent` | 중앙 수집 에이전트 서비스(`true`는 기본 이름 `otelcol`, 서비스 이름이 다르면 그 이름을 값으로 선언한다. 예: `otelcol-contrib`)가 active다 |
| `EXP-BAK-1` | backup-host-key-scope | (러너, 선언 없음) | `host-key-policy.json`에 와일드카드 동작이 없고 삭제가 `locks/*` 하나뿐이다 |
| `EXP-BAK-2` | backup-host-key-scope | (러너) | 수집기 스냅샷의 모든 호스트 서비스 계정 정책이 `host-key-policy.json`과 같은 모양이다 |
| `EXP-BAK-3` | backup-host-key-scope | (러너) | 수집기 스냅샷의 모든 호스트 서비스 계정 정책 리소스가 버킷 하나뿐이다 |
| `EXP-SEC-1` | secret-file-permissions | `sec_roots` | 선언한 경로의 시크릿 후보 파일 중 그룹·기타 쓰기 또는 기타 권한이 열린 것이 없다 |
| `EXP-SEC-2` | secret-file-permissions | `sec_files` | 선언한 파일이 모두 있고 0600 이하 root 소유다 |
| `EXP-SEC-3` | secret-file-permissions | `sec_env_files` | 선언한 시크릿 env 파일이 모두 있고 0640 이하 `root:dockermgmt`다(AGENTS.md 4절 예외) |

- 노드 otelcol OTLP 수신기의 모든 주소 바인드는 설계된 예외(ADR-0012)이므로 `mgmt_wildcard_allowed`에 그 포트를 적는다. 관리 웹이 아니라서 `EXP-MGMT-1`의 대상도 아니다.
- **서버에서 정책을 직접 읽지 않는다**: Host Audit 전용 키는 IAM 정책을 읽을 수 없고 유지보수 키는 쓰지 않는다(최소 권한). `EXP-BAK-2`·`EXP-BAK-3`은 운영자가 읽기 전용 수집기(`scripts/collect-rustfs-policy.py`)로 만든 스냅샷 파일을 `HOST_AUDIT_RUSTFS_POLICY_SNAPSHOT`(러너 경로)로 주면 판정하고, 주지 않으면 점검불가다. 항목 판정을 켜는 변수는 `host_audit_regression_backup_enabled`다.
- 이 섹션에 넣지 않은 것: 평문 인증 정보 정리와 서버 밖 사본(#374 선행), 패치 재부팅(#376), 이미지 버전 목록, `docker compose config --quiet`(운영자 계정의 compose 컨텍스트가 필요해 읽기 전용 원격 점검이 아님).

### 16.3 호스트별 JSON 추가 필드

`security_regression`은 선언이 있는 호스트의 기록에만 추가된다(`schema_version` 유지: 기존 필드 의미는 그대로이고 선택 필드이며 `config_vulnerability`도 같은 방식이다).

```json
"security_regression": {
  "status": "ok",
  "reason": "",
  "results": [{"code": "EXP-SSH-1", "verdict": "통과"}]
}
```

`status`는 `ok` 또는 `probe_failed`(표식 없음, 접속 실패)다. 수집에 실패한 호스트는 보고서의 점검불가 목록에 오르고 비교 대상이 아니다.

### 16.4 태스크 매트릭스

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `AUD-700` | `Probe Security Regression expectations (raw, read-only)` | `ansible.builtin.raw` | All (CentOS 6 ~ Rocky 10, Ubuntu) | 조회 전용, `changed_when: false`, `check_mode: false`, `ignore_unreachable: true`, 선언이 있을 때만 실행. 출력은 항목 ID와 PASS/FAIL/UNK뿐 |
| `AUD-701` | `Add Security Regression verdicts to the per-host audit record` | `ansible.builtin.set_fact` | 러너 | 읽기 전용 (`host_audit_regression_result` 필터) |
| `AUD-710` | `Judge the backup host key policy items on the runner` | `ansible.builtin.set_fact` | 러너 (`delegate_to: localhost`) | 읽기 전용 (저장소 정책 JSON과 선택 스냅샷 파일을 읽어 `host_audit_regression_backup`이 판정, 켜진 실행에서만) |

예약 번호: `AUD-702`~`AUD-709`는 의도적으로 건너뛴 예약 번호이며 태스크가 없다(재사용·추측 금지). `AUD-710`은 백업 정책 판정이라 일부러 700번대와 구분했다.

검증:
- pytest `tests/test_host_audit_regression_probe.py` — 프로브를 가짜 루트와 가짜 조회 명령(`ss`, `docker`, `sshd`, `fail2ban-client`, `auditctl`, `systemctl`)으로 실행해 정상 상태에서 선언한 모든 항목이 통과하고, 항목별로 의도적으로 퇴행시킨 상태(바인드 개방, 제거 포트 복귀, 필터·인증 제거, 기본 문자열, Match 블록 제거·빈 허용 목록·허용 출발지 차단, journald 휘발성, 방화벽 동작, 감사 키 누락·execve 추적, 에이전트 중지, 권한 확대·그룹 오류·파일 누락)에서 해당 항목이 실패로 나오는지, 조회 도구가 답하지 못하면 점검불가인지, 출력에 값이 없는지, 호스트에 아무것도 쓰지 않는지 본다.
- pytest `tests/test_host_audit_regression.py` — 판정(선언 안 한 항목은 해당없음, 말하지 않은 선언 항목은 점검불가), 쉘 메타문자 차단, 백업 정책 판정(수집기 출력 형식 사용: 정상, 삭제 범위 확대, 다른 버킷, 정책 없음, 스냅샷 없음), 보고서 섹션과 Audit Baseline 발견, 항목 단위 악화 비교와 알림 본문(주소·시크릿 없음).
- **molecule Fast Scenario** `VERIFY-AUD-700`(수렴된 호스트에서 선언 항목이 모두 통과하고 프로브가 호스트를 바꾸지 않는다), `VERIFY-AUD-701`(sshd 제한 블록 제거, journald 휘발성, 시크릿 파일 권한 확대를 일부러 만들면 해당 항목이 실패로 보고된다), `VERIFY-AUD-700`이 원복 뒤 다시 통과하는지도 본다(같은 판정 재확인). 컨테이너에서는 fail2ban·감사 규칙 적재·게시 포트를 재현하지 않아 이 항목들은 pytest가 본다.
- `AUD-710`(백업 정책 판정)은 러너에서 저장소 JSON만 읽으므로 molecule 검증이 없고(`INTEGRATED`), pytest `tests/test_host_audit_regression.py`가 판정을 검증한다.

## 17. Remediation Plan (Spec #488 / Ticket-6, #494)

호스트마다 SolidStep 이행계획서 열 구성의 xlsx 1개를 만들고, 모든 호스트를 한 시트에 모은 합계 xlsx 1개를 더한다(CONTEXT.md Remediation Plan). 보고서와 함께 보관하며 정기·수시 실행 모두 만든다. 조치는 하지 않고 이행도 추적하지 않는다: 사람이 채운 파일을 다시 읽는 길은 없고, 이행 여부는 다음 정기 실행의 판정(Audit Baseline의 해소)이 증명한다. xlsx 전부는 zip 하나로 묶여 메일의 두 번째 첨부가 되고 보고서와 함께 보관되며, 재발송은 보관된 zip의 해시를 대조한 뒤 같이 보낸다(Ticket-7, #495, §17.2).

- **파일**: 실행 디렉터리 `xlsx/host-audit-<run_id>-<inventory_hostname>.xlsx`(ASCII, `[A-Za-z0-9._-]` 밖의 글자는 `_`이고, 바뀐 이름과 80자를 넘어 잘린 이름에는 원래 이름의 SHA-256 앞 8자를 붙여 서로 다른 호스트가 같은 파일명을 쓰지 않게 한다). 시트 1개(`이행계획서`), 보관은 `<YYYY-MM>/<run_id>/xlsx/`(§11.1).
- **합계 xlsx**: 실행 디렉터리 `xlsx/host-audit-<run_id>-total.xlsx`(호스트 파일과 같은 위치·보관·SHA-256·Content-Type). 열은 호스트별 파일과 같은 15개, 시트 1개(`이행계획서`)이고 실행 대상 모든 호스트의 행이 들어간다(어느 호스트의 행인지는 자산명 열이 말한다. 담당자는 호스트별 파일과 같이 호스트마다의 값이다). 정렬은 우선순위 → 영향도 → 환경성, 같으면 판정(취약 → 점검불가(수동) → 예외(승인)) → 호스트 이름 → 항목 코드다. 같은 수준 안의 판정 순서는 호스트별 파일과 같고(`order_findings`), 그 뒤에 호스트·코드가 붙는다. 처음에는 판정을 키에 넣지 않았으나(호스트별로 모아 보이게), 같은 수준에서 취약이 예외(승인) 밑으로 밀려 위험한 행이 먼저 보이지 않으므로 판정을 넣기로 정했다(#488 합계 xlsx 후속). 호스트별 파일의 정렬은 바뀌지 않는다. 양호 외 항목이 있는 호스트의 행만 모으되, `점검 결과 없음(점검불가)`·`이행계획서 생성 실패 (…)` 한 줄은 그 호스트가 양호가 아니므로 합계에도 남고(실패 메시지에서 합계 파일은 `합계 xlsx`로 부른다: 호스트 이름이 `total`일 수 있다) 항목 행 뒤에 호스트 순서로 붙는다. 어느 호스트에도 양호 외 항목도 한 줄도 없으면 자산명·담당자가 빈 `양호 외 항목 없음` 한 줄(통제내용 칸)이다. 하단은 호스트별 파일과 같다(KISA 출처 문장, `실행 ID`). 셀 출처 규칙도 같다(행은 호스트별 파일과 같은 함수로 만든다). 호스트가 하나도 없는 실행에는 만들지 않는다. zip 안에서 합계(`total.xlsx`)는 정렬상 `hosts/` 폴더 뒤에 오는데, 이는 압축 안 이름 순이라는 결정(같은 입력이면 같은 바이트)의 결과이고 의도한 순서 변경이 아니다. 파일명·압축 안 이름은 대소문자를 구분한다: 호스트 이름은 관리번호(Inventory Hostname)라 대소문자만 다른 두 호스트가 있지 않고, 호스트별 파일(#494)도 같은 규칙이므로 합계만을 위해 바꾸지 않았다(다만 `TOTAL`처럼 합계 이름과 대소문자만 다른 호스트는 해시 접미사로 구분한다). 호스트 이름이 `total`이면 호스트 파일명이 합계 파일명과 겹치므로 그 호스트의 이름 부분에만 해시 접미사를 붙인다(`host-audit-<run_id>-total-<해시8>.xlsx`).
- **행 범위**: 그 호스트에서 양호 외로 판정된 항목(취약·점검불가(수동)·예외(승인))이 한 행씩이다. 양호·해당없음은 넣지 않는다. 양호 외 항목이 없으면 `양호 외 항목 없음` 한 줄(통제내용 칸)만 있는 파일이다. KISA 점검 결과 자체가 없는 호스트(수집 실패·미점검)는 양호로 보이지 않도록 `점검 결과 없음(점검불가)` 한 줄이다.
- **열(순서대로)**: 그룹(`category`) · 자산명(Inventory Hostname) · 담당자 · 통제내용(`U-xx 항목명`) · 취약점현황(`<판정>: <evidence>`, 메모가 있으면 다음 줄에 HTML 부록과 같은 note) · 점검방법(`check`) · 조치방법 · 위험도(3/2/1) · 이행과제 · 시급성(단기·중기·장기) · 영향도(조치 영향도) · 환경성(조치 난이도) · 우선순위(1~3) · 이행 결과 · 비고. 위험도·시급성·우선순위는 §10.5의 파생 규칙이고, 영향도·환경성은 항목 YAML의 level이다. 이행과제·이행 결과는 사람이 채우므로 비워 둔다.
- **조치방법**: 호스트 OS 계열(steps는 계열(rhel·debian)별로만 두고 버전 차이는 문장 안에 적는다는 스펙 결정에 따라, CentOS 6처럼 systemd가 없는 호스트에도 같은 rhel 단계를 쓰므로 `systemctl`이 들어간 rhel steps에는 service 대안을 적어 둔다. `os-release` ID로 rhel·debian, 보고서 모델 `inventory[].os_family`)의 `steps`. 그 계열의 steps가 없거나 계열을 알 수 없으면 `remediation.summary`다. 계열은 `os-release` ID의 정확한 일치(rhel·centos·rocky·almalinux·ol·fedora·amzn은 rhel, debian·ubuntu는 debian)로만 정한다. `ID_LIKE`는 호스트별 JSON(`schema_version` 2)에 없고 그 스키마를 바꾸지 않으므로 파생 배포판은 계열을 알 수 없는 호스트로 보고 공통 요약을 받는다(틀린 계열의 명령을 싣는 것보다 낫다).
- **담당자**: Asset Inventory의 관리자(직책)를 보고서가 보이는 그대로 싣는다. 값이 없으면 `미지정`, 조회가 실패했으면 `조회 실패`(Asset Inventory 표와 같은 말), Asset Inventory에 그 호스트 항목이나 관리자 칸이 없거나 호스트에 닿지 못해(수집 실패·기록 없음) 선언 값을 읽을 수 없었으면 역시 `조회 실패`(자료 없음을 '배정 안 됨'으로 꾸미지 않는다)이고, 값이 문자열이 아니면 그 표가 보이는 `잘못된 값 …`이다. 담당자를 따로 해석하거나 다른 곳에서 채우지 않으므로 셀 출처 규칙이 그대로 지켜진다(#492 검토에서 정함).
- **비고**: 앞에 Audit Baseline 상태(`[신규]`·`[지속]`·`[재발]` 셋만, 다른 상태는 붙이지 않는다)가 붙고, 점검불가(수동) 행과 Audit Baseline이 없거나 조회되지 않은 실행(첫 실행 포함)에는 붙지 않는다. 그 뒤에 예외 레지스터 상태가 온다: 예외(승인)은 `예외(승인) — 사유: … / 위험: … / 보완: … / 승인: <직책> <승인일> / 만료: <만료일>`(날짜가 없거나 형식이 틀리면 레지스터 표처럼 `-`), 만료로 취약이 된 행은 `예외 만료(<만료일>)`, 승인 대기는 `예외 승인 대기`. 예외 값은 보고서 모델의 해당 호스트 발견(`findings[].hosts[].exception`, 레지스터 표와 같은 값)에서 읽는다. 이 필드는 보고서 모델 안에만 있다(Audit Baseline 문서와 보관 파일은 `appendix`와 id 색인만 쓰고 `findings`를 직렬화하지 않는다).
- **취약점현황과 비고의 겹침**: 취약점현황은 HTML 부록과 같은 증적·메모(같은 말을 보여 주는 요구)이고 비고는 이행계획서 양식의 상태 열이다. 둘 다 호스트 발견 항목에서 나온 값이라 어긋나지 않는다. 활성 예외로 점검불가(수동)이 예외(승인)이 된 행은 Audit Baseline의 발견(예외 포함)이므로 `[신규]`·`[지속]` 앞머리가 붙는다(판정이 점검불가(수동)인 행에만 붙이지 않는다).
- **정렬**: 우선순위 → 영향도(낮은 것 먼저) → 환경성(쉬운 것 먼저) → 판정(취약 → 점검불가(수동) → 예외(승인)) → 항목 코드(§10.5 `order_findings` 그대로).
- **하단**: KISA 출처 문장과 `실행 ID: <run_id>`가 표 아래 빈 줄 하나 뒤에 온다.
- **셀 출처 규칙**: 모든 셀 문자열은 보고서 모델이나 항목 YAML에 이미 있는 값이거나 위 고정 문구(열 이름, `양호 외 항목 없음`, 비고 문구의 연결어)다. xlsx 전용 비공개 값 필터는 두지 않는다. `host_audit_remediation_plan`은 모델과 카탈로그만 읽고 파일·lookup을 쓰지 않는다. 담당자는 직책이라 개인정보도 없다.
- **판정 순서와 남는 디렉터리**: 맨 끝의 xlsx 쓰기 판정은 보관·메일·알림 판정 뒤에 있어, 앞 판정이 먼저 실패하면 그 메시지가 앞선다(실패한 호스트는 로그의 `ignoring` 줄에 남는다). xlsx 쓰기 실패 한 건이 실행 디렉터리를 남기는 비용(러너 디스크)은 증적 보존을 우선한 결정이며, 남은 디렉터리는 오래된 실행 정리(§14.2)가 보존 일수 뒤에 지운다.
- **한 줄 파일의 자리**: `양호 외 항목 없음`과 `점검 결과 없음(점검불가)`는 통제내용 칸에 한 줄로 들어가고 위험도·우선순위 칸은 비어 있어 발견 행과 섞여도 구분된다. 한 호스트의 기록이 이상해 계획을 못 만들면 그 호스트만 `이행계획서 생성 실패 (<예외 종류: 메시지>)` 한 줄 파일(담당자는 아는 값 그대로)이 되고 다른 호스트는 계속된다. 로그에는 호스트와 예외 종류만 남기는 태스크가 있고(메시지는 레코드 값을 인용할 수 있어 `xlsx` 한 줄 파일에만 둔다), 모든 호스트가 실패했으면(필터·카탈로그 자체의 오류) 빈 증적을 보관하지 않도록 실행을 멈춘다(일부만 실패했을 때는 실패시키지 않는다: 계획 생성은 호스트별 격리, 파일 쓰기는 증적 보존을 위해 중단이라는 구분이다).
- **카탈로그에 없는 코드**: 저장된 기록에 카탈로그에 없는 항목 코드가 있으면 통제내용은 `U-99 (카탈로그에 없는 항목)`이고 위험도·시급성·영향도·환경성·우선순위·점검방법·조치방법 셀은 빈 칸이다(None을 셀에 넣지 않는다). 쓰기 모듈도 문자열·정수가 아닌 값은 문자열로, None은 빈 셀로 쓰고, 짝 없는 서로게이트 같은 XML에 못 쓰는 글자는 뺀다.
- **쓰기 실패와 실행 흐름**: xlsx를 쓰지 못해도(`ignore_errors`) 보관·메일·KISA 악화 알림·Audit Baseline 포인터는 계속한다(그것들은 xlsx에 기대지 않는다). 실패는 보관·메일 판정처럼 맨 끝(`Fail the run when a Remediation Plan xlsx could not be written`, 호스트 이름만 밝힘)에서 실행을 실패로 끝내고, 정리는 그 실행의 디렉터리를 남긴다(`AUD-630`은 보관 여부와 무관하게 xlsx 쓰기 실패를 '남긴다'로 판정하고 `AUD-632`가 이유를 보여 준다). 보관을 끈 실행은 xlsx가 러너에만 있지만 zip이 메일의 두 번째 첨부로 가고 정리는 메일 판정 뒤(`always`)에 돌므로, 메일 성공 뒤 정리가 디렉터리를 지워도 xlsx는 메일에 남는다(#494의 전환 기간 한계는 #495에서 닫혔다). 메일이 실패하면 보관을 끈 실행은 디렉터리를 남긴다(§14).
- **실패 처리**: `AUD-025`의 `rows`는 모듈의 `no_log` 인자다(호스트 증적과 예외 사유가 러너의 syslog·journal 호출 기록에 남지 않게 한다). `no_log`는 모듈 결과 안의 같은 값까지 가려 `row 2 has ********`처럼 원인을 못 읽게 하므로, 모듈이 가림 대상을 24자 이상 값(증적 같은 자유 문장)으로 좁혀 행 번호·경로·호스트 이름은 보이게 한다. 오류 메시지는 행 번호와 개수만 적는다. 호스트마다 모듈을 한 번씩 부르는 것은 실패한 호스트를 라벨로 남기기 위해서다. 만들기에 실패하면 실행을 멈춘다. xlsx도 이번 실행의 증적이라 빠진 채 보관·메일로 넘어가지 않으며, 실패 원인이 될 입력(None 셀, 형식이 다른 셀, 인코딩 불가 글자)은 위처럼 모듈이 흡수한다. 쓰다 실패해도 `xlsx/`에 임시 파일을 남기지 않고, 프로세스가 죽어 남더라도 임시 파일 이름이 점(`.`)으로 시작해 `AUD-512`(숨김 파일을 찾지 않음)가 목록에 올리지 않는다(`mkstemp`로 만들고 `fsync` 뒤 `replace`). 정수 셀은 2^53을 넘으면 문자열로 쓴다(Excel은 숫자를 double로 저장). 쓰기 오류(디스크 가득 등)는 `dest`를 밝힌 실패 메시지로 낸다. 셀이 xlsx 한도(32,767자, Excel처럼 UTF-16 단위로 센다)보다 길면 잘라 `…`를 붙이고 모듈이 경고를 낸다. 시트 이름(31자 이하, 금지 문자·가장자리 작은따옴표)과 열 너비(1~255, 머리글보다 많으면 오류)는 모듈이 검증한다. 길이 한도는 줄바꿈 정규화와 XML에 못 쓰는 글자를 뺀 뒤의 길이로 판단하고 경고도 같은 기준이다. check 모드는 파일이 이미 같은 바이트면 `changed`가 아니다. 호스트마다 필터를 다섯 번 부르지 않도록(호스트·발견 탐색은 호스트 수에 비례해 다시 돌지만 수십 대 규모에서는 무시할 만하다) `host_audit_remediation_plans`가 모든 호스트의 계획을 한 번에 만든다.
- **같은 입력이면 같은 바이트**: 쓰기 모듈이 zip 항목 시각을 1980-01-01로 고정하고 항목 순서를 고정하며 압축하지 않는다(`ZIP_STORED`: deflate 결과는 zlib 빌드에 따라 달라 러너 이미지가 바뀌면 같은 입력이 다른 바이트가 되기 때문이다). 보관 해시로 동일성을 확인한다. 러너 이미지에는 스프레드시트 라이브러리를 더하지 않는다(표준 라이브러리 `zipfile`). 모듈은 시트 1개, 문자열·정수, 머리글 굵게·열 너비·줄바꿈·틀 고정만 쓴다. 호스트별 JSON(`schema_version` 2)은 바뀌지 않는다.

### 17.1 태스크 매트릭스

`AUD-025` 앞의 `Build the Remediation Plan of every host`(호스트별 계획과 합계를 `{파일명: 계획}`(`_host_audit_remediation_by_file`)로 한 번에 만드는 `set_fact`. 쓰기·옛 파일 정리·묶기·생성 실패 판정이 이 하나를 읽는다)와 `Name the hosts whose Remediation Plan could not be built`(생성 실패 호스트를 로그에 남기는 `debug`), `Stop when …`(전 호스트 생성 실패 시 중단)과 맨 끝의 `Fail the run when a Remediation Plan xlsx could not be written`(실패 판정)과 아래 정리 태스크들은 AUD-025의 준비·보고·판정 보조 태스크라 별도 SPEC-ID를 두지 않는다(`AUD-026`·`AUD-615`는 아래 17.2). 동작은 위 실패 처리 항목과 `tests/test_host_audit_remediation_plan_report.py`가 고정한다. 이 보조 태스크의 순서와 역할은 다음과 같다. `Collect the hosts …`는 쓰기에 실패한 파일(`_host_audit_xlsx_failed_files`)과 그 호스트 이름(합계는 `합계 xlsx`, `_host_audit_xlsx_failed_hosts`), 묶을 수 있는지(`_host_audit_xlsx_pack`)를 한 번만 정한다. `Check whether the xlsx directory exists`·`Find`·`Remove the xlsx files that this attempt did not write`는 같은 실행 ID의 이전 시도가 남긴 xlsx(쓰기에 실패한 호스트·합계의 옛 파일, 이번 대상에 없는 호스트의 파일)를 보관 전에 지운다: AUD-512가 `xlsx/`를 재귀로 올리므로 그대로 두면 이번 실행의 증적으로 오른다. 범위는 `*.xlsx`다(`xlsx/`에는 이 역할의 모듈만 쓰고 이름이 모두 `host-audit-<run_id>-<host 또는 total>.xlsx`라 다른 파일이 생길 길이 없다. zip은 zip 단계가, 숨김 임시 파일은 AUD-512가 따로 다룬다). 찾기·지우기 실패는 보관·메일을 막지 않고 요약으로 모여 맨 끝에서 실행을 실패로 끝낸다(AUD-025의 원칙: 보조 산출물 때문에 보관·메일이 막히지 않는다. 지우지 못한 옛 파일이 올라가는 위험은 실행 실패와 남긴 실행 디렉터리, 오류 메시지로 드러난다). `Summarize the Remediation Plan xlsx problem of this run`은 쓰기·옛 파일 정리 실패를 `_host_audit_xlsx_problem`(failed·targets: 실패한 호스트 이름과 `이전 시도 xlsx 삭제`·`xlsx zip`)으로 모으고, 묶기 실패는 `Remember that the xlsx zip …`가 같은 사실에 더한다. 맨 끝 판정·메시지·정리 `cleanup.yml`은 이 값 하나만 읽는다. 옛 파일 정리를 쓰기·묶기 모듈의 옵션으로 옮기지 않은 이유: 모듈은 한 파일을 쓰는 책임만 지고(AUD-025·026은 호스트마다·실행마다 따로 돈다), 정리 대상은 이번 시도의 호스트 집합이라 역할 변수에서만 알며, 실패를 요약 사실로 모으는 일도 태스크 층의 몫이라 그대로 두었다. SPEC-ID 검증기(`scripts/validate-ansible-specs.py`)가 강제하는 것은 docs 표와 태스크의 ID·이름 일치뿐이고 molecule 검증(`[VERIFY-…]`)은 `INTEGRATED`로 표시만 할 뿐 요구하지 않는다. 스펙 #488이 보고서 단계를 molecule 대상 밖으로 정했으므로 AUD-025·026·615·629·633에 `[VERIFY-…]`를 더하지 않는다(검증은 pytest, ADR-0013).

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `AUD-025` | `Write the Remediation Plan xlsx of every host` | `host_audit_xlsx_write` (role `library/` 커스텀 모듈) | 러너 | 호스트별 xlsx와 합계 xlsx를 쓴다(파일 이름 목록을 도는 반복문 하나). 같은 입력이면 같은 바이트, 이미 같은 파일이면 `changed` 없음. 파일 `0600`, `xlsx/`는 만들 때 `0700`. 보고서 모델 뒤, 보관(AUD-512~514) 앞. 보관·메일·정리를 묶은 block 안의 첫 태스크다. 실패는 모아 맨 끝 판정에서 실행을 실패로 끝낸다(위 '쓰기 실패와 실행 흐름'). 계획은 `host_audit_remediation_files`(파일명을 키로 한 dict: 안에서 `host_audit_remediation_plans`가 호스트별 계획을 한 번 만들고 합계는 그 행을 모은다)로 set_fact에 한 번 만든다(`no_log`는 아니다: 필터 예외의 원인이 가려지지 않게 하고, 성공 때의 fact는 `-v`에서만 찍히며 `report.html`과 같은 내용) 반복문은 파일 이름(ASCII)만 돈다(반복문 item은 실패 결과에 그대로 찍히므로) |
| `AUD-026` | `Pack every Remediation Plan xlsx into one zip` | `host_audit_zip_write` (role `library/` 커스텀 모듈) | 러너 | 이번 실행의 xlsx 전부(호스트별과 합계, `members`: 파일명→압축 안 이름)를 압축 안 이름 순으로 `host-audit-<run_id>-xlsx.zip`(같은 디렉터리)에 압축 없이(`ZIP_STORED`) 고정 시각으로 묶는다(압축 안 이름은 `total.xlsx`, `hosts/<Inventory Hostname>.xlsx`): 같은 xlsx면 같은 바이트, 이미 같은 파일(모드 `0600`)이면 `changed` 없음. AUD-025와 보관(AUD-512~514) 사이, 메일 요약(AUD-612) 앞. xlsx 쓰기 실패가 있거나 호스트가 없으면 건너뛰고, 묶기 실패는 `ignore_errors`로 받아 맨 끝 판정에 모은다(17.2) |

검증: pytest `tests/test_host_audit_remediation_plan.py`(행 범위, 한 줄 파일, 계열별 steps와 summary 대체, 담당자, 비고 세 문구와 Baseline 앞머리 규칙, 빈칸 열, 정렬, 셀 출처), `tests/test_host_audit_xlsx_write.py`(openpyxl로 다시 열어 값·머리글 서식·너비·줄바꿈·틀 고정, 같은 바이트), `tests/test_host_audit_remediation_plan_report.py`(`report.yml`의 AUD-025와 보관 목록, Content-Type). 보고서 단계는 molecule 대상이 아니라 `[VERIFY-…]`는 없고(`INTEGRATED`, AUD-710과 같음) 위 pytest가 검증한다. 모듈 인자 템플릿에서 호스트 증적의 `{{ }}`가 평가되지 않는지도 `tests/test_host_audit_remediation_plan_report.py`가 본다.

### 17.2 xlsx zip: 첨부·보관·재발송 (Ticket-7, #495)

호스트별 xlsx는 24대 규모에서 파일이 많으므로 합계 xlsx와 함께 전부 zip 하나로 묶어 메일에 붙인다. 압축 안에서만 폴더 이름을 가진다: `total.xlsx`(루트)와 `hosts/<Inventory Hostname>.xlsx`(호스트 이름은 파일명과 같은 ASCII 규칙). 실행 디렉터리와 버킷의 파일은 `host-audit-<run_id>-<host 또는 total>.xlsx`로 납작하게 둔다. 별도 xlsx를 메일에 따로 붙이지 않는다.

- **묶기(`AUD-026`)**: `host_audit_zip_write`(표준 라이브러리 `zipfile`, 러너 이미지 변경 없음)가 이번 실행의 xlsx를 `members`(디스크 파일명→압축 안 이름)대로 압축 안 이름 순으로, 압축 없이 고정 시각(1980-01-01)으로 묶어 `xlsx/host-audit-<run_id>-xlsx.zip`(파일명은 `host_audit_remediation_zip_name`, xlsx와 같은 ASCII 규칙)에 쓴다. 같은 xlsx면 같은 바이트이므로 보관 해시로 동일성을 확인한다. xlsx 쓰기에 실패한 호스트가 하나라도 있으면 zip을 만들지 않는다(일부만 든 zip이 해시까지 붙어 완성본처럼 메일로 가고 3년 보관되는 것을 막는다). 그 실행의 메일은 보고서만 싣고(요약에 `xlsx_zip`이 없다) 실패는 맨 끝 판정이 호스트 이름과 함께 실행을 실패로 끝낸다. 호스트가 하나도 없으면 묶을 것이 없어 건너뛴다. 묶기 자체의 실패(디스크 등)는 `ignore_errors`로 받아 `_host_audit_xlsx_problem`에 zip을 더하고(`Remember that the xlsx zip could not be written`; 지우기는 모듈 결과의 `failed`를 읽는다) 맨 끝 판정과 정리(디렉터리를 남김)가 xlsx 쓰기 실패와 함께 처리한다. 묶기 전에 같은 실행 ID의 이전 시도가 남긴 zip을 지운다(`Remove a leftover xlsx zip of an earlier attempt`: 이번에 묶지 못했을 때 옛 zip이 해시·첨부·보관에 오르지 않게). 요약·본문의 zip 보관 경로는 보고서와 같이 업로드 전의 의도 값이다(업로드가 실패하면 AUD-516이 실행을 실패로 끝내고 재발송은 AUD-633에서 멈춘다). 묶는 파일은 이번 실행 계획(합계 포함)의 파일명 목록(`members`)이다. 압축 안 이름이 `..`·`/`로 시작·역슬래시·빈 부분을 갖거나 겹치면 모듈이 실패하고 `names`와는 함께 쓰지 못한다(`names`만 쓰면 이전처럼 납작한 이름이다): 같은 실행 ID로 다시 돌렸거나 대상을 좁힌 수시 실행이 `xlsx/`에 이전 실행의 xlsx를 남겼어도 zip에 들어가지 않고, 목록의 파일이 없으면 모듈이 실패한다. 보조 첨부 때문에 보관·메일이 막히지 않는다는 AUD-025의 원칙과 같다. 이름·경로·보관 위치는 role 변수(`_host_audit_xlsx_zip_name`·`_path`·`_archive`, `vars/main.yml`) 한 곳에서 정한다. zip은 통째로 메모리에 만들고 해시를 두 번(AUD-615, AUD-513) 구한다: 파일이 수 KB~수백 KB(수십 호스트)라 스트리밍보다 단순한 쪽을 택했다.
- **해시와 요약(`AUD-615`·`AUD-612`)**: zip의 SHA-256을 구해 메일 요약 `mail_summary.json`의 `xlsx_zip`(`file_name`·`sha256`·`size`·`archive`)에 싣는다. 보고서 해시(`report`)와 별개다. 본문과 머리글 `X-Host-Audit-Xlsx-Zip-SHA256`에도 실린다. 요약이 이 키를 갖지 않는 옛 실행은 zip 줄이 없다. 해시나 파일명이 빈 기록은 검증할 수 없으므로 요약에 싣지 않는다.
- **보관**: zip도 `<YYYY-MM>/<run_id>/xlsx/`로 올라가며(`AUD-512`~`514`, Content-Type `application/zip`) 파일별 SHA-256이 남는다. xlsx 자체도 그대로 보관된다.
- **첨부(`AUD-605`·`AUD-606`)**: 보고서에 이어 zip이 두 번째 첨부다. 메일 요약(AUD-612) 단계를 xlsx·zip 쓰기 뒤로 옮겨(구조 변경) 요약이 zip 해시를 알고, 정리(cleanup)는 메일 판정 뒤에 돌므로 보관을 끈 실행에서도 xlsx는 지워지기 전에 메일에 실린다.
- **재발송(`AUD-629`·`AUD-633`)**: §13.4. 해시가 다르거나 zip을 받지 못하거나 요약의 zip 기록 형식·이름이 맞지 않으면 보고서도 보내지 않는다. 요약 자체가 없으면(404) 기록된 해시를 몰라 검증할 수 없으므로 zip은 보내지 않고 보고서만 보내며 그 사실을 로그에 남긴다. 요약의 zip 기록을 믿는 기준은 `host_audit_mail_resend_summary`와 같다(`schema_version`이 있는 요약만). 반대로 요약이 zip을 기록했는데 보관된 zip이 없거나 해시가 다르면 보고서도 보내지 않는다: 스펙이 정한 대로 해시가 다르면 보내지 않는 것이 무결성 증적을 우선하는 결정이고(처음 보낸 것과 다른 파일이 나가면 안 된다), 운영자는 원인(보관 누락·변조)을 먼저 풀어야 한다. 메일 본문과 첨부가 어긋나지 않도록 요약에 zip이 있는데 첨부 경로가 없으면 메일은 보내지 않고 이유를 낸다(`AUD-603`의 문제 목록).
- **운영 확인(미실시)**: Gmail이 zip 안의 xlsx를 막지 않는지는 첫 실제 실행의 메일 수신으로 확인한다(#495 인수 조건, 운영자 몫).
- **보관 중복**: zip은 보관된 xlsx와 같은 내용을 한 번 더 담지만(압축 안 함), 재발송이 같은 바이트를 해시로 검증하며 보내려면 zip 자체를 보관해야 한다. 규모(호스트당 수 KB~수백 KB)로 보아 3년 보관 비용은 실행당 수 MB 이하라 감수한다. 재발송의 보고서 첨부 이름도 요약 값이 아니라 실행 ID에서 정한다.
- **압축 안 함(`ZIP_STORED`)을 유지하는 이유와 크기 실측**: 같은 입력이면 같은 바이트(사용자 이야기 35)와 재발송의 해시 대조가 요구이고, deflate 결과는 같은 레벨이어도 zlib 구현·빌드(zlib, zlib-ng 등)에 따라 달라질 수 있다. 레벨과 `ZipInfo`를 고정해도 러너 이미지가 바뀌면 같은 입력이 다른 바이트가 될 수 있고, 테스트는 한 빌드에서만 돌아 그 보장을 증명하지 못한다. 그래서 압축하지 않는다(#494 결정 유지). 크기 실측: 양호 외 67항목이 전부 찬 최악의 호스트 1대가 xlsx 약 88 KB(압축하면 약 16 KB)다. 호스트 25대면 약 2.2 MB, 100대면 약 9 MB이고 base64로 부풀어도 relay 한도(25 MB)는 약 200대부터 닿는다. 한도에 닿으면 메일 실패(AUD-610)로 드러나므로 그때 보고서만 보내기나 압축 방식(바이트 고정이 가능한 다른 방법)을 다시 정한다.
- **메일 크기**: zip은 호스트당 수 KB~수백 KB의 xlsx를 묶은 것이라 수십 호스트에서 수 MB 이하이고, 보고서 HTML과 base64로 부풀어도 Workspace relay 한도(25 MB)보다 한참 작다. 한도에 닿을 규모가 되면 메일 실패(AUD-610)로 드러나고 원본·zip은 버킷에 그대로이므로 크기 상한과 보고서만 보내기 되돌림은 그때 더한다.
- **check 모드**: xlsx 쓰기가 파일을 만들지 않으므로 묶기(AUD-026)는 건너뛴다.
- **재발송 정리**: 받기·검증·발송을 block으로 묶고 `always`에서 내려받은 디렉터리를 지운다(AUD-628). 검증에서 멈춘 재발송도 러너에 파일을 남기지 않는다.
- **번호**: 스펙이 정한 재발송 대조 번호 `AUD-630`은 정리 판정(§14)이 먼저 쓰고 있어 `AUD-633`으로 둔다(3-Way 검증은 중복 ID를 허용하지 않는다).

## 18. Log Review Report (Spec #544 / Ticket-3 #558, ADR-0015)

정기 실행은 전월 한 달의 **Log Review Report** 초안(A4 HTML)을 만들어 Host Audit 메일의 세 번째 첨부로 보내고 같은 실행 보관 경로(`<YYYY-MM>/<run_id>/log_review/host-audit-<run_id>-log-review.html`)에 남긴다. Host Audit 보고서의 일부가 아니라 별도 첨부다. 호스트에는 접속하지 않고 OpenObserve만 읽는다(ADR-0009 읽기 전용 그대로).

- **만드는 실행**: 정기 실행만. 수시 실행은 `host_audit_log_review_enabled=true`일 때만(같은 달 결재본이 여러 부 생기지 않게). check 모드는 만들지 않는다. 만들지 않은 실행의 메일은 첨부 둘(또는 하나)로 정상 발송된다.
- **점검 기간**: 실행 시작 시각이 속한 보고서 시간대(KST) 월의 전월 1일 00:00 ~ 말일 24:00(끝 미포함). 정기 실행은 매월 1일 07:00 KST라 `2026-11/` 실행이 10월을 점검한다. 필터 `host_audit_log_review_period`.
- **구성**: 머리(기간·대상·데이터·항목 상태 집계) → 1부 로그 검토 19개(AK-034 순서·문구) → 2부 보안시스템 정책 적정성 9개(1차는 점검자가 채우는 빈 표) → 3부 로그 관리 상태 → 마지막 쪽 결재란(점검자·정보보호관리자·정보보호책임자(CISO) 서명·일자). 항목마다 상태·점검 방법·판정 기준·결과 표와 사람이 쓰는 칸(최종 판정·점검자 소견·조치 내역, 언제나 빈 칸)이 있다.
- **항목 상태**: `자동 판정`(이상 없음/확인 필요), `일부 자동`, `사람 대조`, `점검 불가(사유)`, `조회 실패(사유)`. 1부 8~11·14~19는 매달 `점검 불가(애플리케이션 접속기록·업무 기록 미수집)`이다. 판정 함수가 아직 없는 항목은 `점검 불가(미구현)`으로 나온다(빼거나 이상 없음으로 쓰지 않는다).
- **이번 티켓의 실제 값은 3부 수집 공백 하나다**: 수집 대상 호스트(`host_audit_log_review_collect_hosts`, Silent Host와 같은 수집 로스터)와 장비(`host_audit_log_review_devices`, `fortigate_firewalls` 그룹과 syslog 전송이 확인된 스위치 `host_audit_log_review_switch_syslog_devices`(= `o2c_switch_syslog_roster`)의 관리번호) 중 점검 기간에 로그가 하루도 없으면 `전월 로그 없음`, 하루 이상 빈 날이 있으면 `끊김`(빈 날짜 범위와 일수). 호스트는 `system_logs`의 `host_name`, 장비는 스위치 `system_logs`·FortiGate `security_logs`의 `device_id`를 KST 일자별로 센다. 공백 이름은 1부 판정이 '이상 없음'으로 단정하지 않도록 판정 문맥에 남는다(후속 #559).
- **판정 위치와 확장(후속 티켓)**: 판정은 모두 필터에 있다. 항목 정의는 `filter_plugins/host_audit_log_review_items.py`의 표(`PART1`·`PART2`·`PART3`)이고, 판정은 묶음별 모듈(`host_audit_log_review_<묶음>.py`)의 `JUDGES = {항목 key: judge(ctx)}`, 그 판정이 쓰는 조회는 같은 모듈의 `QUERIES = {항목 key: [{name, sql, size}]}`다. 모듈을 더하면 `host_audit_log_review.py`의 `_JUDGE_MODULES`에 한 줄을 더한다. 조회만 더하는 항목은 태스크(`tasks/log_review.yml`)와 템플릿(`templates/log_review.html.j2`)을 고치지 않는다. 판정에 새 기준 입력(호스트별 기록·허용 계정, 작업 설정 문서, 서명본 목록 등)이 필요하면 그 입력을 AUD-804의 `_meta.settings`에 티켓마다 키 하나로 더하고(문서를 새로 읽으면 AUD-802의 `host_audit_openbao_log_review_docs`와 `host_audit_openbao_required`에도), 판정 함수는 `ctx['settings'][<키>]`로 읽는다. 한 항목의 판정 오류는 그 항목만 `조회 실패(판정 오류 …)`로 표시하고 실행을 맨 끝에서 실패로 끝낸다(AUD-807).
- **조회**: OpenObserve `POST /api/<org>/_search` 하나뿐이다(AUD-803, 조회 이름별 반복, 결과는 `no_log`). 주소·조직은 `inventory/services/openobserve`, 계정은 조회 전용 용도의 `secrets/services/openobserve/readonly`(Host Audit 계열 정책 `openobserve-readonly`가 읽기만 허용)이고 admin 자격은 쓰지 않는다. **OpenObserve 오픈소스 빌드는 RBAC가 없어 서버가 조회 전용을 강제하지 못한다(#556).** 그래서 이 역할이 OpenObserve에 `_search` POST 외의 호출을 하지 않는다는 것을 `tests/test_host_audit_log_review_tasks.py`가 지킨다(계정이 유출되면 쓰기도 가능하다는 한계는 그대로다).
- **조회 실패**: 문서를 읽지 못함·401/403·연결 불가·결과가 조회 한도에 닿음(잘렸을 수 있음)은 해당 항목의 `조회 실패(사유)`로 남고 메일은 그대로 나간다. 사유에는 상태 코드만 쓰고 주소·계정·응답 본문은 쓰지 않는다. 모델 생성·렌더링 자체가 실패하면 첨부를 빼고 메일을 보낸 뒤 맨 끝에서 실행을 실패로 끝낸다(AUD-807).
- **메일·보관·재발송**: 해시는 AUD-806, 요약의 `log_review`(`file_name`·`sha256`·`size`·`archive`·`period`), 본문과 머리글 `X-Host-Audit-Log-Review-SHA256`. 보관은 output_dir 전체를 올리는 AUD-512~514가 함께 하고 보관 성공(AUD-614) 뒤에만 보낸다. 재발송은 요약이 기록한 경우만 `log_review/<실행 ID에서 정한 이름>`을 받아(AUD-634) 기록된 해시와 대조한다(AUD-635: 받지 못함·이름 불일치·해시 불일치면 하나도 보내지 않는다). 같은 실행 ID로 다시 돌린 실행은 쓰기 전에 `log_review/`를 지운다(이전 시도의 파일이 보관·첨부되지 않게).
- **수신자**: 보고서에 출발지·계정명이 들어가므로 메일 수신자(`inventory/config/host_audit.mail_recipients`)는 점검자·결재자로 한정한다(ADR-0015 Consequences).

### 18.1 태스크 매트릭스

| Spec ID | 태스크 명칭 | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `AUD-800` | `Decide whether this run drafts the Log Review Report` | `ansible.builtin.set_fact` | 러너 | 정기 실행 또는 플래그, check 모드 제외 |
| `AUD-801` | `Fix the Log Review period and its OpenObserve searches` | `ansible.builtin.set_fact` | 러너 | 필터 `host_audit_log_review_period`·`host_audit_log_review_queries`(같은 시작 시각이면 같은 값) |
| `AUD-802` | `Read the OpenObserve address and the read-only search account (host_audit_openbao_log_review_docs)` | `ansible.builtin.set_fact` | 러너 | 공용 읽기 지점 `lookup('openbao_doc')`, `errors='ignore'`, `no_log` |
| `AUD-803` | `Search OpenObserve for the review period (POST _search only)` | `ansible.builtin.uri` | 러너 | 읽기 전용 조회, 실패는 상태 코드로 받음(`changed_when: false`, `no_log`) |
| `AUD-804` | `Build the Log Review Report model` | `ansible.builtin.set_fact` | 러너 | 필터 `host_audit_log_review_results`·`host_audit_log_review_model` |
| `AUD-805` | `Render the Log Review Report A4 HTML` | `ansible.builtin.template` | 러너 | `log_review/`(`0700`) 아래 `0600` |
| `AUD-806` | `Compute the SHA-256 of the Log Review Report to attach` | `ansible.builtin.stat` | 러너 | 읽기 전용. 메일 요약(AUD-612)이 싣는 해시 |
| `AUD-807` | `Fail the run when the Log Review Report could not be drafted` | `ansible.builtin.assert` | 러너 | 모델·렌더링·판정 오류만 실패(조회 실패는 실패 아님) |
| `AUD-634` | `Get the archived Log Review Report` | `ansible.builtin.uri` | 러너 | 요약이 기록한 실행만, 이름은 실행 ID에서 |
| `AUD-635` | `Assert the archived Log Review Report exists and matches its recorded SHA-256` | `ansible.builtin.assert` | 러너 | 다르면 재발송 중단 |

`Remove a leftover Log Review Report of an earlier attempt`·`Create the Log Review Report directory`·`Resolve the OpenObserve search target`·`Remove a Log Review Report that could not be completed`·`Summarize the Log Review Report of this run`과 재발송의 `Read the Log Review Report record of the archived summary`·`Compute the SHA-256 of the downloaded Log Review Report`·`Say that the Log Review Report is not resent without its recorded hash`는 위 태스크의 보조 태스크라 SPEC-ID를 두지 않는다. 보고서 단계는 Molecule 대상 밖이라 `[VERIFY-…]`가 없고 검증은 pytest다(ADR-0013): 모델 필터 단위 `tests/test_host_audit_log_review.py`, 공유 렌더링 `tests/test_host_audit_log_review_render.py`, 조회 경로·메일·보관·재발송 `tests/test_host_audit_log_review_tasks.py`·`tests/test_host_audit_xlsx_zip_report.py`.

### 18.2 1부 계정·시간 항목 1~5번 (#559)

판정은 `filter_plugins/host_audit_log_review_accounts.py`이고 테스트는 `tests/test_host_audit_log_review_accounts.py`다. 서버 sshd·sudo·su 기록(`security_logs`, `security_semantics` VRL 필드)과 auditd 계정 관리 기록만 본다(장비 관리자 로그인은 #562). 조회는 모두 OpenObserve에서 시(로그인 성공·sudo·su·계정 변경) 또는 분(로그인 실패) 단위로 집계해 받는다: 원시 이벤트를 받으면 자동화 로그인과 Ansible `become`만으로 조회 한도에 닿기 때문이다. 시각은 수신 시각 `_timestamp`의 KST다.

| 번호 | 판정 | 상태 |
|---|---|---|
| 1 | SSH 로그인 성공 중 호스트별 허용 계정 밖 계정. 허용 계정은 provisioning 선언 사용자(`accounts`, `state: absent` 제외, `resolve_connection`의 관리 계정)·bootstrap 사용자(`_boot_summary.username`)·root이고, `agents_only` 호스트는 Asset Inventory 계정(보고서 모델 `asset_inventory`)과 root다. 목록을 알 수 없는 호스트(점검 대상 밖·접속 해석 실패·Asset Inventory 수집 실패)는 '허용 계정 목록 없음'으로 행에 나온다. 존재하지 않는 계정 시도(`Invalid user` 줄, `event_outcome` 없음)는 요약에 별도 통계로만 적는다 | 자동 판정 |
| 2 | 같은 계정·같은 호스트에서 `failure_window_minutes`분 안에 `failure_threshold`회 이상 실패(존재하지 않는 계정 시도 제외, 분 단위 집계라 구간 경계는 분 단위) | 자동 판정 |
| 3 | 평일 업무시간 밖·주말·공휴일의 SSH 로그인 성공 | 자동 판정(그 해 공휴일 목록이 없으면 일부 자동) |
| 4 | 업무시간 밖 sudo·su 성공과 auditd 계정 관리 기록(ADD_USER·USER_MGMT 등). Ansible `become`(명령에 `BECOME-SUCCESS-`)은 자동화 건수로 따로 세고, 자동화 건만 있는 행은 확인 필요로 세지 않는다 | 자동 판정(위와 같음) |
| 5 | 계정별 접속일·호스트 목록. 휴직·휴가자 명단과의 대조는 점검자가 한다 | 사람 대조 |

- **수집 공백 연결**: 3부 수집 공백 호스트(수집 대상 호스트 중)는 1~4번 표에 `비고`로 붙고, 발견이 없어도 행으로 남는다. 공백이 있거나 수집 공백 조회가 실패하면 그 항목은 `일부 자동`·`확인 필요`이고 요약에 이름이 적힌다(로그가 없어서 이상 없음이 되지 않게). 5번은 요약에 적는다.
- **개인정보처리시스템**: 판정 문맥 `settings['personal_info_systems']`(호스트 이름 목록)가 있으면 행마다 `예`·`아니오`와 요약의 해당 행 수를, 없으면 `미지정`을 적는다. 값의 원본은 로그 검토 작업 설정 문서(#560)이고, 그 문서를 읽는 쪽이 AUD-804에 이 키를 더한다.
- **입력**: AUD-804 `_meta.settings.accounts`(`hosts`는 필터 `host_audit_log_review_account_hosts`가 이름만 남겨 만든다. 공개 키·접속 주소는 넘기지 않는다).
