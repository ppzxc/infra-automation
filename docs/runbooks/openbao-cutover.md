# OpenBao 구조 일괄 전환 런북 (Spec #511 / Ticket-1)

옛 `infra/prod/host` 구조에서 새 구조([ADR-0014](../adr/0014-openbao-storage-structure-and-access-policy.md))로 한 번에 넘어가는 일회성 절차다. 이중 읽기가 없으므로 소비자 코드가 경로를 바꾸는 순간이 곧 전환이다. 반복 운영(secret_id 발급, OpenTofu 적용)은 [openbao-operations](openbao-operations.md)를 따른다.

공개 저장소이므로 동결 창 시각, 카나리 Asset, 미참조 계정 목록, 러너 CIDR, 실행 기록은 이 문서에 쓰지 않는다. 모두 운영자 로컬 비공개 노트 `~/.local/share/infra-automation/openbao-restructure/`에 두고 이 문서는 그 노트를 가리킨다. 이슈에는 통과 여부만 적는다.

## 1. 전제와 병합 단위

- `infra` 네임스페이스는 이미 있고 비어 있다. 새로 만들 것은 그 안의 마운트·정책·AppRole·userpass다.
- **준비 PR 여러 개**: 병합해도 운영에 영향이 없다(스키마·`index.yml`·등록 도구, OpenTofu 코드, 이전 스크립트, 러너 이미지 `jsonschema`, Periodic Check 템플릿 코드, 이 문서들).
- **전환 PR 하나**: 모든 소비자의 경로·키 변경, 접두사 변수 폐지, `VAULT_TOKEN` 대체 경로 제거, 테스트·fixture 교체. 동결 창 안에서 병합한다.
- 알림 text/plain 전환은 전환 PR보다 먼저 병합돼 있어야 한다.
- 옮기지 않는 것: 어떤 호스트도 가리키지 않는 계정 문서(목록은 비공개 노트), 소프트 삭제된 `switches/` 문서, 읽는 곳이 없는 키. 옛 네임스페이스를 지우기 전까지는 원본이 남아 있고, 필요하면 `operator`로 다시 등록한다.

## 2. 전환 순서

1~5단계는 동결 전에 끝낸다. 그래서 창이 짧다.

1. 준비 PR을 모두 병합하고 Semaphore 러너 이미지를 다시 빌드한다.
2. `admin`으로 한 번만 bootstrap한다. `infra` 안에 applier 정책과 AppRole을 만든다.
3. OpenTofu apply로 마운트 `inventory/`·`secrets/`, 정책, AppRole(계열별 7개, `periodic_check`, `agent_session`), userpass와 운영자 사용자를 만든다.
4. 계열별 secret_id를 수동 발급하고(operations §2) Semaphore Environment를 계열별 7개와 Periodic Check용 1개 만든다. `applier`는 적용할 때마다 발급해 OpenTofu 템플릿에 넣고(operations §4), `agent_session`은 Semaphore 밖이고 secret_id가 24시간 만료라 Environment 없이 7단계 직전(동결 창 안)에 발급한다. 이 단계에서는 템플릿에 붙이지 않는다. Periodic Check 템플릿은 만들어 두되 스케줄은 아직 걸지 않는다.
5. 이전 스크립트 dry-run으로 적재를 연습한다(전체 검증, 값 해시 대조). 새 Service `semaphore` 문서는 이전 대상이 아니라 새로 발급하는 값이므로 dry-run이 통과한 뒤 등록 도구 `put`으로 등록한다.
6. **동결 창을 시작한다.** 스케줄을 전부 끄고, 옛 KV 쓰기를 멈추고, 이전 스크립트를 실제로 실행한다.
7. 전환 PR을 병합하고 템플릿마다 계열 Environment로 바꾼다. 에이전트 세션은 새 `agent_session` AppRole로 바꾼다.
8. 확인 목록(§4)을 통과하고 Periodic Check를 1회 통과시킨다.
9. 스케줄을 다시 켜고 Periodic Check 매일 스케줄을 건다. 동결 창이 끝난다.

### 이전 스크립트

`openbao_migrate`는 한 번 쓰고 버리는 스크립트다. 옛 구조를 `admin` 토큰으로 읽고, 새 문서 전체를 등록 도구와 같은 검증 코드로 먼저 검증한다. 하나라도 실패하면 아무것도 쓰지 않는다. 쓰기는 `cas=0`이고, 다시 실행하면 내용이 같은 문서는 건너뛰고 다른 문서는 경로·키 이름의 차이만 보인다. 끝나면 옛 값과 새 값의 해시 대조 보고서를 낸다(경로와 일치 여부만 있고 값은 없다).

## 3. 동결 창 규칙

- 목표 길이는 2시간이다.
- 시간대는 평일 업무 시간 중 매일·매월 스케줄이 없는 구간으로 잡는다. 정확한 시각은 Semaphore 스케줄 목록을 조회해 비공개 노트에 적는다(이 문서에는 쓰지 않는다).
- 창 동안 Semaphore 스케줄을 **전부** 끄고 수동 실행도 하지 않는다.
- 옛 KV 쓰기 금지는 운영 규칙이다. 사람이 `admin`으로 쓰므로 정책으로는 막을 수 없다.
- 창이 끝날 때까지 확인 목록을 통과하지 못하면 §5에 따라 되돌린다.

## 4. 계열별 확인 목록

계열마다 대표 실행 1회와 거부 시험을 통과시킨다. 카나리 Asset은 비공개 노트가 정한다.

| 계열 | 대표 실행 |
|---|---|
| `provision` | Host Provisioning `--check`, 카나리 1대 |
| `host_agents` | Config All `--check`(카나리 1대), Deploy Restic `--check` |
| `backup_maintenance` | Repo Maintenance 실제 실행 1회 |
| `openobserve_config` | dry_run이 없어 apply하지 않는다. 렌더링 결과를 서버 알림과 비교만 한다. 실제 apply는 다음 정기 변경 때 한다 |
| `host_audit` | On-demand, 카나리 1대(드리프트 포함) |
| `network_backup` | Cisco·FortiGate 백업 실제 실행 |
| `github_webhook_watch` | 실제 실행 |
| `periodic_check` | 1회 통과(스키마·참조·인벤토리 대조) |

- **거부 시험**: AppRole마다 자기 범위 밖 경로 하나를 읽어 403을 확인한다. 새 정책이 열어야 할 것은 열고 막아야 할 것은 막는지 보는 시험이다. 어떤 경로를 쓰는지는 비공개 노트에 둔다.
- 값은 출력하지 않는다. 결과는 통과·실패만 기록한다.

## 5. 되돌리기

- **바로 고친다**: 원인이 데이터(문서 값·키)이면 `operator`로 그 자리에서 고친다.
- **되돌린다**: 원인이 코드·정책 구조이거나 창이 끝날 때까지 확인 목록을 통과하지 못하면 되돌린다.
  1. 전환 PR을 revert한다.
  2. 템플릿을 옛 Environment로 돌린다.
  3. 에이전트 세션을 옛 AppRole로 되돌린다(옛 AppRole은 §6까지 남아 있다).
  4. 스케줄을 다시 켠다.
- 새 마운트 데이터는 지우지 않고 다음 시도 때 재사용한다(이전 스크립트를 다시 실행하면 차이만 보고된다).
- 되돌리면 옛 KV가 정본이다. 창 안에서 새 마운트에 `operator`로 고친 값이 있으면 옛 KV에도 같은 수정을 `admin`으로 반영하고 기록한다.
- 되돌린 뒤 옛 KV를 `admin`이 고쳤다면 다음 시도 전에 이전 스크립트를 다시 실행해 차이 요약(경로·키 이름)을 확인한다. `cas=0` 재실행은 다른 문서를 덮어쓰지 않으므로, 달라진 문서는 `operator`로 새 문서를 직접 고친다.
- 옛 Environment와 옛 AppRole은 §6의 정리 단계까지 그대로 둔다. 옛 `infra/prod/host`는 §3의 쓰기 금지 규칙으로 동결 시점의 내용 그대로 남아 있어 데이터 복원이 필요 없다. 새 `semaphore` Service 문서는 새 마운트에만 있고 옛 구조는 쓰지 않는다.

## 6. 옛 구조 삭제

정기 작업 전체가 새 구조로 한 바퀴 돈 뒤에 지운다. 월간 Host Audit 1회가 포함돼야 하고 전환 뒤 최소 2주가 지나야 한다. 드물게 도는 작업의 늦게 드러나는 문제를 옛 데이터로 고치기 위해서다.

1. raft 스냅샷을 뜬다.
2. `admin`으로 `infra/prod/host`와 `infra/prod`를 삭제한다.
3. 옛 AppRole 두 개(Semaphore용·에이전트용), `approle-policy`, 옛 Environment를 지운다.
4. 이전 스크립트와 그 테스트를 제거하는 PR을 낸다.
