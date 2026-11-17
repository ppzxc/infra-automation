# OpenBao 문서 도구 (`scripts/openbao_docs.py`)

> Spec #511. 하위 명령 `validate`(로컬 검증), `put`(검증 후 쓰기), `check`(전체 대조)가 같은 검증 코드(`scripts/openbao_validation.py`)를 쓴다. 이 문서에는 하위 명령별 절이 있고, 저장소가 공개라서 주소·계정·키 값은 쓰지 않는다(운영자 로컬 비공개 노트).

## Periodic Check (`check`, Ticket-8 #519)

Semaphore 템플릿 "OpenBao — Periodic Check"가 `periodic_check` AppRole Environment로 **매일 1회** 돌린다(템플릿·스케줄 생성은 일괄 전환 티켓). 코드는 `scripts/openbao_check.py`이고 `openbao_docs.py check`가 부른다.

### 입력

| 이름 | 내용 |
|---|---|
| `VAULT_ADDR` | OpenBao 주소 |
| `VAULT_NAMESPACE` | 기본 `infra` |
| `VAULT_TOKEN` 또는 `VAULT_ROLE_ID`+`VAULT_SECRET_ID` | 토큰이 없으면 AppRole로 로그인한다 |
| `--tofu-dir` | OpenTofu 코드 디렉터리(기본 `tofu/openbao`). 저장소 루트에서 돈다 |

Semaphore API 읽기는 Service `semaphore`를 쓴다: 주소 `inventory/services/semaphore`, 토큰 `secrets/services/semaphore/inventory_read`(`inventory_read`). OpenBao 토큰과 섞지 않는다.

### 점검 항목과 규칙 이름

출력(stdout)과 알림은 `문서 경로<TAB>JSON 포인터<TAB>규칙 이름` 줄뿐이다. 값은 어디에도 내지 않는다.

| 항목 | 판정 | 규칙 이름 |
|---|---|---|
| 모든 문서를 스키마와 대조 | 실패 | jsonschema 규칙 이름(`additionalProperties` 등), `no_schema`, `yaml_parse`, `non_string_key` |
| 참조 검사(`via`·`credential`·`access`) | 실패 | `via_missing`, `via_cycle`, `credential_missing`, `become_credential_missing`, `access_credential_missing` |
| 문서를 읽을 수 없음 | 실패 | `read_failed`, `list_failed` |
| Semaphore 인벤토리에만 있는 호스트 | 실패 | `inventory_missing_asset` |
| Asset 문서에만 있음(폐기·편입 대기) | 경고(stderr 로그만) | `orphan_asset` |
| 위의 고아이면서 metadata `updated_time`이 30일 넘음(시각을 읽지 못하면 `orphan_metadata_unreadable`) | 실패 | `orphan_asset_stale` |
| Semaphore 설정 문서 없음·API 접속 실패 | 실패 | `semaphore_config_missing`, `semaphore_unreachable` |
| AppRole secret_id 만료까지 30일 이하 | 실패 | `secret_id_expiring`, `secret_id_lookup_failed` |
| OpenTofu 코드에 없는 정책·role·마운트 | 실패 | `not_in_opentofu`, `unmanaged_lookup_failed` |

- secret_id 만료 점검은 `applier`(1일·1회용)와 `agent_session`(24시간)을 뺀다. 둘은 짧게 쓰는 것이 정상이다.
- 문서를 읽지 못한 실행(`read_failed`)에서는 참조 검사를 건너뛴다(가짜 위반을 막기 위해). 읽기를 고친 뒤 다시 돌린다.
- 점검이 접속 설정 오류(종료 코드 2)나 로그인 실패로 시작하지 못하면 알림 URL을 읽을 수 없어 알림이 가지 않는다. 템플릿 실패 상태가 유일한 신호이므로 `periodic_check` secret_id 만료에 유의한다.
- OpenTofu 코드에는 있는데 서버에 없는 객체는 점검 대상이 아니다. `plan`이 잡는다.
- 고아 판정은 상태 저장소 없이 계산하는 근사다("고아가 된 지 30일"이 아니라 "고아이면서 30일간 수정 없음").
- 정적 인벤토리(`static`, `static-yaml`, `yaml`)만 읽는다. 파일형 인벤토리는 API로 본문을 얻을 수 없어 건너뛴다.

### 종료 코드와 알림

- 종료 코드: 0 정상, 1 실패(템플릿이 실패로 끝난다), 2 설정 오류.
- 실패하면 `secrets/services/alert/notify` URL로 `text/plain` 요약(위 세 칸 줄, 최대 50줄)을 보낸다. 정상이면 보내지 않는다.

### 실패 대응

1. Semaphore 템플릿 로그에서 실패 줄(`문서 경로`, `규칙 이름`)과 경고 줄을 확인한다. 알림에도 같은 줄이 있다.
2. 규칙별 조치:
   - 스키마·참조 규칙: 해당 문서를 고쳐 `openbao_docs.py put`으로 다시 등록한다. 스키마를 바꾼 PR 뒤라면 데이터 이전이 빠진 문서다. 참조 위반은 Credential을 먼저 등록하고 Endpoint를 나중에 등록한다.
   - `read_failed`·`list_failed`: `periodic_check` 정책과 토큰(네임스페이스 `infra`)을 확인한다. 문서가 깨진 것이 아니라 읽기 권한 문제일 수 있다.
   - `inventory_missing_asset`: 인벤토리에 새로 넣은 호스트의 Asset 문서를 `put`으로 등록한다(편입 체크리스트). 인벤토리에서 빠졌어야 하는 호스트면 인벤토리를 고친다.
   - `orphan_asset_stale`: 폐기된 호스트라면 Asset 문서를 정리한다(`operator`에는 삭제 권한이 없으므로 비상용 `admin` 런북). 편입 대기 중이라면 문서를 한 번 갱신하거나 인벤토리에 넣는다.
   - `semaphore_*`: `inventory/services/semaphore`·`secrets/services/semaphore/inventory_read` 문서와 토큰 유효성, Semaphore 접속을 확인한다.
   - `secret_id_expiring`: `openbao-operations` 런북으로 해당 role의 secret_id를 새로 발급하고 Environment를 교체한다(180일 교체 주기).
   - `not_in_opentofu`: 손으로 만든 객체다. 의도한 것이면 `tofu/openbao`에 코드로 옮기고, 아니면 `admin` 런북으로 지운다. 악의적 변경 가능성도 함께 본다(#505).
3. 고친 뒤 템플릿을 수동으로 한 번 더 돌려 통과를 확인한다.

CI는 실제 OpenBao에 접속하지 않는다. `tests/test_openbao_docs_check.py`가 공용 가짜 OpenBao·가짜 Semaphore·알림 수신기로 위 판정과 "알림·출력에 값이 없음"을 고정한다.
