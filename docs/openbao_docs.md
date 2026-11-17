# OpenBao 문서 등록·검증 도구 (`openbao_docs`)

`scripts/openbao_docs.py`는 OpenBao `infra` 네임스페이스의 `inventory/`·`secrets/` 문서를 스키마로 검증하고 등록한다. 등록과 수정은 이 도구로만 한다. 설계 배경은 Spec #511(맵 #500)과 ADR-0014다. 공개 저장소라 실제 주소·계정·토큰은 이 문서에 적지 않는다. 키 정의의 원본은 `schemas/openbao/`의 스키마이고, 경로 패턴과 스키마의 대응은 `schemas/openbao/index.yml` 한 파일이다.

문서 경로는 `<마운트>/<경로>`다(예: `inventory/assets/ns0001`, `inventory/assets/ns0001/endpoints`, `secrets/assets/ns0001/credentials/admin01`). 출력은 문서 경로 + JSON 포인터 + 규칙 이름뿐이고 값은 마운트와 관계없이 내지 않는다.

---

## 1. `validate` — 로컬 검증

```
python3 scripts/openbao_docs.py validate <루트 디렉터리>
```

루트 아래 `<마운트>/<경로>.yml`이 문서 하나다. OpenBao에 접속하지 않는다. 스키마 검증 뒤 문서 사이 참조(`via` 존재·순환, `credential`·`become.credential`, `access`의 Credential 이름)를 검사한다. `secrets/` 문서는 비밀 자리에 null을 적는다. 종료 코드는 0 통과, 1 위반, 2 사용법 오류다.

## 2. `put` — 검증 후 쓰기

```
export VAULT_ADDR=...            # VAULT_NAMESPACE는 기본 infra
export VAULT_TOKEN=...           # operator 토큰. 없으면 프롬프트로 받는다
python3 scripts/openbao_docs.py put <문서 경로> <입력 YAML> [--merge]
```

### 입력

| 마운트 | 입력 YAML | 값 |
|---|---|---|
| `inventory/` | 문서 전체 | YAML에 그대로 적는다 |
| `secrets/` | 필드 이름과 비밀이 아닌 값(`type`, `username` 등). 비밀 필드는 `null` | 비밀 값은 `getpass` 프롬프트로 받는다 |
| `secrets/` `private_key` | 개인키 **파일 경로** | 도구가 파일을 읽어 문서에 넣는다 |

- 비밀 필드에 값을 적으면 `secret_value_in_file`로 거부한다. 명령행 인자와 환경변수로는 문서의 비밀 값을 받지 않는다(셸 이력·프로세스 목록·sudo 로그에 남지 않게 하기 위해서다). 환경변수는 접속 설정(`VAULT_ADDR`·`VAULT_NAMESPACE`)과 operator 토큰뿐이다.
- 자산대장 xlsx 가져오기는 없다. 처음 일괄 적재는 전환 이전 스크립트가 한다.

### 동작 순서

1. 현재 문서를 읽는다(없으면 새 문서).
2. `--merge`면 현재 문서에 입력을 덮어 합친다. 그 밖에는 입력이 문서 전체다. 합친 뒤 **전체 문서**를 스키마로 검증한다. 위반이면 쓰지 않는다. KV v2 `patch`는 쓰지 않고 항상 전체를 통째로 쓴다.
3. 참조를 검사한다. 쓰려는 문서가 **새로 깨뜨리는** 참조만 막는다(`credential_missing`, `become_credential_missing`, `via_missing`, `via_cycle`, `access_credential_missing`). 이미 깨져 있던 참조와 다른 문서의 깨진 참조는 경고(표준오류)만 낸다.
4. 바뀌는 키를 보여주고 확인(`y`)을 받는다. `secrets/` 문서는 키 이름과 `변경됨`만 낸다. 바뀌는 것이 없으면 쓰지 않고 끝난다.
5. `cas=<읽은 버전>`으로 쓴다(새 문서는 `cas=0`). 읽은 뒤 다른 쪽이 문서를 바꿨다면 쓰기가 실패한다(`conflict`). 이 경우 다시 실행한다.

`--merge`는 추가·덮어쓰기만 한다(키를 지울 수는 없다. 지우려면 전체 문서를 다시 `put`한다). `secrets/` 문서에서 기존 비밀을 그대로 두려면 그 필드를 입력에서 **빼고**, 새 값을 줄 필드만 `null`로 적는다. 프롬프트는 검증을 통과한 뒤에 나오고 빈 값은 거부한다. 소프트 삭제된 문서를 다시 만들 때는 남아 있는 버전을 `cas`로 쓴다.

종료 코드는 0 성공(변경 없음 포함), 1 거부·실패, 2 사용법·접속 설정 오류다. `operator`에는 삭제 권한이 없다. 삭제는 비상용 `admin` 런북(`docs/runbooks/openbao-operations.md`)으로만 한다.

## 3. 새 Asset 편입 순서

참조 검사 때문에 순서가 강제된다. **Credential 먼저, Endpoint 다음**이다.

1. `secrets/assets/<ns>/credentials/<이름>` — Credential을 등록한다(`put`, 비밀은 프롬프트).
2. `inventory/assets/<ns>` — Asset 문서를 등록한다. `access`에 적은 Credential 이름이 있어야 통과한다.
3. `inventory/assets/<ns>/endpoints` — Endpoint를 등록한다. `credential`·`become.credential`이 있어야 하고, `via`가 가리키는 Endpoint가 있어야 하며 순환이 없어야 한다.
4. 필요하면 `secrets/assets/<ns>/agents`(에이전트 비밀)를 등록한다.
5. Semaphore 인벤토리 그룹에 호스트를 넣는다(그룹 소속의 원본은 Semaphore 인벤토리다).
6. 편입 체크리스트의 나머지(방화벽, whitelist, 키 발급)를 이어서 한다.

미리 형식만 보려면 같은 YAML을 `validate`용 트리에 두고 §1을 먼저 돌린다.

---

## 4. Periodic Check (`check`, Ticket-8 #519)

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

- 소프트 삭제된 문서는 목록에 나와도 없는 문서로 본다(`read_failed`가 아니다).
- secret_id는 role마다 가장 늦게 만료되는 것이 30일 이하일 때만 알린다(교체 중 남은 옛 secret_id는 알리지 않는다).
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
