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
