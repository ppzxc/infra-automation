# 11. 수동 관리 docker compose의 프로젝트·서비스 이름 규칙

- **Status**: Accepted
- **Date**: 2026-10-15
- **Deciders**: Overseer Engineering Team & User
- **Context**: FUNA Cluster(ns0325·ns0327·ns0338) Host Agents 편입 (#219, 용어는 `CONTEXT.md`의 FUNA Cluster)

---

## 1. Context & Problem Statement

FUNA Cluster는 앱과 인프라(Caddy·keepalived·Valkey)를 사람이 손으로 설치한 docker compose로 운영한다. 지금 이 구성에는 다음 문제가 있다.

1. **두 디렉터리가 compose 프로젝트 하나를 공유한다.** 프로젝트 이름을 디렉터리 basename에 맡기면 어느 한쪽 디렉터리의 이름이나 `-p`가 바뀔 때 두 스택이 한 프로젝트가 된다. 한 스택에서 `docker compose up --remove-orphans`(또는 `down`)를 하면 상대 스택의 컨테이너가 고아로 판정되어 지워진다.
2. **경로 이전이 이름을 흔든다.** 앱과 인프라를 일반 계정 홈에서 ADR-0002 표준 경로(`/opt/services/<프로젝트>`)로 옮기면 디렉터리 basename이 바뀌어, 이름을 명시하지 않은 프로젝트는 컨테이너·네트워크·볼륨 이름이 통째로 달라진다.
3. **이름이 곳곳에서 어긋난다.** 컨테이너 이름, 다른 컨테이너가 찾는 네트워크 이름, 로그의 `service.name`을 각자 정해 두면 앱이 늘 때 출처가 겹치거나 찾을 수 없다. Host Agents의 컨테이너 로그 수집(#221)은 `<프로젝트>-<서비스>`를 `service.name`으로 쓴다.

Docker Compose는 프로젝트 이름을 다음 우선순위로 정한다(높은 쪽이 이긴다).

1. `-p` 명령행 플래그
2. `COMPOSE_PROJECT_NAME` 환경 변수
3. compose 파일 최상위 `name:`
4. compose 파일이 든 디렉터리의 basename
5. 파일을 지정하지 않았을 때 현재 디렉터리의 basename

컨테이너 기본 이름은 `<프로젝트>-<서비스>-<번호>`다.

---

## 2. Decision Outcomes (결정 사항)

1. **디렉터리 하나 = compose 프로젝트 하나.** 두 디렉터리가 프로젝트 하나를 공유하지 않는다.
2. **최상위 `name:`을 명시한다.** 값은 디렉터리 이름과 같게 둔다(`/opt/services/<프로젝트>`의 `<프로젝트>`). 경로가 바뀌어도 이름이 흔들리지 않는다.
3. **서비스 이름은 구성요소로 짓고 제품명을 반복하지 않는다.** 예: 프로젝트 `funa`의 서비스 `api`, 프로젝트 `proxy`의 서비스 `caddy`. `funa` 프로젝트에 `funa`라는 서비스를 두면 컨테이너가 `funa-funa-1`이 된다.
4. **`container_name:`을 쓰지 않는다.** 컨테이너 이름은 Compose가 `<프로젝트>-<서비스>-<번호>`로 짓게 둔다. 쓰는 쪽은 번호를 뗀 식별자를 기준으로 삼는다.
5. **식별자 `<프로젝트>-<서비스>`를 세 곳에 똑같이 쓴다.**
   - 컨테이너 이름(`<프로젝트>-<서비스>-<번호>`의 앞부분)
   - 공유 네트워크에서의 **명시적 alias**(`networks.<이름>.aliases`). 다른 프로젝트의 컨테이너(예: Caddy)는 이 alias로 앱을 찾는다. 컨테이너 이름이 바뀌어도 연결이 깨지지 않는다.
   - 로그 `service.name`(Host Agents가 compose 라벨 `com.docker.compose.project`와 `com.docker.compose.service`로 만든다)
6. **`COMPOSE_PROJECT_NAME`을 전역 환경(profile.d·env 파일)에 두지 않는다.** 우선순위 2번이 `name:`을 덮어 프로젝트 이름이 셸 환경에 따라 달라진다.

---

## 3. Alternatives Considered (검토한 대안)

| 대안 | 기각 이유 |
|---|---|
| **역할 이름 프로젝트에 앱을 서비스로 넣는다** (예: 프로젝트 `proxy` 안에 `caddy`와 `funa-api`) | 앱과 인프라의 수명이 한 프로젝트에 묶여, 앱 배포(`up`·`down`·`--remove-orphans`)가 인프라 컨테이너에 닿는다. 앱을 추가할 때마다 인프라 compose를 고쳐야 한다. |
| **제품명 반복** (프로젝트 `funa`·서비스 `funa`) | 컨테이너가 `funa-funa-1`처럼 중복되고 `service.name`도 `funa-funa`가 되어 의미 없는 겹침이 생긴다. |
| **두 디렉터리가 프로젝트 하나를 공유** (`-p`나 `COMPOSE_PROJECT_NAME`으로 같게 맞춤) | 현재 상태다. 한쪽 compose가 다른 쪽 컨테이너를 고아로 판정해 지울 수 있다(고아 판정 위험). |
| **`name:` 없이 디렉터리 basename에 맡김** | 우선순위 4번이라 경로 이전·디렉터리 이름 변경에 이름이 따라 바뀐다. 이전 대상인 이번 작업에서 가장 위험한 경우다. |
| **`container_name:`으로 이름 고정** | 같은 이름의 컨테이너를 두 프로젝트가 만들 수 없고, 롤링 교체(`up --scale`·재생성 중 두 컨테이너 공존)가 막힌다. 라벨로 출처를 이미 알 수 있어 이득이 없다. |

---

## 4. Consequences & Trade-offs

- **장점**
  - 경로를 옮겨도 프로젝트·네트워크·볼륨 이름이 그대로라 이전 중 컨테이너가 새로 만들어지거나 고아가 되지 않는다.
  - 프로젝트가 디렉터리 단위로 격리되어 한 스택의 `down`·`--remove-orphans`가 다른 스택을 건드리지 않는다.
  - `<프로젝트>-<서비스>` 하나로 컨테이너, 네트워크 alias, 로그 `service.name`이 일치해 앱이 늘어도 출처가 겹치지 않는다.
- **단점·주의**
  - 이름 규칙은 수동 관리 compose 파일의 관례다. 저장소의 Ansible이 파일 내용을 검사하지 않으므로 리뷰와 카나리 체크리스트로 지킨다.
  - 이름을 바꾸는 순간 새 프로젝트로 취급된다. 기존 스택을 이 규칙으로 옮길 때는 옛 컨테이너를 먼저 내리고 새 이름으로 올린다(노드를 서비스에서 뺀 상태에서 수행).
  - 컨테이너 이름이 바뀌므로 이름에 기대는 감시(ns0270 Uptime Kuma push cron 등)는 새 식별자로 고쳐야 한다.
