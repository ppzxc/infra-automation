# FUNA Env Role Task Specification

`funa_env` 역할은 FUNA Cluster(ns0325·ns0327·ns0338, `CONTEXT.md`)의 환경 값을 **Ansible이 OpenBao에서 읽어 노드 파일로 렌더링**한다. 예전의 누구나 읽을 수 있는 전역 환경 파일(`global_env.sh`)과 계정마다 다시 매핑한 사본을 대체한다. 결정의 근거는 #213(global_env 대체 방식), 구현 단위는 #222다.

---

## 1. 개요 (What)

- **적용 대상**: 인벤토리 그룹 **`funa_cluster`** 소속 호스트. 그룹에 속하지 않은 호스트에는 아무것도 만들지 않는다(`funa_env_enabled`는 그룹 소속에서 파생한다. Semaphore 인벤토리는 static이라 group_vars를 쓰지 않는다).
- **실행 위치**: `playbooks/site.yml`(HOST PROVISIONING)에서 `docker_engine` **바로 뒤**. `dockermgmt` 그룹(DOC-014)이 있는 상태에서 렌더링되고, 그룹이 없으면 그 이름을 대며 실패한다(check 모드는 파일 단계를 건너뛴다).
- **역할 분리 이유**: 새 역할로 두었다. 값의 원천(OpenBao 4개 경로)·대상 그룹·실행 시점(docker_engine 뒤)이 `common`/`docker_engine`과 다르고, 단일 책임(SRP)을 지켜 그룹 하나로 켜고 끈다. 기존 역할의 선택 기능으로 넣으면 모든 호스트가 이 입력 변수를 안고 다니게 된다.

### 렌더링 결과

| 파일 | 소유·권한 | 내용 | 읽는 쪽 |
|---|---|---|---|
| `/etc/funa-cluster/cluster.env` | `0644 root:root` | 비시크릿: 노드별 값 + 클러스터 공통 값 | 모든 서비스 `env_file:`, `--env-file` 보간 |
| `/etc/funa-cluster/proxy.secrets.env` | `0640 root:dockermgmt` | Caddy 시크릿만 | proxy 서비스만 |
| `/etc/funa-cluster/vrrp.secrets.env` | `0640 root:dockermgmt` | keepalived 시크릿만 | vrrp 서비스만 |
| `/etc/profile.d/funa-cluster.sh` | `0644 root:root` | 읽을 수 있는 위 파일만 `set -a`로 불러오는 로더(운영 alias 없음, `common`의 `99-aliases.sh`가 이미 배포) | 로그인 셸 |

시크릿 파일의 `0640 root:dockermgmt`는 AGENTS.md의 0600 규칙 예외다(근거는 AGENTS.md §4).

### 값의 원천 (OpenBao, 값은 Git에 두지 않는다)

KV 키 이름이 곧 환경 변수 이름이다. 이 문서와 저장소에는 값이 없다.

| OpenBao 경로 | 렌더링 위치 | 읽는 키 | 필수 키 (없으면 실패) |
|---|---|---|---|
| `hosts/<Inventory Hostname>` | `cluster.env` / `proxy.secrets.env` | `funa_env_node_keys`(→ `cluster.env`)와 `funa_env_node_secret_keys`(→ `proxy.secrets.env`)에 적은 키만(이 KV에는 접속 정보도 있다) | `FUNA_NODE_EXTERNAL_HOSTNAME`, `FUNA_NODE_EXTERNAL_WILDCARD_HOSTNAME`, `FUNA_NOTIFICATION_HEADER`, `FUNA_NODE_NAME`(funa 로그의 `service.node.name`, 값은 인벤토리 호스트명), `CLOUDFLARE_API_TOKEN`(노드마다 값이 다르다) |
| `clusters/funa` | `cluster.env` | 키 전부 | `FUNA_FLOATING_HOSTNAME`, `FUNA_HEALTH_CHECK_URI`, `FUNA_SERVICE_NAME`, `FUNA_NOTIFICATION_SMTP_{FROM,HOST,PORT,TO,USERNAME}`, `FUNA_NOTIFICATION_NAVER_WORKS_BOT_URL`, `TZ` |
| `clusters/funa/proxy` | `proxy.secrets.env` | 키 전부(비어 있으면 실패) | `FUNA_ADMIN_TOKEN`, `DB_PASSWORD`(`CLOUDFLARE_API_TOKEN`은 노드 KV와 합쳐 확인) |
| `clusters/funa/vrrp` | `vrrp.secrets.env` | 키 전부(비어 있으면 실패) | `FUNA_NOTIFICATION_SMTP_PASSWORD`, `FUNA_NOTIFICATION_NAVER_WORKS_BOT_TOKEN` |

- 필수 키 목록과 노드 키 목록은 `roles/funa_env/defaults/main.yml`에서 바꾼다.
- 경로가 없거나(404) 키가 빠지거나 값이 비면 **무엇이 빠졌는지 경로와 키 이름**을 대며 실패한다. 값은 출력하지 않는다.
- 시크릿 키(`proxy`·`vrrp` 경로)가 `cluster` 값에 같은 이름으로 있으면 비시크릿 파일로 새는 것이므로 실패한다.
- 값에 `${`로 시작하는 셸 참조(`${NAME}`, `${NAME:-default}` 등)가 들어 있으면 렌더링 전에 `경로: 키 contains a shell reference`로 실패한다(비시크릿·시크릿·노드별 값 모두, 값은 출력하지 않는다). 옛 `global_env.sh`에서 옮겨 온 참조 문자열이 그대로 Caddy와 알림 문구에 남는 사고(#225 카나리)를 막는다. `$NAME`과 값 중간·끝의 `$` 한 글자는 막지 않는다(비밀번호에 `$`가 들어갈 수 있다).
  - **근거(Compose 공식 문서 <https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/>)**: 보간은 따옴표 없는 값과 큰따옴표 값에만 적용되고, 작은따옴표 값은 그대로 둔다. 이 역할은 `$`가 든 값을 항상 작은따옴표로 감싸므로 `$NAME`은 문자 그대로 전달된다. 그래서 `${` 존재 여부만 판정한다. 값에 `${`가 있다는 것은 옛 참조가 옮겨졌다는 신호이지 정상 비밀번호가 아니다.
- 값에 개행·NUL·작은따옴표가 있거나 키 이름이 환경 변수 이름이 아니면 실패한다. 공백·`$`·`#` 등이 있는 값은 작은따옴표로 감싸(compose dotenv와 셸이 같게 읽도록) 쓴다.
- `COMPOSE_PROJECT_NAME`을 이 파일들에 넣지 않는다(ADR-0011).

### 인벤토리 설정

Semaphore Static 인벤토리에서 FUNA Cluster 호스트를 `servers`에 두면서 그룹 `funa_cluster`에도 넣는다(`docs/semaphore-setup.md`). 방화벽 규칙을 건드리지 않으려면 `firewall_unmanaged`에도 넣는다(`docs/security.md`).

---

## 2. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `FUNA-001` | `Look up the dockermgmt group` | `ansible.builtin.getent` | All | 조회 전용(`check_mode: false`) |
| `FUNA-002` | `Assert the dockermgmt group exists (docker_engine runs first)` | `ansible.builtin.assert` | All | 조회 전용. 그룹이 없으면 그룹 이름과 `docker_engine` 선행을 대며 실패(check 모드 제외) |
| `FUNA-003` | `Fetch OpenBao KV (hosts/<host>, clusters/funa, clusters/funa/proxy, clusters/funa/vrrp)` | `ansible.builtin.uri` | All | 조회 전용, 컨트롤러에서 호스트마다 실행, `no_log` |
| `FUNA-004` | `Assert OpenBao answered every FUNA lookup` | `ansible.builtin.assert` | All | 조회 전용. 200/404 외 응답이나 토큰 없음은 상태 코드만 대며 실패 |
| `FUNA-005` | `Build the environment files from the KV contents` | `ansible.builtin.set_fact` | All | 메모리 내 계산(`funa_env_resolve`), `no_log` |
| `FUNA-006` | `Assert the OpenBao values are complete and valid` | `ansible.builtin.assert` | All | 조회 전용. 빠진 경로·키와 셸 참조(`${`)가 든 키를 이름으로만 보고 |
| `FUNA-007` | `Ensure the environment directory exists` | `ansible.builtin.file` | All | `0755 root:root` 일치 시 `ok` |
| `FUNA-008` | `Render the non-secret environment file (cluster.env)` | `ansible.builtin.copy` | All | 내용·권한 비교 (`0644 root:root`) |
| `FUNA-009` | `Render the consumer secret environment files (proxy, vrrp)` | `ansible.builtin.copy` | All | 내용·권한 비교 (`0640 root:dockermgmt`), `no_log`·`diff: false` |
| `FUNA-010` | `Deploy the login shell loader (profile.d)` | `ansible.builtin.template` | All | 내용·권한 비교 (`funa-cluster.sh.j2`) |

> 이 역할은 OpenBao 조회 외에 `shell`/`command`를 쓰지 않는다. 값이 바뀌면 파일만 갱신하며 서비스를 재기동하지 않는다. compose는 다음 `up`에서 새 값을 읽는다.
