# FUNA Env Role Task Specification

`funa_env` 역할은 FUNA Cluster(ns0325·ns0327·ns0338, `CONTEXT.md`)의 환경 값을 **Ansible이 OpenBao에서 읽어 노드 파일로 렌더링**한다. 예전의 누구나 읽을 수 있는 전역 환경 파일(`global_env.sh`)과 계정마다 다시 매핑한 사본을 대체한다. 결정의 근거는 #213(global_env 대체 방식), 구현 단위는 #222다.

---

## 1. 개요 (What)

- **적용 대상**: 인벤토리 그룹 **`funa_cluster`** 소속 호스트. 그룹에 속하지 않은 호스트에는 아무것도 만들지 않는다(`funa_env_enabled`는 그룹 소속에서 파생한다. Semaphore 인벤토리는 static이라 group_vars를 쓰지 않는다).
- **실행 위치**: `playbooks/site.yml`(HOST PROVISIONING)에서 `docker_engine` **바로 뒤**. `dockermgmt` 그룹(DOC-014)이 있는 상태에서 렌더링되고, 그룹이 없으면 그 이름을 대며 실패한다(check 모드는 파일 단계를 건너뛴다).
- **역할 분리 이유**: 새 역할로 두었다. 값의 원천(OpenBao 문서 5개)·대상 그룹·실행 시점(docker_engine 뒤)이 `common`/`docker_engine`과 다르고, 단일 책임(SRP)을 지켜 그룹 하나로 켜고 끈다. 기존 역할의 선택 기능으로 넣으면 모든 호스트가 이 입력 변수를 안고 다니게 된다.

### 렌더링 결과

| 파일 | 소유·권한 | 내용 | 읽는 쪽 |
|---|---|---|---|
| `/etc/funa-cluster/cluster.env` | `0644 root:root` | 비시크릿: 노드별 값 + 클러스터 공통 값 | 모든 서비스 `env_file:`, `--env-file` 보간 |
| `/etc/funa-cluster/proxy.secrets.env` | `0640 root:dockermgmt` | Caddy 시크릿만 | proxy 서비스만 |
| `/etc/funa-cluster/vrrp.secrets.env` | `0640 root:dockermgmt` | keepalived 시크릿만 | vrrp 서비스만 |
| `/etc/profile.d/funa-cluster.sh` | `0644 root:root` | 읽을 수 있는 위 파일만 `set -a`로 불러오는 로더(운영 alias 없음, `common`의 `99-aliases.sh`가 이미 배포) | 로그인 셸 |

시크릿 파일의 `0640 root:dockermgmt`는 AGENTS.md의 0600 규칙 예외다(근거는 AGENTS.md §4).

### 값의 원천 (OpenBao, 값은 Git에 두지 않는다)

문서 경로·네임스페이스(`infra`)·인증은 공용 읽기 지점(`lookup('openbao_doc', ...)`, [openbao_integration.md](openbao_integration.md))이 정한다. 읽는 문서와 필수 키는 `roles/funa_env/vars/main.yml`의 `funa_env_openbao_required`가 선언한다. 저장 키는 snake_case이고(`FUNA_` 접두사를 떼고 소문자: `FUNA_NODE_NAME`→`node_name`, `DB_PASSWORD`→`db_password`, `TZ`→`tz`) 렌더링 때 같은 파일의 `funa_env_key_map` 대응표가 컨테이너 env 이름으로 바꾼다. 이 문서와 저장소에는 값이 없다.

| 문서 | 렌더링 위치 | 필수 키 (없으면 실패) |
|---|---|---|
| `inventory/assets/<Inventory Hostname>`의 `funa` 절 | `cluster.env` | `node_external_hostname`, `node_external_wildcard_hostname`, `notification_header`, `node_name`(funa 로그의 `service.node.name`, 값은 인벤토리 호스트명) |
| `inventory/services/funa` | `cluster.env` | `floating_hostname`, `health_check_uri`, `service_name`, `notification_smtp_{from,host,port,to,username}`, `notification_naver_works_bot_url`, `tz` |
| `secrets/services/funa/proxy` | `proxy.secrets.env` | `admin_token`, `db_password` |
| `secrets/services/funa/vrrp` | `vrrp.secrets.env` | `notification_smtp_password`, `notification_naver_works_bot_token` |
| `secrets/assets/<Inventory Hostname>/credentials/cloudflare` | `proxy.secrets.env`(`CLOUDFLARE_API_TOKEN`) | `token`(노드마다 값이 다르다. Cloudflare는 Service가 아니라 노드 Asset의 Credential이다) |

- 대응표에 없는 저장 키(스키마에도 없다)는 렌더링 전에 키 이름을 대며 실패한다. 대응표와 스키마(`schemas/openbao`)가 같은 키 집합인지, 선언한 필수 키가 스키마 `required`와 같은지는 `tests/test_funa_env.py`가 정적으로 검사한다.
- 문서가 없거나(404) 접근이 거부되면 대체값 없이 문서 경로와 상태 코드만 대며 실패한다. 키가 빠지거나 값이 비면 문서 패턴과 키 이름을 대며 실패한다. 값은 출력하지 않는다.
- 시크릿 키(`proxy`·`vrrp`)가 `cluster` 값에 같은 이름으로 있으면 비시크릿 파일로 새는 것이므로 실패한다.
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
| `FUNA-003` | `Read the OpenBao documents declared in funa_env_openbao_required` | `ansible.builtin.set_fact` | All | 조회 전용(`lookup openbao_doc`, 컨트롤러, `check_mode: false`), `no_log`. 문서가 없거나 403이면 경로와 상태 코드만 대며 실패 |
| `FUNA-005` | `Build the environment files from the OpenBao documents` | `ansible.builtin.set_fact` | All | 메모리 내 계산(`funa_env_resolve`, 대응표로 env 이름 변환), `no_log` |
| `FUNA-006` | `Assert the OpenBao values are complete and valid` | `ansible.builtin.assert` | All | 조회 전용. funa 절의 빠진 키, 대응표에 없는 키, 셸 참조(`${`)가 든 키를 이름으로만 보고 |
| `FUNA-007` | `Ensure the environment directory exists` | `ansible.builtin.file` | All | `0755 root:root` 일치 시 `ok` |
| `FUNA-008` | `Render the non-secret environment file (cluster.env)` | `ansible.builtin.copy` | All | 내용·권한 비교 (`0644 root:root`) |
| `FUNA-009` | `Render the consumer secret environment files (proxy, vrrp)` | `ansible.builtin.copy` | All | 내용·권한 비교 (`0640 root:dockermgmt`), `no_log`·`diff: false` |
| `FUNA-010` | `Deploy the login shell loader (profile.d)` | `ansible.builtin.template` | All | 내용·권한 비교 (`funa-cluster.sh.j2`) |
| `FUNA-011` | `Look up the keepalived config directory` | `ansible.builtin.stat` | All | 조회 전용(`check_mode: false`) |
| `FUNA-012` | `Keep the keepalived config directory root-only (script security)` | `ansible.builtin.file` | All | `0755 root:root` 일치 시 `ok`. 디렉터리가 없으면 건너뛴다(만들지 않는다) |
| `FUNA-013` | `Find the keepalived scripts and config files` | `ansible.builtin.find` | All | 조회 전용(`check_mode: false`), `*.sh`·`*.conf`만 |
| `FUNA-014` | `Keep the keepalived scripts and config files root-owned and not writable` | `ansible.builtin.file` | All | 스크립트 `0755`, 설정 `0644`, `root:root` 일치 시 `ok` |
| `FUNA-015` | `Deploy the unit that starts the keepalived container after boot` | `ansible.builtin.template` | All | 내용·권한 비교 (`funa-vrrp-ensure.service.j2`, `0644 root:root`). `docker.service` 뒤에 한 번 실행하고, 컨테이너가 있는데 안 떠 있을 때만 `docker start`(없거나 떠 있으면 아무것도 하지 않는다) |
| `FUNA-016` | `Enable the keepalived start-after-boot unit` | `ansible.builtin.systemd` | All | `enabled: true`(`daemon_reload`). 서비스를 지금 시작하지 않는다. `funa_env_systemd_manage: false`이면 건너뜀(테스트용). 체크 모드에서 `FUNA-015`가 `changed`이면 건너뜀(파일이 아직 없으면 systemd가 서비스를 찾지 못해 실패하기 때문. 내용만 바뀌는 경우에도 건너뛰므로 그때의 enable 여부는 체크에서 보이지 않는다) |
| `FUNA-017` | `Assert every declared document holds its required keys` | `ansible.builtin.assert` | All | 조회 전용. `funa_env_openbao_required` 선언을 돌며 없거나 빈 필수 키를 패턴과 키 이름으로만 보고 |

> 이 역할은 OpenBao 조회 외에 `shell`/`command`를 쓰지 않는다(`FUNA-015`의 유닛 안 `ExecStart`는 부팅 때 systemd가 실행하는 것이고 이 역할의 태스크가 아니다). 값이 바뀌면 파일만 갱신하며 서비스를 재기동하지 않는다. compose는 다음 `up`에서 새 값을 읽는다.

### 재부팅 뒤 keepalived 기동 보장 (#443)

FUNA 노드를 재부팅하면 `network_mode: host`인 keepalived 컨테이너가 `Exited (255)`로 남고 자동으로 올라오지 않았다(2026-11-06, 3대 모두). `restart` 정책은 원인이 아니었다(같은 `unless-stopped`인 caddy·funa-api는 올라왔다). dockerd가 `live-restore`로 시작하면서 이 컨테이너를 다시 띄우지 않았고, 부팅 로그에 기동 시도 자체가 없었다.

- `funa-vrrp-ensure.service`(`FUNA-015`·`FUNA-016`)는 `docker.service` 뒤에 한 번 실행한다. 컨테이너(`funa_env_vrrp_container`, 기본 `vrrp-keepalived-1`)가 없으면 넘어가고, 있는데 안 떠 있을 때만 `docker start`한다.
- `PartOf=docker.service`와 `RemainAfterExit=yes`라서 `systemctl restart docker`로 dockerd가 다시 시작되면 이 유닛도 다시 실행된다(그 사이 죽은 컨테이너를 되살린다). `stop`과 `start`를 따로 하면 이 유닛은 정지된 채 남는다.
- 운영자가 일부러 멈춰 둔 keepalived도 **재부팅과 `systemctl restart docker`(패키지 업그레이드 포함) 때 시작된다**(`unless-stopped`와 다르다). 점검하려고 멈춰 둔 채 dockerd를 재시작하면 되살아나므로 유의하고, 계속 멈춰 두려면 이 유닛을 비활성화한다.
- 이 유닛은 부팅과 dockerd 재시작 때만 동작한다. 컨테이너가 나중에 따로 죽는 것은 막지 않는다. 감시는 호스트에 이미 있는 root cron이 맡는다(컨테이너가 `Running`일 때만 Kuma push 모니터에 신호를 보내므로 멈추면 push가 끊겨 알림이 난다). 이 cron은 이 저장소가 배포하지 않는다.
- 확인: 재부팅 뒤 `docker ps`에 `vrrp-keepalived-1`이 `Up`이고 VIP가 자기 노드에 돌아와 있어야 한다.
