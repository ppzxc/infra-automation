# FUNA Cluster 환경 변수 관리: global_env 대체 표준 조사

- 질문: [#211](https://github.com/ppzxc/infra-automation/issues/211), 상위 map [#209](https://github.com/ppzxc/infra-automation/issues/209). 결정은 [#213](https://github.com/ppzxc/infra-automation/issues/213)(grilling)이 내린다. 이 문서는 근거만 모은다.
- 조사일: 2026-10-14
- 1차 출처
  - Docker Compose 문서: [Interpolation][dc-interp], [Environment variables precedence][dc-prec], [Set environment variables (`env_file`)][dc-set], [Pre-defined variables][dc-envvars], [Best practices][dc-best], [Secrets][dc-secrets], [Networking `extra_hosts`][dc-net] (Context7 `/websites/docker_compose` + 원문)
  - Docker Engine 문서: [Linux post-install (docker 그룹 경고)][de-post], [Security][de-sec], [journald logging driver][de-journald]
  - `systemd.exec(5)` (systemd 259 man page. Rocky 9의 systemd 252에서도 아래 인용 동작은 같다고 보지만 252 원문은 대조하지 않았다), `pam_env.conf(5)`, `bash(1)` INVOCATION
  - [The Twelve-Factor App: III. Config][12f]
  - OpenBao 문서: [Agent template][ob-tpl], [Process supervisor][ob-sup], [AppRole auto-auth][ob-approle] (Context7 `/websites/openbao`)
  - [getsops/sops][sops] (Context7 `/getsops/sops`)
  - Caddy 문서: [Caddyfile concepts — Environment variables][caddy-env]
  - 저장소: ADR-0002, `roles/monitoring`·`roles/backup`의 secrets env 렌더링, funa 저장소 `docker/prod/compose.yml`
- 실험: 로컬 Docker Engine 29.8.2 / Docker Compose v5.6.0(WSL2)에서 scratch 프로젝트로 `docker compose config`·`up`을 돌려 확인했다. 운영 3대의 compose 버전은 [#210](https://github.com/ppzxc/infra-automation/issues/210)에서 확인해야 한다(`env_file`의 `path`/`required` 긴 문법은 Compose 2.24.0 이상).

## 표기 규칙

| 태그 | 의미 |
|---|---|
| **출처** | 위 1차 출처에 문장으로 적힌 내용 |
| **실험** | 로컬에서 직접 돌려 확인한 동작 |
| **추론** | 출처와 실험에서 끌어낸 판단. 운영에서 관측한 것은 아니다 |
| **권고** | 이 조사의 제안. #213에서 뒤집을 수 있다 |

## 핵심 답변

1. **업계 표준은 "변수를 로그인 셸에 두지 않고, 소비자가 직접 읽는 파일로 둔다"이다.** compose는 프로젝트 `.env`·`--env-file`·`env_file:`을 스스로 읽는다(출처). systemd 서비스는 `EnvironmentFile=`로 읽는다(출처). `/etc/profile.d`와 `/etc/environment`는 로그인 세션 전용이라 Semaphore·systemd·cron에서 띄운 compose에는 닿지 않는다(출처). 지금 구조가 계정별 `global.env` 재매핑을 낳은 것도 이 때문이다(추론).
   - 호스트 조사(#210, 결과 미게시) 기준으로 현행 구조의 위험은 셸 의존보다 크다. 현행 공유 파일은 읽기 권한 범위가 넓고, 시크릿·비시크릿·셸 alias가 한 파일에 섞여 있다. 계정별 `global.env`(`VAR=${VAR}` 재매핑)는 `env_file:`로 인프라 컨테이너에 키 전체가 넘어간다. 즉 각 컨테이너가 자기에게 필요 없는 키까지 받는다. 앱 compose는 노드별 값만 셸 보간으로 쓴다. 대체안은 이 두 문제(넓은 노출, 컨테이너별 최소 권한 부재)를 먼저 풀어야 한다.
2. **비시크릿과 시크릿을 다른 파일·다른 권한으로 가른다.** 비시크릿 노드 값(노드 이름, 내부 호스트명/IP)은 compose를 돌리는 모든 계정이 읽을 수 있어야 한다. 그래서 `0640 root:dockermgmt`가 맞다. compose는 env 파일을 **호출한 사용자 권한으로** 읽기 때문이다(실험). 시크릿은 env 변수보다 **compose `secrets:` 파일 마운트**가 표준이다(Docker·systemd 둘 다 env 변수는 시크릿에 부적합하다고 적는다, 출처). 그리고 `secrets: file:`은 데몬이 bind mount하므로 **호출 계정이 못 읽는 `0600 root` 파일로도 동작한다**(실험). AGENTS.md의 "민감 파일 0600 이하" 규칙을 지키면서, 운영자가 compose를 직접 호출하는 방식을 유지한 채 여러 계정이 같은 프로젝트를 다룰 수 있는 방법은 이것뿐이다(추론). compose를 root가 띄우는 systemd 유닛으로 바꾸면(§4.3) 0600 env 파일도 가능해진다.
3. **값의 출처는 Ansible(Semaphore) 실행 시점에 정한다.** 노드별 값은 Ansible facts나 OpenBao의 호스트별 비시크릿 경로, 클러스터 공통 비시크릿은 role defaults, 시크릿은 OpenBao에서 읽어 렌더링한다. 저장소의 `roles/monitoring`(`/etc/otelcol-contrib/secrets.env`)과 `roles/backup`(`/etc/restic/env`)이 이미 이 방식이다. 저장소 `inventory/host_vars`·`group_vars`는 Semaphore 정적 인벤토리에 적용되지 않으므로 출처로 쓰면 안 된다(추론, PR #204 경험).
4. **compose 보간과 컨테이너 env는 다른 경로다.** `${FUNA_NODE_INTERNAL_HOSTNAME}` 같은 보간은 셸 → `--env-file` → 프로젝트 `.env` 순서로만 채워진다. `env_file:`은 보간에 쓰이지 않는다(출처, 실험). 반대로 logging driver의 `env` 옵션과 Caddyfile `{$VAR}`는 **컨테이너 안의** 환경을 본다(출처). 따라서 노드 값 하나가 두 경로 모두에 필요할 수 있다.
5. **권고 패턴**: Ansible이 노드 단위 비시크릿 파일 한 개(예: `/etc/funa-cluster/node.env`, `0640 root:dockermgmt`)만 소유한다. 컨테이너에는 `env_file:` 절대경로로, 보간에는 `--env-file` 두 개(노드 파일 → 앱 `.env`)로 넘긴다. 앱 `.env`·`funa.env`는 지금처럼 수동 관리한다. 시크릿은 `secrets:` 파일(`0600 root`)로 둔다. 대안 4개와 장단점은 아래 §4에 있다.

## 1. 지금 구조가 왜 깨지는가

| 사실 | 태그 | 근거 |
|---|---|---|
| `/etc/profile`(따라서 `/etc/profile.d/*.sh`)는 **대화형 로그인 셸이나 `--login`** 일 때만 읽힌다. 비대화형 셸(스크립트, `ssh host cmd`, Ansible `shell`)은 읽지 않고 `BASH_ENV`만 본다 | 출처 | `bash(1)` INVOCATION |
| `/etc/environment`·`/etc/security/pam_env.conf`는 `pam_env`가 **로그인할 때** 읽는다 | 출처 | `pam_env.conf(5)` "When someone logs in, this file is read" |
| systemd 시스템 서비스는 서비스 관리자의 환경을 기본으로 물려받지 않는다(`PassEnvironment=`로 명시해야 함) | 출처 | `systemd.exec(5)` PassEnvironment= |
| compose 보간 우선순위: ① 셸 환경 ② `--env-file` ③ (`--env-file`이 없을 때만) 프로젝트 디렉터리 `.env` | 출처 | [Interpolation][dc-interp] |
| 따라서 로그인 셸 env에 기대는 compose는 **누가, 어떤 셸로** 실행했느냐에 따라 값이 달라진다. 값이 없으면 경고 한 줄 뒤 빈 문자열로 보간된다(`${VAR:?}` 가드가 없으면) | 실험 | `The "APP_VERSION" variable is not set. Defaulting to a blank string.` |
| 현행 공유 파일은 읽기 권한 범위가 넓고 시크릿·비시크릿·셸 alias가 섞여 있다. 계정별 `global.env`는 값을 복사하지 않고 `VAR=${VAR}` 형태로 다시 가리킨다. `env_file:` 내용은 셸·`--env-file`·`.env`에서 보간되므로(§2.1 실험), 지금은 compose를 띄운 셸에 공유 파일이 source돼 있어야 값이 채워진다 | 호스트 조사(#210, 결과 미게시) + 실험 | 맵 #209 |
| 계정별 `global.env`는 인프라 compose의 `env_file:`이다. 파일의 모든 키가 각 컨테이너 env에 들어가므로, 한 컨테이너만 쓰는 값도 다른 인프라 컨테이너에서 `docker inspect`로 보인다 | 호스트 조사(결과 미게시) + 추론 | [dc-prec] |
| 민감 값이 0600보다 넓은 권한의 파일에 있으면 AGENTS.md §4.2 "민감 파일 0600 이하"에 어긋난다 | 추론 | AGENTS.md |
| 셸 환경이 최고 우선순위이므로, 이전 기간에 운영자 셸에 `global.env`가 계속 source되면 새 파일 값을 **조용히 덮는다** | 출처 + 실험 | `NODE_HOST=from-shell docker compose --env-file … config` → `hostname: from-shell` |

마지막 줄은 #213의 "구·신 방식 공존과 철거 순서"에 바로 걸린다. 새 파일로 바꾼 노드에서는 `global.env` source를 먼저 끊거나, 적어도 같은 키를 남기지 않아야 한다.

## 2. 메커니즘별 사실

### 2.1 Docker Compose

| 항목 | 내용 | 태그 |
|---|---|---|
| 프로젝트 `.env` | 프로젝트 디렉터리(`--project-directory` → 첫 `-f` 파일의 디렉터리 → `PWD`)의 `.env`를 보간과 Compose 자체 설정(`COMPOSE_*`)에 쓴다 | 출처 [dc-interp] |
| `.env`는 컨테이너로 가지 않는다 | `.env` 값은 compose 파일이 `${VAR}`로 참조할 때만 컨테이너에 들어간다 | 출처 [dc-interp] |
| `--env-file` 여러 개 | 순서대로 읽고 뒤 파일이 앞 파일을 덮는다. **`--env-file`을 하나라도 주면 프로젝트 `.env`는 자동으로 읽지 않는다** | 출처 + 실험 (`--env-file node.env`만 주면 `.env`의 `APP_VERSION` 누락) |
| `--env-file` 상대경로 | "relative to the current working directory" | 출처 |
| `COMPOSE_ENV_FILES` | `--env-file`이 없을 때 쓸 파일 목록(쉼표 구분). **셸에서 export하면 동작하지만, 프로젝트 `.env` 안에 적으면 무시된다** | 출처 [dc-envvars] + 실험 |
| `env_file:` 속성 | 컨테이너 env를 채운다. 여러 개면 순서대로 덮는다. `required: false`(2.24.0+), `format`(2.30.0+) | 출처 [dc-set] |
| `env_file:`과 보간 | `env_file:`의 값은 compose 파일 `${VAR}` 보간의 **출처가 아니다**. 반대로 `env_file:` **내용 안의** `${VAR}`는 셸 → `--env-file` → `.env` 순서로 보간된다. `X=${NODE_HOST}` 줄이 `--env-file`의 값으로 채워지고, 셸에 같은 키가 있으면 셸 값이 이긴다 | 실험 |
| `env_file:` 읽는 주체 | **compose CLI가 호출 사용자 권한으로** 읽는다. 못 읽으면 `permission denied`로 실패 | 실험 (`chmod 000` → `open …/node.env: permission denied`) |
| 컨테이너 env 우선순위 | `run -e` > 보간된 `environment`/`env_file` > `environment` > `env_file` > 이미지 `ENV` | 출처 [dc-prec] |
| 필수 변수 가드 | `${VAR:?error}`는 비었거나 없으면 오류로 중단, `${VAR:-default}`는 기본값 | 출처 [dc-interp] |
| 시크릿 | top-level `secrets:` + 서비스 `secrets:` → `/run/secrets/<name>`. 공식 이미지의 `*_FILE` 관례와 함께 쓴다 | 출처 [dc-secrets] |
| `secrets: file:` 읽는 주체 | 호출 사용자가 못 읽는 `chmod 000` 파일도 컨테이너 안 `/run/secrets/pw`에서 읽혔다. compose CLI가 내용을 읽지 않고 데몬이 bind mount한다 | 실험 (`alpine:3.22`, root 컨테이너) |
| 시크릿 권고 | "Be cautious about including sensitive data in environment variables" → Secrets 사용 | 출처 [dc-best] |
| `host-gateway` | `extra_hosts: ["host.docker.internal:host-gateway"]`. Linux에서는 기본 bridge의 호스트 IP | 출처 [dc-net] |

주의: `secrets: file:`은 bind mount이므로 원본 파일의 소유·권한이 그대로 보인다. 컨테이너 프로세스가 root가 아니면(예: ADR-0002의 `user: "998:2000"`) `0600 root` 파일은 컨테이너 안에서도 못 읽는다. 그 경우 소유자를 컨테이너 UID로 맞추거나 `0640 root:<컨테이너 GID>`로 둔다(추론). FUNA 컨테이너의 실행 UID는 #210에서 확인할 항목이다. 또 이 실험은 SELinux가 없는 WSL2에서 했다. Rocky 9는 기본이 enforcing이고, `daemon.json`에서 SELinux 지원을 켰다면 bind mount한 시크릿 파일에 라벨(`:z`/`:Z` 또는 `container_file_t`)이 필요할 수 있다. 운영 노드의 SELinux·daemon 설정(#210)으로 다시 확인해야 한다(미검증).

### 2.2 컨테이너 안에서 env를 보는 소비자

| 소비자 | 보는 곳 | 태그 |
|---|---|---|
| logging driver `env` 옵션 (journald·fluentd 공통) | "if these variables are specified **for the container**". 즉 컨테이너 env. 보간 변수만으로는 안 된다 | 출처 [de-journald] |
| Caddyfile `{$VAR}` | Caddy 프로세스 env를 **Caddyfile 파싱 전에** 치환. `{env.VAR}`는 런타임 치환(지원 필드 한정) | 출처 [caddy-env] |
| 앱(Spring, OTel Java agent) | 컨테이너 env | 추론 |

funa `docker/prod/compose.yml`은 `logging.options.env: "SERVICE_NAME,FUNA_NODE_NAME,FUNA_NODE_EXTERNAL_HOSTNAME,FUNA_NODE_INTERNAL_HOSTNAME"`을 쓴다. 그런데 `environment:`에는 이 키들이 없고 저장소의 `funa.env`는 빈 파일이다. 운영 서버의 `funa.env`에 이 키가 들어 있는지, 아니면 로그에 실제로 안 붙고 있는지는 #210에서 확인해야 한다(추론).

### 2.3 systemd

| 항목 | 내용 | 태그 |
|---|---|---|
| `EnvironmentFile=` | 절대경로, `KEY=VALUE` 줄 단위, `#`/`;` 주석, `-` 접두사면 없어도 무시. 프로세스 실행 직전에 서비스 관리자(root)가 읽는다. `Environment=`보다 우선 | 출처 `systemd.exec(5)` |
| env와 시크릿 | "environment variables are not suitable for passing secrets … exposed to unprivileged clients via D-Bus IPC … propagated down the process tree". `LoadCredential=`을 쓰라고 한다 | 출처 `systemd.exec(5)` |
| `LoadCredential=` | 파일을 `$CREDENTIALS_DIRECTORY`에 읽기 전용으로 노출. 유닛 사용자와 root만 접근 | 출처 `systemd.exec(5)` |

compose는 `docker compose`라는 단발성 CLI이므로 systemd 유닛의 `EnvironmentFile=`은 **compose 프로젝트를 systemd 유닛으로 띄울 때만** 의미가 있다(`ExecStart=docker compose up -d`, `Type=oneshot`, `RemainAfterExit=yes` 형태. 추론). 이 경우 EnvironmentFile은 root가 읽으므로 `0600 root`여도 된다. 다만 유닛 env는 compose 보간의 "셸 환경"으로 들어가 최고 우선순위가 된다.

### 2.4 12-factor

- "An app's config is everything that is likely to vary between deploys" — 노드 이름·내부 호스트명은 정의상 config다(출처 [12f]).
- 판별 기준: "whether the codebase could be made open source at any moment, without compromising any credentials" → 시크릿은 Git 밖(출처). AGENTS.md §4와 같은 결론.
- "env vars are granular controls … never grouped together as 'environments'" → `global_env`처럼 "운영 환경 묶음" 하나를 만들기보다 소비자별로 필요한 키만 넘기라는 뜻(출처, 해석은 추론).
- 12-factor는 "env로 주입하라"까지만 말하고 파일 위치·권한·시크릿 분리는 다루지 않는다. 시크릿에 env를 쓰지 말라는 Docker·systemd 문서가 더 최근의 1차 출처다(추론).

### 2.5 OpenBao Agent

| 항목 | 내용 | 태그 |
|---|---|---|
| file template 모드 | `template { source/contents, destination, perms, exec { command = [...] } }`. 결과가 바뀔 때만 `exec`. `perms` 미지정 시 기존 파일 권한을 따르고 없으면 `0644`. 문서상 `user`/`group` 파라미터는 없다(에이전트 실행 계정이 소유) | 출처 [ob-tpl] |
| 누락 키 | `error_on_missing_key = true` + `template_config.exit_on_retry_failure = true` 둘 다 켜야 누락 시 종료 | 출처 [ob-tpl] |
| process supervisor 모드 | `env_template` + **단 하나의** `exec`. 자식 프로세스 env에 시크릿 주입, 바뀌면 재시작. **file `template`과 함께 쓸 수 없다** | 출처 [ob-sup] |
| 인증 | AppRole auto-auth: `role_id_file_path`, `secret_id_file_path`를 호스트에 둔다 | 출처 [ob-approle] |

평가(추론): Agent는 시크릿이 자주 바뀌거나(동적 시크릿, 짧은 TTL) Ansible 재실행 없이 회전을 반영해야 할 때 맞다. FUNA 쪽은 정적 값이 대부분이다. Agent를 넣으면 노드마다 상주 데몬 하나와 **호스트에 상시 저장되는 AppRole secret_id**가 늘어난다. process supervisor는 `docker compose`(단발 CLI)를 감싸는 데 맞지 않는다. 그래서 기본안이 아니라 "시크릿 회전 요구가 생기면" 대안이다.

### 2.6 sops

- "an editor of encrypted files". dotenv(ENV)·YAML·JSON·INI·BINARY 지원, age·PGP·클라우드 KMS, `--hc-vault-transit` 플래그 존재(출처 [sops]).
- `sops exec-env <file> <cmd>`: 복호화한 값을 env로 넣고 명령 실행(출처).
- OpenBao transit과의 호환은 문서로 확인하지 못했다(Vault API 호환이라 될 가능성은 있으나 **미검증**).
- 평가(추론): 시크릿 원본이 OpenBao로 이미 정해져 있다. sops는 "암호문을 Git에 둔다"는 두 번째 원천을 만든다. 저장소에 시크릿을 커밋하지 않는다는 AGENTS.md 원칙과도 결이 다르다. 채택 이유가 없다.

### 2.7 저장소의 기존 패턴

| 위치 | 하는 일 | 태그 |
|---|---|---|
| `roles/monitoring/tasks/main.yml` `[MON-…]` | OpenBao에서 읽은 `host_agents_secrets`로 `secrets.env.j2`를 렌더링해 `/etc/otelcol-contrib/secrets.env`(`0600 root:root`, `no_log`, `diff: false`), `notify: Restart otelcol-contrib`. 유닛은 `EnvironmentFile=` | 저장소 |
| `roles/backup` | 같은 방식으로 `/etc/restic/env`, 유닛 `EnvironmentFile=` | 저장소 |
| ADR-0002 §2.2 | `/opt/services/<app>/.env` "시크릿 환경변수 (권한: 600)" | 저장소 |

ADR-0002의 `.env 0600`은 **소유자가 곧 compose 호출자일 때만** 성립한다. FUNA는 `application`·`infrastructure`·`ppzxc`가 같은 프로젝트를 다룰 수 있으므로, `.env`에 시크릿을 두는 한 0600과 다중 운영자가 충돌한다(실험으로 확인한 CLI 읽기 권한 동작에서 나온 추론). §3 권고가 시크릿을 `.env`에서 빼는 이유다.

## 3. 평가 기준별 비교

| 방식 | 시크릿/비시크릿 분리 | 권한 모델 | Ansible 관리 | 로그인 셸 의존 제거 | 노드별 값 | 비고 |
|---|---|---|---|---|---|---|
| 현행 `/etc/profile.d/global_env.sh` + 계정별 `global.env` | 없음 | 넓은 읽기 범위, 키 전체가 인프라 컨테이너 env로 | 수동 | 안 됨 | 가능 | 셸 env가 최고 우선순위라 디버깅이 어렵다 |
| `/etc/environment`(pam_env) | 없음 | 보통 world-readable | 쉬움 | 안 됨(로그인 세션 전용) | 가능 | 시크릿 불가, 서비스·cron·Semaphore에 안 닿음 |
| 프로젝트 `.env`(compose 기본) | `.env` 하나에 섞이기 쉽다 | 호출자가 읽어야 함 | Ansible이 통째로 쓰면 수동 관리 영역과 겹침 | **됨** | 가능 | compose 표준 경로. 플래그 불필요 |
| **노드 파일 + `--env-file` 2개 + `env_file:`** | 됨(노드 파일은 비시크릿 전용) | `0640 root:dockermgmt` | Ansible이 파일 하나만 소유 | **됨**(호출 방식 고정 필요) | 자연스러움 | §4 권고안 |
| 프로젝트 `.env`에 `blockinfile` 관리 블록 | 됨(블록은 비시크릿만) | 호출자가 읽어야 함 | 블록만 관리, 나머지는 수동 | **됨**, 호출 방식 변화 없음 | 가능 | 한 파일 두 주인 |
| compose 프로젝트를 systemd 유닛으로 + `EnvironmentFile=` | 파일 분리 가능 | root가 읽으므로 0600 가능 | 쉬움(유닛·파일 모두 템플릿) | **됨** | 가능 | 수동 `docker compose up`과 경로가 갈라짐 |
| compose `secrets:` 파일 | 시크릿 전용 | `0600 root`로도 동작 | Ansible 템플릿 | 해당 없음 | 가능 | 이미지가 `*_FILE`이나 파일 읽기를 지원해야 함 |
| OpenBao Agent template | 시크릿 전용 | `perms` 지정, 소유자는 에이전트 계정 | Agent 설치·AppRole 배포 필요 | 해당 없음 | 가능 | 회전 자동, 상주 데몬·상시 자격증명 증가 |
| sops | 시크릿 전용 | 복호화 키 배포 필요 | `community.sops` 등 추가 | 해당 없음 | 가능 | 시크릿 원천 이중화 |

## 4. 권고 패턴과 대안

### 4.1 권고안: Ansible 소유 노드 파일 1개 + 앱 파일 수동 유지 + 시크릿은 파일 마운트

```text
/etc/funa-cluster/node.env           # Ansible 소유, 비시크릿만, 0640 root:dockermgmt
/opt/services/funa/compose.yml       # 수동 (ADR-0002 경로)
/opt/services/funa/.env              # 수동, 비시크릿 (APPLICATION_VERSION 등), 0640 root:dockermgmt 또는 0664 + SGID 상속
/opt/services/funa/funa.env          # 수동, 컨테이너 env (비시크릿)
/opt/services/funa/secrets/<name>    # 시크릿 1개당 파일 1개, 0600 root (컨테이너 UID에 맞춤)
/opt/services/caddy/…                # 같은 구조
```

1. **노드 파일(권고)**: Ansible이 `ansible.builtin.template`으로 `/etc/funa-cluster/node.env`를 렌더링한다. 값의 출처:
   - 노드별(이름, 내부 호스트명/IP): Ansible facts(`ansible_facts.hostname`, `ansible_facts.default_ipv4`) 또는 OpenBao의 호스트별 비시크릿 경로. 이미 #203에서 tcpcheck 대상을 OpenBao에서 직접 읽은 전례가 있다.
   - 클러스터 공통 비시크릿: role defaults(필요하면 Semaphore 인벤토리 그룹 `funa_cluster`로 범위 지정).
   - 저장소 `inventory/host_vars`·`group_vars`는 Semaphore에 적용되지 않으므로 쓰지 않는다.
   - 경로를 `/opt/services` 밖(`/etc`)에 두는 이유: "Ansible이 쓰는 파일"과 "사람이 고치는 앱 설정"의 주인을 디렉터리 단위로 가른다. `/opt/services/<app>`은 수동 관리로 남는다(맵 결정). 경로 이름은 #213에서 정한다.
2. **컨테이너 env**: 각 compose의 서비스에 `env_file:`로 절대경로를 건다. logging driver `env` 옵션과 Caddyfile `{$VAR}`가 이 값을 본다.
   ```yaml
   env_file:
     - path: /etc/funa-cluster/node.env
       required: true
     - path: funa.env
   ```
3. **보간**: compose가 노드 파일과 앱 `.env`를 둘 다 보간에 쓰도록 **호출을 고정**한다. 뒤 파일이 이긴다.
   ```sh
   docker compose --env-file /etc/funa-cluster/node.env --env-file .env up -d
   ```
   - `--env-file`을 주면 `.env` 자동 로드가 꺼지므로 `.env`도 명시해야 한다(실험).
   - 호출 방식을 고정하는 수단은 런북 명령, 짧은 래퍼 스크립트, 또는 4.3의 systemd 유닛 중 하나다. 셸에 `COMPOSE_ENV_FILES`를 export하는 방법도 동작하지만 다시 로그인 셸에 기대므로 권하지 않는다. `.env` 안의 `COMPOSE_ENV_FILES`는 무시된다(실험).
   - compose 파일의 노드 값 참조는 `${FUNA_NODE_INTERNAL_HOSTNAME:?node.env 누락}`으로 바꿔, 빠뜨리면 빈 문자열로 뜨지 말고 실패하게 한다.
4. **보간 자체를 줄인다(선택)**: Host Agents otelcol이 같은 호스트에 있으므로 `OTEL_EXPORTER_OTLP_*_ENDPOINT=http://${FUNA_NODE_INTERNAL_HOSTNAME}:<OTLP 포트>`은 `extra_hosts: ["host.docker.internal:host-gateway"]` + `http://host.docker.internal:<OTLP 포트>`로 바꿀 수 있다. 노드 값을 몰라도 되는 compose가 된다. 단 `host-gateway`는 기본 bridge의 호스트 IP로 풀린다. otelcol의 수신 주소와 방화벽(이 맵은 방화벽을 건드리지 않는다)에서 `backend` 네트워크 → 그 IP가 열려 있는지 확인해야 한다(추론, 미검증). 이 항목과 logging driver 전환(fluentd → journald)은 funa 저장소 쪽 변경이다.
5. **시크릿**: 컨테이너마다 자기가 쓰는 시크릿만 받는다(지금은 공유 파일 하나의 키 전체가 인프라 컨테이너마다 들어간다). 노드 파일은 비시크릿 전용이라 모든 컨테이너에 걸어도 된다. 시크릿은 env 변수로 넘기지 않는다. 이미지가 `*_FILE`이나 설정 파일 경로를 지원하면 compose `secrets:`로 `/run/secrets/<name>`에 마운트한다. 원본은 `0600 root`(컨테이너 UID가 root가 아니면 그 UID 소유). compose 호출자가 못 읽어도 동작한다(실험). Ansible이 OpenBao에서 읽어 렌더링할지, 앱 설정처럼 수동으로 둘지는 "앱 설정은 수동" 결정과 함께 #213에서 정한다. Ansible이 맡는다면 `roles/monitoring`의 `secrets.env` 태스크(`no_log: true`, `diff: false`, `mode: '0600'`)를 그대로 따른다.
   - 꼭 env로 넘겨야 하는 시크릿이 있으면 `env_file:` 대상 파일이 되고, 그 파일은 호출자가 읽어야 한다. 이때는 0600 규칙과 다중 운영자가 충돌한다. 해결은 (a) 프로젝트별로 호출 계정을 하나로 정하고 그 계정 소유 0600, (b) 4.3의 systemd 유닛으로 root가 띄우기 둘 중 하나다.
6. **권한 근거**: `docker` 그룹은 "root-level privileges"를 준다(출처 [de-post]). compose를 돌릴 수 있는 계정은 `docker inspect`로 컨테이너 env를 볼 수 있다. 그러므로 파일 권한이 막는 상대는 **docker 그룹이 아닌 계정**이다. 비시크릿 노드 파일을 `0640 root:dockermgmt`로 두는 것은 이 기준에서 충분하다. 시크릿을 env가 아니라 파일 마운트로 두면 `docker inspect`에도 드러나지 않는다(추론).

### 4.2 대안 A: 프로젝트 `.env`에 Ansible 관리 블록

`ansible.builtin.blockinfile`로 `/opt/services/funa/.env`·`/opt/services/caddy/.env` 안에 `# BEGIN/END ANSIBLE MANAGED node identity` 블록을 쓴다.

- 장점: compose 호출이 지금과 같은 `docker compose up -d`로 남는다. 운영자가 플래그를 잊을 일이 없다.
- 단점: 한 파일에 주인이 둘이다. 수동 편집이 블록을 건드리면 다음 실행에 덮인다. 앱마다 같은 값이 복제된다. 컨테이너 env 경로(logging `env`, Caddy `{$VAR}`)는 별도로 `environment:`에 `KEY: ${KEY}`를 나열해야 한다.
- 선택 조건: 운영자 호출 습관을 바꾸기 어렵고 앱이 2개(funa, caddy)뿐이라 복제 비용이 작을 때.

### 4.3 대안 B: compose 프로젝트를 systemd 유닛으로

`/etc/systemd/system/funa-app.service`에 `WorkingDirectory=/opt/services/funa`, `EnvironmentFile=/etc/funa-cluster/node.env`, `EnvironmentFile=-/etc/funa-cluster/secrets.env`, `ExecStart=/usr/bin/docker compose up -d`, `ExecStop=/usr/bin/docker compose down`.

- 장점: 로그인 셸 의존이 완전히 사라진다. EnvironmentFile은 root가 읽으므로 0600 시크릿 env도 가능하다. 재부팅 순서(`After=docker.service`)도 명시된다. Ansible로 유닛·파일을 템플릿화하기 쉽다.
- 단점: 운영자가 수동으로 `docker compose up`을 치면 유닛 env가 없는 다른 결과가 나온다. 유닛 env는 보간에서 셸과 같은 최고 우선순위다. systemd 문서 스스로 env는 시크릿에 부적합하다고 적는다. 노드 배출·카나리 절차(keepalived VIP 이양)와 유닛 시작/정지의 관계를 새로 정해야 한다.
- 선택 조건: compose 실행을 사람 손에서 떼어 내고 싶을 때. 맵의 "앱 설정은 수동" 방침과는 거리가 있다.

### 4.4 대안 C: OpenBao Agent로 시크릿 파일 렌더링

노드마다 `bao agent`(AppRole auto-auth) + `template { destination = "/opt/services/funa/secrets/db", perms = "0600" … }`.

- 장점: 시크릿 회전이 Ansible 실행 없이 반영된다. `exec`로 재시작까지 묶을 수 있다.
- 단점: 상주 데몬 + 노드마다 AppRole secret_id 파일. `perms`만 있고 소유자는 에이전트 계정. process supervisor 모드는 file template과 같이 못 쓰고 단일 프로세스를 감싸는 모델이라 compose와 맞지 않는다. 현재 저장소에는 Agent 운영 선례가 없다.
- 선택 조건: 동적 시크릿(짧은 TTL DB 계정 등)을 쓰기 시작할 때.

### 4.5 쓰지 않을 것

- `/etc/environment`·`/etc/profile.d`: 로그인 세션 전용이라 문제의 원인 그대로다. 시크릿을 둘 수도 없다.
- sops: 시크릿 원천이 OpenBao와 Git 암호문 둘로 나뉜다. OpenBao transit 호환도 미검증.

## 5. 변수 분류 규칙 (#210 결과에 적용)

`global_env.sh`의 전체 변수 목록은 #210이 아직 수집 중이다. 지금 보이는 이름은 funa compose가 참조하는 `FUNA_NODE_NAME`, `FUNA_NODE_INTERNAL_HOSTNAME`, `FUNA_NODE_EXTERNAL_HOSTNAME`, `SERVICE_NAME`, `CONTAINER_HOSTNAME`뿐이다(값 미확인). 목록이 나오면 변수마다 아래 순서로 판정한다.

| 질문 | 예 → 위치 |
|---|---|
| 노출되면 피해가 나는 값인가(비밀번호, 토큰, 키) | OpenBao. 호스트에는 `secrets:` 파일(0600) |
| 노드마다 다른 비시크릿인가(이름, 내부/외부 호스트명, IP) | Ansible 노드 파일. 출처는 facts 또는 OpenBao의 호스트별 비시크릿 경로 |
| 3대가 같은 비시크릿인가(VIP, 클러스터 이름, 공통 엔드포인트) | Ansible 노드 파일. 출처는 role defaults |
| 앱 릴리스와 함께 바뀌는가(버전, JAR 이름) | 앱 `.env`(수동, funa 저장소 `docker/prod/.env`와 같은 키) |
| 실제 소비처가 없는가 | 삭제 |

그리고 각 변수의 **소비 경로**(compose 보간 / 컨테이너 env / 둘 다 / 셸 스크립트·cron)를 함께 적어야 §4.1의 2·3번 중 어디에 걸지 정해진다.

## 6. #213에 넘기는 열린 질문

1. 노드 파일 경로와 이름(`/etc/funa-cluster/node.env` 제안), 소유 그룹 `dockermgmt`로 확정할지.
2. 보간 경로: `--env-file` 2개 고정(권고) / 대안 A `blockinfile` / 대안 B systemd 유닛 중 무엇. 호출을 무엇으로 고정할지(런북 명령, 래퍼, 유닛).
3. 시크릿을 Ansible이 OpenBao에서 렌더링할지, 앱 설정처럼 수동으로 둘지. 그리고 FUNA·Caddy 이미지가 파일 기반 시크릿을 받는지.
4. ADR-0002의 "`.env` = 시크릿, 0600" 문구를 "`.env` = 비시크릿 보간 값, 시크릿은 `secrets/`"로 고칠지(이 맵의 ADR 개정 범위와 함께).
5. 이전 순서: `env_file:` 내용이 `--env-file`에서도 보간되므로(§2.1 실험), 기존 `global.env`(`VAR=${VAR}`)는 노드 파일을 `--env-file`로 넘기는 순간 셸 없이도 채워진다. 이것을 과도기 다리로 쓸 수 있다. 다만 셸에 같은 키가 남아 있으면 셸 값이 이긴다. 순서 제안: 노드 파일 배포 → compose 파일의 `:?` 가드와 `env_file:` 반영 → 운영자 셸에서 `global.env` source 제거(셸 env가 최우선이라 남아 있으면 새 값을 덮는다) → `global_env.sh` 철거. 카나리 노드(ns0338)에서 `docker compose --env-file … config --environment`로 해석 결과를 비교한 뒤 진행.
6. OTLP 엔드포인트를 `host-gateway`로 바꿔 노드 값 의존을 없앨지(funa 저장소 변경, otelcol 수신 주소·방화벽 확인 필요).

[dc-interp]: https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/
[dc-prec]: https://docs.docker.com/compose/how-tos/environment-variables/envvars-precedence/
[dc-set]: https://docs.docker.com/compose/how-tos/environment-variables/set-environment-variables/
[dc-envvars]: https://docs.docker.com/compose/how-tos/environment-variables/envvars/
[dc-best]: https://docs.docker.com/compose/how-tos/environment-variables/best-practices/
[dc-secrets]: https://docs.docker.com/compose/how-tos/use-secrets/
[dc-net]: https://docs.docker.com/compose/how-tos/networking/
[de-post]: https://docs.docker.com/engine/install/linux-postinstall/
[de-sec]: https://docs.docker.com/engine/security/
[de-journald]: https://docs.docker.com/engine/logging/drivers/journald/
[12f]: https://12factor.net/config
[ob-tpl]: https://openbao.org/docs/agent-and-proxy/agent/template
[ob-sup]: https://openbao.org/docs/agent-and-proxy/agent/process-supervisor
[ob-approle]: https://openbao.org/docs/agent-and-proxy/autoauth/methods/approle
[sops]: https://github.com/getsops/sops
[caddy-env]: https://caddyserver.com/docs/caddyfile/concepts#environment-variables
