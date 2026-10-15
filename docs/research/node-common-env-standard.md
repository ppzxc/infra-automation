# 노드 공통 환경 변수: 업계 표준과 `98-node-env.sh`에 더할 후보 조사

- 질문: 일반 노드가 로그인 셸·systemd·컨테이너에 기본으로 갖는 공통 환경 변수의 업계 표준은 무엇인가. `roles/common`의 `98-node-env.sh`(템플릿 `roles/common/templates/node-env.sh.j2`, 문서 `docs/common.md`)가 배포하는 `NODE_*` 11개(`NODE_NAME`, `NODE_HOSTNAME`, `NODE_INTERNAL_HOSTNAME`, `NODE_WILDCARD_HOSTNAME`, `NODE_PRIMARY_IPV4`, `NODE_INTERFACE`, `NODE_GATEWAY`, `NODE_ENV`, `NODE_IDC`, `NODE_ROLE`, `NODE_ADMIN_USER`)에 더할 만한 변수(`TZ`, `LANG`/`LC_*`, 프록시, 환경/리전 식별자 등)가 있는가. 이슈 [#233](https://github.com/ppzxc/infra-automation/issues/233)의 열린 질문 2·3을 판단할 근거를 모으는 것이 목적이다. **결정은 하지 않는다.**
- 조사일: 2026-10-15
- 선행 조사: [funa-env-management-standard.md](funa-env-management-standard.md)(#211). Compose 보간·`env_file:`·systemd `EnvironmentFile=`·12-factor 해석은 거기 있으므로 여기서는 반복하지 않고 링크한다.
- 1차 출처
  - [The Twelve-Factor App: III. Config][12f]
  - systemd man page: [environment.d(5)][sd-envd], [systemd.exec(5)][sd-exec], [systemd-system.conf(5)][sd-sysconf], [locale.conf(5)][sd-locale], [localtime(5)][sd-localtime], [machine-id(5)][sd-mid]. freedesktop.org 사이트 접속이 계속 실패해(연결 끊김) **로컬 man page(systemd 259.5)** 를 읽었다. 이 문서의 systemd 인용은 모두 이 판본이다.
  - [pam_env.conf(5)][pam-env], [bash(1) INVOCATION][bash-start] (로컬 man 대조), [tzset(3)][tzset] (로컬 man 대조)
  - [POSIX.1-2024 Environment Variables][posix-env], [FHS 3.0 `/etc`][fhs-etc]
  - OpenTelemetry (Context7 `/open-telemetry/semantic-conventions`, `/open-telemetry/opentelemetry-specification`): [host 엔티티][otel-host], [deployment 속성][otel-deploy], [cloud 속성][otel-cloud], [service 속성][otel-service], [Resource SDK `OTEL_RESOURCE_ATTRIBUTES`][otel-res-sdk]
  - AWS EC2 [인스턴스 메타데이터 카테고리][aws-imds], GCP [미리 정의된 메타데이터 키][gcp-md]
  - Ansible [Setting the remote environment][ans-env], Docker Engine [daemon proxy][docker-proxy], curl man page(로컬 대조) [ENVIRONMENT][curl-env], npm [`npm install`][npm-install]
  - 저장소: AGENTS.md, CONTEXT.md, ADR-0006, ADR-0011, `roles/common`, `roles/funa_env`, `roles/monitoring`, `docs/common.md`, `docs/funa_env.md`
- **접근하지 못한 출처**: CIS Benchmark(RHEL 계열) 원문은 등록 후 내려받는 PDF라 읽지 못했다. CIS의 셸 기본값 관례는 이 문서에서 **확인 못 함**으로 둔다. 대신 이 저장소가 채택한 점검 기준은 Host Audit의 KISA-2026(ADR-0009, `docs/host_audit.md`)이고, 그 항목 U-12(`TMOUT`)·U-30(`umask`)을 §6에서 코드로 확인했다.
- 저장소 부재 확인 방법: `.git`과 `*.tsv`(패키지 목록)를 뺀 저장소 전체에서 `TMOUT`, `HISTSIZE`, `HISTFILESIZE`, `umask`, `http_proxy`, `https_proxy`, `no_proxy`, `localectl`, `locale_gen`, `locale.conf`, `{{ locale` 를 대소문자 무시로 grep했다(`roles/*/files`, `inventory`, `molecule`, `tests` 포함). 아래 "없음"은 이 grep 기준이다.

## 표기 규칙

| 태그 | 의미 |
|---|---|
| **출처** | 위 1차 출처에 문장으로 적힌 내용 |
| **코드** | 이 저장소 코드에서 직접 확인한 내용 |
| **추론** | 출처와 코드에서 끌어낸 판단. 운영 노드에서 관측한 것이 아니다 |
| **확인 못 함** | 확인하지 못한 항목. 확인한 것처럼 쓰지 않는다 |
| **판정** | 결론 요약 표의 "더할 후보/더하지 말 것" 분류. 이 조사의 비구속 제안이며 #233에서 뒤집을 수 있다. 결정이 아니다 |

## 결론 요약

**"노드가 기본으로 가져야 할 공통 환경 변수 목록"이라는 업계 표준은 찾지 못했다**(출처에 없음). 표준이 정하는 것은 세 층이다.

1. 로그인·프로세스 기본값: `HOME`, `LOGNAME`, `PATH`, `LANG`, `LC_*`, `TZ`. POSIX가 이름과 의미를 정하고, 값은 로그인이나 systemd가 채운다. 노드 관리자가 새로 정의하는 변수가 아니다.
2. 텔레메트리: OpenTelemetry가 속성 키(`host.name`, `deployment.environment.name`, `cloud.region` 등)와, 그것을 환경 변수로 나르는 `OTEL_RESOURCE_ATTRIBUTES` 한 가지를 정한다.
3. 클라우드 노드 정체성(instance-id, region, zone, hostname): AWS·GCP 모두 **환경 변수가 아니라 메타데이터 서비스**로 준다.

따라서 `NODE_*`는 이 저장소의 지역 규약이고, 이름을 맞출 외부 표준은 없다. 이름 충돌 위험만 하나 있다(§5).

| 후보 | 판정 | 한 줄 이유 | 절 |
|---|---|---|---|
| `TZ` (로그인 셸) | 더하지 말 것 | 시스템 타임존의 단일 출처는 `/etc/localtime`(`COMMON-001`이 이미 설정). `TZ`를 따로 두면 출처가 둘이고, 값이 비면 UTC가 된다 | §3.1 |
| `TZ` (컨테이너용) | 조건부 후보 | 컨테이너는 호스트 로그인 셸을 받지 않는다. FUNA는 이미 `cluster.env`의 `TZ`로 해결했다. 전 노드로 넓힐 때만, `timezone` 값에서 파생해 출처를 하나로 | §3.1 |
| `LANG`/`LC_*` | 더하지 말 것 | 출처는 `/etc/locale.conf`다. 저장소의 `locale` 기본값은 **소비하는 태스크가 없다**. 빠진 것은 변수가 아니라 태스크다 | §3.2 |
| `http_proxy` 등 | 더하지 말 것 | 저장소에 프록시 사용 근거가 없다. 소비자(Docker 데몬, curl, Ansible)마다 읽는 경로가 다르다 | §3.3 |
| `OTEL_RESOURCE_ATTRIBUTES` | 조건부 후보 | 노드 식별을 환경 변수로 나르는 유일한 표준. 다만 Host Agents가 이미 `host.*`·`deployment.environment.name`을 찍는다. 앱 SDK가 직접 내보내는 텔레메트리에도 필요하고 값의 출처가 하나일 때만 | §4.1 |
| `OTEL_SERVICE_NAME` | 더하지 말 것 | `service.name`은 서비스별 값이다. 노드 공통 값이 아니다 | §4.1 |
| 리전/존 (`NODE_REGION`, `NODE_ZONE`) | 더하지 말 것 | `cloud.*`는 클라우드 제공자를 전제한다. 이 저장소의 `NODE_IDC`가 같은 자리를 이미 채운다 | §4.2 |
| 호스트 ID (`NODE_ID`) | 더하지 말 것(현 시점) | semconv의 `host.id`는 비클라우드에서 `machine-id`를 쓰라고 한다. 파일에서 바로 읽을 수 있고 로그인 셸 소비처가 확인되지 않았다 | §4.2 |
| `umask`, `TMOUT` | `98-node-env.sh`에 넣지 말 것(별도 파일은 별개 문제) | 노드 식별이 아니라 셸 정책이다. 다만 이 저장소 자체 점검(Host Audit KISA U-12·U-30)이 이 둘을 전역 프로필에서 요구하고, 지금 배포하는 곳은 `dockermgmt`용 `umask 0002` 하나뿐이다 | §6 |
| `HISTSIZE` | 더하지 말 것 | 저장소에 이를 요구하는 점검·문서가 없다(CIS 원문은 **확인 못 함**) | §6 |
| 환경 식별자 (`NODE_ENV`) | 변수 추가가 아니라 정리 대상 | `NODE_ENV`(기본 `production`)와 `host_agents_environment`(호스트별 필수, 기본값 없음)가 같은 개념의 두 출처다. 이름도 Node.js 관례와 겹친다 | §4.3, §5 |

## 1. 지금 배포하는 것과 없는 것

| 항목 | `98-node-env.sh` | `/etc/environment` | `docs/common.md` 열거 | 근거 |
|---|---|---|---|---|
| `NODE_NAME`~`NODE_ADMIN_USER` 11개 | 있음 | 있음(같은 값) | 있음 | 코드 |
| `NODE_SSH_PORT` | 있음 | 있음 | **없음**("등"에 포함) | 코드 |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | 있음(기본값 로컬 수신) | 있음 | **없음** | 코드 |
| `custom_environment_variables` 반복 | 있음(기본 빈 딕셔너리) | 있음 | 없음 | 코드 |
| `TZ` | 없음 | 없음 | 없음 | 코드 |
| `LANG`/`LC_*` | 없음 | 없음 | 없음 | 코드 |
| 프록시 변수 | 없음 | 없음 | 없음 | 코드(전체 grep, 일치 없음) |
| `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_SERVICE_NAME` | 없음 | 없음 | 없음 | 코드 |
| `umask` | 없음 | 해당 없음 | 없음 | 코드. 유일한 선례는 `docker_engine`의 `/etc/profile.d/docker_mgmt.sh`(`DOC-018`)로 `dockermgmt` 그룹 구성원에게만 `umask 0002` |
| `TMOUT` | 없음 | 해당 없음 | 없음 | 코드. 배포하는 곳이 없다. 점검하는 곳은 있다(Host Audit `KISA-2026:U-12`, §6) |
| `HISTSIZE` | 없음 | 해당 없음 | 없음 | 코드(grep 일치 없음) |
| 셸 alias | 해당 없음 | 해당 없음 | 있음 | `99-aliases.sh`(`COMMON-018`) |

추가로 코드에서 확인한 사실은 다음과 같다.

- 타임존은 `COMMON-001`(`community.general.timezone`, `timezone: "Asia/Seoul"`)이 `/etc/localtime`으로 설정한다. 환경 변수는 아니다(코드).
- `roles/common/defaults/main.yml`에 `locale: "en_US.UTF-8"`이 있지만, `roles`·`playbooks` 어디에도 이 값을 읽는 태스크가 없다(`{{ locale` 참조·`localectl`·`locale_gen`·`locale.conf` grep 일치 없음. 코드). 로케일은 선언만 있고 적용은 하지 않는다.
- `roles/backup`의 restic 래퍼는 스스로 `LC_ALL=C`를 지정한다(코드). 노드의 `LANG`에 기대지 않는 선례다.
- `roles/funa_env`는 `clusters/funa` KV에 있는 `TZ` 등을 `/etc/funa-cluster/cluster.env`(`0644 root:root`)로 렌더링하고, `/etc/profile.d/funa-cluster.sh` 로더가 읽을 수 있는 파일만 `set -a`로 불러온다(`docs/funa_env.md`, 코드). 즉 `TZ`를 환경 변수로 주는 경로가 FUNA 한정으로 이미 있다.
- 두 파일 모두 `common` 역할이 전 노드에 배포한다. 파일 안의 `NODE_ROLE`은 `filter_plugins/node_env.py`의 `node_role_from_groups` 한 곳에서 계산한다(`docs/common.md`, 코드).

## 2. 변수가 닿는 경로와 표준 위치

로그인 셸, systemd 서비스, 컨테이너는 서로 다른 경로로 환경을 받는다. `98-node-env.sh`가 어디에 닿는지가 후보 판단의 전제다.

| 소비자 | 환경을 받는 경로 | 이 저장소의 `98-node-env.sh`/`/etc/environment`가 닿는가 | 태그 |
|---|---|---|---|
| 대화형 로그인 셸 | bash는 로그인 셸일 때 `/etc/profile`을 읽는다. 배포판의 `/etc/profile`이 `/etc/profile.d/*.sh`를 불러오는 것은 배포판 관례다 | 닿는다 | 출처 [bash-start]. 로컬 `/etc/profile`(Ubuntu)이 `profile.d`를 순회함을 확인. **Rocky/CentOS의 `/etc/profile`은 확인 못 함** |
| 비대화형 셸(스크립트, `ssh host cmd`, Ansible) | `BASH_ENV`가 있을 때만 그 파일을 읽는다. `/etc/profile`은 읽지 않는다 | 안 닿는다 | 출처 [bash-start] |
| PAM 로그인 | `pam_env`가 로그인 때 `/etc/security/pam_env.conf`를 읽고 그 뒤 `/etc/environment`(단순 `NAME=VALUE`)를 읽는다 | 닿는다(로그인 세션 한정) | 출처 [pam-env] |
| systemd 시스템 서비스 | 시스템 서비스 관리자는 자신의 환경을 서비스에 물려주지 않는다(`PassEnvironment=`로 명시). 대신 `DefaultEnvironment=`(`system.conf`), `Environment=`, `EnvironmentFile=`이 있다 | **안 닿는다** | 출처 [sd-exec], [sd-sysconf] |
| systemd 사용자 서비스 | `/etc/environment.d/*.conf`는 **사용자 서비스 관리자**(`systemd --user`)가 띄우는 서비스용이다. `/etc/environment`는 하위 호환으로 같이 읽힌다 | 시스템 서비스에는 해당 없음 | 출처 [sd-envd] |
| 컨테이너 | 호스트 환경을 물려받지 않는다. compose `env_file:`·`environment:`로 넣는다 | 안 닿는다 | [선행 조사 §2.1](funa-env-management-standard.md) |

- FHS 3.0은 `/etc`를 "구성 파일"의 위치로 정의하고, 셸 초기화 파일로는 `profile`(sh 로그인용, 선택)과 `csh.login`만 나열한다. `/etc/profile.d`와 `/etc/environment`는 FHS 본문에 없다(출처 [fhs-etc]). 즉 이 둘은 표준이 아니라 배포판·PAM 관례다(추론).
- `/etc/environment`는 셸이 해석하지 않는 단순 `NAME=VALUE` 파일이다(출처 [pam-env]). 지금 템플릿이 두 파일에 같은 값을 렌더링하는 것은 이 제약 안에서 성립한다(코드).
- 시스템 서비스에 노드 공통 값을 주는 systemd의 정식 수단은 `DefaultEnvironment=`(`/etc/systemd/system.conf` 또는 `system.conf.d/`)이다. "Added in version 205"로 적혀 있어 Rocky 9의 systemd 252 이전부터 있던 기능이다(출처 [sd-sysconf]). 252 판본의 문구와는 대조하지 않았다(**확인 못 함**).
- CentOS 6(systemd 없음)과 CentOS 7(systemd 219)은 저장소가 지원하는 레거시 경로(raw)다(CONTEXT.md, [os-compat-matrix](host-agents-os-compat-matrix.md)). 위 systemd 항목이 두 OS에서 같은지는 **확인 못 함**.
- 이 저장소는 지금까지 시스템 서비스에 노드 공통 변수를 주는 선례가 없다. 서비스는 역할별 `EnvironmentFile=`(`roles/monitoring`, `roles/backup`)을 쓴다(코드, [선행 조사 §2.7](funa-env-management-standard.md)).

## 3. 표준 위치가 따로 있는 후보

### 3.1 `TZ`

| 사실 | 태그 |
|---|---|
| POSIX는 `TZ`를 "timezone information을 나타내는 변수"로 정의한다 | 출처 [posix-env] |
| `TZ`가 환경에 없으면 시스템 타임존(`/etc/localtime`)을 쓴다. **`TZ`가 있는데 값이 비었거나 해석할 수 없으면 UTC**를 쓴다 | 출처 [tzset] |
| `/etc/localtime`은 `/usr/share/zoneinfo/...`를 가리키는 심볼릭 링크이며 시스템 전역 타임존이다. `timedatectl set-timezone`이 이 링크를 바꾼다 | 출처 [sd-localtime], timedatectl(1) |
| systemd가 서비스에 기본으로 넣는 변수 목록(`$PATH`, `$LANG`, `$USER` 등)에 `TZ`는 없다 | 출처 [sd-exec] |
| 저장소는 `/etc/localtime`을 설정하고(`COMMON-001`), 컨테이너용 `TZ`는 FUNA `cluster.env`에만 있다 | 코드 |

- 더하지 말 것(로그인 셸): 출처가 `/etc/localtime`으로 이미 있다. 같은 값을 `TZ`로 또 두면 출처가 둘이 되고, 한쪽이 비면 UTC로 조용히 바뀐다(추론).
- 조건부 후보(컨테이너): 컨테이너는 호스트의 로그인 셸·`/etc/localtime`을 받지 않으므로 컨테이너 env 파일에 `TZ`가 필요할 수 있다(추론). FUNA는 이미 그렇게 한다. 전 노드로 넓힌다면 `timezone` 기본값에서 파생해 값의 출처를 하나로 둔다. 컨테이너 이미지가 `TZ`를 실제로 읽는지는 이미지마다 달라 **확인 못 함**.

### 3.2 `LANG`/`LC_*`

| 사실 | 태그 |
|---|---|
| `/etc/locale.conf`가 시스템 전역 로케일을 설정하고, systemd가 부팅 초기에 읽어 "every service or user"가 상속한다. `LANG`, `LANGUAGE`, `LC_CTYPE`~`LC_IDENTIFICATION`을 쓸 수 있고 `LC_ALL`은 이 파일에 쓸 수 없다 | 출처 [sd-locale] |
| 갱신 수단은 `localectl`이다 | 출처 [sd-locale] |
| `$LANG`은 systemd가 서비스에 넣는 기본 변수 목록에 있고 값의 출처는 `locale.conf`다("Added in version 208") | 출처 [sd-exec] |
| `LC_ALL`은 "모든 로케일 범주의 값을 정한다". 다른 `LC_*`·`LANG`보다 우선한다는 것은 이 문장에서 끌어낸 추론이다 | 출처 [posix-env] + 추론 |
| 저장소의 `locale` 기본값은 읽는 태스크가 없다. `roles/backup`은 `LC_ALL=C`를 자체 지정한다 | 코드 |

- 더하지 말 것: 시스템 서비스·로그인 셸이 모두 `locale.conf`를 통해 받는 값이라 `profile.d`에 `LANG`을 넣으면 로그인 셸에서만 덮어쓰는 두 번째 출처가 된다(추론).
- 짚을 점: 문제는 환경 변수 누락이 아니라 `locale` 변수에 대응하는 태스크가 없다는 것이다. 새 변수를 더하기 전에 이 선언을 적용할지, 지울지를 정하면 된다. 이 항목은 #233 범위 밖이므로 별도 이슈 후보다.
- Rocky 252, CentOS 7(219), CentOS 6에서 `locale.conf` 동작이 같은지는 **확인 못 함**(CentOS 6은 systemd가 없다).

### 3.3 프록시 (`http_proxy`, `https_proxy`, `no_proxy`)

| 사실 | 태그 |
|---|---|
| curl은 대소문자 변수를 모두 읽고 소문자가 우선한다. `http_proxy`만 소문자 전용이다. `NO_PROXY`는 호스트·CIDR 목록 | 출처 [curl-env] |
| Docker 데몬은 **자신의 시작 환경**에서 `HTTP_PROXY`·`HTTPS_PROXY`·`NO_PROXY`를 읽는다. 일반 설치는 `docker.service.d/http-proxy.conf` 같은 systemd drop-in으로 준다 | 출처 [docker-proxy] |
| Ansible은 프록시를 작업 단위 `environment:` 키워드로 준다. 이 값은 다른 사용자나 다른 플러그인에 영향을 주지 않는다 | 출처 [ans-env] |
| 저장소는 프록시 변수를 어디에도 설정하지 않는다 | 코드 |

- 더하지 말 것: 소비자마다 읽는 경로가 다르다. 로그인 셸의 `profile.d`는 Docker 데몬·systemd 서비스에 닿지 않는다(§2). 이 저장소에 프록시를 쓰는 노드가 있는지는 코드로 알 수 없다(**확인 못 함**, 소유자에게 물을 항목).
- 주의: 프록시 URL에 인증 정보가 들어갈 수 있다. 그 경우 `profile.d`(`0644`)에 두면 AGENTS.md §4.2 위반이다(추론). 프록시 주소는 인프라 상세이므로 공개 저장소에는 값을 두지 않는다.

## 4. 텔레메트리·클라우드 이름과의 대응

### 4.1 `OTEL_RESOURCE_ATTRIBUTES`와 `service.*`

| 사실 | 태그 |
|---|---|
| SDK는 `OTEL_RESOURCE_ATTRIBUTES`(`key1=value1,key2=value2`)를 읽어 리소스에 **보조 값으로** 병합한다. 사용자가 코드로 준 리소스가 우선이다. `,`와 `=`는 퍼센트 인코딩해야 하고, 해석 오류가 나면 변수 전체가 버려진다 | 출처 [otel-res-sdk] |
| `service.name`은 "수평 확장된 서비스의 모든 인스턴스에서 같아야" 한다. 값이 없으면 `unknown_service:<실행파일>`로 대체된다 | 출처 [otel-service] |
| `deployment.environment.name`은 Stable이며 예시 값은 `production`, `staging`, `development`, `test`다. 이 속성은 서비스의 유일성 판단에 영향을 주지 않는다 | 출처 [otel-deploy] |
| Host Agents는 `host.name`(=Inventory Hostname), `host.id`, `host.ip`, `host.arch`, `os.*`, `deployment.environment.name`을 로그·메트릭에 찍는다. `deployment.environment.name`은 호스트별 필수이며 기본값이 없다 | 코드 (CONTEXT.md, ADR-0006 §2.3, `docs/monitoring.md`) |

- 조건부 후보 `OTEL_RESOURCE_ATTRIBUTES`: 노드 식별을 환경 변수로 나르는 표준은 이것 하나뿐이다. 하지만 노드 단위 텔레메트리는 이미 Host Agents가 찍으므로 필요한 곳은 **앱 SDK가 직접 내보내는 텔레메트리**에 한정된다(추론). 그 경우에도 (a) 소비 경로가 `/etc/profile.d`가 아니라 컨테이너 `env_file:`여야 하고(§2), (b) `deployment.environment.name`의 값이 한 곳에서 와야 한다(§4.3). 앱이 실제로 이 변수를 읽는지, 지금 앱 텔레메트리에 `host.*`가 빠져 있는지는 **확인 못 함**.
- 더하지 말 것 `OTEL_SERVICE_NAME`: 서비스별 값이다. ADR-0011은 `service.name`을 compose 라벨 `<프로젝트>-<서비스>`에서 만들기로 정했다(코드). 노드 공통 변수로 두면 그 규칙과 충돌한다.
- 참고: `98-node-env.sh`에 이미 있는 `OTEL_EXPORTER_OTLP_ENDPOINT`는 OTel SDK 표준 이름이다(출처 [otel-spec-env]). 이것이 노드 공통 변수 목록 안에 이미 섞여 있다는 점은 #233 열린 질문 2(c)의 통합 범위를 정할 때 같이 보아야 한다.

### 4.2 리전·존·호스트 ID

| 이름 | 출처 | 태그 |
|---|---|---|
| AWS 인스턴스 메타데이터 카테고리: `ami-id`, `hostname`, `instance-id`, `instance-type`, `local-hostname`, `local-ipv4`, `public-ipv4`, `placement/`, `tags/` 등. 메타데이터 서비스(IMDS) 경로로 조회하며 환경 변수가 아니다 | [aws-imds] | 출처 |
| AWS `placement` 아래에 Region, Availability Zone ID 등이 추가됐다 | [aws-imds] 릴리스 노트(Context7 발췌) | 출처. `placement/region` 경로는 위 카테고리 표로 직접 확인하지 못했다 |
| GCP 메타데이터 키: `instance/hostname`, `instance/id`, `instance/name`, `instance/machine-type`, `instance/attributes/`, `project/project-id`, `project/numeric-project-id` | [gcp-md] | 출처. `instance/zone`·`instance/tags`는 페이지 일부만 읽어 **확인 못 함** |
| OTel `cloud.region`("클라우드 제공자 안의 지리적 리전"), `cloud.availability_zone`, `cloud.provider`, `cloud.platform`, `cloud.account.id`. 모두 Development 단계 | [otel-cloud] | 출처 |
| OTel `host.id`: 클라우드면 제공자의 instance_id, **비컨테이너 시스템은 `machine-id`**. `host.name`, `host.type`(클라우드면 머신 타입), `host.arch`, `host.ip`(Opt-In) | [otel-host] | 출처 |
| `/etc/machine-id`: 설치 또는 부팅 때 정해지는 32자 16진수 ID | [sd-mid] | 출처 |

- 더하지 말 것 `NODE_REGION`/`NODE_ZONE`: 두 클라우드 모두 이 값을 환경 변수가 아니라 메타데이터로 준다(출처). OTel `cloud.*`는 클라우드 제공자 전제의 이름이다. 이 저장소는 온프레미스 IDC 중심이고 위치 구분을 `NODE_IDC`가 맡는다(코드). 표준에 맞춰 이름을 바꿀 근거는 없다(추론).
- 더하지 말 것(현 시점) `NODE_ID`: semconv가 비클라우드의 `host.id`로 `machine-id`를 쓰라고 하므로 값의 원천은 `/etc/machine-id`다. Host Agents가 이미 `host.id`를 찍는다(코드). 로그인 셸·컨테이너 소비처는 확인되지 않았다.

### 4.3 환경 식별자: `NODE_ENV`와 `host_agents_environment`

| 항목 | 값의 출처 | 기본값 | 허용 값 검증 | 태그 |
|---|---|---|---|---|
| `NODE_ENV` | `roles/common`의 `node_env` | `production` | 없음 | 코드 |
| `deployment.environment.name` | `host_agents_environment` (`roles/monitoring`) | **없음(호스트별 필수)** | `production`·`staging`·`development`·`test` 외에는 변경 전에 실패(`MON-037`) | 코드 (ADR-0006 §2.3) |

- 한 노드의 "운영 환경"이 두 변수에 따로 선언된다. 두 값이 어긋나도 막는 곳이 없다(코드에서 둘을 연결하는 지점을 찾지 못함. 추론).
- `NODE_ENV`는 기본값이 `production`이라서, `host_agents_environment`를 의도적으로 "기본값 없음"으로 둔 ADR-0006의 결정과 방향이 반대다. 이 상충이 있는지, 의도된 것인지는 코드만으로 알 수 없다(**확인 못 함**).
- 12-factor는 환경 변수를 "각각 독립적인 세부 제어"로 두고 "environments로 묶지 말라"고 한다(출처 [12f]). 이 서술은 `NODE_ENV` 하나로 환경 묶음을 나타내는 방식에 대한 반대 근거로 읽을 수 있다. 다만 12-factor는 변수 이름을 정하지 않는다(추론).

## 5. #233 열린 질문 3(이름 충돌)에 직접 걸리는 근거

| 사실 | 태그 |
|---|---|
| POSIX: 유틸리티가 쓰는 환경 변수 이름은 대문자·숫자·밑줄만으로 이루어지고, 소문자를 포함한 이름 공간은 **애플리케이션용으로 예약**돼 있다. 대문자 접두어 예약 규칙은 읽은 범위에서 찾지 못했다 | 출처 [posix-env] + 추론(부재 확인은 페이지 요약 기준) |
| `NODE_ENV=production`이면 npm은 `devDependencies`를 설치하지 않는다. Node.js 생태계가 읽는 이름이다. Node.js 자체도 `NODE_OPTIONS` 등 `NODE_` 접두어 변수를 읽는다 | 출처 [npm-install], Node.js CLI 문서(Context7 `/nodejs/node`) |
| `98-node-env.sh`·`/etc/environment`의 `NODE_ENV`는 기본 `production`으로 전 노드 로그인 셸에 export된다 | 코드 |
| FUNA의 `FUNA_*` 접두어를 제거하면(#233 요구 2) 제품 중립 이름이 `NODE_*`, `TZ` 등과 같은 이름 공간을 쓰게 된다 | 코드 (#233 본문) |

- `NODE_` 접두어는 이 저장소의 `NODE_*`(노드 식별)와 Node.js의 `NODE_*`(런타임 설정)가 같은 이름 공간이다. 현재 `NODE_ENV`만 값의 의미까지 겹친다(`production`, 추론). 노드에서 Node.js 앱을 돌린다면 로그인 셸에서 의도치 않게 `production`으로 동작할 수 있다. 그런 앱이 이 노드들에 있는지는 **확인 못 함**.
- Node.js 문서에서 `NODE_ENV`와 `NODE_OPTIONS`의 위치는 확인했지만, `NODE_NAME` 같은 다른 이름이 Node.js·주요 런타임과 충돌하는지는 전수 조사하지 않았다(**확인 못 함**).

## 6. 셸 기본값 관례 (`umask`, `TMOUT`, `HISTSIZE`)

- CIS Benchmark의 해당 항목(기본 `umask`, `TMOUT`, 셸 타임아웃 등)은 원문을 읽지 못했다. **확인 못 함**.
- 저장소가 채택한 기준은 CIS가 아니라 Host Audit의 KISA-2026이다(ADR-0004·ADR-0009가 CIS 감사 파일럿을 대체, 코드). 관련 항목은 다음과 같다(`docs/host_audit.md`, `roles/host_audit/files/kisa/`).

| 항목 | 판정 기준 | 읽는 위치 | 태그 |
|---|---|---|---|
| `KISA-2026:U-12` 세션 종료 시간 | 전역 sh 프로필의 `TMOUT`이 1~600초(여러 곳이면 가장 큰 값). 없으면 취약 | `/etc/profile`, `/etc/profile.d/*.sh`, `/etc/bashrc`, `/etc/bash.bashrc` | 코드 (`U-12.sh`) |
| `KISA-2026:U-30` UMASK 설정 관리 | 전역 프로필·`login.defs`의 **모든** umask 값이 022 비트를 포함. 지정이 없으면 취약 | `/etc/profile`, `/etc/bashrc`, `/etc/bash.bashrc`, `/etc/login.defs`, `/etc/profile.d/*.sh` | 코드 (`U-30.sh`) |

- 저장소 안의 배포 사실: `umask`는 `docker_engine`의 `DOC-018`이 `dockermgmt` 그룹 한정으로 `/etc/profile.d/docker_mgmt.sh`에 `umask 0002`를 둔다(ADR-0002). `TMOUT`을 배포하는 곳은 없다. `HISTSIZE`는 배포도 점검도 없다(코드).
- 두 사실을 겹친 추론(실행해 보지 않았고 Host Audit 결과도 보지 않았다): `U-30.sh`는 `/etc/profile.d/*.sh`의 모든 `umask` 줄을 읽으므로, `DOC-018`의 `umask 0002`(`0002 & 022`가 022가 아님)는 Docker 호스트에서 `U-30` 취약으로 잡힐 수 있다. `TMOUT`을 어디서도 배포하지 않으므로 `U-12`도 별도 설정이 없는 노드에서는 취약으로 나올 수 있다. 이 충돌이 의도된 예외인지는 코드만으로 알 수 없다(**확인 못 함**).
- 결론에 쓰는 의미: 셸 정책(`umask`, `TMOUT`)을 `common`의 `profile.d`에 전 노드 공통으로 둘 근거는 CIS가 아니라 **저장소 자체 점검 기준**에 있다. 다만 이것은 이 문서가 묻는 "노드 식별 변수 후보"가 아니라 별개 주제이고, 어느 쪽이든 아래 구조적 근거 때문에 `98-node-env.sh`와는 파일을 나눈다.
- 구조적 근거(추론): `98-node-env.sh`는 "노드가 누구인가"를 나타내는 값 파일이고, `umask`·`TMOUT`는 "세션이 어떻게 동작하는가"를 정하는 정책이다. 둘을 한 파일에 두면 `custom_environment_variables`처럼 값 목록으로 다룰 수 없는 `if`·`umask` 구문이 섞인다. `/etc/environment`는 셸 구문을 해석하지 않으므로(§2) 이 둘은 같은 템플릿을 공유할 수 없다. 넣는다면 `DOC-018`처럼 별도 `profile.d` 파일이다.

## 7. #233 판단에 넘기는 사실 정리

결정은 하지 않는다. 열린 질문별로 위 근거 중 해당하는 것만 모았다.

| #233 열린 질문 | 관련 사실 |
|---|---|
| 2. 전 노드 공통 `profile.d`의 의미 (a) 로더를 모든 노드에 / (b) 모든 노드가 같은 변수 집합을 받는 새 역할 / (c) `98-node-env.sh`와 통합 | `98-node-env.sh`는 이미 전 노드에 배포된다(§1). 로그인 셸 한정이라 시스템 서비스·컨테이너에는 안 닿는다(§2). 노드 공통 값을 서비스에 주는 정식 수단은 `DefaultEnvironment=`이고 컨테이너는 `env_file:`이다. `/etc/environment`는 셸 구문을 못 쓰고 `98-node-env.sh`는 쓸 수 있다(§2, §6). `funa-cluster.sh` 로더의 `set -a`·읽을 수 있는 파일만 불러오는 방식은 FUNA 한정으로 이미 있다(§1). 통합할 때 `OTEL_EXPORTER_OTLP_ENDPOINT`, `NODE_SSH_PORT`도 같은 파일에 있음을 알아야 한다(§1, §4.1) |
| 3. 접두어를 뺀 이름의 충돌 | POSIX는 접두어 규칙이 없다(§5). 이미 `NODE_ENV`가 Node.js 관례와 의미까지 겹친다(§5). `TZ`는 POSIX 정의 이름이라 제품 중립 변수로 올려도 의미가 겹치지 않는다. 다만 빈 값이면 UTC가 된다(§3.1) |
| (참고) 더할 변수 | §결론 요약의 표. 로그인 셸 `profile.d`에 새로 더할 확실한 후보는 없다. 후보는 조건부 둘(`TZ` 컨테이너용, `OTEL_RESOURCE_ATTRIBUTES`)이고 둘 다 소비 경로가 컨테이너 env 파일이다 |

## 8. 확인하지 못한 항목

1. CIS Benchmark(RHEL 계열) 원문. 셸 기본값(`umask`, `TMOUT`) 관례. 대체로 KISA-2026 점검 항목(§6)을 근거로 삼았다. Host Audit의 실제 점검 결과(`U-12`·`U-30`이 어느 노드에서 취약으로 나왔는지)는 보지 않았다.
2. systemd 252(Rocky 9)·219(CentOS 7)·CentOS 6에서 `locale.conf`, `DefaultEnvironment=`, `environment.d`의 동작과 man page 문구. 로컬 man은 259.5였고 "Added in version" 표기만 확인했다.
3. Rocky/CentOS의 `/etc/profile`이 `profile.d/*.sh`를 순회하는지(Ubuntu만 로컬 확인).
4. AWS `placement/region`·GCP `instance/zone` 경로의 정확한 이름(페이지 일부만 읽음).
5. 이 저장소 노드들이 프록시를 쓰는지, Node.js 앱이 있는지, 앱 컨테이너가 `TZ`·`OTEL_RESOURCE_ATTRIBUTES`를 실제로 읽는지.
6. `NODE_ENV` 기본값(`production`)과 `host_agents_environment` 필수화가 의도된 병존인지.
7. `NODE_*` 전체 이름이 다른 런타임·도구의 변수와 충돌하는지(전수 조사 안 함).

[12f]: https://12factor.net/config
[sd-envd]: https://www.freedesktop.org/software/systemd/man/latest/environment.d.html
[sd-exec]: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
[sd-sysconf]: https://www.freedesktop.org/software/systemd/man/latest/systemd-system.conf.html
[sd-locale]: https://www.freedesktop.org/software/systemd/man/latest/locale.conf.html
[sd-localtime]: https://www.freedesktop.org/software/systemd/man/latest/localtime.html
[sd-mid]: https://www.freedesktop.org/software/systemd/man/latest/machine-id.html
[pam-env]: https://man7.org/linux/man-pages/man5/pam_env.conf.5.html
[bash-start]: https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html
[tzset]: https://man7.org/linux/man-pages/man3/tzset.3.html
[posix-env]: https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap08.html
[fhs-etc]: https://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch03s07.html
[otel-host]: https://github.com/open-telemetry/semantic-conventions/blob/main/docs/registry/entities/host.md
[otel-deploy]: https://github.com/open-telemetry/semantic-conventions/blob/main/docs/registry/attributes/deployment.md
[otel-cloud]: https://github.com/open-telemetry/semantic-conventions/blob/main/docs/registry/attributes/cloud.md
[otel-service]: https://github.com/open-telemetry/semantic-conventions/blob/main/model/service/registry.yaml
[otel-res-sdk]: https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/resource/sdk.md
[otel-spec-env]: https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/protocol/exporter.md
[aws-imds]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
[gcp-md]: https://docs.cloud.google.com/compute/docs/metadata/predefined-metadata-keys
[ans-env]: https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_environment.html
[docker-proxy]: https://docs.docker.com/engine/daemon/proxy/
[curl-env]: https://curl.se/docs/manpage.html
[npm-install]: https://github.com/nodejs/node/blob/main/deps/npm/docs/content/commands/npm-install.md
