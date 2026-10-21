# Semaphore 셋업 가이드 (Host Agents · OpenObserve · Host Audit)

> Semaphore UI에 Host Agents 템플릿 4개, OpenObserve — Config, Host Audit 템플릿 3개를 등록하는 절차다. 값은 저장소 코드 기준이며, 시크릿은 모두 OpenBao에 두고 Git에는 두지 않는다.
> OpenBao 구조와 공통 접속 모듈은 [openbao_integration.md](openbao_integration.md), 배포 내용은 [Host Agents 배포 내역서](host-agents-deploy-inventory-simple.md)를 본다.

---

## 0. 등록 순서 요약

1. Key Store: Git 저장소 접근 키
2. Repository: `ppzxc/infra-automation`, branch `main`
3. Inventory: Static 인벤토리 (Semaphore UI에서 편집, `inventory/hosts.yml.example` 형식)
4. Variable Group(Environment): OpenBao 접속 값 (모든 템플릿 공용 1개)
5. Task Template 8개 (아래 §5)
6. Schedule: Repo Maintenance(매일), Host Audit — Monthly(월 1회)
7. 확인 실행: Config `--check` → Deploy(1대) → Deploy(전체) → Repo Maintenance → OpenObserve — Config → Host Audit(§7.1)

---

## 1. 러너(컨트롤러) 요구사항

템플릿은 모두 Semaphore 러너에서 실행된다. Repo Maintenance와 OpenObserve — Config는 러너에서만 동작하고 호스트에 접속하지 않는다.

| 항목 | 이유 |
|---|---|
| ansible-core, Python 3 | 기본 |
| `bunzip2` | restic 배포 파일(`.bz2`) 압축 해제 (Deploy, Repo Maintenance) |
| `sshpass` | CentOS 6/7 중 비밀번호로 접속하는 호스트에 바이너리를 업로드할 때 (MON-104) |
| GitHub releases로 나가는 HTTPS | otelcol·restic·resticprofile 다운로드. 호스트는 인터넷에 접근하지 않음 |
| OpenBao, OpenObserve, RustFS로 가는 네트워크 | KV 조회, 이벤트 전송, repo 유지보수 |
| 쓰기 가능한 `$HOME/.cache/host-agents` | 검증된 바이너리 캐시 |
| 사설 CA를 쓴다면 러너 신뢰 저장소에 CA 등록 | OpenObserve 등록 이벤트와 Repo Maintenance는 인증서를 검증함 |
| **Host Audit** 추가: GitHub releases(Trivy 바이너리)와 Trivy 취약점 DB 레지스트리로 나가는 HTTPS | Package Vulnerability. DB 레지스트리는 `host_audit_trivy_db_repository`로 내부 미러를 지정할 수 있다 |
| **Host Audit** 추가: `smtp-relay.gmail.com:587` 아웃바운드, 러너의 공인 IP가 Workspace relay 허용 IP에 등록 | 메일 발송(IP 인증, STARTTLS) — [SMTP 릴레이 확보](https://github.com/ppzxc/infra-automation/issues/105) |
| **Host Audit** 추가: 실행 사이에 유지되는 `$HOME/.cache/host-audit`(또는 `host_audit_cache_dir`) | Trivy 바이너리·DB 캐시. 유지되지 않으면 DB 갱신 실패 시 7일 캐시 규칙이 동작하지 않아 Package Vulnerability가 점검불가로 나온다 |
| **Host Audit** 추가: `timeout` 명령, 메모리 1024M 이상 | Trivy DB 갱신 시간 제한, Trivy 판정(호스트마다 순차) |

Galaxy 의존성은 저장소 루트 `requirements.yml`에 있으며, 실행 로그의 `Starting galaxy collection install process`로 Semaphore가 설치하는 것을 확인할 수 있다.

---

## 2. Key Store

| 이름(예) | 종류 | 용도 |
|---|---|---|
| `github-deploy-key` | SSH Key | Repository clone (`git@github.com:ppzxc/infra-automation.git`) |
| `none` | None | Task Template의 SSH Key 칸에 지정 |

대상 호스트의 SSH 키와 계정은 Key Store에 두지 않는다. `playbooks/common/resolve_connection.yml`이 OpenBao `hosts/<host>`와 `users/`에서 키를 가져와 임시 파일로 만들고, 실행이 끝나면 지운다. 그래서 템플릿의 SSH Key는 `None`으로 둔다.

---

## 3. Repository · Inventory

| 항목 | 값 |
|---|---|
| Repository URL | `git@github.com:ppzxc/infra-automation.git` |
| Branch | `main` |
| Access Key | `github-deploy-key` |
| Inventory 종류 | **Static** (Semaphore UI에서 YAML 편집). `inventory/hosts.yml`은 `.gitignore` 대상이라 저장소 checkout에 없으므로 File 종류로는 쓸 수 없다. 형식은 `inventory/hosts.yml.example` 참고 |
| Inventory 사용자 자격증명 | None |

인벤토리에는 Inventory Hostname(관리번호, 예: `ns0332`)만 있다. 접속 IP와 포트는 OpenBao에서 동적으로 채운다. Host Agents 대상은 `servers` 그룹이다.

**Host Agents를 적용하지 않는 호스트**: Semaphore Static 인벤토리에서 `servers`에는 두되 `host_agents_excluded` 그룹에도 넣는다. Deploy·Config·Backup·Repo Maintenance가 모두 이 그룹을 뺀다. 템플릿의 Limit이나 `target_hosts`로 따로 빼지 않는다.

**백업만 적용하는 호스트**: 로그를 다른 체계가 수집하는 호스트는 `servers`에 두고 `host_agents_backup_only` 그룹에도 넣는다(ADR-0006 §2.1). Deploy·Config·Backup이 이 호스트에는 otelcol 단계를 건너뛰고 restic·resticprofile만 적용하며, Repo Maintenance도 포함한다. OpenBao `hosts/<host>/agents`에 `o2_ingest_token`은 없어도 된다. 매일의 `job=backup` 결과는 OpenObserve로 가지 않는다. `host_agents_excluded`와 함께 넣지 않는다(제외가 우선한다).

**호스트 편입·폐기 절차**: 인벤토리에 호스트를 넣거나 빼는 작업(`servers`·`host_agents_excluded`·`host_agents_backup_only` 그룹 변경)을 마친 뒤 **`OpenObserve — Config`를 다시 실행**한다. 이 템플릿이 인벤토리에서 수집 로스터(`servers` − Host Agents Exclusion − Host Agents Backup Only, ns0266·ns0332 포함)와 유지보수 로스터(`servers` − Host Agents Exclusion)를 만들어 Silent Host 등 부재 알림의 SQL에 반영한다. 재실행을 잊으면 신규 호스트는 감시에서 빠지고 폐기한 호스트는 계속 Silent Host로 울린다. 며칠 이상 계획 정지하는 호스트는 폐기 대신 OpenBao `agents/openobserve`의 `silent_host_exceptions`(만료일 필수)에 등록한다. 앱 텔레메트리 무소식 알림(`infra-app-telemetry-silent`)의 대상은 수집 로스터 중 OpenBao `hosts/<host>/agents`의 `otel_app_telemetry`가 `true`인 호스트다(Config가 호스트마다 읽는다 — `OpenObserve — Config`의 OpenBao 토큰이 `hosts/*/agents` 읽기 권한을 가져야 하며, 스위치를 바꾸면 Config를 다시 실행한다). 스위치 syslog 알림(Spec #277)의 수신 중단 감시 장비(`o2c_switch_syslog_roster`)·업링크 포트(`o2c_switch_uplinks`)·잡음 메시지 코드(`o2c_switch_noise_events`)는 이 템플릿의 Environment(`-e`)로 덮어쓰며, 새 스위치에 syslog 전송을 설정한 뒤 목록에 더하고 Config를 다시 실행한다(절차는 [런북](runbooks/alerts.md) 스위치 syslog 절).

**방화벽을 건드리지 않는 호스트**: `servers`(또는 `loadbalancers`)에 두면서 `firewall_unmanaged` 그룹에도 넣는다. HOST PROVISIONING(`site.yml`)이 이 호스트의 방화벽(UFW·firewalld·iptables, CentOS 7 raw 경로 포함) 태스크를 모두 건너뛴다. sshd·SELinux·fail2ban·auditd·sudo 정책은 그대로 적용한다. Host Audit 드리프트 검사는 같은 인벤토리로 `site.yml`을 check 실행하므로 따로 설정할 것이 없다. 프로비저닝 전에 `--check --diff`로 방화벽 태스크가 하나도 나오지 않는지 확인한다(#220).

**FUNA Cluster 호스트**: `servers`에 두면서 `funa_cluster` 그룹에도 넣는다(ns0325·ns0327·ns0338). HOST PROVISIONING(`site.yml`)이 `docker_engine` 뒤에 `funa_env` 역할을 실행해 OpenBao 값으로 `/etc/funa-cluster/`의 환경 파일을 렌더링한다. 그룹에 없는 호스트에는 아무것도 생기지 않는다. 필요한 OpenBao 경로와 키는 `docs/funa_env.md`(#222). 이 그룹은 `NODE_ROLE`에 쓰이지 않는다.

**프로비저닝에서 제외하는 호스트**: 기본은 `servers`의 모든 호스트를 `provision_excluded` 그룹에 둔다. 새 호스트가 `servers`에 추가되면 먼저 이 그룹에도 넣는다. 프로비저닝 대상으로 **확인된 호스트만** 이 그룹에서 빼고 아래 `provision_allowed`로 옮긴다. Semaphore 자신, 중앙 OpenObserve/RustFS 호스트, 관리번호 재부여 대기 호스트는 허용 목록에 넣지 않는다. Host Provisioning의 사전 검증이 이 그룹의 호스트가 `target_hosts`에 있으면 접속 전에 실패시킨다. 그룹이 인벤토리에 없으면 빈 그룹으로 본다. 다른 템플릿에는 영향이 없다. 이 그룹은 `provision_allowed`보다 우선한다(허용 목록에도 있는 호스트라도 거부). 그러므로 대상으로 옮길 때는 제외에서 먼저 빼야 한다.

**프로비저닝을 허용하는 호스트(기본 거부)**: Host Provisioning은 `provision_allowed` 그룹에 속한 호스트만 `target_hosts`로 받는다. 그룹이 없거나 비어 있으면(기본 상태) 어떤 호스트도 허용되지 않아 모든 프로비저닝이 접속 전에 실패한다. 그래서 `servers`에 새로 추가된 호스트는 자동으로 막힌다. 운영 절차는 확인 → 허용 → 실행 → 허용 해제다. (1) 대상 호스트가 프로비저닝 대상임을 확인한다. (2) Semaphore 인벤토리에서 `provision_excluded`에서 빼고 `provision_allowed`에 넣는다. (3) Host Provisioning을 `target_hosts`로 실행한다. (4) 끝나면 `provision_allowed`에서 빼고 다시 `provision_excluded`에 넣는다.

**Host Audit에서 빼는 호스트**: 러너(Semaphore 서버)에서 접속할 수 없는 호스트 등은 `host_audit_excluded` 그룹에 넣는다. Host Audit — Monthly·On-demand가 이 그룹을 빼며(`host_audit_scope_pattern`), 보고서와 Asset Inventory에도 나오지 않는다. 다른 템플릿에는 영향이 없다.

```yaml
all:
  children:
    servers:
      hosts:
        ns0266: {}
        ns0294: {}
    host_agents_excluded:   # Host Agents 미적용. 적용할 때 여기서 뺀다.
      hosts:
        ns0266: {}
    host_agents_backup_only:   # otelcol 없이 백업만. 지금은 비어 있다.
      hosts: {}
    host_audit_excluded:   # Host Audit 대상에서 뺀다(러너에서 접속 불가 등).
      hosts:
        ns0332: {}
    firewall_unmanaged:   # HOST PROVISIONING이 방화벽만 건드리지 않는다.
      hosts:
        ns0325: {}
    provision_excluded:   # Host Provisioning 제외. 기본은 servers 전체. 확인된 대상만 빼서 provision_allowed로 옮긴다. provision_allowed보다 우선한다.
      hosts:
        ns0266: {}
        ns0332: {}
    provision_allowed:   # Host Provisioning 허용 목록(기본 거부). 비어 있음이 기본. 확인된 대상만 제외에서 빼고 넣는다.
      hosts: {}
    funa_cluster:   # FUNA Cluster 환경 파일 렌더링(funa_env).
      hosts:
        ns0325: {}
```

---

## 4. Variable Group (Environment)

Host Agents 4개가 **같은 Variable Group 하나를 공유**한다. Repo Maintenance도 Deploy와 같은 AppRole로 로그인한다(BAK-087).

> **OpenObserve — Config도 같은 AppRole로 로그인한다**(O2C-000). 받은 토큰을 `VAULT_TOKEN`보다 먼저 쓰고, AppRole 값이 없거나 로그인이 실패할 때만 `VAULT_TOKEN`으로 조회한다(O2C-001). 둘 다 쓸 수 없으면 입력 누락으로 실패하며, 실패 메시지에 OpenBao 응답 코드가 나온다.

**Environment variables**

| 키 | 값(예) | 필수 | 비고 |
|---|---|---|---|
| `VAULT_ADDR` | `https://openbao.internal:8200` | ● | 기본값 `http://openbao:8200` |
| `VAULT_NAMESPACE` | `infra/prod/host/` | | 이 값이 기본값 |
| `VAULT_MOUNT` | `secret` | | 이 값이 기본값 |
| `OPENBAO_HOSTS_PREFIX` | `hosts/` | | 이 값이 기본값 |

**Secrets** (Semaphore Variable Group의 Secret 탭)

| 키 | 필수 | 비고 |
|---|---|---|
| `VAULT_ROLE_ID` | ● | OpenBao AppRole |
| `VAULT_SECRET_ID` | ● | OpenBao AppRole |
| `VAULT_TOKEN` | OpenObserve — Config에는 ● | Deploy·Config는 AppRole이 있으면 AppRole이 우선하고, Repo Maintenance는 토큰이 있으면 토큰을 쓴다(BAK-087은 토큰이 없을 때만 로그인) |

**AppRole 정책이 읽을 수 있어야 하는 KV 경로** (mount `secret`, namespace 기준)

| 경로 | 쓰는 템플릿 |
|---|---|
| `hosts/<host>`, `hosts/<host>/users/*`, `users/*` | Deploy, Config, Host Audit (SSH 접속) |
| `hosts/<host>/agents` | Deploy, Config, Repo Maintenance, Host Audit (Configuration Drift의 Config `--check` 하위 실행) |
| `agents/openobserve` | Deploy, Config, Repo Maintenance, OpenObserve — Config, Host Audit (Configuration Drift) |
| `agents/rustfs` | Deploy, Config, Repo Maintenance, Host Audit(엔드포인트) |
| `agents/host_audit` | Host Audit, Host Audit — Resend (전용 보관 키 `storage_access_key`/`storage_secret_key`, 선택 `storage_bucket`·`storage_endpoint`·`storage_region` — [host_audit.md §11](host_audit.md#11-보관과-audit-baseline-125); 메일 수신자 `mail_to`·발신자 `mail_from` — [host_audit.md §13](host_audit.md#13-메일-발송-126)) |

필요한 키 목록은 [배포 내역서 Full §5](host-agents-deploy-inventory-full.md#5-입력-openbao-kv-v2-git에는-시크릿-없음)를 본다. 템플릿별로 추가로 필요한 키는 다음과 같다.
- **호스트별 선택 키 `hosts/<host>/agents`**: `otel_docker_metrics`(docker 메트릭), `otel_app_telemetry`(boolean, 컨테이너 앱 텔레메트리 OTLP HTTP 수신 — traces는 `app_traces` 스트림, metrics는 기존 경로. 기본 꺼짐, ADR-0012), `otel_container_logs`(docker 컨테이너 로그를 `app_logs`로 수집, 기본 꺼짐. 컨테이너가 compose에서 `json-file` 드라이버(`max-size`·`max-file`)와 `com.docker.compose.project`·`com.docker.compose.service` 라벨 전달 옵션(`logging.options.labels`)을 써야 한다. compose를 먼저 `json-file`로 전환한 뒤 Config를 실행한다: 이전 구현이 둔 rsyslog 규칙이 이때 제거되고 rsyslog가 재시작된다).
- **Repo Maintenance**: `agents/rustfs`의 `maintenance_access_key`/`maintenance_secret_key`. 모든 `backup-prod-*` 버킷에서 삭제(prune)할 권한이 있어야 한다.
- **OpenObserve — Config**: `agents/openobserve`의 `api_user`/`api_password`, `alert_webhook_url`(네이버웍스 봇 text API). 알림 검증용 `controller_ingest_token`(합성 레코드 주입). 선택으로 `alert_webhook_token`·`alert_webhook_auth_header`(봇은 `X-NANOIT-ACCESS`).
- **Host Audit 메일**: `agents/host_audit`의 `mail_to`(받는 사람, 목록 또는 `,`·`;` 구분 문자열)와 `mail_from`(보내는 주소 1개). 주소는 개인정보라 저장소와 템플릿 Extra variables에 고정하지 않는다. 한 번만 다른 사람에게 보낼 때는 `host_audit_mail_to`로 덮어쓴다(값은 로그에 나오지 않는다). 템플릿 Survey에는 두지 않으므로 API 실행의 `environment`로 넘긴다(§5 실행 시 입력).

---

## 5. Task Template

공통 설정: Inventory `inventory/hosts.yml`, Repository `infra-automation`, Variable Group은 §4의 것, **Limit은 비움**.

| 이름 | Playbook | CLI args | Survey variables | 실행 방식 | 대상 |
|---|---|---|---|---|---|
| Host Provisioning | `playbooks/provision_hosts.yml` | (없음) | `target_hosts`, `target_admin_users` | 수동 | `target_hosts`로 지정한 서버만(필수, 기본 5대까지). `provision_allowed` 그룹에 있는 호스트만 가능(기본 거부). 지정하지 않거나 허용 목록에 없으면 접속 전에 실패한다 |
| Host Agents — Deploy All | `playbooks/host_agents.yml` | (없음) | `target_hosts` | 수동 | `target_hosts`로 지정(필수, 전체는 `servers` 입력), 한 번에 25%씩. otelcol과 restic 모두 설치·설정 |
| Host Agents — Config All | `playbooks/host_agents.yml` | `--tags agents_config` | `target_hosts` | 수동 | `target_hosts`로 지정(필수). otelcol과 restic **설정 모두** 재적용(설치·repo 초기화·등록 이벤트는 하지 않음) |
| Host Agents — Deploy Restic | `playbooks/host_agents.yml` | `--tags backup` | `target_hosts` | 수동 | `target_hosts`로 지정(필수), 한 번에 25%씩 (restic·resticprofile만 설치·설정) |
| Host Agents — Repo Maintenance | `playbooks/host_agents_maintenance.yml` | (없음) | (없음) | **스케줄** (§6) | `servers`의 repo (러너에서 실행) |
| OpenObserve — Config | `playbooks/openobserve_config.yml` | (없음) | (없음) | 수동 | localhost (OpenObserve API). Silent Host 로스터를 만들려고 `servers` 인벤토리를 읽는다 |
| Host Audit — Monthly | `playbooks/host_audit.yml` | `-e host_audit_run_kind=scheduled` | (없음 — 두지 않는다) | **스케줄** (§6) | `servers:loadbalancers:overseer` 전체 (Host Agents Exclusion 호스트 포함, `host_audit_excluded` 제외) |
| Host Audit — On-demand | `playbooks/host_audit.yml` | (없음) | `target_hosts`, `host_audit_mail_enabled`, `host_audit_storage_enabled` | 수동 | 위와 같음. `target_hosts`로 좁힐 수 있다 |
| Host Audit — Resend | `playbooks/host_audit_resend.yml` | (없음) | `host_audit_resend_run_id`, `host_audit_resend_month` | 수동 | localhost (Host Audit 버킷 → 메일) |

**실행 시 입력 (Survey variables)**

Semaphore v2.19의 Run 창에는 자유 형식 Extra variables 칸이 없다. Message, 템플릿이 허용한 Prompt(Limit 등), 템플릿에 정의한 **Survey variables**만 보인다. 실행할 때 넘길 변수는 템플릿 편집 → Survey Variables에 정의한다(값은 `--extra-vars`로 전달된다).

| 템플릿 | 변수 | 형식 | 기본값 | 필수 |
|---|---|---|---|---|
| Host Provisioning | `target_hosts` | String | (없음) | 예 |
| Host Provisioning | `target_admin_users` | String | 템플릿에 설정한 기본값(관리자 계정 JSON 목록) | 아니오 |
| Deploy All, Config All, Deploy Restic | `target_hosts` | String | (없음) | 예 |
| On-demand | `target_hosts` | String | (비움 = 전체) | 아니오 |
| On-demand | `host_audit_mail_enabled`, `host_audit_storage_enabled` | Enum `true`/`false` | `true` | 예 |
| Resend | `host_audit_resend_run_id` | String | (없음) | 예 |
| Resend | `host_audit_resend_month` | String `YYYY-MM` | (비움) | 아니오 |

- **Host Provisioning은 `playbooks/provision_hosts.yml`만 쓴다.** `site.yml`을 Semaphore 템플릿에 직접 연결하지 않는다. `site.yml` 직접 실행(기본 대상 `servers:loadbalancers`)은 CLI 전용이다. 인벤토리를 공용으로 쓰므로 대상 지정이 없으면 새로 추가된 서버까지 전부 프로비저닝되기 때문이다.
- Host Provisioning의 `target_hosts`는 인벤토리 호스트명을 쉼표로 구분한 문자열이다(예: `ns0001,ns0002`). `provision_hosts.yml`의 사전 검증(localhost)이 접속 전에 다음을 확인하고 어기면 한국어 메시지로 즉시 실패한다. 값이 없거나 비어 있음, 호스트 패턴(`:`, `!`, `&`, `*`)·공백·빈 항목, 인벤토리에 없는 이름, 그룹 이름(`all`·`servers`·`loadbalancers` 등), `provision_excluded` 소속 호스트(제외, 허용보다 우선), `provision_allowed`에 없는 호스트(그룹이 없거나 비어 있으면 모두 거부, 허용하려면 그룹에 넣고 끝나면 뺀다), 개수가 `provision_max_hosts`(기본 5)를 넘음. 더 많은 호스트를 한 번에 하려면 `provision_max_hosts`를 명시적으로 올린다(Environment 또는 API `environment`). 이 검증은 `--tags`로도 건너뛸 수 없다.
- Deploy All·Config All·Deploy Restic의 `target_hosts`는 **기본값이 없고 비워 둘 수 없다**(Survey 필수). 인벤토리가 공용이라 새 서버가 계속 추가되므로, 대상을 입력하지 않아 전체에 도는 일을 막는다. 전체에 적용하려면 `servers`를 직접 입력한다. `host_agents.yml`은 `target_hosts | default('servers')`라 빈 문자열이 넘어오면 대상 패턴이 깨지므로 Survey 필수가 이를 막는 장치다. Host Audit은 빈 값을 전체로 처리한다.
- **Config All이 하는 일**: otelcol 설정과 restic 설정을 모두 재적용한다. restic 설정 블록(`roles/backup/tasks/main.yml`)이 `agents_config`와 `backup` 두 태그를 모두 가져서, `--tags agents_config`가 두 에이전트의 설정을 함께 돌린다. 설치와 repo 초기화, 등록 이벤트는 Deploy All·Deploy Restic에만 있다.
- Monthly에는 Survey를 두지 않는다. 정기 실행은 항상 전체 대상·보관·발송이어야 Audit Baseline이 맞다.
- Survey에 없는 변수(아래의 `host_audit_mail_to`, `host_audit_drift_enabled`, `backup_maintenance_read_subset` 등)는 API로 실행할 때 `POST /api/project/<id>/tasks`의 `environment`(JSON 문자열)로 넘긴다. 자주 쓰게 되면 해당 템플릿 Survey에 추가한다.

**restic 백업만 적용할 때 (Host Agents — Deploy Restic)**

- Deploy에서 `backup` 역할만 실행한다. restic·resticprofile 바이너리 배포, 백업 설정, timer/cron, repo 초기화, `job=inventory` 이벤트까지 하고 otelcol은 건드리지 않는다. OS 프로브, OpenBao 입력 검증, 연결 해석·임시 개인키 정리는 `always` 태그라 함께 돈다.
- 멱등이라 백업 설정만 바꿨을 때도 이 템플릿을 다시 돌리면 된다. 이미 수렴한 설치·스케줄 단계는 `ok`로 지나간다.
- restic **설정만** 따로 돌리는 템플릿은 두지 않는다. `--tags agents_config,backup`은 교집합이 아니라 합집합이라 otel 설정과 restic 설치가 같이 돈다. `--tags agents_config --skip-tags otel`은 쓰지 않는다. `monitoring` 역할 전체가 `otel` 태그를 물려받아 `always`인 OS 프로브·입력 검증까지 건너뛰므로 backup이 입력 미정의로 실패한다.

**Host Audit — Monthly와 On-demand** ([host_audit.md](host_audit.md), ADR-0009)

- 둘은 같은 플레이북이고 실행 종류만 다르다. **Monthly의 결과만 Audit Baseline이 된다.** 다음 정기 실행이 이 결과와 비교해 신규·지속·해소·재발을 표시한다. On-demand(기본값 `on_demand`)는 보관·발송되지만 기준선이 되지 않는다.
- `host_audit_run_kind=scheduled`는 Monthly 템플릿의 CLI args에만 고정한다. On-demand의 CLI args·Survey에 넣지 않는다. 부분 대상(`target_hosts`)으로 돈 실행이 기준선이 되면 다음 정기 실행에서 나머지 호스트의 발견이 모두 '신규'로 나온다.
- Monthly 템플릿을 수동 **Run**하는 것은 그 달 정기 실행이 실패했을 때 다시 돌리는 경우만이다. 그 실행도 기준선이 된다.
- On-demand에서 쓸 수 있는 변수:
  - Survey `target_hosts`(예: `ns0266,ns0294`): 대상 좁히기(Inventory Hostname)
  - Survey `host_audit_mail_enabled`·`host_audit_storage_enabled`를 `false`로: 시험 실행. 보관을 끄면 비교하지 않고 러너 로컬에만 남는다
  - API `environment`만: `{"host_audit_mail_to": "a@example.com"}` 이번 실행만 수신자 덮어쓰기(로그에 나오지 않는다), `{"host_audit_drift_enabled": false}`·`{"host_audit_packages_enabled": false}` 해당 섹션 수집·판정 건너뛰기(정기 실행에는 쓰지 않는다)
- Host Audit은 `--check`로 돌리지 않는다. 그 자체가 읽기 전용이고, check 모드에서는 보관·발송을 하지 않는다.
- Variable Group은 §4의 것을 그대로 쓴다. Configuration Drift가 `site.yml`·Host Agents Config를 하위 실행하므로 AppRole이 Deploy·Config와 같은 KV 경로를 읽을 수 있어야 한다(§4 표).

**Host Audit 보고서 다시 보내기 (Host Audit — Resend)**

- 다시 점검하지 않고, 버킷에 보관된 실행의 보고서를 같은 첨부(같은 SHA-256)로 다시 보낸다. 메일 발송이 실패했거나 받는 사람을 추가할 때 쓴다.
- Survey `host_audit_resend_run_id`(예: `ha-20261031T220000Z`) — 실행 ID는 메일 제목 아래·본문 상단, 실패 메시지, Semaphore 로그(`AUD-003`)에 있다.
- 기본 형식(`ha-<UTC 시작 시각>`)이 아닌 실행 ID면 Survey `host_audit_resend_month`에 `2026-11`(KST 기준 실행 시작 월)을 함께 준다.
- 수신자는 지금의 OpenBao `agents/host_audit.mail_to`다(또는 `host_audit_mail_to`). 받은 보고서의 SHA-256이 보관된 요약의 값과 다르면 보내지 않는다.

**CIS 감사 파일럿 템플릿 삭제**

`playbooks/audit_rhel9_cis.yml`은 저장소에서 제거됐다(ADR-0009, #118). Semaphore에 이 플레이북을 가리키는 템플릿을 만들어 둔 적이 있으면 프로젝트 → Task Templates에서 해당 템플릿의 스케줄을 먼저 지우고 템플릿을 삭제한다. 남겨 두면 실행 시 플레이북을 찾지 못해 실패한다.

**특정 호스트만 실행할 때**

- Run 창의 Survey `target_hosts`에 `ns0266`처럼 넣는다(기본값이 없다. 전체는 `servers`를 직접 입력). 값은 FQDN이 아니라 Inventory Hostname이다. Limit 칸은 쓰지 않는다.
- `target_hosts`는 플레이북 안에서 `servers`와 교집합을 구한다. `servers`에 없는 이름을 넣으면 오류 없이 대상 0대로 끝난다.
- Limit을 템플릿에 고정하지 않는다. 고정해 두면 일부 호스트만 처리되고도 성공으로 표시된다. 스케줄로 도는 Repo Maintenance에서는 특히 주의한다.

**미리 보기**

- Config와 OpenObserve — Config는 CLI args에 `--check --diff`를 추가하면 바뀔 내용만 보여 준다. 별도 템플릿으로 두거나 실행할 때 추가한다.
- **OpenObserve — Config는 반영 전에 계획 전용으로 먼저 확인한다.** Semaphore에는 dry run이 없어 계획을 실행한 뒤에야 읽게 되므로, task `environment`에 `{"o2c_plan_only": true}`를 넣어 먼저 실행한다. OpenObserve를 읽고 계획(`O2C-013`)과 관리 밖 `infra-` 알림 줄(`unmanaged infra- alert on server (kept): …`)만 출력하고, 마지막에 `plan only: no changes were made`를 남긴 채 쓰기·주입 없이 정상 종료한다. 계획에서 `delete alert`가 의도한 폐기 알림뿐인지 확인한 뒤 `o2c_plan_only` 없이 다시 실행한다. 서버에서 지우는 알림은 역할 변수 `o2c_retired_alerts`에 이름이 있는 것뿐이다(접두어만으로는 지우지 않는다, [OpenObserve Config 명세](openobserve_config.md)).
- Repo Maintenance를 수동으로 돌릴 때 쓸 수 있는 변수(Survey가 없으므로 API `environment`로 넘긴다):
  - `{"backup_maintenance_read_subset": "always"}`: 10% 데이터 읽기 검사를 강제
  - `{"backup_maintenance_read_subset": "never"}`: 10% 데이터 읽기 검사를 생략

---

## 6. Schedule

### 6.1 Repo Maintenance

| 항목 | 값 |
|---|---|
| Template | Host Agents — Repo Maintenance |
| 의도한 시각 | 매일 05:00 **KST** |
| Cron | Semaphore 스케줄 시간대가 **Asia/Seoul**이면 `0 5 * * *`, 기본값인 **UTC**면 `0 20 * * *`(전날 20:00 UTC) |

- Semaphore 스케줄은 기본적으로 **UTC**로 계산한다. 서버 설정 `SEMAPHORE_SCHEDULE_TIMEZONE=Asia/Seoul`(또는 config의 `schedule.timezone`)로 바꿀 수 있다. 저장하기 전에 화면에 표시되는 **Next run**이 KST 05:00인지 확인한다.
- 매일 돌아도 10% 읽기 검사는 "첫째 일요일"에만 한다. 판정은 플레이북이 `backup_maintenance_timezone: Asia/Seoul` 기준 날짜로 하므로, 스케줄을 UTC 20:00으로 잡아도 KST 날짜로 맞게 판정된다.
- 호스트의 백업은 KST 02:00~03:59에 돈다. 그래서 05:00 유지보수와 겹치지 않는다.

### 6.2 Host Audit — Monthly

| 항목 | 값 |
|---|---|
| Template | Host Audit — Monthly |
| 의도한 시각 | 매월 1일 07:00 **KST** |
| Cron | Semaphore 스케줄 시간대가 **Asia/Seoul**이면 `0 7 1 * *`. 기본값인 **UTC**면 07:00 KST가 전달 말일 22:00 UTC라 표준 cron으로 표현할 수 없으므로 `0 0 1 * *`(1일 09:00 KST)로 잡는다 |

- 저장하기 전에 **Next run**이 KST 1일 07:00(또는 09:00)인지 확인한다. 보관 경로의 월(`<YYYY-MM>/`)은 KST 기준 실행 시작 월이다.
- 07:00은 호스트 백업(KST 02:00~03:59)과 Repo Maintenance(매일 05:00)가 끝난 뒤다. Configuration Drift 하위 실행이 대상 수에 비례해 오래 걸릴 수 있다(`host_audit_drift_timeout` 기본 3600초).
- **점검 주기**: ISMS 2.11.2(취약점 점검 및 조치)는 정기 점검을 요구한다. 내부 지침에는 **분기 1회 이상** 점검하고 결과를 결재·보관하도록 정하고, 그 이행 수단으로 **월 1회 자동 실행**(이 스케줄)을 둔다. 월 보고서 중 분기마다 최소 한 부는 결재란에 서명해 ISMS 증적 보관 위치에 둔다.

Deploy, Config, Backup, OpenObserve — Config, Host Audit — On-demand, Host Audit — Resend는 스케줄을 걸지 않는다.

---

## 7. 첫 실행 순서와 확인 포인트

| 순서 | 실행 | 확인 |
|---|---|---|
| 1 | Host Agents — Config All + `--check --diff` + `target_hosts=<1대>` | OpenBao 로그인과 KV 검증 통과(필수 키 누락 시 변경 전에 실패) |
| 2 | Host Agents — Deploy All + `target_hosts=<1대>` | otelcol 서비스 기동, repo 초기화, 마지막에 `job=inventory` 이벤트 전송 |
| 3 | Host Agents — Deploy All (전체) | 신규 호스트는 `site.yml`을 먼저 실행한 뒤 Deploy |
| 4 | Host Agents — Repo Maintenance (수동 Run) | `[BAK-087]` AppRole 로그인 → check → forget, `job=maintenance` 이벤트 |
| 5 | OpenObserve — Config + `--check` → 실제 실행 | VRL 함수, 파이프라인, 통지 대상, 알림 반영 |

OpenObserve에서 `backup_logs` 스트림에 `job=inventory`, `job=backup`(다음 날 새벽), `job=maintenance` 이벤트가 들어오는지 확인한다.

### 7.1 Host Audit 첫 실행

준비: RustFS `host-audit` 버킷과 전용 키([host_audit.md §11.5](host_audit.md#115-버킷-준비-운영자-1회)), OpenBao `agents/host_audit`의 보관 키·`mail_to`·`mail_from`(§4), [SMTP 릴레이 확보](https://github.com/ppzxc/infra-automation/issues/105).

| 순서 | 실행 | 확인 |
|---|---|---|
| 1 | On-demand + `target_hosts=<1대>` + `host_audit_storage_enabled=false` + `host_audit_mail_enabled=false` | 접속, 수집, 보고서 생성(`AUD-024` 경로). 4개 섹션이 모두 나오는지, 점검불가 사유 확인 |
| 2 | On-demand + `target_hosts=<1대>` | 버킷 `<YYYY-MM>/<run_id>/` 업로드, 메일 수신, 본문의 SHA-256 = 첨부 해시, 로그에 수신자 주소 0건 |
| 3 | Resend + `host_audit_resend_run_id=<2의 run_id>` | 같은 해시로 재발송 |
| 4 | On-demand(전체) | 실행 시간, 러너 메모리, CentOS 6/7·Host Agents Exclusion 호스트가 보고서에 있는지 |
| 5 | Configuration Drift 노이즈 정리 | [Configuration Drift 티켓](https://github.com/ppzxc/infra-automation/issues/124) 댓글의 절차(수렴 호스트에 두 번 실행, 남는 행은 고치거나 `host_audit_drift_ignore`) |
| 6 | Monthly 템플릿 수동 Run 1회 | 첫 Audit Baseline. 표지의 비교 기준이 '첫 실행', 버킷에 `baseline/<run_id>.json` 생성 |
| 7 | 다음 달 1일 스케줄 실행 | 비교 기준이 6의 run_id, 신규·지속·해소·재발 표시 |

첫 정기 보고서(6)는 출력해 검토·결재란에 서명하고 ISMS 증적 보관 위치에 둔다. 결과(run_id, 보관 경로)는 [Semaphore 구성과 첫 운영 실행 티켓](https://github.com/ppzxc/infra-automation/issues/127)에 기록한다.

---

## 8. 자주 겪는 문제

| 증상 | 원인 | 조치 |
|---|---|---|
| 수정을 머지했는데 로그에 예전 코드가 돈다(`Checkout repository to <예전 해시>`) | 실패한 태스크를 **Re-run**하면 원래 태스크의 커밋으로 다시 실행된다 | 템플릿 목록의 **Run**으로 새 태스크를 실행한다. 그래도 같으면 Repository Branch가 `main`인지 확인한다 |
| `OpenBao 자격증명 없음` | 템플릿에 Variable Group이 연결되지 않았거나 Secret이 비어 있다 | §4 확인 |
| `AppRole 로그인 실패(status=…)` | `VAULT_ADDR`/`VAULT_NAMESPACE`가 틀렸거나 secret_id가 만료됐다 | AppRole 재발급 |
| `OpenBao 조회 실패 — status=[200, 200, 403]` 등 | AppRole 정책에 해당 KV 경로가 없다 | §4 경로를 정책에 추가 |
| `유지보수 필수 입력 누락: agents/rustfs.maintenance_access_key` 등 | 표시된 키가 OpenBao에 없다. Maintenance 전용 키는 Deploy 성공으로 확인되지 않는다 | 표시된 경로에 키 등록 |
| `유지보수 필수 입력 누락: hosts/<host>/agents.restic_password` | Host Agents가 적용되지 않은 호스트다 | 적용 전이면 `host_agents_excluded` 그룹에 넣는다 |
| CentOS 6/7 업로드 실패(MON-109) | 러너에 `sshpass`가 없다 | 러너 이미지에 설치 |
| 대상이 0대로 끝난다 | `target_hosts`가 `servers` 밖이거나, FQDN으로 입력했거나, `host_agents_excluded`에 속한 호스트다 | Inventory Hostname으로 입력, 제외 그룹 확인 |
| Host Audit 보고서는 만들어졌는데 실행이 실패로 끝난다 | 보관(업로드·Audit Baseline 조회) 또는 메일 단계 실패. 보고서는 러너에 남고, 업로드됐다면 버킷에도 있다 | 로그의 `AUD-5xx`/`AUD-6xx` 메시지 확인. 메일만 실패했으면 Resend로 다시 보낸다 |
| Package Vulnerability가 매번 점검불가 | Trivy DB 갱신 실패 + 7일 이내 캐시 없음(러너 `HOME`이 실행마다 초기화) | DB 레지스트리 접근 확인, `host_audit_cache_dir`를 유지되는 경로로, 또는 `host_audit_trivy_db_repository`로 내부 미러 |
| 비교 기준이 매달 '첫 실행'으로 나온다 | 정기 실행이 실패해 `baseline/` 포인터가 생기지 않았거나, Monthly 템플릿에 `-e host_audit_run_kind=scheduled`가 빠졌다 | §5 Monthly CLI args 확인, 실패 원인 해결 후 Monthly 수동 Run |
