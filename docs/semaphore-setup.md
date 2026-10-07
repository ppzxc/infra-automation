# Semaphore 셋업 가이드 (Host Agents · OpenObserve)

> Semaphore UI에 Host Agents 템플릿 3개와 OpenObserve — Config를 등록하는 절차다. 값은 저장소 코드 기준이며, 시크릿은 모두 OpenBao에 두고 Git에는 두지 않는다.
> OpenBao 구조와 공통 접속 모듈은 [openbao_integration.md](openbao_integration.md), 배포 내용은 [Host Agents 배포 내역서](host-agents-deploy-inventory-simple.md)를 본다.

---

## 0. 등록 순서 요약

1. Key Store: Git 저장소 접근 키
2. Repository: `ppzxc/infra-automation`, branch `main`
3. Inventory: Static 인벤토리 (Semaphore UI에서 편집, `inventory/hosts.yml.example` 형식)
4. Variable Group(Environment): OpenBao 접속 값 (모든 템플릿 공용 1개)
5. Task Template 4개 (아래 §5)
6. Schedule: Repo Maintenance만 (주 1회)
7. 확인 실행: Config `--check` → Deploy(1대) → Deploy(전체) → Repo Maintenance → OpenObserve — Config

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

**Host Agents를 적용하지 않는 호스트**: Semaphore Static 인벤토리에서 `servers`에는 두되 `host_agents_excluded` 그룹에도 넣는다. Deploy·Config·Repo Maintenance가 모두 이 그룹을 뺀다. 템플릿의 Limit이나 `target_hosts`로 따로 빼지 않는다.

```yaml
all:
  children:
    servers:
      hosts:
        ns0266: {}
        ns0270: {}
    host_agents_excluded:   # Host Agents 미적용. 적용할 때 여기서 뺀다.
      hosts:
        ns0266: {}
```

---

## 4. Variable Group (Environment)

Host Agents 3개가 **같은 Variable Group 하나를 공유**한다. Repo Maintenance도 Deploy와 같은 AppRole로 로그인한다(BAK-087).

> **OpenObserve — Config는 AppRole 로그인을 하지 않고 `VAULT_TOKEN`만 쓴다**(O2C-001). 같은 Variable Group을 붙이되 `VAULT_TOKEN` Secret이 있어야 하며, 없으면 입력 누락으로 실패한다.

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
| `hosts/<host>`, `hosts/<host>/users/*`, `users/*` | Deploy, Config (SSH 접속) |
| `hosts/<host>/agents` | Deploy, Config, Repo Maintenance |
| `agents/openobserve` | Deploy, Config, Repo Maintenance, OpenObserve — Config |
| `agents/rustfs` | Deploy, Config, Repo Maintenance |

필요한 키 목록은 [배포 내역서 Full §5](host-agents-deploy-inventory-full.md#5-입력-openbao-kv-v2-git에는-시크릿-없음)를 본다. 템플릿별로 추가로 필요한 키는 다음과 같다.
- **Repo Maintenance**: `agents/rustfs`의 `maintenance_access_key`/`maintenance_secret_key`. 모든 `backup-prod-*` 버킷에서 삭제(prune)할 권한이 있어야 한다.
- **OpenObserve — Config**: `agents/openobserve`의 `api_user`/`api_password`, `alert_webhook_url`. 선택으로 `alert_webhook_token`.

---

## 5. Task Template

공통 설정: Inventory `inventory/hosts.yml`, Repository `infra-automation`, Variable Group은 §4의 것, **Limit은 비움**.

| 이름 | Playbook | CLI args | 실행 방식 | 대상 |
|---|---|---|---|---|
| Host Agents — Deploy | `playbooks/host_agents.yml` | (없음) | 수동 | `servers`, 한 번에 25%씩 |
| Host Agents — Config | `playbooks/host_agents.yml` | `--tags agents_config` | 수동 | `servers` |
| Host Agents — Repo Maintenance | `playbooks/host_agents_maintenance.yml` | (없음) | **스케줄** (§6) | `servers`의 repo (러너에서 실행) |
| OpenObserve — Config | `playbooks/openobserve_config.yml` | (없음) | 수동 | localhost (OpenObserve API) |

**특정 호스트만 실행할 때**

- 실행 시 Extra variables로 `{"target_hosts": "ns0266"}`을 넘긴다. 값은 FQDN이 아니라 Inventory Hostname이다.
- `target_hosts`는 플레이북 안에서 `servers`와 교집합을 구한다. `servers`에 없는 이름을 넣으면 오류 없이 대상 0대로 끝난다.
- Limit을 템플릿에 고정하지 않는다. 고정해 두면 일부 호스트만 처리되고도 성공으로 표시된다. 스케줄로 도는 Repo Maintenance에서는 특히 주의한다.

**미리 보기**

- Config와 OpenObserve — Config는 CLI args에 `--check --diff`를 추가하면 바뀔 내용만 보여 준다. 별도 템플릿으로 두거나 실행할 때 추가한다.
- Repo Maintenance를 수동으로 돌릴 때 쓸 수 있는 Extra variables:
  - `{"backup_maintenance_read_subset": "always"}`: 10% 데이터 읽기 검사를 강제
  - `{"backup_maintenance_read_subset": "never"}`: 10% 데이터 읽기 검사를 생략

---

## 6. Schedule (Repo Maintenance)

| 항목 | 값 |
|---|---|
| Template | Host Agents — Repo Maintenance |
| 의도한 시각 | 매주 일요일 05:00 **KST** |
| Cron | Semaphore 스케줄 시간대가 **Asia/Seoul**이면 `0 5 * * 0`, 기본값인 **UTC**면 `0 20 * * 6`(토요일 20:00 UTC) |

- Semaphore 스케줄은 기본적으로 **UTC**로 계산한다. 서버 설정 `SEMAPHORE_SCHEDULE_TIMEZONE=Asia/Seoul`(또는 config의 `schedule.timezone`)로 바꿀 수 있다. 저장하기 전에 화면에 표시되는 **Next run**이 KST 일요일 05:00인지 확인한다.
- "첫째 일요일" 판정(10% 읽기 검사)은 플레이북이 `backup_maintenance_timezone: Asia/Seoul` 기준 날짜로 한다. 스케줄을 UTC 토요일 20:00으로 잡아도 KST로는 일요일이라 판정이 맞다.
- 호스트의 백업은 KST 02:00~03:59에 돈다. 그래서 05:00 유지보수와 겹치지 않는다.

Deploy, Config, OpenObserve — Config는 스케줄을 걸지 않는다.

---

## 7. 첫 실행 순서와 확인 포인트

| 순서 | 실행 | 확인 |
|---|---|---|
| 1 | Host Agents — Config + `--check --diff` + `target_hosts=<1대>` | OpenBao 로그인과 KV 검증 통과(필수 키 누락 시 변경 전에 실패) |
| 2 | Host Agents — Deploy + `target_hosts=<1대>` | otelcol 서비스 기동, repo 초기화, 마지막에 `job=inventory` 이벤트 전송 |
| 3 | Host Agents — Deploy (전체) | 신규 호스트는 `site.yml`을 먼저 실행한 뒤 Deploy |
| 4 | Host Agents — Repo Maintenance (수동 Run) | `[BAK-087]` AppRole 로그인 → check → forget, `job=maintenance` 이벤트 |
| 5 | OpenObserve — Config + `--check` → 실제 실행 | VRL 함수, 파이프라인, 통지 대상, 알림 반영 |

OpenObserve에서 `backup_logs` 스트림에 `job=inventory`, `job=backup`(다음 날 새벽), `job=maintenance` 이벤트가 들어오는지 확인한다.

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
