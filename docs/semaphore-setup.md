# Semaphore 셋업 가이드 (Host Agents · OpenObserve · Host Audit)

> Semaphore UI에 Host Agents 템플릿 3개, OpenObserve — Config, Host Audit 템플릿 3개를 등록하는 절차다. 값은 저장소 코드 기준이며, 시크릿은 모두 OpenBao에 두고 Git에는 두지 않는다.
> OpenBao 구조와 공통 접속 모듈은 [openbao_integration.md](openbao_integration.md), 배포 내용은 [Host Agents 배포 내역서](host-agents-deploy-inventory-simple.md)를 본다.

---

## 0. 등록 순서 요약

1. Key Store: Git 저장소 접근 키
2. Repository: `ppzxc/infra-automation`, branch `main`
3. Inventory: Static 인벤토리 (Semaphore UI에서 편집, `inventory/hosts.yml.example` 형식)
4. Variable Group(Environment): OpenBao 접속 값 (모든 템플릿 공용 1개)
5. Task Template 7개 (아래 §5)
6. Schedule: Repo Maintenance(주 1회), Host Audit — Monthly(월 1회)
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
| `hosts/<host>`, `hosts/<host>/users/*`, `users/*` | Deploy, Config, Host Audit (SSH 접속) |
| `hosts/<host>/agents` | Deploy, Config, Repo Maintenance, Host Audit (Configuration Drift의 Config `--check` 하위 실행) |
| `agents/openobserve` | Deploy, Config, Repo Maintenance, OpenObserve — Config, Host Audit (Configuration Drift) |
| `agents/rustfs` | Deploy, Config, Repo Maintenance, Host Audit(엔드포인트) |
| `agents/host_audit` | Host Audit, Host Audit — Resend (전용 보관 키 `storage_access_key`/`storage_secret_key`, 선택 `storage_bucket`·`storage_endpoint`·`storage_region` — [host_audit.md §11](host_audit.md#11-보관과-audit-baseline-125); 메일 수신자 `mail_to`·발신자 `mail_from` — [host_audit.md §13](host_audit.md#13-메일-발송-126)) |

필요한 키 목록은 [배포 내역서 Full §5](host-agents-deploy-inventory-full.md#5-입력-openbao-kv-v2-git에는-시크릿-없음)를 본다. 템플릿별로 추가로 필요한 키는 다음과 같다.
- **Repo Maintenance**: `agents/rustfs`의 `maintenance_access_key`/`maintenance_secret_key`. 모든 `backup-prod-*` 버킷에서 삭제(prune)할 권한이 있어야 한다.
- **OpenObserve — Config**: `agents/openobserve`의 `api_user`/`api_password`, `alert_webhook_url`. 선택으로 `alert_webhook_token`.
- **Host Audit 메일**: `agents/host_audit`의 `mail_to`(받는 사람, 목록 또는 `,`·`;` 구분 문자열)와 `mail_from`(보내는 주소 1개). 주소는 개인정보라 저장소와 템플릿 Extra variables에 고정하지 않는다. 한 번만 다른 사람에게 보낼 때는 실행할 때 Extra variables `{"host_audit_mail_to": "a@example.com"}`로 덮어쓴다(값은 로그에 나오지 않는다).

---

## 5. Task Template

공통 설정: Inventory `inventory/hosts.yml`, Repository `infra-automation`, Variable Group은 §4의 것, **Limit은 비움**.

| 이름 | Playbook | CLI args | 실행 방식 | 대상 |
|---|---|---|---|---|
| Host Agents — Deploy | `playbooks/host_agents.yml` | (없음) | 수동 | `servers`, 한 번에 25%씩 |
| Host Agents — Config | `playbooks/host_agents.yml` | `--tags agents_config` | 수동 | `servers` |
| Host Agents — Repo Maintenance | `playbooks/host_agents_maintenance.yml` | (없음) | **스케줄** (§6) | `servers`의 repo (러너에서 실행) |
| OpenObserve — Config | `playbooks/openobserve_config.yml` | (없음) | 수동 | localhost (OpenObserve API) |
| Host Audit — Monthly | `playbooks/host_audit.yml` | `-e host_audit_run_kind=scheduled` | **스케줄** (§6) | `servers:loadbalancers:overseer` 전체 (Host Agents Exclusion 호스트 포함) |
| Host Audit — On-demand | `playbooks/host_audit.yml` | (없음) | 수동 | 위와 같음. `target_hosts`로 좁힐 수 있다 |
| Host Audit — Resend | `playbooks/host_audit_resend.yml` | (없음) | 수동 | localhost (Host Audit 버킷 → 메일) |

**Host Audit — Monthly와 On-demand** ([host_audit.md](host_audit.md), ADR-0009)

- 둘은 같은 플레이북이고 실행 종류만 다르다. **Monthly의 결과만 Audit Baseline이 된다.** 다음 정기 실행이 이 결과와 비교해 신규·지속·해소·재발을 표시한다. On-demand(기본값 `on_demand`)는 보관·발송되지만 기준선이 되지 않는다.
- `host_audit_run_kind=scheduled`는 Monthly 템플릿의 CLI args에만 고정한다. On-demand에 넣거나 Extra variables로 넘기지 않는다. 부분 대상(`target_hosts`)으로 돈 실행이 기준선이 되면 다음 정기 실행에서 나머지 호스트의 발견이 모두 '신규'로 나온다.
- Monthly 템플릿을 수동 **Run**하는 것은 그 달 정기 실행이 실패했을 때 다시 돌리는 경우만이다. 그 실행도 기준선이 된다.
- On-demand에서 쓸 수 있는 Extra variables:
  - `{"target_hosts": "ns0266,ns0270"}`: 대상 좁히기(Inventory Hostname)
  - `{"host_audit_mail_to": "a@example.com"}`: 이번 실행만 수신자 덮어쓰기(로그에 나오지 않는다)
  - `{"host_audit_mail_enabled": false}`, `{"host_audit_storage_enabled": false}`: 시험 실행. 보관을 끄면 비교하지 않고 러너 로컬에만 남는다
  - `{"host_audit_drift_enabled": false}`, `{"host_audit_packages_enabled": false}`: 해당 섹션 수집·판정을 건너뛴다(정기 실행에는 쓰지 않는다)
- Host Audit은 `--check`로 돌리지 않는다. 그 자체가 읽기 전용이고, check 모드에서는 보관·발송을 하지 않는다.
- Variable Group은 §4의 것을 그대로 쓴다. Configuration Drift가 `site.yml`·Host Agents Config를 하위 실행하므로 AppRole이 Deploy·Config와 같은 KV 경로를 읽을 수 있어야 한다(§4 표).

**Host Audit 보고서 다시 보내기 (Host Audit — Resend)**

- 다시 점검하지 않고, 버킷에 보관된 실행의 보고서를 같은 첨부(같은 SHA-256)로 다시 보낸다. 메일 발송이 실패했거나 받는 사람을 추가할 때 쓴다.
- Extra variables `{"host_audit_resend_run_id": "ha-20261031T220000Z"}` — 실행 ID는 메일 제목 아래·본문 상단, 실패 메시지, Semaphore 로그(`AUD-003`)에 있다.
- 기본 형식(`ha-<UTC 시작 시각>`)이 아닌 실행 ID면 `"host_audit_resend_month": "2026-11"`(KST 기준 실행 시작 월)을 함께 준다.
- 수신자는 지금의 OpenBao `agents/host_audit.mail_to`다(또는 `host_audit_mail_to`). 받은 보고서의 SHA-256이 보관된 요약의 값과 다르면 보내지 않는다.

**CIS 감사 파일럿 템플릿 삭제**

`playbooks/audit_rhel9_cis.yml`은 저장소에서 제거됐다(ADR-0009, #118). Semaphore에 이 플레이북을 가리키는 템플릿을 만들어 둔 적이 있으면 프로젝트 → Task Templates에서 해당 템플릿의 스케줄을 먼저 지우고 템플릿을 삭제한다. 남겨 두면 실행 시 플레이북을 찾지 못해 실패한다.

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

## 6. Schedule

### 6.1 Repo Maintenance

| 항목 | 값 |
|---|---|
| Template | Host Agents — Repo Maintenance |
| 의도한 시각 | 매주 일요일 05:00 **KST** |
| Cron | Semaphore 스케줄 시간대가 **Asia/Seoul**이면 `0 5 * * 0`, 기본값인 **UTC**면 `0 20 * * 6`(토요일 20:00 UTC) |

- Semaphore 스케줄은 기본적으로 **UTC**로 계산한다. 서버 설정 `SEMAPHORE_SCHEDULE_TIMEZONE=Asia/Seoul`(또는 config의 `schedule.timezone`)로 바꿀 수 있다. 저장하기 전에 화면에 표시되는 **Next run**이 KST 일요일 05:00인지 확인한다.
- "첫째 일요일" 판정(10% 읽기 검사)은 플레이북이 `backup_maintenance_timezone: Asia/Seoul` 기준 날짜로 한다. 스케줄을 UTC 토요일 20:00으로 잡아도 KST로는 일요일이라 판정이 맞다.
- 호스트의 백업은 KST 02:00~03:59에 돈다. 그래서 05:00 유지보수와 겹치지 않는다.

### 6.2 Host Audit — Monthly

| 항목 | 값 |
|---|---|
| Template | Host Audit — Monthly |
| 의도한 시각 | 매월 1일 07:00 **KST** |
| Cron | Semaphore 스케줄 시간대가 **Asia/Seoul**이면 `0 7 1 * *`. 기본값인 **UTC**면 07:00 KST가 전달 말일 22:00 UTC라 표준 cron으로 표현할 수 없으므로 `0 0 1 * *`(1일 09:00 KST)로 잡는다 |

- 저장하기 전에 **Next run**이 KST 1일 07:00(또는 09:00)인지 확인한다. 보관 경로의 월(`<YYYY-MM>/`)은 KST 기준 실행 시작 월이다.
- 07:00은 호스트 백업(KST 02:00~03:59)과 Repo Maintenance(일요일 05:00)가 끝난 뒤다. Configuration Drift 하위 실행이 대상 수에 비례해 오래 걸릴 수 있다(`host_audit_drift_timeout` 기본 3600초).
- **점검 주기**: ISMS 2.11.2(취약점 점검 및 조치)는 정기 점검을 요구한다. 내부 지침에는 **분기 1회 이상** 점검하고 결과를 결재·보관하도록 정하고, 그 이행 수단으로 **월 1회 자동 실행**(이 스케줄)을 둔다. 월 보고서 중 분기마다 최소 한 부는 결재란에 서명해 ISMS 증적 보관 위치에 둔다.

Deploy, Config, OpenObserve — Config, Host Audit — On-demand, Host Audit — Resend는 스케줄을 걸지 않는다.

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
