# Backup Role Task Specification

> **상태: 구현됨(modern, legacy_el7, legacy_el6 경로 + 중앙 Repo Maintenance).** `backup` 역할은 [ADR-0006 Host Agents](adr/0006-host-agents-otelcol-resticprofile.md)에 따라 `restic` + `resticprofile`로 `servers` 그룹 전체의 설정 파일을 RustFS(S3 API)에 백업합니다. 항상 `monitoring`(otelcol)과 함께 `playbooks/host_agents.yml`로만 배포됩니다.

---

## 1. 개요 및 구현 기능 (What)

- **바이너리 배포**: 컨트롤러가 다운로드·SHA256 검증한 `restic`/`resticprofile`을 버전 디렉터리(`/opt/host-agents/<agent>/<version>/`)에 배치하고 `/usr/local/bin` symlink로 활성화 (ADR-0006 §2.8).
- **호스트별 저장소**: RustFS에 **호스트마다 전용 버킷**(규칙 `backup-prod-<호스트명>`, `hosts/<host>/agents`의 `rustfs_bucket`으로 재정의)과 그 버킷 루트의 전용 repo, 호스트 전용 백업 키(삭제는 `locks/*`만)와 비밀번호 (§2.5). 스냅샷 `host` 라벨은 OS hostname이 아닌 Inventory Hostname(`nsXXXX`)으로 고정(프로파일 `backup.host`).
- **일일 백업 스케줄**: systemd timer(`Persistent=true`) 또는 `/etc/cron.d/host-agents-backup`(CentOS 6/7, Rocky 8), 02:00–03:59 호스트별 고정 분.
- **백업 결과 방출**: status-file + `/var/log/host-agents/backup.jsonl` → otelcol → OpenObserve `backup_logs` (§2.6).
- **중앙 유지보수**: `check` / `forget --prune`은 호스트가 아닌 Semaphore "Host Agents — Repo Maintenance" 템플릿이 컨트롤러에서 실행 (§7).

---

## 2. 왜 구현해야 하는가? (Why)

1. **ISMS 2.9.3 백업 및 복구관리**: 백업 대상·주기·방법·보관기간·소산 절차를 정의하고 이행 증적(`backup_logs`, Semaphore 이력, 분기 복구 테스트 결과서)을 남깁니다.
2. **랜섬웨어 내성**: Object Lock을 사용할 수 없으므로(RustFS 제약) 백업 전용 호스트 키로 호스트 침해 시에도 스냅샷 삭제를 막습니다.

---

## 3. 백업 표준 (ISMS)

| 구분 | 경로 / 값 |
|---|---|
| 필수(제외 불가) | `/etc`, `/var/spool/cron`, `/usr/local/bin`, `/usr/local/etc`, `/usr/local/sbin` |
| 조건부 표준 | `/opt/services` (존재 시) |
| 선택 (`backup_extra_paths`) | `/root`, `/home`, `/data` 등 |
| 제외 | `/home/*/.cache`, `**/node_modules`, `*.tmp`, `*.swp`, `/etc/restic/password`, `--exclude-caches` |
| 주기 / RPO | 1일 1회 / 24h |
| 보존 | daily 7, weekly 4, monthly 12 |
| 무결성 | 주 1회 `check`, 월 1회 `check --read-data-subset=10%`, 실패 시 prune 차단 (중앙) |
| 로그 | `/var/log` 제외 — OpenObserve 전송이 로그 백업 |
| 소산 | 서버 측 S3→S3 원격 복제 (전제조건) |
| 복구 테스트 | 분기 1회, ADR-0006 §2.11 runbook |

호스트별 오버라이드(`hosts/<host>/agents`): `backup_extra_paths`, `backup_exclude_paths`(필수 경로 제외 불가), `backup_pre_hooks`(DB 덤프 등 `run-before`).

---

## 4. 무엇을 변경하는가? (What Changes)

- 📁 `/opt/host-agents/{restic,resticprofile}/<version>/`, `/usr/local/bin/{restic,resticprofile}` (symlink)
- 🔐 `/etc/restic/` (`0700`): `env`(RustFS 키, `diff: false`), `password`(`0600`), `profiles.yaml`
- ⏰ `host-agents-backup.service` + `.timer` 또는 `/etc/cron.d/host-agents-backup`
- 📝 `/var/lib/host-agents/restic-status.json`, `/var/log/host-agents/backup.jsonl`, `/usr/local/sbin/host-agents-backup-event`, `/etc/logrotate.d/host-agents-backup` (§6)

---

## 5. 태스크 매트릭스 (Task Matrix)

구현된 태스크만 이 표에 기재합니다(3-Way 검증기 `MISSING IN CODE` 방지). 계획 매트릭스는 [ADR-0006 §3](adr/0006-host-agents-otelcol-resticprofile.md#3-계획-태스크-매트릭스-구현-시-docsmd로-이관)을 참조하고, 구현 커밋에서 `BAK-0xx`(modern) / `BAK-1xx`(legacy_el6) / `BAK-2xx`(legacy_el7, 그리고 CentOS 6과 공유하는 legacy 태스크) 행을 이관합니다. backup은 CentOS 6/7 차이가 버전 행뿐이라 `tasks/legacy.yml` 하나를 공유하며 `BAK-1xx`(CentOS 6 전용) 태스크는 없습니다.

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `BAK-001` | `Load the shared Host Agents version table and constants from monitoring` | `ansible.builtin.include_vars` | All | 읽기 전용 (버전·체크섬 표 단일 출처 `monitoring/vars/main.yml`, `tags: always`) |
| `BAK-003` | `Deliver pinned restic binary` | `ansible.builtin.include_tasks` | All | 컨트롤러 캐시(.bz2 → `MON-055`) + SHA256 검증 후 버전 디렉터리 푸시 (`MON-040`~`049`) |
| `BAK-004` | `Deliver pinned resticprofile binary` | `ansible.builtin.include_tasks` | All | `no_self_update` 빌드 tarball + SHA256 검증 후 버전 디렉터리 푸시 (`MON-040`~`049`) |
| `BAK-010` | `Assert RustFS endpoint and bucket are configured` | `ansible.builtin.assert` | All | 읽기 전용 (엔드포인트가 비어 있거나 끝 슬래시/형식 오류, 버킷 이름이 `[A-Za-z0-9._-]{3,63}`이 아니면 호스트 실패) |
| `BAK-011` | `Check which conditional standard backup paths exist` | `ansible.builtin.stat` | All | 읽기 전용, `check_mode: false` (`/opt/services` 존재 시에만 백업 대상에 포함) |
| `BAK-012` | `Derive repository, source list, excludes and schedule` | `ansible.builtin.set_fact` | All | 순수 함수 (repo = `s3:<endpoint>/<bucket>`(버킷은 호스트 전용, 루트에 repo), 필수 경로 + 조건부 + `backup_extra_paths`, CentOS 6/7·Rocky 8은 cron, restic 경로는 `host_agents_version_row` 행) |
| `BAK-013` | `Derive the scheduled hour/minute and run command` | `ansible.builtin.set_fact` | All | 순수 함수 (`random(seed=inventory_hostname)`으로 02:00~03:59 고정 분, `unlock` 후 `backup`) |
| `BAK-020` | `Ensure restic config directory exists (0700)` | `ansible.builtin.file` | All | 디렉터리 존재 시 `ok` (`/etc/restic`, `0700`) |
| `BAK-021` | `Ensure restic cache directory exists (0700)` | `ansible.builtin.file` | All | 디렉터리 존재 시 `ok` (`/var/cache/restic`) |
| `BAK-022` | `Deploy restic credentials env file (0600, no_log, no diff)` | `ansible.builtin.template` | All | Checksum 비교 (`no_log`, `diff: false`, `0600`) |
| `BAK-023` | `Deploy restic repository password file (0600, no_log, no diff)` | `ansible.builtin.copy` | All | Checksum 비교 (`no_log`, `diff: false`, `0600`) |
| `BAK-024` | `Deploy resticprofile profile (validated with resticprofile show)` | `ansible.builtin.template` | All | Checksum 비교; 새 바이너리의 `resticprofile show`가 통과해야 교체 (시크릿 미포함, `backup.host` = Inventory Hostname) |
| `BAK-025` | `Ensure backup result directories exist (log 0755, state 0755)` | `ansible.builtin.file` | All | 디렉터리 존재 시 `ok` (`/var/log/host-agents`, `/var/lib/host-agents`) |
| `BAK-026` | `Deploy the backup result hook (POSIX sh, one JSON line per run)` | `ansible.builtin.copy` | All | Checksum 비교 (`0755`, POSIX 도구만 — jq 없음) |
| `BAK-027` | `Deploy logrotate configuration for backup.jsonl` | `ansible.builtin.template` | All | Checksum 비교 (`/etc/logrotate.d/host-agents-backup`, 주간·8회·`create 0640`) |
| `BAK-030` | `Switch restic install symlink to the delivered version` | `ansible.builtin.include_tasks` | All | 설정 검증 후 symlink 교체 (`MON-050`~`053`) |
| `BAK-031` | `Switch resticprofile install symlink to the delivered version` | `ansible.builtin.include_tasks` | All | 설정 검증 후 symlink 교체 (`MON-050`~`053`) |
| `BAK-040` | `Deploy backup systemd service` | `ansible.builtin.template` | Rocky 9/10, Ubuntu, Debian | Checksum 비교 (`ProtectSystem=strict`, 쓰기는 restic 캐시와 `backup_hook_write_paths`(기본 `/var/backups`)만) |
| `BAK-041` | `Deploy backup systemd timer (Persistent=true)` | `ansible.builtin.template` | Rocky 9/10, Ubuntu, Debian | Checksum 비교 (`Persistent=true`) |
| `BAK-042` | `Apply pending systemd reload before enabling the timer` | `ansible.builtin.meta` | Rocky 9/10, Ubuntu, Debian | `flush_handlers` (유닛 변경 시에만 `daemon-reload`) |
| `BAK-043` | `Enable and start the backup timer` | `ansible.builtin.systemd` | Rocky 9/10, Ubuntu, Debian | 상태 비교 (check 모드 제외) |
| `BAK-044` | `Deploy backup cron.d schedule (Rocky 8 and non-systemd hosts)` | `ansible.builtin.template` | Rocky 8 | Checksum 비교 (`/etc/cron.d/host-agents-backup`) |
| `BAK-045` | `Remove the cron.d schedule on systemd-timer hosts` | `ansible.builtin.file` | Rocky 9/10, Ubuntu, Debian | `state: absent` (스케줄러 이중 실행 방지) |
| `BAK-050` | `Probe whether the restic repository exists (restic cat config)` | `ansible.builtin.shell` | All | 읽기 전용 (`changed_when: false`, check 모드에서는 건너뜀(바이너리가 아직 없을 수 있음), Deploy 한정 — `agents_config` 제외) |
| `BAK-051` | `Fail when the repository probe errors for a reason other than a missing repository` | `ansible.builtin.assert` | All | 읽기 전용 (저장소 부재가 아닌 오류에서는 init하지 않고 실패) |
| `BAK-052` | `Initialize the restic repository when it does not exist` | `ansible.builtin.shell` | All | 프로브 결과 조건 (저장소가 없을 때만 `init`) |
| `BAK-060` | `Assert the controller OpenObserve ingestion token exists` | `ansible.builtin.assert` | All | 읽기 전용 (`no_log`, Deploy 한정 — 토큰 또는 `o2_endpoint` 없으면 호스트 실패) |
| `BAK-061` | `Emit the job=inventory event to backup_logs` | `ansible.builtin.uri` | All (controller) | Deploy 마지막 태스크이자 한정(`agents_config` 제외, check 모드 제외). 실행마다 이벤트 1건 전송(`changed`) |
| `BAK-070` | `Load the shared Host Agents version table and constants from monitoring` | `ansible.builtin.include_vars` | Controller | 읽기 전용 (고정 restic 버전·체크섬의 단일 출처 — 별도 버전 표 없음) |
| `BAK-071` | `Fetch maintenance KV from OpenBao (hosts/<hostname>/agents, agents/openobserve, agents/rustfs)` | `ansible.builtin.uri` | Controller | GET, `check_mode: false`, `no_log` |
| `BAK-072` | `Resolve and assert the maintenance inputs (repo password, maintenance key, controller token)` | `ansible.builtin.block` | Controller | 읽기 전용 (`no_log`; 비밀번호·유지보수 키·컨트롤러 토큰·엔드포인트 누락 시 해당 호스트 실패) |
| `BAK-073` | `Detect the controller architecture for the pinned restic` | `ansible.builtin.command` | Controller | 읽기 전용 (`uname -m`, `run_once`) |
| `BAK-074` | `Resolve the controller restic paths from the pinned version table` | `ansible.builtin.set_fact` | Controller | 순수 함수 (`run_once`, Deploy와 같은 캐시 경로) |
| `BAK-075` | `Download the pinned restic release on the controller and verify SHA256` | `ansible.builtin.get_url` | Controller | 체크섬 일치 시 `ok` (`run_once`) |
| `BAK-076` | `Decompress restic into the shared controller cache` | `ansible.builtin.shell` | Controller | `creates:` 가드 (임시 파일 후 `mv`) |
| `BAK-077` | `Derive repository and the monthly read-subset decision` | `ansible.builtin.set_fact` | Controller | 순수 함수 (repo = `s3:<endpoint>/<bucket>/<host>`, 월간 read-subset 판정) |
| `BAK-078` | `Run restic check` | `ansible.builtin.command` | Controller | 읽기 전용 (`changed_when: false`, `failed_when: false` — 결과는 이벤트와 최종 판정에서 처리) |
| `BAK-079` | `Run restic check --read-data-subset (first Sunday of the month)` | `ansible.builtin.command` | Controller | 읽기 전용, 첫째 일요일(또는 `backup_maintenance_read_subset=always`)에만 실행 |
| `BAK-080` | `Run restic forget --prune only when every check succeeded` | `ansible.builtin.command` | Controller | 모든 check 성공 시에만 실행 (실패 호스트는 prune 차단), `--retry-lock`, 강제 unlock 없음 |
| `BAK-081` | `Build the job=maintenance events (host x command)` | `ansible.builtin.set_fact` | Controller | 순수 함수 (건너뛴 명령은 이벤트 없음) |
| `BAK-082` | `Post the job=maintenance events to backup_logs` | `ansible.builtin.uri` | Controller | 호스트당 1회 전송(`changed`), 컨트롤러 토큰, 인증서 기본 검증 |
| `BAK-084` | `Ensure the controller restic cache directory exists` | `ansible.builtin.file` | Controller | 디렉터리 존재 시 `ok` (`0755`, `run_once`) |
| `BAK-085` | `Derive the restic environment from the repository` | `ansible.builtin.set_fact` | Controller | 순수 함수 (`no_log`; 시크릿은 `environment`로만 전달) |
| `BAK-086` | `Assert the controller architecture is supported` | `ansible.builtin.assert` | Controller | 읽기 전용 (`x86_64`/`aarch64`만 — 고정 릴리스에 없는 아키텍처는 명확한 메시지로 실패) |
| `BAK-087` | `Log in to OpenBao with AppRole when no token is given (same as resolve_connection.yml)` | `ansible.builtin.uri` | Controller | POST `auth/approle/login`, `run_once`, `no_log`, `check_mode: false` — 토큰 미지정 + `VAULT_ROLE_ID`/`VAULT_SECRET_ID`가 있을 때만 (Deploy와 같은 Semaphore Environment) |
| `BAK-088` | `Use the AppRole client token for the maintenance KV lookups` | `ansible.builtin.set_fact` | Controller | 순수 함수 (`no_log`; 발급 토큰을 BAK-071이 우선 사용) |
| `BAK-083` | `Fail the host when any maintenance command failed` | `ansible.builtin.assert` | Controller | 이벤트 전송 뒤 판정(전송 실패도 실패로 처리) — 한 호스트라도 실패하면 Semaphore 실행 실패 |

---
| `BAK-201` | `Check which conditional standard backup paths exist (raw, read-only)` | `ansible.builtin.raw` | legacy_el6, legacy_el7 | `changed_when: false`, `check_mode: false` (`raw_exists_cmd`) |
| `BAK-202` | `Present the raw probe like the modern stat results` | `ansible.builtin.set_fact` | legacy_el6, legacy_el7 | 순수 함수 (`BAK-012`가 modern과 같은 식으로 소비) |
| `BAK-203` | `Ensure restic and result directories exist (raw)` | `ansible.builtin.raw` | legacy_el6, legacy_el7 | `raw_dir_cmd` sentinel (`0700`/`0700`/`0755`/`0755`) |
| `BAK-204` | `Deploy restic credentials env file (raw, 0600, no_log, no diff)` | `ansible.builtin.import_tasks` | legacy_el6, legacy_el7 | ADR-0005 sentinel, `_raw_secret` (`no_log`, check 모드에서도 내용 비노출) |
| `BAK-205` | `Deploy restic repository password file (raw, 0600, no_log, no diff)` | `ansible.builtin.import_tasks` | legacy_el6, legacy_el7 | ADR-0005 sentinel, `_raw_secret` (`no_log`) |
| `BAK-206` | `Deploy the backup result hook (raw, POSIX sh, one JSON line per run)` | `ansible.builtin.import_tasks` | legacy_el6, legacy_el7 | sentinel (modern과 같은 `host-agents-backup-event.sh`, 마지막 개행 포함) |
| `BAK-207` | `Deploy logrotate configuration for backup.jsonl (raw)` | `ansible.builtin.import_tasks` | legacy_el6, legacy_el7 | sentinel |
| `BAK-208` | `Deploy resticprofile profile (raw, validated with resticprofile show)` | `ansible.builtin.import_tasks` | legacy_el6, legacy_el7 | sentinel + 새 resticprofile로 `show` 검증(BAK-024와 같은 명령). modern과 같은 템플릿 렌더링 결과 — `host_agents_version_row` 행의 resticprofile(CentOS 6은 0.29.1 + restic 0.17.3에서 `show` 통과 확인) |
| `BAK-209` | `Deliver pinned restic binary (raw)` | `ansible.builtin.include_tasks` | legacy_el6, legacy_el7 | 컨트롤러 캐시 → scp, 원격 sha256sum 불일치 시에만 실행, `version` 스모크 테스트 — `host_agents_version_row` 행(CentOS 6은 0.17.3) |
| `BAK-210` | `Deliver pinned resticprofile binary (raw)` | `ansible.builtin.include_tasks` | legacy_el6, legacy_el7 | 컨트롤러 캐시 → scp, 원격 sha256sum 불일치 시에만 실행, `version` 스모크 테스트 — `host_agents_version_row` 행(CentOS 6은 0.29.1) |
| `BAK-211` | `Switch restic install symlink to the delivered version (raw)` | `ansible.builtin.include_tasks` | legacy_el6, legacy_el7 | `MON-212` 헬퍼 (readlink sentinel) |
| `BAK-212` | `Switch resticprofile install symlink to the delivered version (raw)` | `ansible.builtin.include_tasks` | legacy_el6, legacy_el7 | `MON-212` 헬퍼 (readlink sentinel) |
| `BAK-213` | `Deploy backup cron.d schedule (raw)` | `ansible.builtin.import_tasks` | legacy_el6, legacy_el7 | sentinel (`/etc/cron.d/host-agents-backup`, `0644`). 템플릿은 modern cron.d와 동일 |
| `BAK-215` | `Probe whether the restic repository exists (raw, restic cat config)` | `ansible.builtin.raw` | legacy_el6, legacy_el7 | `changed_when: false`, `check_mode: false`, `LC_ALL=C`, `no_log`, Deploy 한정 |
| `BAK-216` | `Fail when the repository probe errors for a reason other than a missing repository` | `ansible.builtin.assert` | legacy_el6, legacy_el7 | 읽기 전용 (BAK-051과 같은 rc/메시지 판정) |
| `BAK-217` | `Initialize the restic repository when it does not exist (raw)` | `ansible.builtin.raw` | legacy_el6, legacy_el7 | 프로브 결과 조건 (저장소가 없을 때만 `init`), `no_log` |

## 6. 백업 관측성 및 알림 계약 (ADR-0006 §2.6)

호스트는 `resticprofile`의 `run-finally` 훅(`/usr/local/sbin/host-agents-backup-event`)으로 `/var/log/host-agents/backup.jsonl`에 실행마다 한 줄 JSON을 추가하고(`status-file`은 `/var/lib/host-agents/restic-status.json`), `monitoring`의 otelcol이 `json_parser`(본문 원문 유지, 필드는 attributes로 파싱, `ts`를 이벤트 시각으로 사용)로 읽어 OpenObserve `backup_logs` 스트림(보존 1년)으로 보냅니다. 서버 측 알림은 아래 **고정 필드명**만 사용합니다.

| 이벤트 | 발생원 | 필드 |
|---|---|---|
| `job=backup` | 호스트 훅 | `job`, `host`, `command`(`backup`), `success`(bool), `exit_code`, `duration`(초), `error`(실패 시 마지막 오류 요약, ≤500자), `ts`(UTC ISO8601) |
| `job=maintenance` | 중앙 Repo Maintenance(후속 티켓) | `job`, `host`, `command`(`check`/`forget`…), `success`, `duration`, `error` |
| `job=inventory` | Deploy 종료 시 컨트롤러(`BAK-061`, Config 제외; OpenBao `agents/openobserve`의 `controller_ingest_token`으로 인증, 인증서는 기본 검증) | `job`, `host`, `deployed_at`(UTC ISO8601) |

표준 알림:

| 알림 | 조건 |
|---|---|
| 백업 실패 | `job=backup` 이고 `success=false` — 즉시 |
| 백업 누락 | 호스트별 마지막 `job=backup`·`success=true`가 **26h** 초과 |
| 무결성 검사 실패 | `job=maintenance`, `command=check`, `success=false` |
| 유지보수 누락 | 호스트별 마지막 `command=check`가 **8일** 초과 |
| 수집 중단 | 호스트 `hostmetrics` 메트릭 부재 **15분** |
| 미실행 호스트 | `job=inventory` 등록 후 `job=backup` 이벤트가 없음 |

---

## 7. 중앙 Repo Maintenance 런북 (ADR-0006 §2.5)

`playbooks/host_agents_maintenance.yml`(`roles/backup/tasks/maintenance.yml`)는 호스트에 접속하지 않고 컨트롤러에서 `servers` 호스트별 repo를 유지보수합니다.

**Semaphore 템플릿 "Host Agents — Repo Maintenance"**

| 항목 | 값 |
|---|---|
| Playbook | `playbooks/host_agents_maintenance.yml` |
| 스케줄 | 매주 일요일 05:00 (`0 5 * * 0`) |
| Environment | `VAULT_ADDR`, `VAULT_TOKEN`(또는 `vault_token`), 선택 `VAULT_NAMESPACE`/`VAULT_MOUNT` — 시크릿은 Git에 두지 않음 |
| 수동 실행 | `-e target_hosts=<host>`(1대), `-e backup_maintenance_read_subset=always\|never` |

**호스트별 순서**: `check` → (첫째 일요일(`backup_maintenance_timezone`, 기본 Asia/Seoul 기준 달력일) 또는 `always`) `check --read-data-subset=10%` → 모든 check가 성공한 경우에만 `forget --keep-daily 7 --keep-weekly 4 --keep-monthly 12 --prune`. `check`가 실패한 호스트는 `prune`을 건너뜁니다(데이터 삭제 차단). 강제 `unlock`은 하지 않고 `--retry-lock 30m`만 사용합니다.

**OpenBao 입력**: `hosts/<host>/agents`의 `restic_password`(호스트별 repo 비밀번호), `agents/rustfs`의 `maintenance_access_key`/`maintenance_secret_key`(RustFS 유지보수 키 — `forget`/`prune`의 삭제 권한 보유), `agents/openobserve`의 `controller_ingest_token`. `o2_endpoint`/`rustfs_endpoint`는 Extra variables 또는 `group_vars`가 우선이고, 없으면 `agents/openobserve`의 `o2_endpoint`/`o2_org`, `agents/rustfs`의 `rustfs_endpoint`를 씁니다. 버킷은 Extra variables > `hosts/<host>/agents`의 `rustfs_bucket` > 규칙 `<rustfs_bucket_prefix>_<호스트명>`(기본 `backup-prod-ns****`)이며 공용 `agents/rustfs`의 `rustfs_bucket`은 쓰지 않습니다(Deploy와 같은 해석). 유지보수 키는 모든 호스트 버킷(`backup-prod-*`)에 접근할 수 있어야 합니다. 사설 CA는 컨트롤러 신뢰 저장소에 등록하거나 `backup_maintenance_ca_file`로 지정합니다.

**restic 바이너리**: Deploy와 같은 고정 버전·체크섬(`monitoring/vars/main.yml`)을 컨트롤러 캐시(`host_agents_cache_dir`)에서 사용합니다.

**이벤트**: 호스트×명령마다 `job=maintenance` 이벤트(`host`, `command`(`check`/`forget`), `success`, `duration`, `error`)를 `backup_logs`로 전송하며(§6), 실패 호스트가 하나라도 있으면 Semaphore 실행이 실패합니다. 8일 이상 `check` 이벤트가 없으면 "유지보수 누락" 알림이 발생하므로 Semaphore 스케줄 자체의 중단도 감지됩니다.
