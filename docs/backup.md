# Backup Role Task Specification

> **상태: 구현됨(modern 경로).** legacy_el6/el7 경로·결과 방출(status-file/jsonl/logrotate)·중앙 유지보수는 후속 티켓입니다. `backup` 역할은 [ADR-0006 Host Agents](adr/0006-host-agents-otelcol-resticprofile.md)에 따라 `restic` + `resticprofile`로 `servers` 그룹 전체의 설정 파일을 RustFS(S3 API)에 백업합니다. 항상 `monitoring`(otelcol)과 함께 `playbooks/host_agents.yml`로만 배포됩니다.

---

## 1. 개요 및 구현 기능 (What)

- **바이너리 배포**: 컨트롤러가 다운로드·SHA256 검증한 `restic`/`resticprofile`을 버전 디렉터리(`/opt/host-agents/<agent>/<version>/`)에 배치하고 `/usr/local/bin` symlink로 활성화 (ADR-0006 §2.8).
- **호스트별 저장소**: RustFS `host-backups/<host>/`에 호스트 전용 repo, 호스트 전용 백업 키(삭제는 `locks/*`만)와 비밀번호 (§2.5).
- **일일 백업 스케줄**: systemd timer(`Persistent=true`) 또는 `/etc/cron.d/host-agents-backup`(CentOS 6/7, Rocky 8), 02:00–03:59 호스트별 고정 분.
- **백업 결과 방출**: status-file + `/var/log/host-agents/backup.jsonl` → otelcol → OpenObserve `backup_logs` (§2.6).
- **중앙 유지보수**: `check` / `forget --prune`은 호스트가 아닌 Semaphore "Host Agents — Repo Maintenance" 템플릿이 실행.

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
- 📝 `/var/lib/host-agents/restic-status.json`, `/var/log/host-agents/backup.jsonl` + logrotate 설정

---

## 5. 태스크 매트릭스 (Task Matrix)

구현된 태스크만 이 표에 기재합니다(3-Way 검증기 `MISSING IN CODE` 방지). 계획 매트릭스는 [ADR-0006 §3](adr/0006-host-agents-otelcol-resticprofile.md#3-계획-태스크-매트릭스-구현-시-docsmd로-이관)을 참조하고, 구현 커밋에서 `BAK-0xx`(modern) / `BAK-1xx`(legacy_el6) / `BAK-2xx`(legacy_el7) 행을 이관합니다.

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `BAK-001` | `Load the shared Host Agents version table and constants from monitoring` | `ansible.builtin.include_vars` | All | 읽기 전용 (버전·체크섬 표 단일 출처 `monitoring/vars/main.yml`, `tags: always`) |
| `BAK-003` | `Deliver pinned restic binary` | `ansible.builtin.include_tasks` | All | 컨트롤러 캐시(.bz2 → `MON-055`) + SHA256 검증 후 버전 디렉터리 푸시 (`MON-040`~`049`) |
| `BAK-004` | `Deliver pinned resticprofile binary` | `ansible.builtin.include_tasks` | All | `no_self_update` 빌드 tarball + SHA256 검증 후 버전 디렉터리 푸시 (`MON-040`~`049`) |
| `BAK-010` | `Assert RustFS endpoint and bucket are configured` | `ansible.builtin.assert` | All | 읽기 전용 (비어 있거나 끝 슬래시/형식 오류면 호스트 실패) |
| `BAK-011` | `Check which conditional standard backup paths exist` | `ansible.builtin.stat` | All | 읽기 전용, `check_mode: false` (`/opt/services` 존재 시에만 백업 대상에 포함) |
| `BAK-012` | `Derive repository, source list, excludes and schedule` | `ansible.builtin.set_fact` | All | 순수 함수 (repo = `s3:<endpoint>/<bucket>/<host>`, 필수 경로 + 조건부 + `backup_extra_paths`, Rocky 8은 cron) |
| `BAK-013` | `Derive the scheduled hour/minute and run command` | `ansible.builtin.set_fact` | All | 순수 함수 (`random(seed=inventory_hostname)`으로 02:00~03:59 고정 분, `unlock` 후 `backup`) |
| `BAK-020` | `Ensure restic config directory exists (0700)` | `ansible.builtin.file` | All | 디렉터리 존재 시 `ok` (`/etc/restic`, `0700`) |
| `BAK-021` | `Ensure restic cache directory exists (0700)` | `ansible.builtin.file` | All | 디렉터리 존재 시 `ok` (`/var/cache/restic`) |
| `BAK-022` | `Deploy restic credentials env file (0600, no_log, no diff)` | `ansible.builtin.template` | All | Checksum 비교 (`no_log`, `diff: false`, `0600`) |
| `BAK-023` | `Deploy restic repository password file (0600, no_log, no diff)` | `ansible.builtin.copy` | All | Checksum 비교 (`no_log`, `diff: false`, `0600`) |
| `BAK-024` | `Deploy resticprofile profile (validated with resticprofile show)` | `ansible.builtin.template` | All | Checksum 비교; 새 바이너리의 `resticprofile show`가 통과해야 교체 (시크릿 미포함) |
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
