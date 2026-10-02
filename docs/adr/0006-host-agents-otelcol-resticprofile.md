# 6. Host Agents 설계: `otelcol-contrib` + `resticprofile` 최초 설치 및 상시 재구성

- **Status**: Accepted (설계 확정, 미구현)
- **Date**: 2026-09-28
- **Deciders**: Overseer Engineering Team & User
- **Context**: `servers` 그룹 전체(CentOS 6 ~ Rocky Linux 10, Ubuntu/Debian)에 **Host Agents**를 Semaphore UI에서 최초 설치하고 운영 중 수시로 설정을 재적용. 인벤토리는 호스트명만 전달되며 나머지는 OpenBao에서 공급.
- **Design map**: [Host Agents (otelcol + resticprofile) — design map](https://github.com/ppzxc/infra-automation/issues/8) (결정별 상세 근거는 각 티켓의 resolution comment)

---

## 1. Context & Problem Statement

- 로그/메트릭은 OTLP로 **OpenObserve**(커뮤니티판 v1.0.4, 백엔드 저장소 S3)에, 백업은 S3 API로 **RustFS**(1.0.0, OpenObserve와 동일 서버)에 적재합니다.
- 수집·백업 대상은 **ISMS**(ISMS-P 아님) 인증기준 2.9.3 백업 및 복구관리, 2.9.4 로그 및 접속기록 관리를 충족해야 합니다. ISMS는 시스템 로그 보존기간·백업 주기에 숫자를 정하지 않고 "조직이 정의한 기준을 실제로 이행하는지"를 심사합니다. 1~2년 보존·월 1회 점검은 개인정보처리시스템 접속기록(안전성 확보조치 기준 제8조)에만 해당합니다.
- 기존 `roles/monitoring`은 otelcol-contrib 0.108.0을 설치하지만 (a) `creates:` 가드로 업그레이드가 불가능하고, (b) gRPC exporter에 `organization` 헤더가 없어 OpenObserve가 전량 거부하며, (c) `site.yml`·`maintenance.yml`에서 서로 다른 경로로 실행됩니다. restic 코드는 없습니다.
- CentOS 6/7은 AnsiballZ가 동작하지 않으므로(ADR-0005) Raw Provisioning Path를 확장해야 합니다. (`common`/`security`의 raw 경로는 구현 완료, #28. Host Agents용 확장만 미구현.)

---

## 2. Decision Outcomes (결정 사항)

### 2.1 실행 구조 및 Semaphore 모델

- **단일 진입점**: `playbooks/host_agents.yml`만 Host Agents를 다룹니다. `monitoring`은 `site.yml`·`maintenance.yml`에서 제거하고, `site.yml`의 Play 1 / Cleanup play는 `playbooks/common/resolve_connection.yml` / `cleanup_connection.yml` import로 대체합니다(현재 동일 내용 복제 상태).
- **3단 구조**: `import_playbook: common/resolve_connection.yml` → 에이전트 play(`monitoring` + `backup`) → `import_playbook: common/cleanup_connection.yml`. 두 import는 반드시 `tags: [always]` — 없으면 태그 실행 시 자격증명 해석과 **임시 개인키 정리**가 스킵됩니다(현재 `site.yml --tags monitoring`에 존재하는 결함).
- **태그 / Semaphore 템플릿**:

  | 템플릿 | 실행 | 내용 |
  |---|---|---|
  | Host Agents — Deploy | 태그 없음 | 바이너리·계정·디렉터리·init unit·설정·스케줄 전체, restic repo `init`, 종료 시 `job=inventory` 등록 이벤트 |
  | Host Agents — Config | `--tags agents_config` | 설정 템플릿·스케줄만 재적용(핸들러 재시작), check + `--diff` 지원 |
  | Host Agents — Repo Maintenance | Semaphore 스케줄 | 컨트롤러에서 호스트별 `check` → `forget --prune` (§2.5) |

  보조 태그: `agents_install`, `agents_config`, `otel`, `backup`.
- **대상 제한**: `hosts: "{{ target_hosts | default('servers') }}:&servers"` — 축소 가능, `servers` 밖으로 확장 불가. resolve/cleanup도 같은 호스트 집합으로 해석(현재 기본값 `servers:loadbalancers`).
- **미프로비저닝 호스트는 즉시 실패**: 첫 태스크에서 `_is_already_provisioned`를 assert, 아니면 "`site.yml` 먼저 실행". 신규 호스트는 템플릿 2회(site → Deploy) 실행.
- **비밀번호 접속 예외 (2026-10-02 개정, 기존 "부트스트랩 root 설치 경로 없음" 대체)**: SSH 키 없이 `USERNAME/PASSWORD`로만 접속되는 레거시 호스트에도 Host Agents를 설치해야 한다는 운영 요구로, OpenBao `hosts/<호스트>` KV에 `host_agents_allow_password_auth: true`를 **명시한 호스트에 한해** `MON-020`을 통과시킨다(실행 단위·전역 허용은 두지 않음). 근거: 예외가 호스트별 OpenBao 기록(ISMS 증적)으로 남고 신규 호스트에 실수로 비밀번호 설치되는 것을 막는다. 비밀번호는 `sshpass -e`(`SSHPASS` 환경변수)로만 전달해 인자·로그에 노출하지 않으며(임시 공개키를 심는 방식은 하드닝 전 호스트의 `authorized_keys`를 바꾸므로 기각), 실행마다 `PASSWORD-AUTH-EXCEPTION` 경고를 남긴다. 이 예외는 하드닝되지 않은 호스트에 에이전트를 올리는 것이며, **만료 기준은 해당 호스트를 `site.yml`로 하드닝한 시점에 플래그를 제거**하는 것이다. 접속 계정은 root와 일반 계정(sudo 비밀번호) 모두 허용.
- **Dry-run**: Config 경로는 check 모드 + `--diff`로 변경 미리보기가 가능해야 합니다.
- **롤아웃**: 에이전트 play `serial: 25%`; 버전 변경은 runbook대로 `target_hosts`로 카나리 1대 선적용 후 전체.
- **접속 사용자**: `resolve_connection`이 호스트별로 결정합니다 — OpenBao `hosts/<host>`의 `admin_users`(첫 항목이 SSH 계정) / `bootstrap_user`가 있으면 그 호스트만 해당 계정으로 접속하고, 없으면 템플릿의 `target_admin_users` / `bootstrap_user`를 사용합니다. 따라서 서버마다 다른 관리자 계정으로 Host Agents 설치·설정 변경이 가능하며, 모든 대상 호스트 KV에 `admin_users`가 있으면 템플릿의 `target_admin_users`는 생략할 수 있습니다.

### 2.2 설정·시크릿 소스 (OpenBao KV 스키마)

- **Git (`inventory/group_vars/servers`, PR 감사)**: 비시크릿 공용값 — OpenObserve endpoint/org, RustFS endpoint/bucket/region, CA 참조, ISMS 표준 수집·백업 목록.
- **OpenBao `hosts/<host>/agents`** (접속 KV `hosts/<host>`와 분리, `host_agents.yml`만 조회):

  | 키 | 용도 |
  |---|---|
  | `o2_ingest_token` | 호스트 전용 OpenObserve 수집 토큰(이름 = 호스트명, 개별 비활성화 가능) |
  | `rustfs_access_key` / `rustfs_secret_key` | 호스트 전용 RustFS 서비스 계정(§2.5 정책) |
  | `restic_password` | 호스트별 repo 비밀번호(분실 = 복구 불가 → OpenBao 자체 백업 전제) |
  | `otel_extra_logs` / `otel_exclude_logs` | §2.3 오버라이드 |
  | `otel_docker_metrics` | docker 메트릭 opt-in |
  | `backup_extra_paths` / `backup_exclude_paths` / `backup_pre_hooks` | §2.4 오버라이드 |

- **OpenBao `secret/agents/openobserve`, `secret/agents/rustfs`** (`run_once`): 진짜 공용 시크릿만 — 컨트롤러 전용 OpenObserve 수집 토큰(§2.6), RustFS 유지보수 키(§2.5), 사설 CA. 문서에만 존재하고 코드가 읽지 않는 `global/services` 규약은 사용하지 않습니다.
- **누락 처리**: 필수 시크릿 누락 → 해당 호스트 실패(에이전트 한 쪽만 설치된 상태 금지); OpenBao 접근 불가 → 일반/check 모드 모두 실패; 오버라이드 목록 부재 → Git 표준만 적용; `otel_exclude_logs`/`backup_exclude_paths`가 제외 불가 경로(`security_logs` 경로, §2.4 필수 경로)를 지정 → 변경 전 입력 검증 단계에서 해당 호스트 실패(일반/check 모드 동일, 위반 경로와 KV 키를 메시지에 명시). 경고 후 무시는 운영자가 제외가 적용됐다고 오인하므로 기각.
- **시크릿과 diff 분리**: 시크릿은 `/etc/otelcol-contrib/secrets.env`, `/etc/restic/env`에만 렌더링(`no_log: true`, `diff: false`), 본 설정은 `${env:…}`로 참조 → `--diff`가 시크릿 없이 설정 변경만 보여줍니다.

### 2.3 otelcol 수집 표준 (ISMS)

- **수신기**: 모든 OS에서 `filelog`; journald는 rsyslog가 없는 호스트(예: 최소 설치 Debian 12+)에서만 추가. 로컬 OTLP 4317/4318 수신기는 **기본 비활성**(옵션).
- **표준 로그**: `/var/log/messages`, `syslog`, `secure`, `auth.log`, `sudo.log`, `audit/audit.log`, `cron*`, `fail2ban.log`, `dnf.log`, `yum.log`, `dpkg.log`, `firewalld`, `boot.log`, `kern.log`. `wtmp`/`btmp`/`lastlog`(바이너리)는 수집하지 않으며, 접속·인증 증적은 auditd `USER_LOGIN`/`USER_AUTH` + secure/auth.log로 충족합니다.
- **체크포인트 필수**: `file_storage` 확장(`/var/lib/otelcol/storage`)에 filelog 오프셋 저장 — 재시작/설정 재적용 시 누락 없음. 최초 설치는 `start_at: end`(과거 로그 백필 없음).
- **스트림** (OpenObserve에서 스트림별 보존):

  | 스트림 | 내용 | 보존 |
  |---|---|---|
  | `security_logs` | secure, auth.log, audit.log, sudo.log, fail2ban.log, firewalld | 1년 (대상에 개인정보처리시스템 없음 — 포함 시 2년으로 상향) |
  | `system_logs` | messages, syslog, cron, 패키지 로그, boot, kern | 6개월 |
  | `app_logs` | `otel_extra_logs` 기본 목적지 | 서버 측 결정 |
  | `backup_logs` | §2.6 백업·유지보수·등록 이벤트 | 1년 (2.9.3 증적) |

  라우팅: `log_type` 속성 + routing connector → 스트림별 `otlphttp` exporter(각자 `stream-name` 헤더). 로컬 journald는 3개월 유지(`common`).
- **부가정보**: `host.name` = 인벤토리 호스트명(명시), `os.type`, `os.description`, `log.file.path`, `log_type`. 본문은 원문 그대로(파싱·심각도 재작성 없음).
- **hostmetrics**: `cpu, memory, load, filesystem, disk, network, paging, processes`, 간격 **60s**, 프로세스별 `process` 스크레이퍼 비활성.
- **docker 메트릭**: 기본 off, `otel_docker_metrics: true`인 호스트만. 구현 시 `docker_engine`의 동명 변수 `docker_metrics_enabled: true`가 role defaults 누수로 덮어쓰지 않도록 `otel_` 접두사로 분리.
- **오버라이드**: `otel_extra_logs` = glob 목록(→ `app_logs`) 또는 `{path, stream}`; `otel_exclude_logs` = 정확한 경로 일치 제거, 단 `security_logs` 경로는 **제외 불가**.
- **범위 외**: 시간 동기화 점검(2.9.6)은 `common`(chrony) 책임, 동기화 이상은 messages로 이미 수집.

### 2.4 restic 백업 표준 (ISMS)

- **필수 경로(제외 불가)**: `/etc`, `/var/spool/cron`, `/usr/local/bin`, `/usr/local/etc`, `/usr/local/sbin`. **조건부 표준**: `/opt/services`(존재 시). **선택(호스트별 `backup_extra_paths`)**: `/root`, `/home`, `/data`.
- **제외**: `/home/*/.cache`, `**/node_modules`, `*.tmp`, `*.swp`, `/etc/restic/password`, `--exclude-caches`. `/etc/shadow`와 SSH host key는 **포함**(repo 암호화 + 호스트별 분리).
- **로그**: `/var/log`는 restic 대상 아님. OpenObserve 전송(§2.3, 저장소 RustFS)을 2.9.3 로그 백업으로 명시.
- **DB 등 정합성 데이터**: 호스트별 `backup_pre_hooks` → resticprofile `run-before` 덤프 후 덤프 파일 백업.
- **주기/RPO**: 1일 1회, 02:00–03:59 사이 `random(seed=inventory_hostname)`로 호스트별 고정 분; 표준 RPO 24h(`/data` 사용 호스트는 호스트별 조정 가능).
- **보존**: `forget --keep-daily 7 --keep-weekly 4 --keep-monthly 12` (≈1년).
- **무결성**: 매주 `check`, 매월 `check --read-data-subset=10%`, `check` 실패 시 `prune` 차단 — **중앙에서 실행**(§2.5).
- **오버라이드**: `backup_extra_paths` 추가, `backup_exclude_paths`는 필수 경로를 제외할 수 없음.
- **소산**: RustFS는 대상 호스트와 같은 IDC이므로 단독으로 2.9.3 소산 요건을 충족하지 않습니다. 원격지 S3→S3 스트리밍 복제는 서버 측 작업(범위 외)이며 본 설계의 **전제조건**입니다.

### 2.5 restic 저장소 구성·스케줄·권한

- **레이아웃 (2026-10-02 개정)**: 호스트(액세스 키)마다 전용 버킷 `backup_prod_<호스트명>`(`hosts/<host>/agents`의 `rustfs_bucket`으로 재정의 가능)과 그 **버킷 루트**의 repo(`s3:<endpoint>/<bucket>`). 호스트 간 dedup 포기(설정 위주 데이터). 호스트 키 정책은 버킷 단위(`locks/*`만 Delete), 중앙 유지보수 키는 `backup_prod_*` 전체 버킷. 버킷 이름의 밑줄 허용 여부는 서버 측 확인 항목.
- **키 분리(삭제 권한 완화)**:
  - **호스트 키(백업 전용)**: `<host>/*`에 Get/Put/List, Delete는 `<host>/locks/*`만 → 유출돼도 스냅샷·데이터 삭제 불가. restic `backup`이 삭제하는 것은 lock뿐이며 데이터 삭제는 `forget`/`prune`에서만 발생합니다.
  - **유지보수 키(중앙)**: Repo Maintenance 템플릿이 컨트롤러에서 `check`/`forget`/`prune` 실행, 호스트별 repo 비밀번호는 OpenBao에서 조회.
  - RustFS는 서비스 계정별 IAM session policy(`s3:prefix` 조건 포함, 만료 설정 가능)를 지원합니다(admin API `AddServiceAccount`, [rustfs/rustfs `crates/madmin/src/user.rs`](https://github.com/rustfs/rustfs/blob/main/crates/madmin/src/user.rs)). **구현 전 확인**: `s3:DeleteObject`를 `locks/*` 리소스로 한정하는 정책이 실제로 강제되는지.
- **유지보수 일정**: 매주 일요일 05:00 `check` → 성공 시 `forget --prune`; 매월 첫째 일요일 `check --read-data-subset=10%` 추가. 실패는 Semaphore 실패 이력 + `backup_logs` 이벤트.
- **스케줄 방식**: resticprofile 내장 `schedule`은 사용하지 않고 Ansible이 cron 파일 / systemd unit+timer를 직접 템플릿(check/diff 가능, 멱등). resticprofile systemd 스케줄러는 `systemd-analyze calendar`(systemd 236+)·`enable --now`(220+)가 필요해 CentOS 7(219)에서 생성이 실패하고, v0.30.0+의 `systemctl` JSON 출력 의존으로 Rocky 8(239)에서 status/unschedule이 깨집니다([resticprofile #516](https://github.com/creativeprojects/resticprofile/issues/516)).

  | OS | 스케줄러 |
  |---|---|
  | CentOS 6, CentOS 7, Rocky 8 | `/etc/cron.d/host-agents-backup` (놓친 실행 보정 없음 → §2.6 26h 알림으로 보완) |
  | Rocky 9/10, Ubuntu 22.04+, Debian 12+ | systemd timer, `Persistent=true` |

- **실행 계정**: root, systemd에서 `ProtectSystem=strict` + restic 캐시만 쓰기 허용; `/etc/restic` `0700`. (capability 기반 비root는 restic 바이너리를 통한 전체 읽기 노출 + CentOS 6 불가로 기각.)
- **Lock**: `backup --retry-lock 30m`; 호스트는 백업 전 stale-only `restic unlock`(`locks/*` 삭제 권한으로 충분); 중앙 유지보수는 강제 unlock하지 않음.
- **Init**: Deploy에서만 `restic cat config` 프로브 후 부재 시 `init`(Put 권한으로 충분); Config 템플릿은 init하지 않음.
- **RustFS 운영 제약** (서버 측 전제): RustFS ≥ 1.0.0([#2916](https://github.com/rustfs/rustfs/issues/2916) 목록 무음 절단, [#2670](https://github.com/rustfs/rustfs/issues/2670) range read), restic 버킷 **버저닝·Object Lock 비활성**, 파일시스템 복사로 repo 반입 금지.

### 2.6 백업 결과 관제

- **호스트 방출**: `status-file: /var/lib/host-agents/restic-status.json`(덮어쓰기형 상태) + `run-finally` 훅이 한 줄 JSON을 `/var/log/host-agents/backup.jsonl`에 append(`tr -d '\n'` 등 POSIX 도구만, jq 없음) → filelog + `json_parser`(본문 원문 유지) → `backup_logs`. logrotate 설정 동반. (`prometheus-save-to-file`은 otelcol prometheus receiver가 HTTP scrape 전용이라 불채택.)
- **중앙 보고**: Repo Maintenance가 호스트×명령마다 `/api/<org>/backup_logs/_json`으로 `job=maintenance`, `host`, `command`, `success`, `duration`, `error` 이벤트 전송(컨트롤러 전용 토큰). Deploy 종료 시 `job=inventory`(`host`, `deployed_at`) 등록 이벤트.
- **표준 알림 계약** (규칙 생성·통지 채널은 서버 측):

  | 조건 | 기준 |
  |---|---|
  | 백업 실패 | `job=backup`, `success=false` 즉시 |
  | 백업 누락 | 호스트별 마지막 성공 백업 > **26h** |
  | 무결성 검사 실패 | `job=maintenance`, `command=check`, `success=false` |
  | 유지보수 누락 | 호스트별 마지막 check > **8일** |
  | 수집 중단 | 호스트 hostmetrics 부재 > **15분** |
  | 미실행 호스트 | `job=inventory` 등록 후 백업 이벤트 없음 |

### 2.7 OpenObserve 연결 계약 및 로컬 버퍼링

- **연결 값 위치 개정 (2026-10-02)**: 엔드포인트·org·CA 경로는 저장소가 공개(PUBLIC)이므로 Git(`servers.yml`)이 아니라 OpenBao `agents/openobserve`(`o2_endpoint`, `o2_org`, `o2_ca_file`)·`agents/rustfs`(`rustfs_endpoint`, `rustfs_bucket`, `rustfs_region`, `rustfs_ca_file`)에 둔다. 해석 순서는 Extra variables·`group_vars` > OpenBao > 역할 기본값이며, 역할 `defaults`가 `host_agents_shared_secrets`를 지연 평가로 참조해 구현한다(Deploy와 Repo Maintenance 공통).

- **Exporter**: `otlphttp` → `http(s)://<o2>:5080/api/<org>` (**끝 슬래시 금지**, 404), `Authorization: Basic base64(<org>:<o2oi_… 토큰>)`, 로그는 스트림별 `stream-name` 헤더, 메트릭은 메트릭명마다 스트림 자동 생성, gzip 기본값 사용, 사설 CA는 `tls.ca_file`. gRPC(5081)는 대안으로만 둡니다: 원격지 구간의 방화벽/L7 장비가 HTTP/2를 온전히 통과시켜야 하고, 별도 포트와 `organization` 헤더가 필수이며, 배치(1024)·keep-alive 적용 시 호스트당 트래픽 규모에서 성능 이점이 미미합니다. 트레이스 수집 도입 또는 호스트당 수백 KB/s 이상 전송 시 재검토.
- **커뮤니티판 검증 (OpenObserve v1.0.4 소스)**:
  - 스트림별 보존: `src/compaction/src/retention.rs` `generate_jobs()`가 `stream_settings.data_retention`을 enterprise 게이트 없이 적용, 단 전역 `ZO_COMPACT_DATA_RETENTION_DAYS > 0` 필요(서버 전제).
  - 다중 수집 토큰: `/{org}/ingestion-tokens`(list/create), `/{org}/ingestion-tokens/{name}`(enable/disable) 라우트가 무조건 등록, OSS 분기는 Admin/Root 권한 확인뿐(`src/api/management/src/request/organization/ingestion_tokens.rs`). 토큰은 수집 엔드포인트 전용이며 스트림 단위 스코프는 없습니다.
- **로그 버퍼링 = 원본 로그 파일**: 로그 exporter는 소형 영속 큐(`sending_queue.storage: file_storage`, `sizer: bytes`, ~256MB) + `block_on_overflow: true` + `retry_on_failure.max_elapsed_time: 0`. 장기 장애 시 큐가 차면 filelog가 역압으로 읽기를 멈추고, 미전송 로그는 원본 파일에 남아 복구 후 체크포인트부터 재개됩니다. 기본값(`block_on_overflow: false`, 재시도 5분)은 초과분을 **폐기**하므로 사용하지 않습니다.
- **보장 범위**: OpenObserve 장애 **최대 7일**까지 로그 무손실(logrotate 기본값 주 1회 × 4개는 변경하지 않음). 그 이상은 15분 수집 중단 알림으로 방치를 막습니다.
- **메트릭**: 메모리 큐, `block_on_overflow: false`, 기본 재시도 후 폐기. 로그와 파이프라인·exporter 분리(메트릭 역압이 로그를 막지 않도록).
- `file_storage`에 `compaction.on_rebound: true`.

### 2.8 바이너리 버전 고정 및 업그레이드

- **호환성 근거**: Go 1.24+ 바이너리는 Linux 커널 ≥ 3.2 필요, Go 1.23이 2.6.32 지원 마지막([Go 1.24 release notes](https://go.dev/doc/go1.24), [golang/go#67001](https://github.com/golang/go/issues/67001)). 세 바이너리의 공식 linux 빌드는 정적 링크라 glibc(2.12/2.17) 무관, amd64/arm64 제공.
- **버전 표** (`vars/main.yml`, 호스트별 오버라이드 없음):

  | 행 | 대상 | otelcol-contrib | restic | resticprofile |
  |---|---|---|---|---|
  | `default` | CentOS 7+, Rocky 8–10, Ubuntu/Debian | v0.161.0 | 0.19.1 | v0.33.1 |
  | `legacy_el6` | CentOS 6 (커널 2.6.32) | v0.119.0 (go1.23.5) | 0.17.3 (go1.23.3) | v0.29.1 (go1.23.6) |

  `legacy_el6`는 Go 보안 패치가 없는 기한부 예외: 만료일 **2027-12-31**, 경과 시 경고만(실패 아님).
- **체크섬**: 버전×아키텍처별 SHA256을 Git에 고정(`host_agents_checksums`), upstream `checksums.txt`는 기준으로 신뢰하지 않음. 버전 상향 PR에 체크섬 변경 동반.
- **공급 경로**: 대상 호스트는 인터넷 불가로 가정. **컨트롤러(Semaphore)가 다운로드·검증·캐시 후 push**(modern: `ansible.builtin.copy`, legacy: §2.9). 전제: 컨트롤러 → GitHub releases HTTPS 허용, 캐시 미스 시 재다운로드(휘발성 컨테이너 대응).
- **설치 레이아웃**: `/opt/host-agents/<agent>/<version>/<binary>`, `/usr/local/bin/<binary>`는 현재 버전 symlink. 대상 디렉터리 부재 → 설치, symlink 불일치 → 교체 + 핸들러 재시작. `creates:` 제거; check 모드에서 버전 변경이 diff로 표시.
- **재시작 전 검증**: `otelcol-contrib validate --config=…`, `resticprofile --config … show` 실패 시 태스크 실패·서비스 유지. 롤백 = 버전 표 revert PR 후 재실행. 호스트에는 직전 버전 1개만 보존.
- **버전 간 설정 차이**: 양 버전 공통 설정 우선, 필요한 곳만 `{% if %}`. 구현 전 확인 항목이던 `legacy_el6`(v0.119.0)의 `sending_queue` 지원 여부는 아래와 같이 검증했습니다(#48).
- **`sending_queue` 호환성 검증 결과 (otelcol-contrib v0.119.0, 2026-10-01, #48)**:
  - **방법**: 공식 릴리스 `otelcol-contrib_0.119.0_linux_amd64.tar.gz`(SHA256 `4ee77545…48111`, `--version` = 0.119.0)로 실제 템플릿 렌더링본을 `otelcol-contrib validate`. 회귀 테스트: `tests/test_host_agents_legacy_el6.py::test_real_otelcol_0_119_0_validates_the_el6_config_and_rejects_the_modern_one`(`OTELCOL_EL6_BIN` 지정 시 실행).
  - **결과**: modern 설정은 `'sending_queue' has invalid keys: block_on_overflow, sizer`로 거부. 구 이름 `blocking`은 인식됨(잘못된 키는 `invalid keys`, `blocking: maybe`는 타입 오류로 거부되므로 무시되는 키가 아님). `storage: file_storage`, `retry_on_failure.max_elapsed_time: 0`은 그대로 지원.
  - **역압 동작 확인**: 도달 불가 endpoint, `queue_size: 2`의 영속 큐로 filelog 500줄을 흘린 실험에서 `blocking: false`는 `sending queue is full … Rejecting data`(폐기) 로그가 발생했고 `blocking: true`는 거부 없이 큐 대기(역압)했습니다. 종료 시 처리 중이던 요청의 `interrupted due to shutdown … Dropping data`는 양쪽 동일한 in-flight 항목이며 영속 큐 특성으로 el6 고유 문제가 아닙니다.
  - **결정**: 문서화된 대체안(큰 `queue_size` + 무한 재시도, "큐 초과 폐기 가능")은 **불필요** — 역압이 유지되므로 §2.7의 "원본 로그 파일 = 버퍼" 보장은 CentOS 6에도 적용됩니다. 템플릿은 `legacy_el6`에서만 `blocking: true`/`false`와 배치 개수 `queue_size`를 렌더링합니다(modern·legacy_el7 렌더링은 불변).
  - **CentOS 6 예외(축소)**: v0.119.0에는 `sizer: bytes`가 없어 `queue_size`가 bytes가 아닌 **배치(요청) 개수**입니다. `otel_log_queue_batches_legacy_el6: 64` × batch 프로세서 상한 1024건 × 평균 ~1KiB ≈ 스트림당 64MiB(4개 스트림 ≈ 256MiB, modern bytes 예산과 같은 규모). 로그 줄이 평균보다 길면 디스크 사용량이 비례해 커질 수 있으나 상한은 배치 수로 고정됩니다.
  - **backup 측**: 같은 프로파일 템플릿이 resticprofile v0.29.1 + restic 0.17.3에서 `show`를 통과함을 확인(`…::test_real_resticprofile_0_29_1_accepts_the_profile_with_restic_0_17_3`).

### 2.9 CentOS 6/7 분기 (ADR-0005 확장)

- **분기 지점**: `gather_facts: false`로 시작, 첫 태스크 raw 프로브(`cat /etc/os-release /etc/redhat-release`, `uname -m`) → `host_agents_os_path` ∈ {`legacy_el6`, `legacy_el7`, `modern`}. `modern`만 `/usr/bin/python3` + `setup`. legacy는 프로브 결과로 `host_agents_os_*` fact 구성 → 세 경로가 같은 템플릿 공유(템플릿은 `host_agents_os_*`만 참조). CentOS 7도 raw 경로(Python 2.7뿐, 최신 ansible-core는 대상 Python ≥ 3.7 요구).
- **바이너리 업로드**: 컨트롤러 측 `scp`(`delegate_to: localhost`, `command: scp`, `resolve_connection`의 host/port/user/임시 키) → 원격 `sha256sum`을 Git 고정 해시와 비교(ADR-0005 sentinel 겸용) → 버전 디렉터리 + symlink 교체. 소형 파일(설정/unit/cron)은 ADR-0005 base64 헬퍼. (otelcol-contrib 아티팩트 ~100MB+로 base64-over-raw 불가.)
- **check 모드 예외 (ADR-0005 §2.4 부분 개정, Host Agents 한정)**: 읽기 전용 프로브(`sha256sum`, `stat`, 비시크릿 파일 `cat`)는 `check_mode: false`로 실행, 변경 raw 태스크는 스킵, 변경 예정 파일 목록과 컨트롤러 렌더링본 vs 원격 내용 diff를 debug로 출력(시크릿 env 파일 제외). ADR-0005의 Option A는 `common`/`security`에 대해 그대로 유지됩니다.
- **otelcol root 실행 예외 (CentOS 6/7 한정)**: systemd 219는 `AmbientCapabilities`(229+) 미지원, 커널 3.10은 ambient capability(4.3+) 미지원 → 비root `otelcol` + `CAP_DAC_READ_SEARCH`로는 audit.log/secure를 읽을 수 없습니다. legacy는 root로 실행하고 CentOS 7은 나머지 하드닝(`ProtectSystem=full`, `ProtectHome`, `PrivateTmp`, `NoNewPrivileges`) 유지. 로그 파일 그룹/ACL 변경은 `security`·logrotate 책임 침범으로 기각. modern은 비root + capability 유지.
- **init / 스케줄**: CentOS 6 — 기존 SysV 템플릿(`otelcol-contrib.init.j2`, legacy에서 root 실행 + `secrets.env` 적재) 헬퍼 배포 + `chkconfig`(sentinel `chkconfig --list`의 `3:on`, 없을 때만 `--add` + `on`, #48 구현); CentOS 7 — systemd unit 헬퍼 배포 + `daemon-reload`/`enable`(sentinel `is-enabled`); 백업은 양쪽 `/etc/cron.d/host-agents-backup`(sentinel 파일 해시).
- **대체 경로 없음**: 업로드 후 `<binary> --version` 스모크 테스트, 실패 시 호스트 실패(rsyslog 폴백 없음). 첫 실제 CentOS 6 호스트가 카나리(런북: `docs/monitoring.md` §3-5).
- **미검증 위험 (CentOS 6 카나리에서 확인)**: OpenSSH 5.3 대상은 SHA-1 `ssh-rsa`만 지원하고, 컨트롤러 OpenSSH 8.8+는 기본 비활성입니다. 바이너리 업로드 `scp`(`raw_scp_argv`)는 Ansible `ssh_args`를 상속하지 않으므로, 레거시 알고리즘 옵션이 필요하면 raw 태스크는 통과해도 업로드가 실패할 수 있습니다. 런북 1단계에서 확인하고 필요 시 `raw_scp_argv`에 옵션 전달을 추가합니다.
- **배치**: ADR-0005 원칙대로 `roles/monitoring`·`roles/backup` 내부에 `host_agents_os_path` 게이트, `tasks/legacy_el6.yml` / `tasks/legacy_el7.yml`로 `include_tasks`. (구현: 두 OS 차이가 작아 역할마다 `tasks/legacy.yml` 하나를 정적 import하고 OS별 태스크만 조건으로 나눔, #48.)

### 2.10 역할 구성 및 SPEC-ID 규약

- `roles/monitoring`(otelcol, 기존 `MON-*` 계승), 신규 `roles/backup`(restic/resticprofile, `BAK-*`).
- SPEC-ID는 검증기 정규식 `[A-Z]+-\d{3}`(`scripts/validate-ansible-specs.py`)을 따라야 합니다. 경로 구분은 번호 대역으로: `MON-0xx`/`BAK-0xx` = modern, `MON-1xx`/`BAK-1xx` = legacy_el6, `MON-2xx`/`BAK-2xx` = legacy_el7. (기존 `MON-CLEANUP-00x`는 `MON-011~015`로 재번호됨.) 구현에서 CentOS 6/7은 역할마다 `tasks/legacy.yml` 하나를 공유하므로(#48) 대역은 다음과 같이 해석합니다: `1xx` = CentOS 6 **전용** 태스크(`MON-110~122`), `2xx` = CentOS 7 전용 **또는** 두 legacy 경로 공용 태스크(docs 적용 대상 열에 명시). 예외로 raw 공용 헬퍼 `MON-100~108`(#46, 대역 규약 이전 번호)은 1xx에 있지만 두 OS 공용이며 재번호하지 않습니다. backup은 두 OS 차이가 버전 행뿐이라 `BAK-1xx`가 없습니다.
- **스펙 테이블 반영 방식**: 검증기는 `docs/*.md` 테이블의 모든 ID에 대응 태스크를 요구(`MISSING IN CODE`)하므로, 미구현 태스크는 `docs/monitoring.md`·`docs/backup.md` 테이블에 넣지 않습니다. 계획 매트릭스는 본 ADR §3에 두고, 태스크가 구현되는 커밋에서 해당 행을 docs 테이블로 옮기며 `molecule/default/verify.yml`의 `[VERIFY-<ID>]`를 함께 추가합니다.

### 2.11 복구 테스트 Runbook

- **주기**: 분기 1회(ISMS 2.9.3/2.12.2, 정한 주기 미이행 자체가 결함).
- **절차**:
  1. `servers`에서 무작위 1대 선정(선정 방식과 결과를 결과서에 기록).
  2. 해당 호스트 repo(호스트 전용 버킷 `backup_prod_<host>`)의 최신 스냅샷 선택: `restic snapshots --latest 1`.
  3. 대상 호스트에서 호스트 키(읽기 용도)로 `/etc`를 임시 경로에 복구: `restic restore latest --target /tmp/restore-test-<date> --include /etc`.
  4. 원본과 비교(`diff -r /etc /tmp/restore-test-<date>/etc`, 변경 예상 파일 제외), 소요 시간 측정.
  5. 임시 복구본 삭제.
  6. 결과서 작성: 일시, 호스트, 스냅샷 ID, 복구 범위, 성공/실패, 소요 시간, 차이점, 개선 조치. 서명(승인): **CISO**.
- 실패 시 개선 조치를 백로그로 등록하고 다음 분기 테스트에서 재검증.

---

## 3. 계획 태스크 매트릭스 (구현 시 `docs/*.md`로 이관)

| 계획 Spec ID | 경로 | 태스크 개요 | 멱등성 방식 |
|---|---|---|---|
| `MON-0xx` | modern | (`legacy_el6` 만료 경고는 legacy 파일의 `MON-110`으로 구현) (raw OS 프로브·`_is_already_provisioned` assert·OpenBao 입력 검증은 구현되어 `docs/monitoring.md` `MON-020~035`로 이관) | 읽기 전용 |
| `MON-0xx` | modern | otelcol 사용자·그룹, `/var/lib/otelcol/storage`, 버전 디렉터리 | 모듈 상태 비교 |
| `MON-0xx` | modern | 컨트롤러 캐시 → `copy` 바이너리, SHA256 검증, symlink 교체 | 체크섬/링크 대상 비교 |
| `MON-0xx` | modern | `secrets.env`(`diff: false`), config 템플릿, `validate` 후 재시작 | 템플릿 체크섬 |
| `MON-0xx` | modern | systemd unit(비root + `CAP_DAC_READ_SEARCH`), started/enabled | 파일/서비스 상태 |
| `MON-1xx` | legacy_el6 | SysV + `chkconfig`, journald 없음, 컬렉터 로그 logrotate, 만료 경고 — **구현됨**(#48, `docs/monitoring.md` `MON-110/114/119/121/122`; scp·sentinel 등 공용 단계는 `MON-2xx`) | ADR-0005 sentinel |
| `MON-2xx` | legacy_el7 | scp 업로드 + 원격 sha256, systemd unit(root, 하드닝 유지) | ADR-0005 sentinel |
| `BAK-0xx` | modern | restic/resticprofile 바이너리, `/etc/restic`(0700) env/password, profile 템플릿 | 체크섬 |
| `BAK-0xx` | modern | systemd timer(`Persistent=true`) 또는 Rocky 8 cron, status-file/jsonl, logrotate | 파일 체크섬 |
| `BAK-0xx` | modern | Deploy 한정 `restic cat config` → `init`, `job=inventory` 이벤트 | 프로브 결과 조건 |
| `BAK-1xx` | legacy_el6 | 해당 없음 — CentOS 6은 `BAK-2xx`를 legacy_el6 버전 행으로 공유(#48, `docs/backup.md` `BAK-201~217`) | ADR-0005 sentinel |
| `BAK-2xx` | legacy_el7 | 바이너리 scp, env/profile/cron.d 헬퍼 배포 | ADR-0005 sentinel |
| `BAK-0xx` | controller | Repo Maintenance: `check` → `forget --prune`, 월간 10% read, 이벤트 전송 | Semaphore 스케줄 실행 |

---

## 4. Consequences & Trade-offs

- **장점**: 단일 진입점과 태그 분리로 설정 변경이 계정·하드닝을 건드리지 않고 check/diff로 미리보기 가능; 호스트별 자격증명 + 백업 전용 키로 호스트 침해 시 백업 삭제 불가; 원본 로그 파일을 버퍼로 삼아 7일 장애까지 무손실; 모든 OS에서 동일 템플릿.
- **비용/위험**:
  - 신규 호스트는 Semaphore 템플릿 2회 실행 필요.
  - `legacy_el6` 고정 버전은 보안 패치 없음(만료 경고로 가시화). CentOS 6/7 otelcol은 root 실행.
  - Repo Maintenance가 중앙 단일 실패 지점 → 8일 check 누락 알림으로 감지.
  - cron 스케줄 OS는 놓친 백업을 보정하지 못함 → 26h 알림으로 감지.
  - 호스트 간 dedup 없음(저장 용량 증가, 설정 위주라 미미).
- **서버 측 전제조건 (본 설계 범위 외)**: OpenObserve `ZO_COMPACT_DATA_RETENTION_DAYS > 0` 및 스트림별 보존 설정, 호스트별·컨트롤러 수집 토큰 발급, 알림 규칙·통지 채널; RustFS ≥ 1.0.0, 버킷 사전 생성(버저닝/Object Lock off), 호스트별 서비스 계정 + prefix 정책, 유지보수 키, 원격지 S3→S3 소산 복제; Semaphore 컨트롤러의 GitHub releases 아웃바운드; OpenBao 자체 백업.

---

## 5. 확정된 운영 파라미터

- **개인정보처리시스템 여부**: 대상 서버에 없음 → `security_logs` 보존 1년. 향후 포함되면 2년으로 상향(안전성 확보조치 기준 제8조).
- **복구 테스트 결과서 승인**: CISO.
- **OpenObserve 전송 프로토콜**: `otlphttp` 확정 (§2.7).

---

## 6. 참고

- ADR-0001 (관제 아키텍처), ADR-0005 (Raw Provisioning Path)
- [KISA 「ISMS-P 인증기준 안내서」(2023.11)](https://isms.kisa.or.kr) 2.9.3, 2.9.4, 2.9.5, 2.9.6, 2.12.1
- [OpenTelemetry Collector exporterhelper (sending_queue / retry_on_failure)](https://github.com/open-telemetry/opentelemetry-collector/blob/main/exporter/exporterhelper/README.md)
- [OpenObserve v1.0.4 소스](https://github.com/openobserve/openobserve/tree/v1.0.4), [OpenObserve ingestion tokens](https://openobserve.ai/docs/user-guide/account-administration/identity-and-access-management/ingestion-tokens/)
- [restic v0.19.1 S3 backend](https://github.com/restic/restic/blob/v0.19.1/doc/030_preparing_a_new_repo.rst), [resticprofile status file](https://creativeprojects.github.io/resticprofile/monitoring/status/)
