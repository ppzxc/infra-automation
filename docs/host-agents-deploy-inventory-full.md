# Host Agents — Deploy 배포 내역서 (Full)

> Semaphore 템플릿 **Host Agents — Deploy**가 대상 호스트에 설치·구성하는 otelcol-contrib, restic, resticprofile의 상세 내역이다.
> 요약본은 [host-agents-deploy-inventory-simple.md](host-agents-deploy-inventory-simple.md), 설계 근거는 [ADR-0006](adr/0006-host-agents-otelcol-resticprofile.md)·[ADR-0008](adr/0008-log-structuring-edge-envelope-central-semantics.md), 태스크 명세는 [monitoring.md](monitoring.md)·[backup.md](backup.md)를 본다.
> 본 문서의 값은 Git 기본값(`roles/*/defaults`, `roles/monitoring/vars`) 기준이며, 호스트별 OpenBao KV로 추가·제외된 항목은 반영하지 않는다.

---

## 1. 실행 개요

| 항목 | 내용 |
|---|---|
| 플레이북 | `playbooks/host_agents.yml` (태그 없음 = 설치 + 설정 전체) |
| 대상 호스트 | `target_hosts`(기본 `servers`) ∩ `servers`에서 `host_agents_excluded` 그룹을 뺀 호스트, 동시 실행 `serial: 25%` |
| 실행 순서 | ① OpenBao 연결·자격증명 해석 → ② `monitoring` 역할(otelcol) → ③ `backup` 역할(restic·resticprofile) → ④ 임시 개인키 정리 |
| 비교 템플릿 | **Host Agents — Config**(`--tags agents_config`)는 설정 재적용만 하며 바이너리 설치, repo 초기화, 등록 이벤트는 하지 않는다 |
| 신규 호스트 | `site.yml` 실행 후 Deploy 실행 (2회) |

### OS 경로

| 경로 | 대상 OS | 적용 방식 | 서비스 관리 | 백업 스케줄 |
|---|---|---|---|---|
| `modern` | Rocky/RHEL 8·9, Ubuntu/Debian 등 | Ansible 모듈 | systemd | systemd timer (Rocky 8은 cron.d) |
| `legacy_el7` | CentOS 7 | raw | systemd (`systemctl`) | cron.d |
| `legacy_el6` | CentOS 6 | raw | SysV init + chkconfig | cron.d |

---

## 2. 바이너리 버전 및 무결성

버전 표는 `roles/monitoring/vars/main.yml` 한 곳에서 관리하며 호스트별 오버라이드는 없다.

| 구성요소 | default 행 (modern, legacy_el7) | legacy_el6 행 (CentOS 6) | 배포 원본 |
|---|---|---|---|
| otelcol-contrib | 0.161.0 | 0.119.0 (go1.23.5) | `github.com/open-telemetry/opentelemetry-collector-releases` — `otelcol-contrib_<ver>_linux_<arch>.tar.gz` |
| restic | 0.19.1 | 0.17.3 (go1.23.3) | `github.com/restic/restic` — `restic_<ver>_linux_<arch>.bz2` |
| resticprofile | 0.33.1 | 0.29.1 (go1.23.6) | `github.com/creativeprojects/resticprofile` — `resticprofile_no_self_update_<ver>_linux_<arch>.tar.gz` |

- legacy_el6 행은 커널 2.6.32에서 도는 마지막 Go 1.23 빌드로 고정했다. 만료일은 **2027-12-31**이고, 지나면 경고만 출력한다.
- 지원 아키텍처는 amd64, arm64다.

### SHA256 (배포 파일 기준, Git 고정)

| 구성요소 | 버전 | amd64 | arm64 |
|---|---|---|---|
| otelcol-contrib | 0.161.0 | `778c689efa681ff6e4722ce9f66b9b7f57c3ba009ab2e2b43dc2e0315862c731` | `cd5de93213a0dbb90e4998b3b9e4e15ed691ec635cf7cf4147f95799fb16b676` |
| otelcol-contrib | 0.119.0 | `4ee77545daaad658f7282bff98704bc1f31107890e2a2e1d4b1fc31da4648111` | `c5f4480504a12d9445ef5c3d754bd2824a2ea5dbc516c0edd52bb05c3e72f1f7` |
| restic | 0.19.1 | `f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c` | `a5f64aaab53d51e311fa3829124c5b703f2d14cf187d8640b6be3b2b49376465` |
| restic | 0.17.3 | `5097faeda6aa13167aae6e36efdba636637f8741fed89bbf015678334632d4d3` | `db27b803534d301cef30577468cf61cb2e242165b8cd6d8cd6efd7001be2e557` |
| resticprofile | 0.33.1 | `1d7027d15e3e2456e585a210f811d0f72ec40f6b3388f00425642ed579165d70` | `58e4fd6fbe2bd460ee6823c3693f39a10f0f24c90635f0215c19b0ab20bbf5df` |
| resticprofile | 0.29.1 | `458dbc490a3c4f22ddf152d9fc4505a2db50a4dfea418e731567e5284007b00f` | `c178dfe6072b7afd10f2df7b0ad0dfe009900074aa2f48936d31fde600d641c8` |

### 전달 방식

1. 컨트롤러(Semaphore)가 배포 파일을 `~/.cache/host-agents`에 한 번만 받아 위 SHA256으로 검증한다. upstream `checksums.txt`는 기준으로 쓰지 않는다.
2. 검증된 바이너리를 호스트의 `/opt/host-agents/<agent>/<version>/<binary>`로 푸시하고 SHA256을 다시 대조한다. 호스트는 인터넷에 접근하지 않는다.
3. 새 설정을 새 바이너리로 검증(`otelcol-contrib validate`, `resticprofile show`)한 뒤에만 `/usr/local/bin/<binary>` symlink를 새 버전으로 바꾼다.
4. 버전 디렉터리는 현재 버전과 직전 버전 1개만 남긴다(롤백용).
5. symlink 전환 전에 `/usr/local/bin/<binary>`가 일반 파일이면 `/opt/host-agents/<agent>/legacy-<binary>`로 보존한다.

---

## 3. otelcol-contrib (monitoring 역할)

### 3.1 호스트 변경 내역

| 대상 | 소유자·권한 | 적용 경로 | 설명 |
|---|---|---|---|
| 사용자·그룹 `otelcol` | system, shell `/sbin/nologin`, 홈 없음 | modern | 컬렉터 실행 계정. 보조 그룹은 `adm`(Debian 계열) 또는 `systemd-journal`이고, docker 메트릭이 켜져 있고 docker 그룹이 있으면 `docker`가 추가됨 |
| `/opt/host-agents/otelcol-contrib/<ver>/otelcol-contrib` | root, 0755 | 전체 | 바이너리 |
| `/usr/local/bin/otelcol-contrib` | symlink | 전체 | 활성 버전 |
| `/var/lib/otelcol/storage/` | otelcol(legacy는 root), 0750 | 전체 | filelog 읽기 위치(체크포인트)와 로그 영속 큐 |
| `/etc/otelcol/` | root:otelcol, 0750 | 전체 | |
| `/etc/otelcol/config.yaml` | root:otelcol, 0640 | 전체 | 수집 설정(시크릿 없음). 배포 전 `validate` 통과 필수 |
| `/etc/otelcol-contrib/` | root, 0700 | 전체 | |
| `/etc/otelcol-contrib/secrets.env` | root, 0600 | 전체 | `O2_BASIC_AUTH` = base64(`<org>:<o2_ingest_token>`) |
| `/etc/systemd/system/otelcol-contrib.service` | root, 0644 | modern, legacy_el7 | 아래 3.2 참고 |
| `/etc/init.d/otelcol-contrib` | root, 0755 | legacy_el6 | SysV 스크립트, chkconfig 등록 |
| `/var/log/otelcol-contrib.log` | – | legacy_el6 | 컬렉터 자체 stdout/stderr |
| `/etc/logrotate.d/otelcol-contrib` | – | legacy_el6 | 위 로그를 copytruncate로 회전, 4개 보관 |
| 서비스 `otelcol-contrib` | started, enabled | 전체 | 설정이나 바이너리가 바뀌면 재시작 |

**정리 및 사전 작업**
- 레거시 `node_exporter`의 서비스, `/etc/systemd/system/node_exporter.service`, `/usr/local/bin/node_exporter`, 사용자, 그룹을 제거한다(`cleanup_legacy_node_exporter: true`).
- modern 경로에서 `/usr/bin/python3`가 없으면 python3를 설치한다.

### 3.2 systemd 유닛 (modern, legacy_el7)

| 항목 | modern | legacy_el7 |
|---|---|---|
| 실행 계정 | `otelcol` | root |
| 권한 | `CAP_DAC_READ_SEARCH`(로그 읽기 전용 권한)만 부여 | – |
| 하드닝 | `NoNewPrivileges`, `ProtectSystem=full`, `ProtectHome`, `PrivateTmp` | 동일 |
| 재시작 | `Restart=always`, 5초 | 동일 |
| 기타 | `LimitNOFILE=65535`, `EnvironmentFile=/etc/otelcol-contrib/secrets.env` | 동일 |

### 3.3 기본 수집 로그

기본값은 `otel_system_logs`(defaults)이고, 스트림·서비스명·파서는 `roles/monitoring/vars/main.yml`의 고정 상수가 정한다.

| 경로 | 스트림 | service.name | 파서(Envelope Parsing) | 주 대상 OS | 내용 |
|---|---|---|---|---|---|
| `/var/log/messages` | system_logs | syslog | syslog(RFC3164) | RHEL 계열 | 시스템 전반 syslog |
| `/var/log/syslog` | system_logs | syslog | syslog | Debian 계열 | 시스템 전반 syslog |
| `/var/log/secure` | **security_logs** | auth | syslog | RHEL 계열 | SSH·PAM·sudo 인증 |
| `/var/log/auth.log` | **security_logs** | auth | syslog | Debian 계열 | SSH·PAM·sudo 인증 |
| `/var/log/sudo.log` | **security_logs** | sudo | 없음 | 설정 시 | sudo 전용 로그(`Defaults logfile`) |
| `/var/log/audit/audit.log` | **security_logs** | audit | audit | auditd 설치 호스트 | 커널 감사 이벤트 |
| `/var/log/cron*` | system_logs | cron | syslog | RHEL 계열 | cron 실행 기록(회전 파일 포함 글롭) |
| `/var/log/fail2ban.log` | **security_logs** | fail2ban | fail2ban | fail2ban 설치 호스트 | 차단·해제 이벤트 |
| `/var/log/dnf.log` | system_logs | package-manager | dnf | RHEL 8+ | 패키지 설치·변경 |
| `/var/log/yum.log` | system_logs | package-manager | yum | RHEL 6·7 | 패키지 설치·변경 |
| `/var/log/dpkg.log` | system_logs | package-manager | dpkg | Debian 계열 | 패키지 설치·변경 |
| `/var/log/firewalld` | **security_logs** | firewalld | 없음 | firewalld 사용 호스트 | 방화벽 이벤트 |
| `/var/log/boot.log` | system_logs | boot | 없음 | RHEL 계열 | 부팅 시 서비스 기동 |
| `/var/log/kern.log` | system_logs | kernel | syslog | Debian 계열 | 커널 메시지 |

수집 규칙:
- **없는 파일은 오류가 아니다.** OS 계열이 다르거나 해당 서비스가 없으면 그냥 매칭되지 않는다. 그래서 목록은 RHEL과 Debian의 합집합으로 둔다.
- **배포 이후 새로 쓰인 줄부터 수집한다**(`start_at: end`). 기존 내용은 소급하지 않는다. 읽은 위치는 `/var/lib/otelcol/storage`에 저장되므로 재시작해도 중복되거나 빠지지 않는다.
- **원문 본문은 바꾸지 않는다.** 파서는 시각, 프로세스명, PID, severity, audit 필드만 attributes에 올린다. 포맷이 맞지 않는 줄도 버리지 않고 `log.parse_error=true`를 붙여 보낸다.
- **security_logs 경로 6종은 호스트 KV `otel_exclude_logs`로 제외할 수 없다.** 시도하면 해당 호스트는 변경 전에 실패한다. 나머지 system_logs 경로는 제외할 수 있다.
- **호스트별 추가 경로**: KV `otel_extra_logs`로 추가하며, 스트림 기본값은 `app_logs`다. 추가 경로에는 파서를 적용하지 않는다.

**고정 수신기**

| 수신기 | 조건 | 스트림 | service.name | 내용 |
|---|---|---|---|---|
| `filelog/backup_logs` | 항상 | backup_logs | backup | `/var/log/host-agents/backup.jsonl`(백업 결과, 4.4 참고). JSON 필드를 attributes로 파싱 |
| `journald` | rsyslog가 **없는** 호스트만. legacy_el6은 항상 끔 | system_logs | journald | journal 전체. `PRIORITY`를 severity로 매핑 |
| `otlp` | 기본 **비활성**(`otel_otlp_enabled: false`) | app_logs·메트릭 | 앱이 지정 | 켜면 `127.0.0.1:4317`(gRPC)과 `:4318`(HTTP)에서 받음 |

### 3.4 기본 수집 메트릭

| 수신기 | 조건 | 주기 | service.name | 항목 |
|---|---|---|---|---|
| `hostmetrics` | 항상 | 60s | host-metrics | cpu, memory, disk, filesystem, load, network, paging, processes |
| `docker_stats` | KV `otel_docker_metrics: true`인 호스트만 | 60s | docker | 컨테이너별 CPU·메모리·네트워크·블록 IO (`unix:///var/run/docker.sock`) |

### 3.5 모든 로그·메트릭에 붙는 리소스 속성

| 속성 | 출처 | 비고 |
|---|---|---|
| `host.name` | Inventory Hostname (예: `ns0332`) | OS hostname이 아님 |
| `host.id` | `/etc/machine-id` | 없으면(CentOS 6) 생략하고 경고 |
| `host.ip` | 인벤토리 `ip` → KV `ip` → KV `public_ip` | 모두 없으면 생략하고 경고 |
| `host.arch`, `os.type`, `os.name`, `os.version`, `os.description` | OS 프로브 | |
| `deployment.environment.name` | `host_agents_environment` (인벤토리 또는 KV) | **필수**. `production`·`staging`·`development`·`test` 중 하나가 아니면 실패 |

### 3.6 전송 (OpenObserve)

| 구분 | exporter | 대상 | 큐 | 과부하 시 동작 |
|---|---|---|---|---|
| 로그 | `otlphttp/<stream>` ×4 (`security_logs`, `system_logs`, `app_logs`, `backup_logs`) | `<o2_endpoint>/api/<o2_org>`, 헤더 `stream-name: <stream>` | 디스크 영속 큐, 스트림당 64MiB(합계 약 256MiB). legacy_el6은 배치 64개 | 큐가 차면 수집을 멈추고(역압) 원본 파일을 버퍼로 쓴다. 재시도 무제한 |
| 메트릭 | `otlphttp/metrics` | 동일 | 메모리 큐 | 버림(역압 없음) |

- 인증은 HTTP Basic(`Authorization: Basic ${env:O2_BASIC_AUTH}`)이고 값은 `secrets.env`에서 읽는다.
- 사설 CA를 쓰면 `o2_ca_file`을 `tls.ca_file`에 넣는다.
- 공통 프로세서: `memory_limiter`(75%/스파이크 20%), `batch`(1024건/1s).

---

## 4. restic · resticprofile (backup 역할)

### 4.1 호스트 변경 내역

| 대상 | 소유자·권한 | 적용 경로 | 설명 |
|---|---|---|---|
| `/opt/host-agents/restic/<ver>/restic` | root, 0755 | 전체 | 바이너리 |
| `/opt/host-agents/resticprofile/<ver>/resticprofile` | root, 0755 | 전체 | 바이너리(self-update 없는 빌드) |
| `/usr/local/bin/restic`, `/usr/local/bin/resticprofile` | symlink | 전체 | 활성 버전 |
| `/etc/restic/` | root, 0700 | 전체 | |
| `/etc/restic/env` | root, 0600 | 전체 | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`(호스트 전용 RustFS 키), 선택적으로 `AWS_DEFAULT_REGION` |
| `/etc/restic/password` | root, 0600 | 전체 | repo 암호화 비밀번호 |
| `/etc/restic/profiles.yaml` | root, 0600 | 전체 | resticprofile 프로파일(시크릿 없음). 배포 전 `resticprofile show`로 검증 |
| `/var/cache/restic/` | root, 0700 | 전체 | restic 로컬 캐시 |
| `/var/log/host-agents/` | root, 0755 | 전체 | |
| `/var/log/host-agents/backup.jsonl` | 0640 (logrotate가 생성) | 전체 | 백업 결과(4.4 참고) |
| `/var/lib/host-agents/` | root, 0755 | 전체 | `restic-status.json`(resticprofile status-file), `backup.start`(실행 중 임시 파일) |
| `/usr/local/sbin/host-agents-backup-event` | root, 0755 | 전체 | run-before·run-finally 훅(POSIX sh) |
| `/etc/logrotate.d/host-agents-backup` | root, 0644 | 전체 | backup.jsonl 주 단위 회전, 8개 보관, 압축 |
| `/etc/systemd/system/host-agents-backup.service` | root, 0644 | modern(Rocky 8 제외) | oneshot, root, `ProtectSystem=strict` |
| `/etc/systemd/system/host-agents-backup.timer` | root, 0644 | modern(Rocky 8 제외) | `Persistent=true`(놓친 실행은 부팅 후 실행), enabled·started |
| `/etc/cron.d/host-agents-backup` | root, 0644 | Rocky 8, legacy_el6·el7, systemd가 아닌 호스트 | timer를 쓰는 호스트에서는 삭제 |
| RustFS 버킷 내 restic repo | – | 전체 | 없을 때만 `init`(Deploy에서만) |

### 4.2 기본 백업 대상

**백업 경로 (`source`)**

| 경로 | 구분 | 호스트 KV로 제외 | 포함 내용 |
|---|---|---|---|
| `/etc` | 필수 (ISMS 2.9.3) | 불가 | 시스템·서비스 설정 전체: 계정(`passwd`, `shadow`, `group`), sudoers, sshd, 네트워크, 방화벽, systemd 유닛, cron(`/etc/cron.d`, `/etc/crontab`), logrotate, Host Agents 설정(`/etc/otelcol*`, `/etc/restic/env`·`profiles.yaml`) |
| `/var/spool/cron` | 필수 | 불가 | 사용자별 crontab (`crontab -e`로 등록한 작업) |
| `/usr/local/bin` | 필수 | 불가 | 로컬 설치 실행 파일·스크립트. Host Agents 바이너리는 symlink만 들어가고 실제 파일(`/opt/host-agents`)은 대상이 아님 |
| `/usr/local/etc` | 필수 | 불가 | 로컬 설치 소프트웨어 설정 |
| `/usr/local/sbin` | 필수 | 불가 | 로컬 관리 스크립트 (`host-agents-backup-event` 포함) |
| `/opt/services` | 조건부 표준 | 가능 | 디렉터리가 **있을 때만** 포함. 서비스 배포 디렉터리(compose 파일, 설정 등) |
| 호스트 KV `backup_extra_paths` | 선택 | – | 예: `/root`, `/home`, `/data`. 절대 경로만 허용 |

**제외 (`exclude`)**: 모든 호스트에 적용한다.

| 패턴 | 이유 |
|---|---|
| `/home/*/.cache` | 재생성 가능한 사용자 캐시 |
| `**/node_modules` | 재설치 가능한 의존성 |
| `*.tmp`, `*.swp` | 임시·편집기 스왑 파일 |
| `/etc/restic/password` | repo 비밀번호를 repo 안에 두지 않음 |
| `exclude-caches: true` | `CACHEDIR.TAG`가 있는 디렉터리 |
| 호스트 KV `backup_exclude_paths` | 호스트별 추가 제외. 필수 경로나 그 상위 경로는 지정할 수 없음(지정 시 실패) |

> 참고: `/etc/restic/env`(RustFS 호스트 키)와 `/etc/otelcol-contrib/secrets.env`는 `/etc`에 속하므로 백업에 포함된다. repo는 `/etc/restic/password`로 암호화된다.

### 4.3 저장소·스케줄·실행

| 항목 | 값 |
|---|---|
| Repository | `s3:<rustfs_endpoint>/<bucket>` (버킷 루트) |
| 버킷 | `backup-prod-<inventory_hostname>`. 호스트 KV `rustfs_bucket`으로 재정의 가능하고, 공용 `agents/rustfs`의 버킷 값은 쓰지 않음 |
| 스냅샷 host 라벨 | Inventory Hostname(예: `ns0332`) |
| 스케줄 | 매일 **02:00~03:59** 중 하나. `inventory_hostname`을 시드로 분을 고정하므로 호스트마다 다르고 실행마다 같음 |
| 실행 명령 | `resticprofile -f yaml -c /etc/restic/profiles.yaml -n default unlock; ... backup` |
| 잠금 대기 | `retry-lock: 30m` |
| 사전 훅 | `host-agents-backup-event start`, 이어서 KV `backup_pre_hooks`(예: DB 덤프). 훅이 쓸 수 있는 추가 경로는 `/var/backups`(systemd 샌드박스 허용) |
| 사후 훅 | `host-agents-backup-event finish <host>` (성공·실패 모두 실행) |
| 보관 정책 (참고) | Deploy가 아니라 **Host Agents — Repo Maintenance** 템플릿이 컨트롤러에서 `forget --prune` 실행: daily 7 / weekly 4 / monthly 12. 매월 첫째 일요일에 `check --read-data-subset=10%` |

### 4.4 백업 결과 이벤트 (`backup.jsonl` → OpenObserve `backup_logs`)

백업이 한 번 돌 때마다 한 줄씩 append되고, otelcol이 `backup_logs` 스트림으로 보낸다.

```json
{"job":"backup","host":"ns0332","command":"backup","success":true,"exit_code":0,"duration":42,"error":"","ts":"2026-10-07T17:23:00Z"}
```

| 필드 | 의미 |
|---|---|
| `job` | `backup`(호스트 실행) 또는 `inventory`(Deploy 등록 이벤트) |
| `host` | Inventory Hostname |
| `command` | resticprofile 명령 (`backup`) |
| `success`, `exit_code`, `error` | 결과. `error`는 출력 가능한 ASCII만 남겨 500바이트로 자름 |
| `duration` | 초 |
| `ts` | UTC ISO-8601 |

이벤트 기록에 실패해도 백업 자체는 실패로 처리하지 않는다(스크립트는 항상 0으로 종료).

### 4.5 Deploy 전용 작업 (Config 템플릿에서는 하지 않음)

1. **repo 초기화**: `resticprofile ... cat config`로 repo를 조회하고, 없을 때만 `init`한다. repo가 없어서가 아닌 다른 오류(인증, 네트워크 등)면 init하지 않고 실패로 끝낸다.
2. **등록 이벤트**: 플레이 마지막에 컨트롤러가 OpenObserve `backup_logs`에 `{"job":"inventory","host":"<host>","deployed_at":"<UTC>"}`를 POST한다. 앞 단계가 모두 성공해야 실행되며, 컨트롤러 전용 토큰(`controller_ingest_token`)을 쓴다.

---

## 5. 입력 (OpenBao KV v2, Git에는 시크릿 없음)

| KV 경로 | 키 | 필수 | 용도 |
|---|---|---|---|
| `hosts/<host>/agents` | `o2_ingest_token` | ● | otelcol → OpenObserve 인증 |
| | `rustfs_access_key`, `rustfs_secret_key` | ● | 호스트 전용 RustFS 키 → `/etc/restic/env` |
| | `restic_password` | ● | repo 비밀번호 → `/etc/restic/password` |
| | `host_agents_environment` | ●(인벤토리에 없으면) | `deployment.environment.name` |
| | `rustfs_bucket` | | 버킷 재정의 |
| | `otel_extra_logs`, `otel_exclude_logs` | | 수집 경로 추가·제외 |
| | `otel_docker_metrics` | | docker 메트릭 수집 |
| | `backup_extra_paths`, `backup_exclude_paths`, `backup_pre_hooks` | | 백업 경로 추가·제외, 사전 훅 |
| `agents/openobserve` | `o2_endpoint`, `o2_org`, `o2_ca_file`, `controller_ingest_token` | endpoint·token 필수 | 전송 대상과 등록 이벤트 |
| `agents/rustfs` | `rustfs_endpoint`, `rustfs_region`, `rustfs_ca_file` | endpoint 필수 | 백업 대상 |

필수 키가 없거나, 제외할 수 없는 경로를 제외하려 하면 해당 호스트는 **어떤 변경도 하기 전에** 실패한다(fail-closed).
