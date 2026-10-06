# Monitoring Role Task Specification

`monitoring` 역할은 OpenTelemetry Collector Contrib(`otelcol-contrib`)을 기반으로 한 온프레미스 단일 에이전트 관제 파이프라인의 배포, 시스템 계정 격리, `hostmetrics` 리시버를 통한 커널/OS 메트릭 수집, 그리고 레거시 `node_exporter` 자동 정리를 수행합니다.

> **Host Agents 전환 중**: 이 역할은 [ADR-0006](adr/0006-host-agents-otelcol-resticprofile.md)에 따라 `playbooks/host_agents.yml` 전용입니다. `site.yml`·`maintenance.yml`에서는 더 이상 적용되지 않습니다. 진입점, OS 프로브, OpenBao 입력 검증(`MON-020~035`)은 구현되었고, 수집 표준·스트림·버퍼링·버전 고정·CentOS 6/7 분기도 이 표에 이관되었습니다. 아래 매트릭스는 **현재 구현**을 기술합니다.

---

## 1. 개요 및 구현 기능 (What)

- **레거시 Node Exporter 정리 (Cleanup)**: 기존 노드에 잔존할 수 있는 `node_exporter` 데몬 중지, 서비스 비활성화, unit 파일 및 바이너리/계정 자동 제거.
- **전용 격리 시스템 계정 생성**: 권한 탈취 위험을 최소화하기 위해 비로그인 셸(`/sbin/nologin` 또는 `/bin/false`)을 사용하는 `otelcol` 시스템 계정 및 그룹 생성.
- **OpenTelemetry Collector Contrib 배포**: `otelcol-contrib` 바이너리 배포 및 OpenObserve OTLP 아웃바운드 스트리밍 파이프라인 구성.
- **Hostmetrics 리시버 직접 수집**: 별도 프록시/익스포터 없이 OTel Collector의 `hostmetrics` receiver(`collection_interval: 15s`)를 통해 CPU, 메모리, 디스크, 파일시스템, 로드 애버리지, 네트워크, 페이징, 프로세스 지표 수집.
- **ISMS/ISMS-P 기준 OS 보안/감사 로그 수집**: `filelog` receiver를 통한 시스템 보안/감사 로그 수집 및 중앙 OpenObserve로 OTLP Outbound 푸시.
- **Systemd 서비스 유닛 파일 등록**: `otelcol-contrib.service` 유닛 파일을 생성하여 부팅 시 자동 시작 및 프로세스 모니터링 보장.
- **네트워크 포트 아키텍처**: Otel Collector가 중앙으로 **아웃바운드(Outbound)** 전송하므로 **외부 인바운드 방화벽 포트 오픈이 불필요**합니다.

---

## 2. 왜 구현해야 하는가? (Why)

1. **단일 에이전트 통합 관제(Single Agent Observability) 및 ISMS/ISMS-P 컴플라이언스 확보**:
   - 기존의 `node_exporter`와 `otelcol-contrib` 2개 데몬 구조에서 벗어나 단일 OTel Collector 데몬으로 메트릭과 로그를 통합 처리하여 리소스 및 운영 비용을 최소화합니다.
   - 하드웨어 및 OS 리소스 고갈(디스크 풀, 메모리 OOM, CPU 스파이크)을 조기에 발견하고 알림(Alerting)을 발생시키기 위해 실시간 메트릭 수집이 필수적입니다.
   - 시스템 장애 분석 및 보안 감사를 위해 커널 로그(`/var/log/messages`, `syslog`), 인증 보안 로그(`/var/log/secure`, `auth.log`), 관리자 권한 상승 로그(`/var/log/sudo.log`), 커널 감사 로그(`/var/log/audit/audit.log`), 예약 작업 로그(`/var/log/cron*`), 침입 차단 로그(`/var/log/fail2ban.log`), 패키지 설치 이력(`/var/log/dnf.log`, `yum.log`, `dpkg.log`), 방화벽 로그(`/var/log/firewalld`)를 OpenTelemetry 파이프라인을 통해 중앙 OpenObserve로 단일화하여 수집합니다.
2. **최소 권한 원칙 & 포트 노출 제로(Zero Port Exposure)**:
   - 모니터링 데몬을 `root` 권한이 아닌 전용 비특권 `otelcol` 사용자로 실행하여 호스트 장악을 방어합니다.
   - 외부 인바운드 포트를 일체 개방하지 않고 OTLP 아웃바운드로만 통신하여 공격 표면을 완벽히 제거합니다.
3. **OpenObserve 중앙 통합 관제 연동**:
   - Hostmetrics와 OS 로그를 단일 OTLP 스트림으로 결합하여 중앙 OpenObserve 백엔드로 실시간 전송합니다.

---

## 3. 무엇을 변경하는가? (What Changes)

- 📁 **설정 파일 및 바이너리**:
  - `/usr/local/bin/otelcol-contrib` : OpenTelemetry Collector Contrib 바이너리
  - `/etc/otelcol/config.yaml` : OpenObserve 연동 OTLP 파이프라인 설정 (`hostmetrics` + `filelog`)
  - `/etc/systemd/system/otelcol-contrib.service` : OpenTelemetry Collector 서비스 정의
  - `/usr/local/bin/node_exporter`, `/etc/systemd/system/node_exporter.service` : 레거시 파일 자동 삭제 (`absent`)
- ⚙️ **데몬 및 서비스**:
  - `otelcol-contrib` : 서비스 기동(`started`) 및 부팅 시 자동 실행(`enabled`)
  - `node_exporter` : 서비스 중지(`stopped`) 및 비활성화(`disabled`)
- 👤 **사용자 및 그룹**:
  - `otelcol` 시스템 계정 및 그룹 생성
  - `node_exporter` 레거시 시스템 계정 및 그룹 삭제
- 🌐 **네트워크 포트**:
  - 외부 인바운드 포트 불필요 (OTLP Outbound 푸시 방식)

---

## 3-1. Host Agents 진입점과 입력 (`playbooks/host_agents.yml`)

- **호스트 집합**: `target_hosts:&servers` (축소만 가능, `servers` 밖으로 확장 불가). 연결 해석/정리 플레이(`resolve_connection.yml`, `cleanup_connection.yml`)도 `connection_hosts` 변수로 같은 집합만 처리하며 두 import 모두 `tags: [always]`입니다.
- **롤아웃**: `serial: 25%`, `gather_facts: false`. 프로비저닝 assert·OS 프로브·fact 수집·입력 검증은 모두 역할 안에서 수행됩니다.
- **태그**: 설치 단계 `agents_install`, 설정/스케줄 단계 `agents_config`, 역할 공통 `otel`(향후 `backup`). 사전 단계(`MON-020~035`)는 `always`라 `--tags agents_config`에서도 수행됩니다. Deploy = 태그 없음, Config = `--tags agents_config`.
- **사전 단계**: `_is_already_provisioned`가 아니고 `hosts/<호스트>` KV에 `host_agents_allow_password_auth: true`도 없으면 즉시 실패(아래 "비밀번호 접속 예외" 참고) → raw 프로브(`/etc/os-release`, `/etc/redhat-release`, `uname -m`)로 `host_agents_os_path`(`legacy_el6`/`legacy_el7`/`modern`)와 `host_agents_os_*` fact 생성 → `modern`만 `/usr/bin/python3` 보장 + `setup`. `legacy_el7`(CentOS 7, §3-4)과 `legacy_el6`(CentOS 6, §3-5)은 raw 경로로 적용됩니다.
- **OpenBao 입력**: `hosts/<host>/agents`(호스트별)와 `agents/openobserve`, `agents/rustfs`(공용, `run_once`)를 컨트롤러에서 조회합니다.

  | 키 (`hosts/<host>/agents`) | 필수 | 용도 |
  |---|---|---|
  | `o2_ingest_token`, `rustfs_access_key`, `rustfs_secret_key`, `restic_password` | 예 | 호스트 전용 시크릿 (누락 시 해당 호스트 실패) |
  | `otel_extra_logs` | 아니오 | glob(→ `app_logs`) 또는 `{path, stream, service}` 추가. `service`(소문자·숫자·`.-_`)는 선택, 없으면 스트림 이름(`app` 등)으로 보고 |
  | `otel_exclude_logs` | 아니오 | 표준 목록에서 정확히 일치하는 경로 제거. `security_logs` 경로는 제외 불가 |
  | `otel_docker_metrics` | 아니오 | Docker 메트릭 opt-in |
  | `host_agents_environment` | 예(호스트별) | `production` \| `staging` \| `development` \| `test`. 인벤토리 변수가 우선이고 없으면 이 KV 키. **그룹 기본값 없음** — 누락·허용 밖 값은 변경 전 실패(`MON-037`) |
  | `backup_extra_paths`, `backup_exclude_paths`, `backup_pre_hooks` | 아니오 | 필수 백업 경로(`/etc`, `/var/spool/cron`, `/usr/local/{bin,etc,sbin}`)와 그 상위 경로는 제외 불가 |

- **실패 조건 (변경 전, check 모드 포함)**: 필수 키 누락, OpenBao 조회 오류(연결 실패/403/토큰 없음), 제외 불가 경로를 지정한 exclude → 위반 경로와 KV 키를 메시지에 명시. 선택 키 부재는 Git 표준만 적용합니다.
- **공유 시크릿**: `agents/openobserve`, `agents/rustfs`가 없거나 값이 비어 있으면 실패합니다(조회는 호스트마다 수행, TLS 검증은 `host_agents_vault_validate_certs`).
- **제외 판정**: `otel_exclude_logs`는 경로 정규화 후 동일/glob/상위 디렉터리가 `security_logs` 경로를 덮으면 실패합니다(`/var/log/audit`, `/var/log/secure*` 포함).
- **fact 출력**: `host_agents_inputs`(`otel_logs`, `otel_docker_metrics`, `backup_paths`, `backup_exclude_paths`, `backup_pre_hooks`, `errors`; 시크릿 없음), `host_agents_secrets`, `host_agents_shared_secrets`(`no_log`).
- **테스트 seam**: `host_agents_kv_fixture`(`{host, openobserve, rustfs}`)가 정의되면 OpenBao를 조회하지 않습니다(molecule 공용 `group_vars`가 `_is_already_provisioned: true`와 함께 제공).

---

### 비밀번호 접속 예외 (ADR-0006 §2.1 개정)

SSH 키가 없고 `USERNAME/PASSWORD`로만 접속되는 레거시 호스트(CentOS 6/7 등)에도 Host Agents를 설치할 수 있습니다. **호스트별 명시 허용**이 필요합니다.

1. OpenBao `secret/hosts/<호스트>`(접속 정보 KV, `/agents` 아님)에 `"host_agents_allow_password_auth": true`를 추가합니다. 이 플래그가 없는 호스트는 기존처럼 `MON-020`에서 중단됩니다.
2. 접속 계정은 **root** 또는 **일반 계정 + sudo 비밀번호** 모두 가능합니다. 키가 없으면 호스트는 부트스트랩 모드로 접속하므로 계정과 비밀번호는 `hosts/<호스트>/bootstrap`(우선) 또는 `users/<bootstrap_user>`의 `password`에서 읽고(`bootstrap_user`는 `hosts/<호스트>` KV로 호스트별 지정, 기본 `root`), 일반 계정이면 같은 비밀번호가 sudo 비밀번호(`ansible_become_password`)로 쓰입니다.
3. `admin_users`는 접속 계정이 아니라 `Validate an admin user is resolved` 단언을 통과시키는 용도입니다(없으면 `resolve_connection`이 중단).
4. CentOS 6/7 바이너리 업로드는 `sshpass -e scp`(`MON-104`)로 진행합니다. 비밀번호는 `SSHPASS` 환경변수로만 전달되어 인자·프로세스 목록·로그에 나타나지 않습니다(`no_log`). 컨트롤러(Semaphore 러너)에 `sshpass`가 필요하며 없으면 `MON-109`에서 중단합니다. 설정 파일·unit은 기존 base64 raw 전송이라 비밀번호 접속으로 동작합니다.
5. 이 예외로 설치된 호스트는 실행마다 `PASSWORD-AUTH-EXCEPTION` 경고(`MON-029`)가 남습니다(ISMS 증적). **만료 기준**: 해당 호스트를 `site.yml`로 하드닝(키 인증)하면 플래그를 제거합니다.

## 3-2. 바이너리 버전 고정과 전달 (`deliver_binary.yml`)

- 버전·SHA256은 `vars/main.yml`의 `host_agents_versions`/`host_agents_checksums`(Git 고정, 호스트별 오버라이드 없음). 버전 상향 PR은 체크섬 변경을 동반하며 upstream `checksums.txt`는 신뢰하지 않습니다. 현재 `default` 경로: otelcol-contrib v0.161.0.
- 컨트롤러가 tarball을 1회 다운로드해 SHA256을 검증하고 `host_agents_cache_dir`(기본 `~/.cache/host-agents`)에 캐시한 뒤, 인터넷이 없는 호스트에도 `copy`로 푸시합니다.
- 레이아웃: `/opt/host-agents/otelcol-contrib/<version>/otelcol-contrib`, `/usr/local/bin/otelcol-contrib`는 현재 버전 symlink. 호스트에는 현재+직전 버전 1개만 보존합니다.
- 순서: `deliver_binary.yml`(푸시 → 호스트 SHA256 == 컨트롤러가 검증한 tarball 바이너리, 불일치 시 호스트 실패·symlink 불변) → 설정 template의 `validate:`가 **새 버전 바이너리**로 새 설정을 검증(실패 시 설정·symlink 모두 불변, 최초 설치 포함) → `switch_binary.yml`(symlink 교체, 핸들러 재시작, 정리). 일반 파일로 남은 기존 바이너리(0.108.0)는 `<agent_dir>/legacy-<binary>`로 보존합니다. 롤백은 버전 표 revert PR 후 재실행.
- check 모드에서 버전 변경은 `MON-051` symlink diff(`--diff`)와 `MON-045` 표시로 확인합니다.
- `deliver_binary.yml`/`switch_binary.yml`은 `_deliver_*` 변수로 매개화되어 backup 역할(restic/resticprofile)이 재사용합니다(SPEC-ID `MON-040~054`). 호스트 측 위치·소유자는 `host_agents_bin_dir/owner/group` 기본값(`/usr/local/bin`, `root`)입니다.

---

## 3-3. 수집 설정 (`otelcol-contrib.yaml.j2`, `MON-060~065`)

- **수신**: 스트림별 `filelog/<stream>`(`start_at: end`, `storage: file_storage`, `log_type` 속성, 본문 원문 유지, 위 Envelope Parsing으로 필드만 추가) + `hostmetrics`(60s, 8 스크레이퍼). journald는 `/usr/sbin/rsyslogd`가 없는 호스트에서만, `docker_stats`는 `otel_docker_metrics: true`인 호스트에서만, 로컬 OTLP 수신기는 `otel_otlp_enabled: true`일 때만 추가됩니다(기본 off).
- **Envelope Parsing (ADR-0008, `MON-004`/`MON-207`/`MON-025`)**: 수신 본문(원문)은 바이트 단위로 그대로 두고, 파일별 `if:` 조건 operator가 포맷이 정한 필드만 `Timestamp`·`attributes`·`severity`에 붙입니다(수신기 ID는 그대로). 포맷 표는 `vars/main.yml`의 `otel_log_formats`입니다.
  - syslog 계열(`messages`, `syslog`, `secure`, `auth.log`, `sudo.log`, `cron*`, `kern.log`): RFC3164 시각 → `Timestamp`(Probe가 읽은 호스트 타임존, 연도는 수집 시점 기준 추정), `process.executable.name`, `process.pid`, `message`. 줄에 찍힌 hostname은 버리고 리소스 `host.name`을 유지합니다. PRI가 없으므로 severity는 비웁니다.
  - `audit/audit.log`: `audit.type`, `audit.serial`, `msg=audit(epoch:serial)`의 시각, 나머지 `key=value`는 `audit.fields`.
  - `fail2ban.log`(시각·`component`·`process.pid`·`message`·레벨), `dnf.log`(시각·레벨·`message`): 레벨이 있을 때만 `severity_*`. `yum.log`, `dpkg.log`: 시각(`dpkg.action`)만, severity 없음. `journald`: `PRIORITY` → severity(본문 원문 맵 유지). `app_logs`, 사용자 추가 경로, 그리고 RFC3164가 아닌 `sudo.log`(sudo `Defaults logfile` 형식: 호스트·프로그램 없이 `시각 : 사용자 : ...`), `boot.log`(`[  OK  ]` 콘솔 출력), `firewalld`(ISO 시각 + 레벨)는 파싱하지 않습니다(파싱하면 모든 줄이 `log.parse_error` 오탐이 되므로 표에서 뺐고 원문만 전송). 이 경로의 줄은 `process.executable.name` 등 필드가 없으므로 `openobserve_config`의 sshd/sudo 해석 대상이 아닙니다(sudo는 `/var/log/secure`·`auth.log`의 syslog 줄로 해석).
  - 포맷에 맞지 않는 줄은 버리지 않고 원문 그대로 보내며 `log.parse_error=true`를 붙입니다(이벤트 시각이 없으면 수집 시각 사용). 키워드로 severity를 추정하지 않습니다.
  - **Probe 타임존**(`MON-021/022/025`): `/etc/localtime` 링크 대상(systemd 계열), 없으면 `/etc/sysconfig/clock`의 `ZONE=`(CentOS 6)에서 읽어 `host_agents_timezone`에 둡니다. 읽지 못하면 `timezone` 변수(기본 `Asia/Seoul`)로 대체하고 `MON-025`가 WARN을 남깁니다. 세 경로(modern, legacy_el7, legacy_el6) 모두 같은 템플릿이며 0.119.0·0.161.0에서 같은 operator 구성이 동작합니다(pytest `tests/test_envelope_parsing.py`가 실제 바이너리로 검증).
- **백업 결과 수집**: 고정 수신기 `filelog/backup_logs`(`otel_backup_log_path`, `log_type: backup_logs`)가 `json_parser`로 필드를 attributes로 올리되 본문 원문은 유지하고 `ts`를 이벤트 시각으로 씁니다. 필드 계약은 [backup.md §6](backup.md).
- **라우팅**: `logs/in`(memory_limiter, `resource/host`: `host.name`=인벤토리 호스트명, `os.type`, `os.name`, `os.version`, `os.description`, `host.arch`, `host.id`(없으면 생략), `host.ip`(인벤토리 `ip` > 호스트 KV `ip` > `public_ip`, 없으면 생략), `deployment.environment.name`; `service.name`은 파일 그룹·수집기별로 따로 부여; 값 정의는 [ADR-0006 §2.3](adr/0006-host-agents-otelcol-resticprofile.md)) → `routing/logs`(`log_type`) → `security_logs`/`system_logs`/`app_logs`/`backup_logs` 파이프라인 → 스트림별 `otlphttp` exporter(`stream-name` 헤더).
- **전송**: `<o2_endpoint>/api/<o2_org>`(끝 슬래시 금지), `Authorization: Basic ${env:O2_BASIC_AUTH}`, 사설 CA는 `o2_ca_file`. 로그 exporter는 `file_storage` 영속 bytes 큐(`otel_log_queue_bytes`) + `block_on_overflow: true` + `max_elapsed_time: 0`; 메트릭은 별도 메모리 큐(`block_on_overflow: false`) 파이프라인입니다. `file_storage`는 `compaction.on_rebound: true`.
- **시크릿**: `/etc/otelcol-contrib/secrets.env`(`0600`, `no_log`, `diff: false`)에만 있고 설정은 `${env:…}`로 참조합니다. systemd 유닛은 비root `otelcol` + `CAP_DAC_READ_SEARCH` + `EnvironmentFile`.
- **입력 변수**: `o2_endpoint`, `o2_org`, `o2_ca_file`은 **Semaphore Extra variables 또는 `group_vars`(우선) → OpenBao `agents/openobserve`의 같은 이름 키(폴백) → 기본값(`o2_org=default`, 나머지 빈 값)** 순으로 해석합니다. 저장소가 공개라 내부 도메인은 Git에 두지 않고 평상시에는 OpenBao에 둡니다. 이전 gRPC exporter(`otel_target_*`)와 `organization` 헤더 없는 템플릿은 제거되었습니다.

---

## 3-4. CentOS 7 (`legacy_el7`) raw 경로와 카나리 런북 (`MON-2xx`, `BAK-2xx`)

- **번호 대역**: legacy 경로는 한 파일(`tasks/legacy.yml`)을 CentOS 6/7이 공유합니다. 두 OS가 공유하는 태스크와 CentOS 7 전용 태스크는 `MON-2xx`/`BAK-2xx`(적용 대상 열이 `legacy_el6, legacy_el7` 또는 `legacy_el7`), CentOS 6 전용 태스크만 `MON-1xx`(`MON-110~122`)입니다. raw 공용 헬퍼는 기존 번호를 유지합니다: 파일 전달 `MON-100~108`(`raw_upload.yml`, #46), 설치 디렉터리·스모크·symlink `MON-210~212`. backup은 두 OS 차이가 버전 행뿐이라 CentOS 6 전용 태스크가 없고 모두 `BAK-2xx`입니다. 각 태스크의 OS 조건과 대역 일치는 `tests/test_host_agents_legacy_el7.py::test_spec_id_bands_follow_the_os_gate_of_each_legacy_task`가 강제합니다.

- **경로**: OS 프로브가 `legacy_el7`로 분류한 호스트는 AnsiballZ 모듈(python3)을 쓰지 않고 `tasks/legacy.yml`(monitoring, backup 각각, CentOS 6과 공용)을 raw 경로로 실행합니다. 같은 템플릿을 컨트롤러에서 렌더링(`lookup('template')`)해 ADR-0005 헬퍼(write-temp → validate → mv, sentinel)로 올리므로 설정·프로파일·cron 내용은 modern과 동일합니다(바이트 단위 테스트). CentOS 6은 §3-5를 따릅니다.
- **바이너리**: 컨트롤러가 pinned tarball을 검증·캐시한 뒤 `scp`로 업로드하고, 원격 `sha256sum`을 *추출 바이너리의* Git 고정 해시와 비교합니다(`MON-104/105`). 버전 디렉터리에서 스모크 테스트(`MON-211`: otelcol `--version`, restic·resticprofile `version`)를 통과해야만 설정 검증과 symlink 교체로 넘어갑니다. 실패하면 그 호스트만 실패하고 기존 symlink(직전 버전)가 유지됩니다.
- **컬렉터 유닛**: root 실행 + `NoNewPrivileges`, `ProtectSystem=full`, `ProtectHome`, `PrivateTmp`(CentOS 7의 systemd 219가 지원하는 항목만). 유닛 변경 시에만 `daemon-reload`, 이후 `is-enabled`/`is-active` sentinel로 `enable`/`start`(`enable --now` 미사용).
- **백업**: `/etc/cron.d/host-agents-backup`, repo 프로브/`init`은 raw, `backup.jsonl` 증적·logrotate·훅은 modern과 동일합니다. 태그 분리(`agents_install`/`agents_config`)와 Deploy 한정(init, 등록 이벤트)도 동일합니다.
- **check 모드**: 읽기 전용 프로브만 실행되고 변경 raw 태스크는 건너뜁니다. 비시크릿 파일은 컨트롤러 렌더링본과 원격의 diff를, 시크릿 파일은 변경 예정 여부만 출력합니다.
- **정리 범위**: `node_exporter` 레거시 정리(`MON-011~015`)는 legacy 경로에 포함하지 않습니다(CentOS 7에는 이 역할로 설치된 적이 없음).

### 카나리 런북 (첫 실제 CentOS 7 호스트)

CentOS 7 Test Image가 없으므로 첫 실제 호스트가 카나리입니다. 버전 상향 때도 같은 절차를 씁니다.

1. 사전 확인(컨트롤러에서): 대상이 `site.yml`로 프로비저닝됐고, 호스트에 `sha256sum`, `systemctl`, `/etc/cron.d`가 있으며 접속 사용자가 sudo를 쓸 수 있는지 확인합니다. 접속은 개인키 기반이어야 합니다(비밀번호 전용 연결은 `scp` 단계에서 명확한 메시지로 실패).
2. `scp` 서브시스템 확인: 컨트롤러의 OpenSSH 9+는 `scp`가 SFTP로 동작합니다. 대상 `sshd_config`에서 `Subsystem sftp`가 꺼져 있으면 모든 업로드가 실패합니다(`MON-104`). 이 경우 대상에서 sftp를 켜거나 컨트롤러에 구버전 프로토콜 `scp -O`를 쓰는 별도 릴리스를 사용해야 합니다(결과를 이 런북에 기록).
3. dry-run: `ansible-playbook playbooks/host_agents.yml -e target_hosts=<host> --check --diff`. `MON-102/103/107`의 diff와 업로드 예정 보고를 확인합니다(시크릿 내용은 출력되지 않아야 함).
4. 배포: 같은 명령에서 `--check --diff`를 뺍니다. 확인 항목:
   - `systemctl status otelcol-contrib`가 active, `/usr/local/bin/otelcol-contrib --version`이 고정 버전, `/opt/host-agents/<agent>/`에 현재+직전만 남음
   - `/etc/cron.d/host-agents-backup` 존재, `resticprofile ... show` 성공, repo가 생성되고 `job=inventory` 이벤트가 `backup_logs`에 도착
   - OpenObserve에 `host.name=<host>`, `os.description=CentOS Linux 7 (Core)` 로그/메트릭 도착, `security_logs` 스트림에 `/var/log/secure` 포함
   - 수동 백업 1회(`resticprofile -n default backup`) 후 `backup.jsonl`에 한 줄이 쌓이고 `backup_logs`에 수집됨
5. 재실행(멱등): 같은 명령을 다시 실행해 `changed=0`(핸들러 재시작 없음)을 확인합니다.
6. 이상 없으면 `target_hosts`를 넓혀 나머지 CentOS 7 호스트에 확장합니다(`serial: 25%`). 스모크 테스트 실패(예: 구형 glibc/커널)는 해당 호스트만 실패하며 기존 symlink(직전 버전)가 유지되어 데몬은 그대로 동작합니다(새 버전 디렉터리는 디스크에 남으며 다음 실행에서 정리됩니다). 롤백은 버전 표 revert PR 후 재실행입니다.


## 3-5. CentOS 6 (`legacy_el6`) raw 경로와 카나리 런북 (`MON-1xx`, `BAK-1xx`)

- **경로**: CentOS 7과 같은 `tasks/legacy.yml`(monitoring, backup 각각)과 raw 헬퍼(`raw_upload.yml`, `legacy_deliver_binary.yml`, `legacy_switch_binary.yml`)를 씁니다. CentOS 6 전용 태스크(`MON-110/114/119/121/122`)만 `host_agents_os_path == 'legacy_el6'` 조건이 붙고, systemd 태스크(`MON-201/202/213/215`)는 `legacy_el7` 조건이라 실행되지 않습니다(번호 대역은 §3-4).
- **버전 행**: `host_agents_version_row`가 `legacy_el6`이면 `host_agents_versions.legacy_el6`(otelcol-contrib v0.119.0, restic 0.17.3, resticprofile 0.29.1 — 모두 Go 1.23 빌드, 커널 2.6.32 지원)을 씁니다. 체크섬은 릴리스 tarball을 직접 받아 계산한 값입니다. 만료일 `2027-12-31`(`host_agents_version_expiry`)이 지나면 `MON-110`이 모든 실행(Deploy/Config/태그)에서 Ansible `[WARNING]`만 출력합니다(실패 아님). 기준일 `host_agents_today`는 역할 vars(덮어쓰기 대상 아님)입니다.
- **컬렉터 init**: `otelcol-contrib.init.j2`를 `/etc/init.d/otelcol-contrib`(`0755`)로 배포합니다. root로 실행하고(커널 2.6.32에는 ambient capability 없음) `/etc/otelcol-contrib/secrets.env`를 `set -a`로 읽어 `${env:O2_BASIC_AUTH}`를 공급합니다. 부팅 등록은 `chkconfig --list otelcol-contrib`의 `3:on`을 sentinel로, 없을 때만 `chkconfig --add` + `chkconfig on`(`MON-121`). `start`는 컬렉터의 stdin을 `/dev/null`로, stdout/stderr를 로그 파일로 돌려 raw(SSH) 세션이 백그라운드 자식 때문에 매달리지 않습니다. 재시작 핸들러(`Restart otelcol-contrib (raw)`)는 CentOS 6에서 `service otelcol-contrib restart`이며, `stop`은 이전 프로세스가 종료(큐 flush, `file_storage` 잠금 해제)될 때까지 최대 30초 기다린 뒤에만 pidfile을 지웁니다(초과 시 KILL). 컬렉터 자체 로그 `/var/log/otelcol-contrib.log`는 `/etc/logrotate.d/otelcol-contrib`(`MON-122`, `copytruncate`, 주간 4회 보존)로 회전합니다.
- **설정**: 같은 `otelcol-contrib.yaml.j2`이며 `sending_queue`만 legacy_el6 분기입니다. v0.119.0은 `sizer`와 `block_on_overflow`를 모르므로(`validate`가 `invalid keys: block_on_overflow, sizer`로 거부) 구 이름 `blocking: true`와 배치 개수 `queue_size`(`otel_log_queue_batches_legacy_el6: 64`)를 씁니다. 역압은 유지됩니다(ADR-0006 §2.8 확인 결과).
- **백업**: CentOS 7과 같은 태스크(`BAK-2xx`)이며 restic/resticprofile만 legacy_el6 행입니다(`/etc/cron.d/host-agents-backup`, 프로파일·훅·logrotate·repo 프로브/`init` 동일). 프로파일은 resticprofile 0.29.1 + restic 0.17.3의 `show`를 통과합니다.

### 카나리 런북 (첫 실제 CentOS 6 호스트)

CentOS 6 Test Image가 없으므로 첫 실제 호스트가 카나리입니다. §3-4 CentOS 7 런북 절차를 따르되 아래를 바꾸거나 추가합니다.

1. **SSH 알고리즘 확인(가장 먼저)**: CentOS 6의 OpenSSH 5.3은 SHA-1 `ssh-rsa` 서명만 지원하며, 컨트롤러의 OpenSSH 8.8+는 이를 기본 비활성화합니다. `ansible -m raw -a 'cat /etc/redhat-release' <host>`가 실패하면 연결 옵션(`-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa`)이 필요합니다. `MON-104`의 `scp`는 Ansible `ssh_args`를 상속하지 않으므로, raw 태스크가 통과해도 업로드가 실패할 수 있습니다. 결과(필요 여부와 적용 방법)를 이 런북에 기록하고, 필요하면 `raw_scp_argv`에 옵션 전달을 추가하는 후속 작업을 엽니다.
2. **scp 프로토콜**: 컨트롤러 OpenSSH 9+의 `scp`는 SFTP를 씁니다. 대상 `sshd_config`의 `Subsystem sftp`가 켜져 있는지 확인합니다(§3-4 2단계와 동일).
3. **사전 도구**: `sha256sum`, `base64`, `chkconfig`, `service`, `/etc/cron.d`, `/bin/bash`가 있는지 확인합니다(`MON-105/106/119/121`이 사용).
4. **dry-run** → **배포**: `ansible-playbook playbooks/host_agents.yml -e target_hosts=<host> --check --diff` 후 플래그 없이 실행합니다. 확인 항목:
   - `service otelcol-contrib status`가 running, `chkconfig --list otelcol-contrib`가 `3:on`, `/usr/local/bin/otelcol-contrib --version`이 `0.119.0`
   - `/var/log/otelcol-contrib.log`에 `invalid keys`나 401 오류가 없음(secrets env 적재 확인)
   - OpenObserve에 `os.description=CentOS release 6.x (Final)` 로그/메트릭 도착, `security_logs`에 `/var/log/secure` 포함
   - `restic version`이 `0.17.3`, `resticprofile version`이 `0.29.1`, `/etc/cron.d/host-agents-backup` 존재, 수동 백업 1회 후 `backup.jsonl` → `backup_logs` 수집
   - 만료일 이후라면 `MON-110` `[WARNING]`이 출력되는지(실패하지 않는지), `/etc/logrotate.d/otelcol-contrib`이 있고 `logrotate -d /etc/logrotate.d/otelcol-contrib`이 오류 없이 끝나는지
5. **역압 확인(선택, 유지보수 창)**: OpenObserve 수집을 잠시 차단하고 큐가 차면 `filelog`가 읽기를 멈추며 `sending queue is full` 거부 로그가 없는지 확인한 뒤 복구 후 누락 없이 재개되는지 봅니다.
6. **재실행(멱등)**: `changed=0`(재시작 없음)을 확인한 뒤 나머지 CentOS 6 호스트로 넓힙니다. 스모크 테스트(`MON-211`) 실패는 해당 호스트만 실패하고 기존 symlink가 유지됩니다.

---

## 4. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `MON-011` | `Stop and disable legacy node_exporter service` | `ansible.builtin.systemd` | Systemd OS | 서비스 중지/비활성화 시 `ok` |
| `MON-012` | `Remove legacy node_exporter systemd unit file` | `ansible.builtin.file` | Systemd OS | 파일 부존재 시 `ok` |
| `MON-013` | `Remove legacy node_exporter binary` | `ansible.builtin.file` | All | 바이너리 부존재 시 `ok` |
| `MON-014` | `Remove legacy node_exporter user` | `ansible.builtin.user` | All | 유저 부존재 시 `ok` |
| `MON-015` | `Remove legacy node_exporter group` | `ansible.builtin.group` | All | 그룹 부존재 시 `ok` |
| `MON-001` | `Create otelcol system group` | `ansible.builtin.group` | All | 그룹 존재 시 `ok` |
| `MON-002` | `Create otelcol system user` | `ansible.builtin.user` | All | 유저 존재 시 `ok` |
| `MON-003` | `Deliver pinned OpenTelemetry Collector Contrib binary` | `ansible.builtin.include_tasks` | RHEL 7+, Debian | 버전 디렉터리 존재/symlink 일치 시 `ok` (`creates:` 없음 — 버전 상향 시 롤아웃) |
| `MON-004` | `Deploy OpenTelemetry Collector Contrib configuration (Hostmetrics & Log Pipeline)` | `ansible.builtin.template` | RHEL 7+, Debian | Checksum 비교 (`otelcol-contrib.yaml.j2`) |
| `MON-005` | `Create systemd service for otelcol-contrib` | `ansible.builtin.template` | Systemd OS | 파일 내용 일치 시 `ok` |
| `MON-006` | `Ensure otelcol-contrib service is started and enabled` | `ansible.builtin.service` | All | 서비스 기동 상태면 `ok` |
| `MON-020` | `Assert host was provisioned by site.yml (or opted in to password-auth install)` | `ansible.builtin.assert` | All | 읽기 전용 (SSH 키 접속 가능 호스트이거나 `hosts/<호스트>` KV에 `host_agents_allow_password_auth: true`를 명시한 호스트만 통과) |
| `MON-021` | `Probe OS release and architecture from target host (raw, read-only)` | `ansible.builtin.raw` | All | `changed_when: false`, `check_mode: false` |
| `MON-022` | `Classify OS path and set host_agents_os facts from probe` | `ansible.builtin.set_fact` | All | 프로브 결과 순수 함수 |
| `MON-023` | `Check /usr/bin/python3 exists on modern path (raw, read-only)` | `ansible.builtin.raw` | modern | `changed_when: false`, `check_mode: false` |
| `MON-024` | `Gather facts on modern path` | `ansible.builtin.setup` | modern | 읽기 전용 |
| `MON-025` | `Warn when the host timezone could not be read (falling back to the timezone variable)` | `ansible.builtin.debug` | All | 읽기 전용 (Probe가 `/etc/localtime` 링크·`/etc/sysconfig/clock`에서 타임존을 읽지 못한 호스트에만 WARN, `timezone` 변수(기본 `Asia/Seoul`)로 대체) |
| `MON-029` | `Warn that this host is installed through the password-auth exception (ISMS evidence)` | `ansible.builtin.debug` | All | 읽기 전용 (비밀번호 예외로 통과한 호스트에만 `PASSWORD-AUTH-EXCEPTION` 경고를 남김) |
| `MON-026` | `Install python3 on modern path when absent` | `ansible.builtin.raw` | modern | 부재 시에만 실행 (check 모드 스킵) |
| `MON-027` | `Assert python3 is available on modern path` | `ansible.builtin.assert` | modern | 읽기 전용 |
| `MON-030` | `Fetch agents KV from OpenBao (hosts/<hostname>/agents, agents/openobserve, agents/rustfs)` | `ansible.builtin.uri` | All | GET, `check_mode: false`, `no_log` |
| `MON-031` | `Assert OpenBao answered every agents lookup` | `ansible.builtin.assert` | All | 읽기 전용 (오류 시 check 모드에서도 실패) |
| `MON-032` | `Resolve agents KV contents (host + shared)` | `ansible.builtin.set_fact` | All | 순수 함수 (`no_log`) |
| `MON-033` | `Merge agents inputs with the Git standard` | `ansible.builtin.set_fact` | All | 순수 함수 (시크릿 미포함) |
| `MON-034` | `Assert agents inputs are valid before any change` | `ansible.builtin.assert` | All | 읽기 전용 |
| `MON-035` | `Set agents secrets as host facts` | `ansible.builtin.set_fact` | All | 순수 함수 (`no_log`) |
| `MON-036` | `Build and validate the resource attributes of this host` | `ansible.builtin.set_fact` | All | 순수 함수 (프로브 값 + 인벤토리 `ip` + `host_agents_environment`) |
| `MON-037` | `Assert the resource attributes are valid before any change` | `ansible.builtin.assert` | All | 읽기 전용 (환경 누락·허용 밖 값이면 check 모드에서도 실패) |
| `MON-038` | `Warn about resource attributes left out for this host` | `ansible.builtin.debug` | All | 읽기 전용 (`host.id`/`host.ip`가 없는 호스트에만 WARN) |
| `MON-040` | `Ensure controller cache directories exist` | `ansible.builtin.file` | controller | 디렉터리 존재 시 `ok` |
| `MON-041` | `Download pinned release tarball on the controller and verify SHA256` | `ansible.builtin.get_url` | controller | `checksum: sha256:<Git 고정값>` 일치 시 `ok`, 불일치 시 실패 |
| `MON-042` | `Extract the binary into the controller cache` | `ansible.builtin.unarchive` | controller | `creates` (버전×아키텍처별 캐시) |
| `MON-043` | `Read the extracted binary SHA256 on the controller` | `ansible.builtin.stat` | controller | 읽기 전용 |
| `MON-044` | `Read the current install symlink on the host` | `ansible.builtin.stat` | All | 읽기 전용 |
| `MON-045` | `Show planned version change` | `ansible.builtin.debug` | All | 읽기 전용 (버전 변경 표시; check 모드 diff는 MON-051 symlink diff) |
| `MON-046` | `Ensure versioned install directory exists` | `ansible.builtin.file` | All | 디렉터리 존재 시 `ok` |
| `MON-047` | `Push the verified binary into the versioned directory` | `ansible.builtin.copy` | All | 체크섬 비교 |
| `MON-048` | `Read the pushed binary SHA256 on the host` | `ansible.builtin.stat` | All | 읽기 전용, `check_mode: false` |
| `MON-049` | `Assert the pushed binary matches the SHA256 of the verified tarball binary` | `ansible.builtin.assert` | All | 읽기 전용 (불일치 시 호스트 실패, symlink 불변) |
| `MON-050` | `Preserve a pre-existing regular-file binary before the first symlink switch` | `ansible.builtin.copy` | All | `force: false`; 일반 파일 바이너리가 있을 때만 `legacy-<binary>`로 보존 |
| `MON-051` | `Point the install symlink at the new version` | `ansible.builtin.file` | All | symlink 일치 시 `ok`; 변경 시 `Restart otelcol-contrib` 핸들러 |
| `MON-052` | `Find installed version directories` | `ansible.builtin.find` | All | 읽기 전용, `check_mode: false` |
| `MON-053` | `Prune versions older than the previous one` | `ansible.builtin.file` | All | 현재 + 직전 1개만 보존(재실행에도 직전 유지) |
| `MON-054` | `Switch otelcol-contrib install symlink to the delivered version` | `ansible.builtin.include_tasks` | All | 설정 검증 후 symlink 교체 (`MON-051`~`053`) |
| `MON-055` | `Decompress the single-file bz2 release into the controller cache` | `ansible.builtin.shell` | controller | `creates` + `.part` 임시 파일 후 `mv`(부분 파일 방지); `_deliver_format: bz2`(restic)일 때만 |
| `MON-056` | `Make the decompressed binary executable in the controller cache` | `ansible.builtin.file` | controller | 모드 비교 (`0755`), `_deliver_format: bz2`일 때만 |
| `MON-060` | `Assert OpenObserve endpoint is configured without a trailing slash` | `ansible.builtin.assert` | modern | 읽기 전용 (비어 있거나 끝 슬래시면 호스트 실패) |
| `MON-061` | `Ensure otelcol persistent storage directory exists (filelog checkpoints and log queue)` | `ansible.builtin.file` | modern | 디렉터리 존재 시 `ok` |
| `MON-062` | `Detect rsyslog (journald is collected only where rsyslog is absent)` | `ansible.builtin.stat` | modern | 읽기 전용, `check_mode: false` (`/usr/sbin`·`/sbin`) |
| `MON-063` | `Ensure otelcol secrets directory exists` | `ansible.builtin.file` | modern | 디렉터리 존재 시 `ok` (`0700`) |
| `MON-064` | `Decide whether the journald receiver is needed` | `ansible.builtin.set_fact` | modern | 순수 함수 |
| `MON-065` | `Deploy otelcol secrets env file (0600, no_log, no diff)` | `ansible.builtin.template` | modern | Checksum 비교 (`no_log`, `diff: false`) |
| `MON-066` | `Reload systemd units when the otelcol unit changed` | `ansible.builtin.systemd` | modern | 유닛 변경 시에만 실행 (`daemon_reload`) |
| `MON-067` | `Look up the docker socket group (only when docker metrics are enabled)` | `ansible.builtin.getent` | modern | 읽기 전용, `check_mode: false` (그룹이 있으면 `MON-002`가 otelcol을 추가) |
| `MON-100` | `Probe remote hash and mode of the target file (raw, read-only)` | `ansible.builtin.raw` | legacy_el6, legacy_el7 | `changed_when: false`, `check_mode: false` (ADR-0005 sentinel 입력) |
| `MON-101` | `Read the remote file for the check-mode diff (raw, read-only, never for secrets)` | `ansible.builtin.raw` | legacy_el6, legacy_el7 | 읽기 전용, `check_mode: false`, check 모드·비시크릿 파일에서만 실행 |
| `MON-102` | `Show controller-rendered vs remote diff in check mode (secret files excluded)` | `ansible.builtin.debug` | legacy_el6, legacy_el7 | 읽기 전용 (unified diff 출력, 시크릿 env 제외) |
| `MON-103` | `Report a secret file change in check mode without its content` | `ansible.builtin.debug` | legacy_el6, legacy_el7 | 읽기 전용 (내용 없이 변경 예정 여부만 출력) |
| `MON-109` | `Assert sshpass and a password are available for a keyless upload` | `ansible.builtin.command` | legacy_el6, legacy_el7 | 읽기 전용 (`sshpass -V`, `check_mode: false`, SSH 키가 없을 때만. `sshpass`가 없거나 비밀번호가 비어 있으면 업로드 전에 호스트 실패) |
| `MON-104` | `Upload the pinned binary to a staging path with scp from the controller` | `ansible.builtin.command` | legacy_el6, legacy_el7 | 원격 sha256/mode sentinel 불일치 시에만 실행, check 모드 스킵, 실패 시 진단을 위해 `no_log` 없음(키 파일 경로만 노출, 내용 아님) |
| `MON-105` | `Verify the staged binary against the pinned SHA256 and install it atomically (raw)` | `ansible.builtin.raw` | legacy_el6, legacy_el7 | 원격 sha256/mode sentinel 불일치 시에만 실행, 해시 불일치 시 실패(대상 불변), check 모드 스킵 |
| `MON-106` | `Push the small file via write-temp/validate/move (raw, base64)` | `ansible.builtin.raw` | legacy_el6, legacy_el7 | ADR-0005 sentinel (`raw_push_changed`), check 모드 스킵, 시크릿은 `no_log` |
| `MON-107` | `Report the planned binary upload in check mode` | `ansible.builtin.debug` | legacy_el6, legacy_el7 | 읽기 전용 (check 모드에서만, 변경 예정 여부 출력) |
| `MON-108` | `Remove the staged upload after a failed upload or install (raw)` | `ansible.builtin.raw` | legacy_el6, legacy_el7 | rescue 전용 (`rm -f` 스테이징 파일 후 실패 유지, `changed_when`/`failed_when` 선언) |
| `MON-110` | `Warn when the legacy_el6 version row is past its expiry date` | `ansible.builtin.debug` | legacy_el6 | 읽기 전용, `tags: [always]`. `host_agents_today`(vars, 컨트롤러 UTC) > `host_agents_version_expiry.legacy_el6`(2027-12-31)이면 `host_agents_warn` 필터로 실제 Ansible `[WARNING]`을 출력(실패 아님) |
| `MON-114` | `Disable the journald receiver on CentOS 6 (no journald)` | `ansible.builtin.set_fact` | legacy_el6 | 순수 함수 (CentOS 6에는 journald가 없어 항상 `false`) |
| `MON-119` | `Deploy SysV init script for otelcol-contrib (raw, runs as root)` | `ansible.builtin.import_tasks` | legacy_el6 | sentinel (`/etc/init.d/otelcol-contrib`, `0755`, `bash -n` 검증). root 실행, secrets env를 `set -a`로 적재, `start`는 stdin(`</dev/null`)·stdout·stderr를 모두 끊어 raw 세션을 붙잡지 않음. 변경 시 `Restart otelcol-contrib (raw)`(CentOS 6은 `service … restart`) |
| `MON-121` | `Ensure otelcol-contrib is started and enabled via chkconfig (raw, sentinel)` | `ansible.builtin.raw` | legacy_el6 | `raw_sysv_service_cmd`: `service status` 실패 시에만 `start`, `chkconfig --list`에 `3:on`이 없을 때만 `chkconfig --add` + `on` |
| `MON-122` | `Deploy logrotate configuration for the collector log on CentOS 6 (raw)` | `ansible.builtin.import_tasks` | legacy_el6 | sentinel (`/etc/logrotate.d/otelcol-contrib`, `0644`). `/var/log/otelcol-contrib.log`(init 스크립트의 `LOGFILE`)을 `copytruncate`로 주간 회전(재시작 불필요, logrotate 3.7.8 호환 옵션만) |
| `MON-200` | `Assert OpenObserve endpoint is configured without a trailing slash` | `ansible.builtin.assert` | legacy_el6, legacy_el7 | 읽기 전용 (MON-060과 같은 조건) |
| `MON-201` | `Detect rsyslog (raw, read-only; journald is collected only where rsyslog is absent)` | `ansible.builtin.raw` | legacy_el7 | `changed_when: false`, `check_mode: false` (`/usr/sbin`·`/sbin`) |
| `MON-202` | `Decide whether the journald receiver is needed` | `ansible.builtin.set_fact` | legacy_el7 | 순수 함수 |
| `MON-203` | `Ensure otelcol persistent storage directory exists (raw)` | `ansible.builtin.raw` | legacy_el6, legacy_el7 | `raw_dir_cmd` sentinel (경로·모드·소유자 일치 시 `ok`) |
| `MON-204` | `Ensure otelcol config and secrets directories exist (raw)` | `ansible.builtin.raw` | legacy_el6, legacy_el7 | `raw_dir_cmd` sentinel (`0750`/`0700`, root) |
| `MON-206` | `Deploy otelcol secrets env file (raw, 0600, no_log, no diff)` | `ansible.builtin.import_tasks` | legacy_el6, legacy_el7 | ADR-0005 sentinel(`raw_upload.yml`), `_raw_secret`: check 모드에서도 내용 비노출, `no_log` |
| `MON-207` | `Deploy OpenTelemetry Collector configuration (raw, validated with the new binary)` | `ansible.builtin.import_tasks` | legacy_el6, legacy_el7 | sentinel + 새 버전 바이너리 `validate`(임시 파일 검증 후 mv, `host_agents_version_row` 행). modern과 같은 템플릿 렌더링 결과(CentOS 6은 `sending_queue` legacy_el6 분기) |
| `MON-208` | `Deliver pinned OpenTelemetry Collector Contrib binary (raw)` | `ansible.builtin.include_tasks` | legacy_el6, legacy_el7 | `host_agents_version_row` 행(CentOS 6은 v0.119.0) 컨트롤러 캐시 → scp 업로드, 원격 sha256sum(추출 바이너리 해시) 불일치 시에만 실행 (`MON-040`~`043`, `MON-100`~`108`, `MON-210`~`211`) |
| `MON-209` | `Switch otelcol-contrib install symlink to the delivered version (raw)` | `ansible.builtin.include_tasks` | legacy_el6, legacy_el7 | 설정 검증 뒤 `MON-212` (스모크 테스트 실패 시 도달하지 않음) |
| `MON-210` | `Ensure the versioned install directory exists (raw)` | `ansible.builtin.raw` | legacy_el6, legacy_el7 | `raw_dir_cmd` sentinel (`0755`) |
| `MON-211` | `Smoke-test the delivered binary on the host (raw)` | `ansible.builtin.raw` | legacy_el6, legacy_el7 | `<binary> --version`(restic류는 `version`) 비정상 종료 시 호스트 실패, symlink 불변. check 모드 스킵 |
| `MON-212` | `Point the install symlink at the new version (raw)` | `ansible.builtin.raw` | legacy_el6, legacy_el7 | `raw_switch_binary_cmd`: readlink 비교 후 원자적 교체, 일반 파일 바이너리는 `legacy-<binary>`로 보존, 현재+직전만 보존. 변경 시에만 핸들러 |
| `MON-213` | `Deploy systemd unit for otelcol-contrib (raw, runs as root)` | `ansible.builtin.import_tasks` | legacy_el7 | sentinel. root 실행 + `NoNewPrivileges`/`ProtectSystem=full`/`ProtectHome`/`PrivateTmp`. 변경 시 `Reload systemd daemon (raw)` + `Restart otelcol-contrib (raw)` |
| `MON-214` | `Apply pending reload and restart before enabling` | `ansible.builtin.meta` | legacy_el6, legacy_el7 | 유닛/init 스크립트 변경 시에만 daemon-reload·재시작 (`flush_handlers`) |
| `MON-215` | `Ensure otelcol-contrib is enabled and started (raw, sentinel)` | `ansible.builtin.raw` | legacy_el7 | `raw_service_cmd`: `is-enabled`/`is-active` 확인 후에만 enable/start (systemd 219에는 `enable --now`가 없음) |
