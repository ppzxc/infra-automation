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

- **호스트 집합**: `target_hosts:&servers:!host_agents_excluded` (축소만 가능, `servers` 밖으로 확장 불가). 인벤토리 `host_agents_excluded` 그룹의 호스트는 Deploy·Config·Repo Maintenance 모두에서 빠집니다(ADR-0006 §2.1). `host_agents_backup_only` 그룹의 호스트는 대상에 남지만 `enable_otelcol`이 `false`로 파생되어 otelcol 블록(설치·설정·서비스, legacy node_exporter 정리 포함)을 모두 건너뜁니다. 연결 해석/정리 플레이(`resolve_connection.yml`, `cleanup_connection.yml`)도 `connection_hosts` 변수로 같은 집합만 처리하며 두 import 모두 `tags: [always]`입니다.
- **롤아웃**: `serial: 25%`, `gather_facts: false`. 프로비저닝 assert·OS 프로브·fact 수집·입력 검증은 모두 역할 안에서 수행됩니다.
- **태그**: 설치 단계 `agents_install`, 설정/스케줄 단계 `agents_config`, 역할 공통 `otel`(향후 `backup`). 사전 단계(`MON-020~035`)는 `always`라 `--tags agents_config`에서도 수행됩니다. Deploy = 태그 없음, Config = `--tags agents_config`.
- **사전 단계**: `_is_already_provisioned`가 아니고 `hosts/<호스트>` KV에 `host_agents_allow_password_auth: true`도 없으면 즉시 실패(아래 "비밀번호 접속 예외" 참고) → raw 프로브(`/etc/os-release`, `/etc/redhat-release`, `uname -m`)로 `host_agents_os_path`(`legacy_el6`/`legacy_el7`/`modern`)와 `host_agents_os_*` fact 생성 → `modern`만 `/usr/bin/python3` 보장 + `setup`. `legacy_el7`(CentOS 7, §3-4)과 `legacy_el6`(CentOS 6, §3-5)은 raw 경로로 적용됩니다.
- **OpenBao 입력**: `hosts/<host>/agents`(호스트별)와 `agents/openobserve`, `agents/rustfs`(공용, `run_once`)를 컨트롤러에서 조회합니다.

  | 키 (`hosts/<host>/agents`) | 필수 | 용도 |
  |---|---|---|
  | `o2_ingest_token`, `rustfs_access_key`, `rustfs_secret_key`, `restic_password` | 예 | 호스트 전용 시크릿 (누락 시 해당 호스트 실패). `host_agents_backup_only` 호스트는 `o2_ingest_token` 불필요 |
  | `otel_extra_logs` | 아니오 | glob(→ `app_logs`) 또는 `{path, stream, service}` 추가. `service`(소문자·숫자·`.-_`)는 선택, 없으면 스트림 이름(`app` 등)으로 보고 |
  | `otel_exclude_logs` | 아니오 | 표준 목록에서 정확히 일치하는 경로 제거. `security_logs` 경로는 제외 불가 |
  | `otel_docker_metrics` | 아니오 | Docker 메트릭 opt-in |
  | `otel_container_logs` | 아니오 | docker 컨테이너 로그 수집 opt-in(기본 꺼짐, modern 호스트만, docker `json-file` 드라이버 파일). 아래 §3-3 "컨테이너 로그" |
  | `otel_app_telemetry` | 아니오 | boolean. 컨테이너 앱 텔레메트리(Business Telemetry, ADR-0012) 수신 opt-in(기본 꺼짐). 아래 §3-3 "컨테이너 앱 텔레메트리" |
  | `host_agents_environment` | 예(호스트별) | `production` \| `staging` \| `development` \| `test`. 인벤토리 변수가 우선이고 없으면 이 KV 키. **그룹 기본값 없음** — 누락·허용 밖 값은 변경 전 실패(`MON-037`) |
  | `backup_extra_paths`, `backup_exclude_paths`, `backup_pre_hooks` | 아니오 | 필수 백업 경로(`/etc`, `/var/spool/cron`, `/usr/local/{bin,etc,sbin}`)와 그 상위 경로는 제외 불가 |
  | `backup_sqlite_snapshots` | 아니오 | SQLite 파일 절대 경로 목록(안전한 글자만, `..` 불가). 있으면 백업 직전 online backup 스냅샷을 만들어 백업한다(`docs/backup.md` §3-1, #323). 없으면 동작이 바뀌지 않는다 |

- **실패 조건 (변경 전, check 모드 포함)**: 필수 키 누락, OpenBao 조회 오류(연결 실패/403/토큰 없음), 제외 불가 경로를 지정한 exclude → 위반 경로와 KV 키를 메시지에 명시. 선택 키 부재는 Git 표준만 적용합니다.
- **공유 시크릿**: `agents/openobserve`, `agents/rustfs`가 없거나 값이 비어 있으면 실패합니다(조회는 호스트마다 수행, TLS 검증은 `host_agents_vault_validate_certs`).
- **제외 판정**: `otel_exclude_logs`는 경로 정규화 후 동일/glob/상위 디렉터리가 `security_logs` 경로를 덮으면 실패합니다(`/var/log/audit`, `/var/log/secure*` 포함).
- **fact 출력**: `host_agents_inputs`(`otel_logs`, `otel_docker_metrics`, `otel_container_logs`, `otel_app_telemetry`, `backup_paths`, `backup_exclude_paths`, `backup_pre_hooks`, `backup_sqlite_snapshots`, `errors`; 시크릿 없음), `host_agents_secrets`, `host_agents_shared_secrets`(`no_log`).
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

- **수신**: 스트림별 `filelog/<stream>`(`start_at: end`, `storage: file_storage`, `log_type` 속성, 본문 원문 유지, 위 Envelope Parsing으로 필드만 추가) + `hostmetrics`(60s, 9 스크레이퍼: 기존 8개 + `system`). 호스트 메트릭 확장(Spec #253 / #254, `MON-004`): `system.uptime`(`system` 스크레이퍼), `system.linux.memory.available`·`system.memory.limit`, `system.cpu.utilization`, 사용률 3종(`system.memory.utilization`·`system.filesystem.utilization`·`system.paging.utilization`)을 세 경로 공통으로 켜고, EL6(0.119.0)만 `system.cpu.logical.count`를 더 켠다(0.161.0은 기본으로 낸다). 기존 메트릭의 이름과 모양은 바뀌지 않는다(`system.cpu.utilization`은 0.161.0에서 `cpu` 속성 없이 state별 8개, 0.119.0은 CPU별이다). **주의: 수신기 타입 이름 `hostmetrics`는 0.161.0에서 deprecated 별칭이다**(정식 이름은 `host_metrics`, v0.151.0부터). 0.119.0은 `host_metrics`를 모르므로 별칭을 유지하며, 별칭이 제거되면 버전 행(경로)별로 이름을 분기해야 한다. 근거: `docs/research/host-metrics-industry-standard.md`. journald는 `/usr/sbin/rsyslogd`가 없는 호스트에서만, `docker_stats`는 `otel_docker_metrics: true`인 호스트에서만, OTLP 수신기는 `otel_app_telemetry: true`일 때만 추가됩니다(기본 off, 아래 "컨테이너 앱 텔레메트리"). `tcp_check`(서버 도달성, ADR-0010)는 검사하는 쪽 호스트(`host_agents_o2_health_checker`, 기본 ns0266)에만 붙어 `servers` 전체(Backup Only 포함)의 `<ansible_host>:<ansible_port>`를 60초마다 확인하고 별도 `metrics/tcpcheck` 파이프라인으로 보냅니다. contrib 0.161.0 행에 포함되며(legacy_el6의 0.119.0에는 없음) 편입·폐기 후에는 검사하는 쪽에 설정을 다시 반영해야 합니다.
- **컨테이너 로그 (`otel_container_logs: true`, ADR-0006 §2.3 개정 2026-10-15, `MON-068`)**: 컨테이너가 docker `json-file` 드라이버(`max-size`/`max-file` 필수)와 compose 라벨 전달 옵션(`labels: com.docker.compose.project,com.docker.compose.service`)을 쓴다는 전제다. 수신기 `filelog/containers`(ID 고정 = 체크포인트 키)가 글롭 `otel_container_log_glob`(`/var/lib/docker/containers/*/*-json.log`) 하나로 모든 컨테이너를 읽는다. `container` operator(`format: docker`, `add_metadata_from_filepath: false`)가 `log`·`stream`·`time`을 풀고 줄마다 붙은 `attrs`(라벨)는 속성으로 보존한다. Docker가 16KiB로 쪼갠 줄은 `recombine`(마지막 조각만 개행으로 끝남)이 합치고, 본문은 줄 끝 개행만 뗀다. `log_type=app_logs`, `service.name=<프로젝트>-<서비스>`(라벨이 없으면 `otel_container_default_service`=`container`), `container.id`(파일명에서), `log.iostream`(stdout/stderr, 에러 레벨로 간주하지 않음)을 붙인다. **레벨(Spec #236):** 포맷이 실제로 레벨을 가진 줄만 `severity`를 채운다 — JSON 한 줄 로그의 최상위 `level`(logstash 형식·Caddy) 또는 `log.level`(ECS 형식)과 valkey 텍스트 로그의 레벨 문자(`.` debug, `-` debug2, `*` info, `#` warn). 값은 대소문자를 구분하지 않고 trace/debug/info/warn/error/fatal(`critical`·`panic`·`dpanic` 포함)로 매핑한다. JSON에 `level`과 `log.level`이 함께 있으면 최상위 `level`이 이긴다. `severity` 숫자(번호)는 위 매핑이지만 `severity` 텍스트는 원문 토큰 그대로다(`ERROR`, `error`, valkey의 `#` 등). 그래서 알림은 텍스트를 `lower()`로 허용 목록과 비교하며, 수집기 매핑의 error·fatal 단어와 알림 SQL 목록이 같은지 테스트가 확인한다. keepalived처럼 레벨이 없는 줄, JSON이 아닌 줄, 알 수 없는 레벨 단어는 severity가 비며 키워드로 추정하지 않는다. 본문은 그대로고 파싱용 임시 속성(`_lvl`, `_vk`)은 바로 지우며 `log.parse_error`는 붙이지 않는다(`app_logs`에서는 대상이 아닌 줄이 오탐이 되므로). **trace context(Spec #253, ADR-0008):** 같은 임시 JSON에서 trace id 키를 LogRecord의 TraceID/SpanID/flags로 올려 OpenObserve `app_logs`에서 `trace_id`/`span_id`가 되고 View Trace로 이어진다(`otel_app_telemetry`와 무관). 키 형식은 변수 `otel_container_trace_keys`로 두며 기본은 funa(`trace_id`/`span_id`/`trace_flags`)와 Caddy(`traceID`/`spanID`)다. 32자리 16진수이면서 전부 0이 아닌 id(span은 16자리)만 올리고, 없거나 전부 0이거나 형식이 틀리거나 JSON이 아닌 줄은 trace context 없이 그대로 나간다(오류 없음). 본문은 바꾸지 않는다. 이 레벨로 `infra-app-log-errors` 알림이 동작한다(`docs/openobserve_config.md`). 컨테이너 이름은 파일에 없으므로, `labels`에 `com.docker.compose.container-number`가 있으면 `container.name`을 `<프로젝트>-<서비스>-<번호>`로 재구성하고(`container_name:` 직접 지정 시 실제 이름과 다를 수 있음), 이미지의 `org.opencontainers.image.version` 라벨이 있으면 `service.version`으로 올린다. 라벨이 없으면 두 필드는 만들지 않는다. 이름이 바뀐 로테이션 파일은 filelog가 inode로 이어 읽는다. Docker 소켓·docker 그룹이 필요 없다(`otelcol`의 `AmbientCapabilities=CAP_DAC_READ_SEARCH`로 root 소유 파일을 읽는다). 컨테이너 출력이 journald/rsyslog를 거치지 않으므로 `system_logs`와 중복되지 않는다. 꺼진 호스트(기본)는 수신기가 렌더링되지 않는다. legacy(CentOS 6/7 raw) 경로는 검증하지 않아 켜도 수신기를 만들지 않는다. **전환 순서:** compose를 `json-file`로 바꾼 뒤에 Config를 적용한다 — 이전 구현(journald 드라이버)이 배포한 rsyslog 규칙을 `MON-068`이 지우므로, journald 드라이버 컨테이너가 남아 있으면 출력이 시스템 로그 파일로 샌다. docker 문서는 `json-file` 파일을 외부 도구가 읽지 말라고 경고하지만(데몬 전용), Datadog·Elastic 등이 같은 파일을 읽는 것이 업계 기본 방식이다.
- **컨테이너 앱 텔레메트리 (`otel_app_telemetry: true`, ADR-0012)**: 켠 호스트만 컨테이너가 보내는 OTLP를 받는다(꺼진 호스트는 렌더링 결과가 변경 전과 같다). 입력은 `otel_docker_metrics`·`otel_container_logs`와 같은 경로(`host_agents_resolve_inputs`)로 해석하며 boolean이 아니면 키 이름을 대며 실패한다(`MON-034`). 수신기 `otlp`는 **HTTP만** 열고(gRPC 없음) `otel_otlp_bind`(기본 모든 주소)·`otel_otlp_http_port`에 바인드한다. 외부 노출은 호스트 방화벽(public 존 기본 거부)이 막는다. `traces/otlp`는 `memory_limiter` → `resource/host` → `tail_sampling` → `batch` → `otlphttp/app_traces`(헤더 `stream-name: app_traces`, 메모리 큐라 로그의 디스크 큐와 공간을 다투지 않음)이고, `metrics/otlp`는 `memory_limiter` → `resource/host` → `filter/app_metrics` → `batch` → 기존 `otlphttp/metrics`다. `resource/host`가 호스트 Resource Attribute를 덮어쓰고 앱의 `service.name`은 유지한다. OTLP 수신기는 로그 파이프라인에 넣지 않으므로 OTLP로 보낸 로그는 어떤 exporter로도 나가지 않는다(컨테이너 로그와 중복 방지). 역할 변수 `otel_otlp_enabled`·gRPC 포트·`otel_otlp_bind` 루프백 기본값은 이 스위치로 대체되어 없어졌다. 실제 바이너리 검증은 `tests/test_app_telemetry.py`(하네스 `tests/otelcol_harness.py`)다. **잡음 규칙(Spec #253 / #260):** 트레이스는 `tail_sampling`이 `service.name=caddy` span이 든 트레이스만 남기고 `/docs` 아래(`otel_app_docs_regex`, span의 `url.path`·`http.route`) 트레이스는 버린다. 기본 판정은 버림이라 Caddy가 시작하지 않은 트레이스(관리 포트 헬스체크, 스케줄 작업, 백그라운드 클라이언트)는 하위 span까지 나가지 않고, Caddy 트레이스의 하위 span(JDBC 포함)은 하나도 버리지 않는다. 0.161.0은 `drop` 정책(패턴마다 하나)과 `decision_cache`를 쓰고, 0.119.0(legacy_el6)은 이 둘이 없어 `and` 정책 + `invert_match` 정규식으로 같은 결과를 낸다. `decision_wait`(`otel_trace_decision_wait`, 기본 15s)는 SDK export 지연과 요청 시간을 덮어야 한다. 메트릭은 `filter/app_metrics`가 `service.name=caddy` 출처에서 `caddy_http_*` 외(`go_*`·`process_*`·`caddy_admin_*` 등)를 버리고, `http.server.*`에서 `http.route`가 `/docs` 아래이거나 관리 경로인 데이터포인트를 버린다. JVM 런타임·DB 풀·HTTP 클라이언트 메트릭은 남는다. 관리 경로는 비공개 값이라 `otel_app_management_path`(접두어, `/`로 시작)로 받고 저장소 기본값은 비어 있으며, 비면 그 경로 규칙만 렌더링하지 않는다(`/docs` 규칙은 유지). 이 처리기는 `otel_app_telemetry`가 꺼진 호스트에는 렌더링되지 않는다. 검증: `tests/test_noise_rules.py`(0.119.0·0.161.0 실제 바이너리).
  - **Caddy span 속성(`/docs` 트레이스 제거의 전제)**: `tail_sampling`의 `/docs` 제거는 Caddy SERVER span이 `url.path` 속성을 싣는다는 데 기댄다. `docs/research/caddy-otlp-metrics-tracing.md`가 Caddy span 속성에 `url.path`, `client.address`, `user_agent.original`이 있고 `url.query`는 없음을 재현으로 확인했고, `docs/research/trace-noise-removal.md`는 `url.path`가 span 시작 시점에 보인다고 적는다. `http.route`는 라우팅 뒤에 붙어 Caddy span에서는 쓰지 않는다. 카나리 노드 검증(#264)에서 실제 span으로 한 번 더 확인한다.
- **Envelope Parsing (ADR-0008, `MON-004`/`MON-207`/`MON-025`)**: 수신 본문(원문)은 바이트 단위로 그대로 두고, 파일별 `if:` 조건 operator가 포맷이 정한 필드만 `Timestamp`·`attributes`·`severity`에 붙입니다(수신기 ID는 그대로). 포맷 표는 `vars/main.yml`의 `otel_log_formats`입니다.
  - syslog 계열(`messages`, `syslog`, `secure`, `auth.log`, `sudo.log`, `cron*`, `kern.log`): RFC3164 시각 → `Timestamp`(Probe가 읽은 호스트 타임존, 연도는 수집 시점 기준 추정), `process.executable.name`, `process.pid`, `message`. 줄에 찍힌 hostname은 버리고 리소스 `host.name`을 유지합니다. PRI가 없으므로 severity는 비웁니다.
  - `audit/audit.log`: `audit.type`, `audit.serial`, `msg=audit(epoch:serial)`의 시각, 나머지 `key=value`는 `audit.fields`.
  - `fail2ban.log`(시각·`component`·`process.pid`·`message`·레벨), `dnf.log`(시각·레벨·`message`): 레벨이 있을 때만 `severity_*`. `yum.log`, `dpkg.log`: 시각(`dpkg.action`)만, severity 없음. `journald`: `PRIORITY` → severity(본문 원문 맵 유지). `app_logs`, 사용자 추가 경로, 그리고 RFC3164가 아닌 `sudo.log`(sudo `Defaults logfile` 형식: 호스트·프로그램 없이 `시각 : 사용자 : ...`), `boot.log`(`[  OK  ]` 콘솔 출력), `firewalld`(ISO 시각 + 레벨)는 파싱하지 않습니다(파싱하면 모든 줄이 `log.parse_error` 오탐이 되므로 표에서 뺐고 원문만 전송). 이 경로의 줄은 `process.executable.name` 등 필드가 없으므로 `openobserve_config`의 sshd/sudo 해석 대상이 아닙니다(sudo는 `/var/log/secure`·`auth.log`의 syslog 줄로 해석).
  - 포맷에 맞지 않는 줄은 버리지 않고 원문 그대로 보내며 `log.parse_error=true`를 붙입니다(이벤트 시각이 없으면 수집 시각 사용). 파싱에 성공한 줄은 `log.parse_error=false`를 명시합니다(실패가 없어도 OpenObserve에 컬럼이 있어야 파싱 실패율 알림이 동작). 키워드로 severity를 추정하지 않습니다.
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
- **컬렉터 init**: `otelcol-contrib.init.j2`를 `/etc/init.d/otelcol-contrib`(`0755`)로 배포합니다. root로 실행하고(커널 2.6.32에는 ambient capability 없음) `/etc/otelcol-contrib/secrets.env`를 `set -a`로 읽어 `${env:O2_BASIC_AUTH}`를 공급합니다. 부팅 등록은 `chkconfig --list otelcol-contrib`의 `3:on`을 sentinel로, 없을 때만 `chkconfig --add` + `chkconfig on`(`MON-121`). `start`는 `setsid`로 세션·제어 터미널과 분리해 기동하고(컬렉터가 SIGHUP을 종료 신호로 처리해서, `nohup &`는 raw(SSH) 세션이 끝나는 순간의 SIGHUP 경쟁으로 호스트마다 비결정적으로 로그 없이 죽었습니다. 2026-10-12 CentOS 6 9대 수집 중단, Spec #161), stdin을 `/dev/null`로, stdout/stderr를 로그 파일로 돌려 세션이 자식 때문에 매달리지도 않습니다. 기동 뒤 3초 안에 프로세스가 죽으면 로그 꼬리와 함께 0이 아닌 종료코드를 내서 부팅·수동 `service … start`에서도 실패가 드러납니다. 재시작 핸들러(`Restart otelcol-contrib (raw)`)는 CentOS 6에서 `service otelcol-contrib restart`이며, `stop`은 이전 프로세스가 종료(큐 flush, `file_storage` 잠금 해제)될 때까지 최대 30초 기다리고 초과 시 KILL한 뒤에도 소멸을 확인한 다음에만 pidfile을 지웁니다(소멸하지 않으면 실패, `restart`는 거기서 중단). 재시작 뒤 생존은 `MON-216`이 확인해 죽었으면 `start`를 1회 재시도하고, 그래도 죽어 있으면 그 호스트만 실패시킵니다. 컬렉터 자체 로그 `/var/log/otelcol-contrib.log`는 `/etc/logrotate.d/otelcol-contrib`(`MON-122`, `copytruncate`, 주간 4회 보존)로 회전합니다.
- **설정**: 같은 `otelcol-contrib.yaml.j2`이며 `sending_queue`만 legacy_el6 분기입니다. v0.119.0은 `sizer`와 `block_on_overflow`를 모르므로(`validate`가 `invalid keys: block_on_overflow, sizer`로 거부) 구 이름 `blocking: true`와 배치 개수 `queue_size`(`otel_log_queue_batches_legacy_el6: 64`)를 씁니다. 역압은 유지됩니다(ADR-0006 §2.8 확인 결과).
- **백업**: CentOS 7과 같은 태스크(`BAK-2xx`)이며 restic/resticprofile만 legacy_el6 행입니다(`/etc/cron.d/host-agents-backup`, 프로파일·훅·logrotate·repo 프로브/`init` 동일). 프로파일은 resticprofile 0.29.1 + restic 0.17.3의 `show`를 통과합니다.

### 카나리 런북 (첫 실제 CentOS 6 호스트)

CentOS 6 Test Image가 없으므로 첫 실제 호스트가 카나리입니다. §3-4 CentOS 7 런북 절차를 따르되 아래를 바꾸거나 추가합니다.

1. **SSH 알고리즘 확인(가장 먼저)**: CentOS 6의 OpenSSH 5.3은 SHA-1 `ssh-rsa` 서명만 지원하며, 컨트롤러의 OpenSSH 8.8+는 이를 기본 비활성화합니다. `ansible -m raw -a 'cat /etc/redhat-release' <host>`가 실패하면 연결 옵션(`-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa`)이 필요합니다. `MON-104`의 `scp`는 Ansible `ssh_args`를 상속하지 않으므로, `raw_scp_argv`가 `-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa`를 항상 전달합니다(`+`는 기본 알고리즘 뒤에 추가하므로 최신 호스트 협상에는 영향이 없습니다). 실측: ns0294(OpenSSH 5.3)에 러너 OpenSSH 9.9 `scp`가 `no matching host key type found. Their offer: ssh-rsa,ssh-dss`로 실패했습니다.
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

## 3-6. RAID 상태 수집기 (`raid_status.yml`, `MON-230~234`, `MON-240~243`, Spec #322 / Ticket-13, #335)

- **무엇**: HP Smart Array 관리 도구(`ssacli` → `hpssacli` → `hpacucli` 순서로 처음 찾은 것)가 있으면 cron이 5분마다 `ctrl all show config detail`을 한 번 읽어 `/var/log/host-agents/raid.jsonl`에 정규화 JSON 줄을 append한다. 레코드 종류는 `controller`·`logical_drive`·`physical_drive`·`cache_battery`·`tool_status`이고, 도구 원문의 모든 키·값은 레코드마다 `raw`(JSON 문자열)에 담는다. 필드 이름과 상태 어휘는 OpenTelemetry `hw.*` 규약을 따른다(`docs/research/hardware-raid-metrics-industry-standard.md` §6).
- **읽기 전용·설치 없음**: 스크립트는 도구에 `version`과 `ctrl all show config detail`만 넘긴다. 도구가 없으면 아무것도 설치하지 않고 `tool_status=no_tool` 한 줄만 남긴다(#322 결정: 읽기 전용 수집은 Host Agents의 일부라 에이전트만 깔린 호스트에도 배포하고, 패키지 설치는 프로비저닝 대상에서만 한다). 도구 설치 기록은 #334에 있다.
- **안전장치**: 실행 전체를 `flock -n` 하나로 감싸 겹치면 `status=locked`만 남긴다. 도구 호출마다 `timeout`(기본 60초, CentOS 6의 coreutils 8.4는 `-k`가 없어 TERM만)과 `nice -n 19`를 건다. 한 실행의 줄은 임시 파일에 모았다가 한 번에 붙인다. 어떤 경우에도 종료 코드는 0이고 결과는 `tool_status`(`ok`·`no_tool`·`no_controller`·`timeout`·`error`·`locked`)로만 드러난다.
- **이식성**: POSIX sh와 POSIX awk만 쓴다(jq·python 없음). 같은 픽스처가 CentOS 6(gawk 3.1.7)·CentOS 7(gawk 4.0.2)·Ubuntu 22.04(mawk)에서 같은 결과를 내는 것을 컨테이너로 확인했다. 테스트는 `tests/test_raid_status.py`이며 운영 서버 3계열(hpssacli 2.20·2.40, ssacli 3.30·6.60)의 실제 출력(시리얼·WWN 제거)을 픽스처로 쓴다.
- **스케줄**: 모든 OS에서 `/etc/cron.d/host-agents-raid-status` 하나로 통일한다(5분 주기라 놓친 실행 보정이 필요 없고, CentOS 6에는 systemd가 없다). `enable_raid_status: false`면 modern 경로는 cron 파일을 지운다(`MON-234`).
- **수집 경로**: otelcol `filelog/host_status_logs`가 JSON으로 파싱해 `host_status_logs` 스트림으로 보낸다(`service.name=raid`). 백업 결과처럼 본문(원문 JSON)은 유지한다. 같은 수신기에 다른 점검 결과(시각 동기, #336)를 `otel_host_status_logs`로 더한다.
- **로그 회전**: `/etc/logrotate.d/host-agents-raid-status`가 매일 회전, 3개 보관(`create 0640 root root`). otelcol은 modern에서 `CAP_DAC_READ_SEARCH`, legacy에서 root로 읽는다.
- **알림**: `docs/openobserve_config.md`의 RAID 상태 알림 7개(`infra-raid-*`, `infra-host-status-silent`)와 런북 `docs/runbooks/alerts.md#raid-write-cache-disabled` 이하.
- **롤아웃 순서**: Host Agents Deploy(카나리: CentOS 6·CentOS 7·Rocky 9 각 1대) → OpenObserve에 `host_status_logs` 레코드와 컬럼 도착 확인 → 전체 Deploy → `OpenObserve — Config`(plan 결과를 읽은 뒤 적용). Config를 먼저 적용하면 알림 SQL이 아직 없는 컬럼을 읽고, 무소식 알림이 모든 호스트에서 난다.

## 3-7. 시각 동기 수집기 (`time_sync.yml`, `MON-250~254`, `MON-260~263`, Spec #322 / Ticket-14, #336)

- **무엇**: 서버에 이미 있는 시각 동기 도구(`chronyc tracking` → `ntpq -pn` → `timedatectl` 순서로 처음 *답하는* 것)의 출력을 cron이 5분마다 읽어 `/var/log/host-agents/time-sync.jsonl`에 JSON 한 줄(`kind=time_sync`, `family=timesync`)을 append한다. 필드는 항상 같다: `tool`, `sync_status`(`synced`·`unsynced`·`no_tool`·`error`), `synced`(true/false/null), `offset_ms`(시스템 시각 − 기준 시각, 밀리초·부호 있음·모르면 null), `stratum`, `message`.
- **읽기 전용·설치 없음**: 시각을 맞추거나 서비스를 건드리지 않고 아무것도 설치하지 않는다. 도구가 하나도 없으면 `sync_status=no_tool` 한 줄만 남긴다(알림 대상, 아래 알림 참고). 에이전트만 깔린 호스트에도 배포한다(#322 결정: 읽기 전용 수집은 Host Agents의 일부).
- **상태 판정**: chronyc는 `Leap status`가 `Not synchronised`면 `unsynced`, 아니면 `System time`(fast/slow)으로 오차를 낸다. ntpq는 `*`(선택된 피어) 줄의 offset(ms)을 쓰고 선택된 피어가 없으면 `unsynced`다. timedatectl은 동기 여부만 알려 주므로 `offset_ms`는 null이다. 도구는 있는데 데몬이 답하지 않으면(chronyc 종료 코드 ≠ 0, ntpq에 머리줄 없음) 다음 도구로 넘어가고, 끝까지 답이 없으면 `no_tool`이 아니라 `unsynced`(message에 "not answering")다. 도구 호출이 제한 시간(기본 20초)을 넘기면 `error`다. 도구는 로캘에 따라 라벨이 바뀌므로 스크립트가 `LC_ALL=C`로 고정한다.
- **CentOS 6 사실(2026-10-26 조사)**: 조사한 CentOS 6 호스트는 모두 `ntpd`를 끄고 cron의 `rdate`로 하루 한 번(02:00) 맞춘다. 그래서 이 호스트들은 `unsynced`(message `ntpq not answering`)로 남고 시각 동기 미동기 알림 대상이 된다. 상시 동기(ntpd 기동)를 쓸지, 이 알림을 받아들일지는 운영 결정이다(런북 `docs/runbooks/alerts.md#time-unsynced`).
- **안전장치·이식성**: POSIX sh와 POSIX awk만 쓴다(CentOS 6 gawk 3.1.7에서 실제 호스트로 확인). 도구 호출마다 `timeout`(CentOS 6 coreutils 8.4는 `-k` 없음)을 건다. 어떤 경우에도 종료 코드는 0이다.
- **스케줄·경로**: 모든 OS에서 `/etc/cron.d/host-agents-time-sync` 하나(5분 주기), logrotate는 매일·3개 보관. otelcol `filelog/host_status_logs`가 RAID 결과와 같은 수신기에서 파일별 `service.name=timesync`를 달아 `host_status_logs` 스트림으로 보낸다. `enable_time_sync: false`면 modern 경로는 cron을 지운다(`MON-254`).
- **알림**: `docs/openobserve_config.md`의 시각 동기 알림 3개(`infra-time-offset-exceeded`, `infra-time-unsynced`, `infra-time-sync-unavailable`)와 런북 `docs/runbooks/alerts.md#time-offset-exceeded` 이하.
- **롤아웃 순서**: Host Agents Deploy(카나리) → OpenObserve에 `kind=time_sync` 레코드와 `sync_status`·`offset_ms` 컬럼 도착 확인 → 전체 Deploy → `OpenObserve — Config`(plan 결과를 읽은 뒤 적용). Config를 먼저 적용하면 알림 SQL이 아직 없는 컬럼을 읽는다.

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
| `MON-022` | `Classify OS path and set host_agents_os facts from probe` | `ansible.builtin.set_fact` | All | 프로브 결과 순수 함수. |
| `MON-039` | `Set host_agents_conntrack fact from probe` | `ansible.builtin.set_fact` | All | 프로브 결과 순수 함수. 프로브가 커널 conntrack 파일(count·max)을 읽기만 하고 `host_agents_conntrack` fact를 만든다. 참인 호스트의 설정에서만 `system.network.conntrack.count/.max`가 켜진다(스위치 없음, modern·raw 공통) |
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
| `MON-068` | `Remove the obsolete rsyslog container rule (container logs are read from json-file)` | `ansible.builtin.file` | modern | 파일이 없으면 `ok` (이전 journald 드라이버 구현이 둔 규칙만 제거, 변경 시 `Restart rsyslog` 핸들러) |
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
| `MON-119` | `Deploy SysV init script for otelcol-contrib (raw, runs as root)` | `ansible.builtin.import_tasks` | legacy_el6 | sentinel (`/etc/init.d/otelcol-contrib`, `0755`, `bash -n` 검증). root 실행, secrets env를 `set -a`로 적재, `start`는 stdin(`</dev/null`)·stdout·stderr를 모두 끊어 raw 세션을 붙잡지 않음. 변경 시 `Restart otelcol-contrib (raw)`(CentOS 6은 `service … restart`, 직후 `MON-216` 생존 확인). init `start`는 `setsid`로 세션·제어 터미널과 분리해(pty 세션 종료 시 SIGHUP 경쟁 방지, nohup 폴백 없음) 기동하고, 기동 후 `otelcol_sysv_start_grace`(3초) 뒤 PID가 죽어 있으면 로그 꼬리(20줄)와 함께 0이 아닌 종료코드, `stop`은 TERM 후 `otelcol_sysv_stop_timeout`(30초, pidfile은 `otelcol_sysv_pid_path`)까지 기다리고 KILL 뒤에도 소멸을 확인(못 하면 실패, `restart`는 거기서 중단) |
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
| `MON-216` | `Verify otelcol-contrib stayed alive after restart (raw)` | `ansible.builtin.raw` | legacy_el6, legacy_el7 | `Restart otelcol-contrib (raw)` 핸들러와 같은 topic을 listen하는 핸들러(`include_tasks`)가 재시작 뒤 `otelcol_alive_grace_seconds`(기본 5초) 대기 후 CentOS 6 `service status`, CentOS 7 `systemctl is-active`를 확인. 죽었으면 `start`를 1회 재시도·재확인하고, 그래도 죽어 있으면 로그 꼬리(`tail -n 20`/`journalctl -n 20`)와 함께 그 호스트만 실패(나머지 호스트는 계속). 변경이 없으면 핸들러가 돌지 않아 실행되지 않음(`changed=0` 유지), `changed_when: false`. 재시작 핸들러는 종료코드를 삼키고(`failed_when: false`) 실패 판정은 이 핸들러가 전담. EL7은 `activating`(auto-restart) 동안 대기 후 재확인. 기본값 근거는 `roles/monitoring/defaults/main.yml`. modern 경로는 대상 아님 |
| `MON-219` | `Assert the checker host uses the modern path so the health timer is not silently skipped` | `ansible.builtin.assert` | 검사 호스트 | `host_agents_o2_health_checker`가 modern 경로가 아니면 조용히 건너뛰지 않고 실패(생존 타이머 누락 방지) |
| `MON-220` | `Assert the alert webhook URL is available for the health timer` | `ansible.builtin.assert` | modern, 검사 호스트 | OpenObserve 생존 타이머(Spec #184 / Ticket-7)는 `host_agents_o2_health_checker`(기본 ns0266) 한 대에만 배포. OpenBao `agents/openobserve`의 `alert_webhook_url`이 `http(s)://`가 아니면 변경 전에 실패 |
| `MON-221` | `Ensure OpenObserve health config and state directories exist` | `ansible.builtin.file` | modern, 검사 호스트 | `/etc/openobserve-health`, `/var/lib/openobserve-health` (`0700`) |
| `MON-222` | `Deploy the OpenObserve health check script` | `ansible.builtin.copy` | modern, 검사 호스트 | `openobserve-health-check`를 `0755`로 배포. 헬스(`/healthz`) 실패 시 OpenObserve를 거치지 않고 webhook으로 직접 P1 통지, 같은 장애는 60분(`o2_health_renotify_minutes`)마다만 재통지, 복구 통지 없음. webhook 전송 실패는 종료코드 1로 드러나고 다음 실행에서 재시도 |
| `MON-223` | `Deploy the OpenObserve health env file (0600, no_log, no diff)` | `ansible.builtin.template` | modern, 검사 호스트 | webhook URL·토큰(OpenBao 기존 값)을 담는 시크릿 파일 `0600`, `no_log`, diff 없음 |
| `MON-224` | `Deploy the OpenObserve health service and timer units` | `ansible.builtin.template` | modern, 검사 호스트 | `openobserve-health.service`(oneshot)와 `.timer`(`OnUnitActiveSec=5min`) `0644` |
| `MON-225` | `Reload systemd units when the OpenObserve health units changed` | `ansible.builtin.systemd` | modern, 검사 호스트 | 유닛 변경 시에만 `daemon_reload` |
| `MON-227` | `Fetch the SSH endpoint of every server from OpenBao (hosts/<hostname>)` | `ansible.builtin.uri` | 검사 호스트 | 읽기 전용 (GET, `changed_when: false`, `check_mode: false`, `no_log`). `servers`에서 `host_agents_tcpcheck_excluded`를 뺀 모든 호스트를 OpenBao에서 직접 읽어 실행 범위(`target_hosts`)와 무관하게 같은 목록이 나온다 |
| `MON-228` | `Assert OpenBao answered every server endpoint lookup` | `ansible.builtin.assert` | 검사 호스트 | 읽기 전용 (200·404 외 응답이 있으면 포트를 22로 짐작하지 않고 변경 없이 실패, 호스트 이름과 status만 보고) |
| `MON-229` | `Build the server reachability targets (address:port) from the OpenBao values` | `ansible.builtin.set_fact` | 검사 호스트 | 순수 함수 (`host_agents_tcpcheck_targets`: 주소 `ansible_host→public_ip→ip→host→인벤토리→호스트명`, 포트 `ansible_port→port→인벤토리→22`, resolve_connection과 같은 규칙) |
| `MON-226` | `Ensure the OpenObserve health timer is enabled and running` | `ansible.builtin.systemd` | modern, 검사 호스트 | 타이머 `enabled` + `started` |
| `MON-230` | `Ensure the Host Agents result and state directories exist (0755)` | `ansible.builtin.file` | modern | 디렉터리 존재 시 `ok` (`/var/log/host-agents`, `/var/lib/host-agents`, root `0755`, 백업 역할 `BAK-025`와 같은 속성) |
| `MON-231` | `Deploy the RAID status collector script (POSIX sh, read-only)` | `ansible.builtin.copy` | modern | Checksum 비교 (`/usr/local/sbin/host-agents-raid-status`, `0755`) |
| `MON-232` | `Deploy logrotate configuration for raid.jsonl` | `ansible.builtin.template` | modern | Checksum 비교 (`0644`) |
| `MON-233` | `Deploy the RAID status cron.d schedule` | `ansible.builtin.template` | modern | Checksum 비교 (`/etc/cron.d/host-agents-raid-status`, 5분 주기, root, `0644`) |
| `MON-234` | `Remove the RAID status cron.d schedule when the collector is disabled` | `ansible.builtin.file` | modern | `enable_raid_status: false`일 때만, 파일 부존재 시 `ok` |
| `MON-240` | `Ensure the Host Agents result and state directories exist (raw, 0755)` | `ansible.builtin.raw` | legacy_el6, legacy_el7 | `raw_dir_cmd` sentinel (`0755`) |
| `MON-241` | `Deploy the RAID status collector script (raw, POSIX sh, read-only)` | `ansible.builtin.import_tasks` | legacy_el6, legacy_el7 | ADR-0005 sentinel(`raw_upload.yml`) |
| `MON-242` | `Deploy logrotate configuration for raid.jsonl (raw)` | `ansible.builtin.import_tasks` | legacy_el6, legacy_el7 | ADR-0005 sentinel(`raw_upload.yml`) |
| `MON-243` | `Deploy the RAID status cron.d schedule (raw)` | `ansible.builtin.import_tasks` | legacy_el6, legacy_el7 | ADR-0005 sentinel(`raw_upload.yml`) |
| `MON-250` | `Ensure the Host Agents result directory exists (0755)` | `ansible.builtin.file` | modern | 디렉터리 존재 시 `ok` (`/var/log/host-agents`, root `0755`, `MON-230`과 같은 속성) |
| `MON-251` | `Deploy the time sync collector script (POSIX sh, read-only)` | `ansible.builtin.copy` | modern | Checksum 비교 (`/usr/local/sbin/host-agents-time-sync`, `0755`) |
| `MON-252` | `Deploy logrotate configuration for time-sync.jsonl` | `ansible.builtin.template` | modern | Checksum 비교 (`0644`) |
| `MON-253` | `Deploy the time sync cron.d schedule` | `ansible.builtin.template` | modern | Checksum 비교 (`/etc/cron.d/host-agents-time-sync`, 5분 주기, root, `0644`) |
| `MON-254` | `Remove the time sync cron.d schedule when the collector is disabled` | `ansible.builtin.file` | modern | `enable_time_sync: false`일 때만, 파일 부존재 시 `ok` |
| `MON-260` | `Ensure the Host Agents result directory exists (raw, 0755)` | `ansible.builtin.raw` | legacy_el6, legacy_el7 | `raw_dir_cmd` sentinel (`0755`) |
| `MON-261` | `Deploy the time sync collector script (raw, POSIX sh, read-only)` | `ansible.builtin.import_tasks` | legacy_el6, legacy_el7 | ADR-0005 sentinel(`raw_upload.yml`) |
| `MON-262` | `Deploy logrotate configuration for time-sync.jsonl (raw)` | `ansible.builtin.import_tasks` | legacy_el6, legacy_el7 | ADR-0005 sentinel(`raw_upload.yml`) |
| `MON-263` | `Deploy the time sync cron.d schedule (raw)` | `ansible.builtin.import_tasks` | legacy_el6, legacy_el7 | ADR-0005 sentinel(`raw_upload.yml`) |
