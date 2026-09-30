# Monitoring Role Task Specification

`monitoring` 역할은 OpenTelemetry Collector Contrib(`otelcol-contrib`)을 기반으로 한 온프레미스 단일 에이전트 관제 파이프라인의 배포, 시스템 계정 격리, `hostmetrics` 리시버를 통한 커널/OS 메트릭 수집, 그리고 레거시 `node_exporter` 자동 정리를 수행합니다.

> **Host Agents 전환 중**: 이 역할은 [ADR-0006](adr/0006-host-agents-otelcol-resticprofile.md)에 따라 `playbooks/host_agents.yml` 전용입니다. `site.yml`·`maintenance.yml`에서는 더 이상 적용되지 않습니다. 진입점, OS 프로브, OpenBao 입력 검증(`MON-020~035`)은 구현되었고, 수집 표준·스트림·버퍼링·버전 고정·CentOS 6/7 분기는 후속 티켓에서 이 표로 이관됩니다. 아래 매트릭스는 **현재 구현**을 기술합니다.

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
- **사전 단계**: `_is_already_provisioned`가 아니면 즉시 실패("site.yml 먼저 실행") → raw 프로브(`/etc/os-release`, `/etc/redhat-release`, `uname -m`)로 `host_agents_os_path`(`legacy_el6`/`legacy_el7`/`modern`)와 `host_agents_os_*` fact 생성 → `modern`만 `/usr/bin/python3` 보장 + `setup`. legacy 경로는 후속 티켓 전까지 경고 후 해당 호스트를 건너뜁니다.
- **OpenBao 입력**: `hosts/<host>/agents`(호스트별)와 `agents/openobserve`, `agents/rustfs`(공용, `run_once`)를 컨트롤러에서 조회합니다.

  | 키 (`hosts/<host>/agents`) | 필수 | 용도 |
  |---|---|---|
  | `o2_ingest_token`, `rustfs_access_key`, `rustfs_secret_key`, `restic_password` | 예 | 호스트 전용 시크릿 (누락 시 해당 호스트 실패) |
  | `otel_extra_logs` | 아니오 | glob(→ `app_logs`) 또는 `{path, stream}` 추가 |
  | `otel_exclude_logs` | 아니오 | 표준 목록에서 정확히 일치하는 경로 제거. `security_logs` 경로는 제외 불가 |
  | `otel_docker_metrics` | 아니오 | Docker 메트릭 opt-in |
  | `backup_extra_paths`, `backup_exclude_paths`, `backup_pre_hooks` | 아니오 | 필수 백업 경로(`/etc`, `/var/spool/cron`, `/usr/local/{bin,etc,sbin}`)와 그 상위 경로는 제외 불가 |

- **실패 조건 (변경 전, check 모드 포함)**: 필수 키 누락, OpenBao 조회 오류(연결 실패/403/토큰 없음), 제외 불가 경로를 지정한 exclude → 위반 경로와 KV 키를 메시지에 명시. 선택 키 부재는 Git 표준만 적용합니다.
- **공유 시크릿**: `agents/openobserve`, `agents/rustfs`가 없거나 값이 비어 있으면 실패합니다(조회는 호스트마다 수행, TLS 검증은 `host_agents_vault_validate_certs`).
- **제외 판정**: `otel_exclude_logs`는 경로 정규화 후 동일/glob/상위 디렉터리가 `security_logs` 경로를 덮으면 실패합니다(`/var/log/audit`, `/var/log/secure*` 포함).
- **fact 출력**: `host_agents_inputs`(`otel_logs`, `otel_docker_metrics`, `backup_paths`, `backup_exclude_paths`, `backup_pre_hooks`, `errors`; 시크릿 없음), `host_agents_secrets`, `host_agents_shared_secrets`(`no_log`).
- **테스트 seam**: `host_agents_kv_fixture`(`{host, openobserve, rustfs}`)가 정의되면 OpenBao를 조회하지 않습니다(molecule 공용 `group_vars`가 `_is_already_provisioned: true`와 함께 제공).

---

## 3-2. 바이너리 버전 고정과 전달 (`deliver_binary.yml`)

- 버전·SHA256은 `vars/main.yml`의 `host_agents_versions`/`host_agents_checksums`(Git 고정, 호스트별 오버라이드 없음). 버전 상향 PR은 체크섬 변경을 동반하며 upstream `checksums.txt`는 신뢰하지 않습니다. 현재 `default` 경로: otelcol-contrib v0.161.0.
- 컨트롤러가 tarball을 1회 다운로드해 SHA256을 검증하고 `host_agents_cache_dir`(기본 `~/.cache/host-agents`)에 캐시한 뒤, 인터넷이 없는 호스트에도 `copy`로 푸시합니다.
- 레이아웃: `/opt/host-agents/otelcol-contrib/<version>/otelcol-contrib`, `/usr/local/bin/otelcol-contrib`는 현재 버전 symlink. 호스트에는 현재+직전 버전 1개만 보존합니다.
- 순서: 푸시 → 호스트 SHA256 == 컨트롤러 검증본(불일치 시 호스트 실패, symlink 불변) → 기존 설정이 있으면 새 바이너리로 `validate` → symlink 교체(핸들러 재시작). 신규 설정은 `template validate`로 재시작 전에 검증됩니다. 롤백은 버전 표 revert PR 후 재실행.
- `deliver_binary.yml`은 `_deliver_*` 변수로 매개화되어 backup 역할(restic/resticprofile)이 그대로 재사용합니다(SPEC-ID `MON-040~053`).

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
| `MON-005` | `Create systemd service for otelcol-contrib` | `ansible.builtin.copy` | Systemd OS | 파일 내용 일치 시 `ok` |
| `MON-006` | `Ensure otelcol-contrib service is started and enabled` | `ansible.builtin.service` | All | 서비스 기동 상태면 `ok` |
| `MON-020` | `Assert host was provisioned by site.yml` | `ansible.builtin.assert` | All | 읽기 전용 |
| `MON-021` | `Probe OS release and architecture from target host (raw, read-only)` | `ansible.builtin.raw` | All | `changed_when: false`, `check_mode: false` |
| `MON-022` | `Classify OS path and set host_agents_os facts from probe` | `ansible.builtin.set_fact` | All | 프로브 결과 순수 함수 |
| `MON-023` | `Check /usr/bin/python3 exists on modern path (raw, read-only)` | `ansible.builtin.raw` | modern | `changed_when: false`, `check_mode: false` |
| `MON-024` | `Gather facts on modern path` | `ansible.builtin.setup` | modern | 읽기 전용 |
| `MON-025` | `Warn that legacy path hosts are skipped until their tasks land` | `ansible.builtin.debug` | legacy_el6, legacy_el7 | 읽기 전용 |
| `MON-026` | `Install python3 on modern path when absent` | `ansible.builtin.raw` | modern | 부재 시에만 실행 (check 모드 스킵) |
| `MON-027` | `Assert python3 is available on modern path` | `ansible.builtin.assert` | modern | 읽기 전용 |
| `MON-028` | `End role for legacy path hosts` | `ansible.builtin.meta` | legacy_el6, legacy_el7 | 읽기 전용 |
| `MON-030` | `Fetch agents KV from OpenBao (hosts/<hostname>/agents, agents/openobserve, agents/rustfs)` | `ansible.builtin.uri` | All | GET, `check_mode: false`, `no_log` |
| `MON-031` | `Assert OpenBao answered every agents lookup` | `ansible.builtin.assert` | All | 읽기 전용 (오류 시 check 모드에서도 실패) |
| `MON-032` | `Resolve agents KV contents (host + shared)` | `ansible.builtin.set_fact` | All | 순수 함수 (`no_log`) |
| `MON-033` | `Merge agents inputs with the Git standard` | `ansible.builtin.set_fact` | All | 순수 함수 (시크릿 미포함) |
| `MON-034` | `Assert agents inputs are valid before any change` | `ansible.builtin.assert` | All | 읽기 전용 |
| `MON-035` | `Set agents secrets as host facts` | `ansible.builtin.set_fact` | All | 순수 함수 (`no_log`) |
| `MON-040` | `Download pinned release tarball on the controller and verify SHA256` | `ansible.builtin.get_url` | controller | `checksum: sha256:<Git 고정값>` 일치 시 `ok`, 불일치 시 실패 |
| `MON-041` | `Extract the binary into the controller cache` | `ansible.builtin.unarchive` | controller | `creates` (버전×아키텍처별 캐시) |
| `MON-042` | `Read the extracted binary SHA256 on the controller` | `ansible.builtin.stat` | controller | 읽기 전용 |
| `MON-043` | `Read the current install symlink on the host` | `ansible.builtin.stat` | All | 읽기 전용 |
| `MON-044` | `Show planned version change` | `ansible.builtin.debug` | All | 읽기 전용 (check 모드에서 버전 변경 diff 표시) |
| `MON-045` | `Ensure versioned install directory exists` | `ansible.builtin.file` | All | 디렉터리 존재 시 `ok` |
| `MON-046` | `Push the verified binary into the versioned directory` | `ansible.builtin.copy` | All | 체크섬 비교 |
| `MON-047` | `Read the pushed binary SHA256 on the host` | `ansible.builtin.stat` | All | 읽기 전용, `check_mode: false` |
| `MON-048` | `Assert the pushed binary matches the pinned SHA256` | `ansible.builtin.assert` | All | 읽기 전용 (불일치 시 호스트 실패, symlink 유지) |
| `MON-049` | `Validate the new binary before switching the symlink` | `ansible.builtin.command` | All | `changed_when: false`; 기존 설정이 있을 때만 `otelcol-contrib validate` |
| `MON-050` | `Point the install symlink at the new version` | `ansible.builtin.file` | All | symlink 일치 시 `ok`; 변경 시 `Restart otelcol-contrib` 핸들러 |
| `MON-051` | `Find installed version directories` | `ansible.builtin.find` | All | 읽기 전용, `check_mode: false` |
| `MON-052` | `Prune versions older than the previous one` | `ansible.builtin.file` | All | 현재+직전 1개만 보존 |
| `MON-053` | `Ensure controller cache directories exist` | `ansible.builtin.file` | controller | 디렉터리 존재 시 `ok` |
