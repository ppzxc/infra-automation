# Host Agents — Deploy 배포 내역서 (Simple)

> Semaphore **Host Agents — Deploy**(`playbooks/host_agents.yml`, 태그 없음)가 설치하는 항목의 요약이다. 경로별 권한, SHA256, 파서 등 상세 내용은 [Full 버전](host-agents-deploy-inventory-full.md)을 본다.

## 1. 설치 구성요소

| 구성요소 | 버전 (CentOS 6) | 역할 | 실행 형태 |
|---|---|---|---|
| otelcol-contrib | 0.161.0 (0.119.0) | 로그·메트릭 수집 → OpenObserve | 상주 서비스 `otelcol-contrib` |
| restic | 0.19.1 (0.17.3) | 백업 엔진 → RustFS(S3) | 매일 1회 |
| resticprofile | 0.33.1 (0.29.1) | restic 프로파일·스케줄 래퍼 | 매일 1회 (systemd timer 또는 cron.d) |

- 바이너리는 컨트롤러가 받아 SHA256으로 검증한 뒤 푸시한다. 호스트는 인터넷에 접근하지 않는다.
- 설치 위치는 `/opt/host-agents/<agent>/<version>/`이고 `/usr/local/bin/`에 symlink를 둔다. 직전 버전 1개를 롤백용으로 남긴다.
- 레거시 `node_exporter`는 제거한다.

## 2. 주요 파일

| 경로 | 권한 | 내용 |
|---|---|---|
| `/etc/otelcol/config.yaml` | 0640 | 수집 설정 |
| `/etc/otelcol-contrib/secrets.env` | 0600 | OpenObserve 인증 토큰 |
| `/var/lib/otelcol/storage/` | 0750 | 로그 읽기 위치·전송 큐 |
| `/etc/restic/profiles.yaml` | 0600 | 백업 대상·제외·스케줄 훅 |
| `/etc/restic/env`, `/etc/restic/password` | 0600 | RustFS 키, repo 비밀번호 |
| `/var/log/host-agents/backup.jsonl` | 0640 | 백업 결과(실행당 1줄) |
| `host-agents-backup.timer` 또는 `/etc/cron.d/host-agents-backup` | 0644 | 백업 스케줄 |

## 3. 기본 수집 로그

| 스트림 | 경로 (없는 파일은 자동으로 건너뜀) |
|---|---|
| **security_logs** (호스트별 제외 불가) | `/var/log/secure`, `/var/log/auth.log`, `/var/log/audit/audit.log`, `/var/log/sudo.log`, `/var/log/fail2ban.log`, `/var/log/firewalld` |
| system_logs | `/var/log/messages`, `/var/log/syslog`, `/var/log/cron*`, `/var/log/kern.log`, `/var/log/boot.log`, `/var/log/dnf.log`, `/var/log/yum.log`, `/var/log/dpkg.log`, journald(rsyslog가 없는 호스트만) |
| backup_logs | `/var/log/host-agents/backup.jsonl` |
| app_logs | 기본 없음. 호스트 KV `otel_extra_logs`로 추가 |

- 배포 이후 새로 쓰인 줄부터 수집한다. 원문은 그대로 보내고, 시각·프로세스·severity만 추출한다.
- **메트릭**: 60초마다 cpu, memory, disk, filesystem, load, network, paging, processes를 수집한다. docker 컨테이너 메트릭은 호스트 KV로 켠 호스트만 수집한다.

## 4. 기본 백업 대상

| 구분 | 경로 |
|---|---|
| 필수 (제외 불가, ISMS 2.9.3) | `/etc`, `/var/spool/cron`, `/usr/local/bin`, `/usr/local/etc`, `/usr/local/sbin` |
| 있으면 포함 | `/opt/services` |
| 호스트별 추가 | 호스트 KV `backup_extra_paths` (예: `/root`, `/home`, `/data`) |
| 제외 | `/home/*/.cache`, `**/node_modules`, `*.tmp`, `*.swp`, `/etc/restic/password`, `CACHEDIR.TAG`가 있는 디렉터리 |

- **저장소**: RustFS 버킷 `backup-prod-<호스트명>` (호스트 전용 키)
- **스케줄**: 매일 02:00~03:59 중 호스트별 고정 시각
- **보관**: daily 7 / weekly 4 / monthly 12. 정리는 별도 템플릿 **Host Agents — Repo Maintenance**가 수행한다.

## 5. Deploy에서만 하는 일

- restic repo가 없으면 초기화한다.
- 완료 시 OpenObserve `backup_logs`에 `job=inventory` 등록 이벤트를 보낸다.
- 설정만 다시 적용할 때는 **Host Agents — Config**(`--tags agents_config`)를 쓴다.
