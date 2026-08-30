# Monitoring Role Task Specification

`monitoring` 역할은 OpenTelemetry Collector Contrib(`otelcol-contrib`)을 기반으로 한 온프레미스 단일 에이전트 관제 파이프라인의 배포, 시스템 계정 격리, `hostmetrics` 리시버를 통한 커널/OS 메트릭 수집, 그리고 레거시 `node_exporter` 자동 정리를 수행합니다.

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

## 4. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `MON-CLEANUP-001` | `Stop and disable legacy node_exporter service` | `ansible.builtin.systemd` | Systemd OS | 서비스 중지/비활성화 시 `ok` |
| `MON-CLEANUP-002` | `Remove legacy node_exporter systemd unit file` | `ansible.builtin.file` | Systemd OS | 파일 부존재 시 `ok` |
| `MON-CLEANUP-003` | `Remove legacy node_exporter binary` | `ansible.builtin.file` | All | 바이너리 부존재 시 `ok` |
| `MON-CLEANUP-004` | `Remove legacy node_exporter user` | `ansible.builtin.user` | All | 유저 부존재 시 `ok` |
| `MON-CLEANUP-005` | `Remove legacy node_exporter group` | `ansible.builtin.group` | All | 그룹 부존재 시 `ok` |
| `MON-001` | `Create otelcol system group` | `ansible.builtin.group` | All | 그룹 존재 시 `ok` |
| `MON-002` | `Create otelcol system user` | `ansible.builtin.user` | All | 유저 존재 시 `ok` |
| `MON-003` | `Download and install OpenTelemetry Collector Contrib binary` | `ansible.builtin.unarchive` | RHEL 7+, Debian | `creates: /usr/local/bin/otelcol-contrib` |
| `MON-004` | `Deploy OpenTelemetry Collector Contrib configuration (Hostmetrics & Log Pipeline)` | `ansible.builtin.template` | RHEL 7+, Debian | Checksum 비교 (`otelcol-contrib.yaml.j2`) |
| `MON-005` | `Create systemd service for otelcol-contrib` | `ansible.builtin.copy` | Systemd OS | 파일 내용 일치 시 `ok` |
| `MON-006` | `Ensure otelcol-contrib service is started and enabled` | `ansible.builtin.systemd` | Systemd OS | 서비스 기동 상태면 `ok` |


