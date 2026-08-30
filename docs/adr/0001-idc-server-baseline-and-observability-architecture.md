# 1. IDC Server Baseline, Zero-Trust Access, and Hybrid Observability Architecture

- **Status**: Accepted
- **Date**: 2026-08-26
- **Deciders**: Overseer Engineering Team & User
- **Context**: IDC On-Premise Infrastructure Provisioning (CentOS 6 to Rocky Linux 10, Debian/Ubuntu)

---

## 1. Context & Problem Statement

Overseer는 소-중규모 IDC(온프레미스) 환경에서 운영되는 다양한 세대의 리눅스 서버(CentOS 6 레거시부터 Rocky Linux 10, Ubuntu/Debian)를 체계적으로 관리하고 프로비저닝하기 위한 자동화 플랫폼입니다.

기존 인프라의 파편화와 운영 비표준화 문제를 해결하기 위해 다음 네 가지 핵심 영역에 대한 표준 아키텍처 결정이 필요했습니다:
1. **OS 세대별 호환성 (CentOS 6 ~ Rocky 10)**: 패키지 관리자(`yum`, `dnf`, `dnf5`, `apt`), 서비스 관리자(SysVinit vs Systemd), OpenSSH 버전 차이에 따른 전략 수립.
2. **Zero-Trust 접근 제어**: HCP Vault SSH CA와 HashiCorp Boundary를 활용한 단기 인증서(Short-lived certs) 기반 세션 제어 및 비상 Break-glass 채널 구축.
3. **보안 하드닝 (Security Hardening)**: 침입 방지, 감사 로그, 방화벽 서브넷 제어 및 안정적 운영을 위한 SELinux 정책 수립.
4. **통합 관제 및 텔레메트리 (Observability)**: 별도의 `node_exporter` 데몬을 제거하고 `otelcol-contrib` (OpenTelemetry Collector)의 `hostmetrics` 리시버를 통해 호스트 메트릭을 직접 수집하며, 중앙 관제 백엔드로 **OpenObserve**를 사용하는 단일 에이전트 텔레메트리 파이프라인 구축.

---

## 2. Decision Outcomes (결정 사항)

### 2.1 OS 세대별 지원 및 접근 제어 전략 (Hybrid Access Control)
- **CentOS 7 ~ Rocky Linux 10 / Ubuntu**:
  - HCP Vault SSH CA의 `TrustedUserCAKeys` 및 `AuthorizedPrincipalsFile`을 `sshd_config`에 구성.
  - HashiCorp Boundary Worker를 통한 세션 프록시 및 Vault 자격증명 자동 주입(Credential Injection) 연계.
- **CentOS 6 (Legacy)**:
  - OpenSSH 5.3의 CA 서명 미지원 한계로 인해 Vault SSH CA 대신 **오프라인 관리자 전용 공개키 주입** 및 **Boundary Worker 프록시 터널링**을 통해 접근 격리.
  - 레포지토리는 `vault.centos.org` 아카이브 엔드포인트로 고정.

### 2.2 보안 하드닝 (Layered Defense & Permissive SELinux)
- **SELinux 모드**: `permissive` 모드로 설정하여 운영 서비스 장애를 방지하면서 위반 로그를 수집·감사.
- **감사 및 모니터링 (Auditd)**: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config` 변경 감시 및 `execve` 실행 추적.
- **침입 차단 (Fail2ban)**: SSH Brute-force 공격 차단을 위한 fail2ban SSH jail 기본 활성화.
- **방화벽 및 네트워크 격리**:
  - SSH 포트는 전체 공개를 차단하고 **내부 관리망 서브넷 화이트리스트**로만 접근 인가 (Otel Collector 아웃바운드 푸시 구조로 인바운드 모니터링 포트 오픈 불필요).
  - SSH 기본 포트(22) 대신 비표준 커스텀 포트 지정 지원.
- **Sudo 정책**: `timestamp_timeout=15` 및 `/var/log/sudo.log` 독립 로깅 활성화.

### 2.3 텔레메트리 및 관제 파이프라인 (Unified OTel Pipeline with OpenObserve)
- **에이전트 배포 형태**: 각 온프레미스 노드에 **단일 독립형 Systemd 서비스(`otelcol-contrib`)**로 설치.
- **수집 파이프라인 구성**:
  - **Hostmetrics Receiver (`collection_interval: 15s`)**: 호스트 레벨의 OS/하드웨어 메트릭(CPU, Memory, Disk, Filesystem, Load, Network, Paging, Processes)을 커널로부터 직접 수집.
  - **Filelog Receiver**: 시스템 로그(`/var/log/messages`, `/var/log/secure`, `/var/log/audit/audit.log`, `/var/log/sudo.log` 등) 수집 및 정형화.
  - **Prometheus Receiver (선택적)**: Docker Engine 메트릭(`127.0.0.1:9323`) 활성화 시 스크랩.
  - **OTLP Ingestion**: 어플리케이션 OTLP gRPC(4317) / HTTP(4318) 엔드포인트 수신.
- **중앙 백엔드**: 수집된 메트릭, 로그, 트레이스는 OTLP 프로토콜을 통해 중앙 **OpenObserve** 클러스터로 단일화하여 아웃바운드 전송.

---

## 3. Architecture Overview

```mermaid
graph TD
    subgraph "IDC Managed Node (CentOS 7 ~ Rocky 10 / Ubuntu / Debian)"
        SysLog["System Logs (/var/log/*)"]
        AuditLog["Auditd Log (/var/log/audit)"]
        KernelOS["Kernel & OS Stats (CPU, Mem, Disk, Net, Load)"]
        
        OTEL["OpenTelemetry Collector Contrib (Systemd)<br/>- hostmetrics receiver (15s)<br/>- filelog receiver<br/>- otlp exporter"]
        
        KernelOS -->|hostmetrics| OTEL
        SysLog -->|filelog| OTEL
        AuditLog -->|filelog| OTEL
    end

    subgraph "Central Observability & Control Plane"
        OpenObserve["OpenObserve (Central Logs / Metrics / Traces)"]
        Vault["HCP Vault (SSH CA & Secrets)"]
        Boundary["HashiCorp Boundary (Zero-Trust Access)"]
    end

    OTEL -->|OTLP gRPC (4317) / HTTP (4318)| OpenObserve
    Boundary -->|Dynamic SSH Cert Injection| Vault
    Boundary -->|Proxied SSH Session| IDC Managed Node
```

---

## 4. Consequences & Trade-offs

- **장점 (Pros)**:
  - **단일 에이전트 아키텍처**: 별도의 `node_exporter` 데몬 없이 OTel Collector 단일 바이너리로 메트릭/로그/트레이스를 일원화하여 프로세스 관리 오버헤드 감소.
  - **단일 중앙 관제**: OpenObserve로 메트릭과 로그를 통합 관리하여 운영 복잡도 대폭 감소.
  - **무중단 보안**: SELinux `permissive`로 기존 워크로드 중단 없이 보안 가시성 확보, Fail2ban 및 서브넷 화이트리스트로 실시간 위협 차단.
  - **레거시/모던 통합**: 멱등성 있는 단일화된 Ansible 워크플로우 유지 및 구버전 node_exporter 자동 정리.
- **고려사항 (Cons & Mitigations)**:
  - OTel Collector에 메모리 리소스 제한(`memory_limiter` 프로세서)을 적용하여 프로세스 폭주 방지.
  - CentOS 6의 경우 OTEL Collector의 최신 glibc 의존성(>= 2.17)으로 인해 바이너리 호환 여부에 따라 레거시 노드는 Filebeat/rsyslog 폴백 고려 필요.

