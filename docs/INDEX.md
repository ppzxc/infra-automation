# Infra Automation Ansible Roles Index & Matrix

`infra-automation` 프로젝트는 단일 책임 원칙(SRP)에 따라 모듈화된 5대 핵심 역할을 통해 온프레미스 대상 호스트의 라이프사이클을 관리하며, 본 디렉토리는 관련 스펙과 추적 매트릭스를 포함합니다.

---

## 1. 역할 목록 (Roles Index)

1. [Common Baseline (`common`)](common.md) - 시간 동기화(Chrony), 로케일, 관리자 계정, 커널 기본 튜닝
2. [Security Hardening (`security`)](security.md) - SSH 하드닝, 방화벽(UFW/Firewalld/iptables), SELinux, Auditd, firewalld-docker CLI
3. [Access Security (`access_security`)](access_security.md) - OpenBao SSH CA 단기 인증서 신뢰 및 HashiCorp Boundary 접속 메타데이터 통합
4. [Docker Engine (`docker_engine`)](docker_engine.md) - Podman 충돌 제거, 최신 Docker CE 설치 및 하드닝
5. [Monitoring & Observability (`monitoring`)](monitoring.md) - OpenTelemetry Collector (`otelcol-contrib`) 호스트 메트릭 및 시스템 로그 수집 파이프라인
6. [Host Backup (`backup`)](backup.md) - restic + resticprofile 기반 호스트 설정 백업(RustFS S3), ISMS 2.9.3 표준, 중앙 Repo Maintenance 포함
7. [Cisco IOS Switch Backup (`cisco_backup`)](cisco_backup.md) - Cisco 네트워크 스위치 `show running-config` 수집, 무결성 검증, 보관 주기 자동화 및 Semaphore UI 연동
8. [OpenObserve Config (`openobserve_config`)](openobserve_config.md) - 컨트롤러 전용. OpenObserve VRL ingest function(sshd/sudo 해석)·파이프라인·통지 webhook·알림 규칙을 코드로 관리하고 API로 반영 (ADR-0008)

---

## 2. 통합 아키텍처 및 시크릿 관리 (Integrations & Secrets)

* [OpenBao & Semaphore UI Secret Management Integration](openbao_integration.md) - OpenBao KV v2 동적 시크릿 및 Semaphore UI 최신 연동 가이드
* [Host Agents (otelcol + resticprofile) ADR-0006](adr/0006-host-agents-otelcol-resticprofile.md) - Host Agents 설치·재구성, ISMS 수집/백업 표준, OpenBao KV 스키마, CentOS 6/7 분기
* [Semaphore 셋업 가이드](semaphore-setup.md) - Key Store·Repository·Inventory·Variable Group·Host Agents/OpenObserve 템플릿·스케줄(UTC/KST) 등록 절차와 자주 겪는 문제
* Host Agents — Deploy 배포 내역서: [Simple](host-agents-deploy-inventory-simple.md) · [Full](host-agents-deploy-inventory-full.md) - otelcol-contrib·restic·resticprofile 버전/SHA256, 호스트 변경 파일, 기본 수집 로그, 기본 백업 대상
* [Log Structuring ADR-0008](adr/0008-log-structuring-edge-envelope-central-semantics.md) - 엣지 Envelope Parsing + 중앙(OpenObserve VRL·알림) 의미 해석
* [Security Hardening Frameworks Evaluation ADR-0004](adr/0004-hardening-framework-evaluation.md) - dev-sec 및 ansible-lockdown 도입 검토 및 파일럿 전략

