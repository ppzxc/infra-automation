# Infra Automation Ansible Roles Index & Matrix

`infra-automation` 프로젝트는 단일 책임 원칙(SRP)에 따라 모듈화된 5대 핵심 역할을 통해 온프레미스 대상 호스트의 라이프사이클을 관리하며, 본 디렉토리는 관련 스펙과 추적 매트릭스를 포함합니다.

---

## 1. 역할 목록 (Roles Index)

1. [Common Baseline (`common`)](common.md) - 시간 동기화(Chrony), 로케일, 관리자 계정, 커널 기본 튜닝
2. [Security Hardening (`security`)](security.md) - SSH 하드닝, 방화벽(UFW/Firewalld/iptables), SELinux, Auditd, firewalld-docker CLI
3. [Access Security (`access_security`)](access_security.md) - OpenBao SSH CA 단기 인증서 신뢰 및 HashiCorp Boundary 접속 메타데이터 통합
4. [Docker Engine (`docker_engine`)](docker_engine.md) - Podman 충돌 제거, 최신 Docker CE 설치 및 하드닝
5. [Monitoring & Observability (`monitoring`)](monitoring.md) - OpenTelemetry Collector (`otelcol-contrib`) 호스트 메트릭 및 시스템 로그 수집 파이프라인
6. [Cisco IOS Switch Backup (`cisco_backup`)](cisco_backup.md) - Cisco 네트워크 스위치 `show running-config` 수집, 무결성 검증, 보관 주기 자동화 및 Semaphore UI 연동

---

## 2. 통합 아키텍처 및 시크릿 관리 (Integrations & Secrets)

* [OpenBao & Semaphore UI Secret Management Integration](openbao_integration.md) - OpenBao KV v2 동적 시크릿 및 Semaphore UI 최신 연동 가이드
* [Security Hardening Frameworks Evaluation ADR-0004](adr/0004-hardening-framework-evaluation.md) - dev-sec 및 ansible-lockdown 도입 검토 및 파일럿 전략

