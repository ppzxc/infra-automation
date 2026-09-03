# Node Provisioner Ansible Roles Index & Matrix

이 디렉토리는 Overseer 컨트롤 플레인과 연동되는 온프레미스 대상 서버(IDC 타겟 노드) 자동화 레이어를 구성하는 Ansible 역할(Roles)의 스펙과 추적 매트릭스를 포함합니다.

---

## 1. 역할 목록 (Roles Index)

1. [Common Baseline (`common`)](file:///home/ppzxc/projects/node-provisioner/docs/common.md) - 시간 동기화(Chrony), 로케일, 관리자 계정, 커널 기본 튜닝
2. [Security Hardening (`security`)](file:///home/ppzxc/projects/node-provisioner/docs/security.md) - SSH 하드닝, 방화벽(UFW/Firewalld/iptables), SELinux, Auditd, firewalld-docker CLI
3. [Access Security (`access_security`)](file:///home/ppzxc/projects/node-provisioner/docs/access_security.md) - OpenBao SSH CA 단기 인증서 신뢰 및 HashiCorp Boundary 접속 메타데이터 통합
4. [Docker Engine (`docker_engine`)](file:///home/ppzxc/projects/node-provisioner/docs/docker_engine.md) - Podman 충돌 제거, 최신 Docker CE 설치 및 하드닝
5. [Monitoring & Observability (`monitoring`)](file:///home/ppzxc/projects/node-provisioner/docs/monitoring.md) - OpenTelemetry Collector (`otelcol-contrib`) 호스트 메트릭 및 시스템 로그 수집 파이프라인

---

## 2. 통합 아키텍처 및 시크릿 관리 (Integrations & Secrets)

* [OpenBao & Semaphore UI Secret Management Integration](file:///home/ppzxc/projects/node-provisioner/docs/openbao_integration.md) - OpenBao KV v2 동적 시크릿 및 Semaphore UI 최신 연동 가이드

