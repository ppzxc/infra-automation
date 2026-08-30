# Overseer Ansible Roles Index & Matrix

이 디렉토리는 Overseer의 온프레미스 인프라 자동화 레이어를 구성하는 Ansible 역할(Roles)의 스펙과 추적 매트릭스를 포함합니다.

---

## 1. 역할 목록 (Roles Index)

1. [Docker Engine (`docker_engine`)](file:///home/ppzxc/projects/node-provisioner/docs/docker_engine.md) - Podman 충돌 제거, 최신 Docker CE 설치 및 하드닝
2. [Overseer Control Plane (`overseer_control_plane`)](file:///home/ppzxc/projects/node-provisioner/docs/overseer_control_plane.md) - 컨트롤 플레인 호스트 커널 튜닝, memlock, systemd 자동화
3. [Common Baseline (`common`)](file:///home/ppzxc/projects/node-provisioner/docs/common.md) - 시간 동기화(Chrony), 로케일, 관리자 계정, 커널 기본 튜닝
4. [Security Hardening (`security`)](file:///home/ppzxc/projects/node-provisioner/docs/security.md) - SSH 하드닝, 방화벽(UFW/Firewalld/iptables), SELinux, Auditd
5. [OpenBao SSH CA (`openbao_ssh_ca`)](file:///home/ppzxc/projects/node-provisioner/docs/openbao_ssh_ca.md) - OpenBao SSH CA 공개키 배포 및 단기 인증서 신뢰 설정
6. [Boundary Target (`boundary_target`)](file:///home/ppzxc/projects/node-provisioner/docs/boundary_target.md) - HashiCorp Boundary 접속 타겟 메타데이터 등록
7. [Monitoring & Observability (`monitoring`)](file:///home/ppzxc/projects/node-provisioner/docs/monitoring.md) - Node Exporter, Docker 메트릭 및 OpenTelemetry Collector 파이프라인
