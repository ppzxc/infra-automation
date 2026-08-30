# Overseer Control Plane Host Role Task Specification

`overseer_control_plane` 역할은 OpenBao, HashiCorp Boundary 및 PostgreSQL 백엔드가 구동되는 컨트롤 플레인 전용 호스트의 커널 파라미터, 메모리 락(`memlock`), 보안 디렉토리 권한 및 `overseer.service` systemd 유닛을 자동화합니다.

---

## 1. 개요 및 구현 기능 (What)

- **컨트롤 플레인 커널 튜닝**: OpenBao 시크릿 스왑 방지(`vm.swappiness=1`), 파일 디스크립터 확장(`fs.file-max=2097152`), 대규모 연결 큐(`net.core.somaxconn=65535`).
- **OpenBao 메모리 락(`IPC_LOCK` / `memlock`) 권한 부여**: `/etc/security/limits.d/99-overseer.conf`를 통한 무제한 `memlock` 설정.
- **영구 데이터 볼륨 권한 보장**: `/opt/overseer/openbao/data` (0700), `/opt/overseer/postgres/data` (0700) 등.
- **Systemd 서비스 자동 등록 (`overseer.service`)**: OS 재부팅 시 Docker Compose 스택이 자동 기동되도록 등록.

---

## 2. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `CP-001` | `Configure kernel sysctl parameters for Overseer Control Plane` | `ansible.posix.sysctl` | All | 커널 파라미터 일치 시 `ok` |
| `CP-002` | `Configure security limits for OpenBao memlock and process limits` | `ansible.builtin.template` | All | Checksum 비교 |
| `CP-003` | `Create Overseer control plane persistent directories` | `ansible.builtin.file` | All | 디렉토리 및 권한 일치 시 `ok` |
| `CP-004` | `Deploy Overseer systemd service unit` | `ansible.builtin.template` | Systemd OS | Checksum 비교 (`overseer.service.j2`) |
| `CP-005` | `Enable Overseer systemd service` | `ansible.builtin.systemd` | Systemd OS | 서비스 활성화 시 `ok` |
