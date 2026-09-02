# Docker Engine Role Task Specification

`docker_engine` 역할은 RedHat/Rocky Linux 및 Debian/Ubuntu 시스템에서 Podman 및 레거시 패키지 충돌을 정리하고, 최신 공식 Docker CE 및 Docker Compose 플러그인을 설치하며, 보안/운영 하드닝된 `daemon.json`을 배포합니다.

---

## 1. 개요 및 구현 기능 (What)

- **Podman 및 레거시 패키지 완전 제거**: Rocky Linux/RHEL 9/10의 기본 `podman`, `buildah`, `skopeo`, `runc`, `containernetworking-plugins` 등을 제거하여 Docker CE 저장소 패키지와의 충돌 방지.
- **공식 Docker CE 저장소 연동**: 최신 안정화 버전(Stable) 저장소 및 GPG 키 자동 구성.
- **최신 Docker 엔진 & 플러그인 설치**: `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-compose-plugin`, `docker-buildx-plugin`.
- **운영 하드닝된 `daemon.json` 배포**:
  - `log-driver`: `json-file` (max-size: 50m, max-file: 3)으로 컨테이너 로그 디스크 고갈 방지.
  - `live-restore`: `true`로 데몬 재시작 시 컨테이너 무중단 실행 보장.
  - `metrics-addr`: `127.0.0.1:9323`으로 Docker 자체 메트릭을 Prometheus 포맷으로 로컬 노출(OTEL Collector 스크랩 연동).
- **ADR-0002 계정 및 FHS 디렉토리 권한 표준 준수**:
  - 공유 관리 그룹 `dockermgmt`(GID 2000) 및 컨테이너 서비스 계정 `dockersvc`(UID 998) 생성.
  - FHS 표준 경로(`/opt/services`, `/data`, `/backup`) 생성 및 SGID + POSIX Default ACL(`g:dockermgmt:rwx`) 적용.
  - 운영자 세션 전용 umask 스크립트(`/etc/profile.d/docker_mgmt.sh`) 배포 및 홈 디렉터리 편의 심볼릭 링크 생성.

---

## 2. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `DOC-001` | `Remove conflicting packages and Podman stack (RedHat/Rocky)` | `ansible.builtin.package` | RedHat/Rocky | `state: absent` |
| `DOC-002` | `Remove conflicting packages and old Docker stack (Debian/Ubuntu)` | `ansible.builtin.apt` | Debian/Ubuntu | `state: absent` |
| `DOC-003` | `Install Docker repository prerequisites (RedHat/Rocky)` | `ansible.builtin.package` | RedHat/Rocky | 패키지 존재 시 `ok` |
| `DOC-004` | `Configure Docker CE official repository (RedHat/Rocky)` | `ansible.builtin.get_url` | RedHat/Rocky | Checksum 비교 |
| `DOC-005` | `Install Docker repository prerequisites (Debian/Ubuntu)` | `ansible.builtin.apt` | Debian/Ubuntu | 패키지 존재 시 `ok` |
| `DOC-006` | `Create keyrings directory for apt (Debian/Ubuntu)` | `ansible.builtin.file` | Debian/Ubuntu | 디렉토리 존재 시 `ok` |
| `DOC-007` | `Download Docker GPG key (Debian/Ubuntu)` | `ansible.builtin.get_url` | Debian/Ubuntu | Checksum 비교 |
| `DOC-008` | `Configure Docker CE repository (Debian/Ubuntu)` | `ansible.builtin.apt_repository` | Debian/Ubuntu | 저장소 정의 일치 시 `ok` |
| `DOC-009` | `Install latest Docker CE and Compose plugin packages` | `ansible.builtin.package` | All | 패키지 최신 상태 유지 시 `ok` |
| `DOC-010` | `Create /etc/docker directory` | `ansible.builtin.file` | All | 디렉토리 존재 시 `ok` |
| `DOC-011` | `Deploy hardened Docker daemon configuration` | `ansible.builtin.template` | All | Checksum 비교 (`daemon.json.j2`) |
| `DOC-012` | `Ensure Docker and containerd services are started and enabled` | `ansible.builtin.service` | All | 서비스 활성 상태 시 `ok` |
| `DOC-013` | `Add admin user to docker group` | `ansible.builtin.user` | All | 그룹 소속 일치 시 `ok` |
| `DOC-014` | `Ensure dockermgmt system group exists (GID 2000)` | `ansible.builtin.group` | All | GID 일치 시 `ok` |
| `DOC-015` | `Ensure dockersvc system user exists (UID 998)` | `ansible.builtin.user` | All | UID/그룹 일치 시 `ok` |
| `DOC-016` | `Create FHS standard service and data directories (/opt/services, /data, /backup)` | `ansible.builtin.file` | All | 디렉터리 경로 및 권한 일치 시 `ok` |
| `DOC-017` | `Configure POSIX default and access ACLs for docker management` | `ansible.posix.acl` | All | ACL 엔트리 일치 시 `ok` |
| `DOC-018` | `Deploy docker management session umask script (/etc/profile.d/docker_mgmt.sh)` | `ansible.builtin.copy` | All | 파일 내용 및 권한(`0644`) 일치 시 `ok` |
| `DOC-019` | `Add admin and operator users to dockermgmt group` | `ansible.builtin.user` | All | 그룹 소속 일치 시 `ok` |
| `DOC-020` | `Create convenience symlinks in operator home directory` | `ansible.builtin.file` | All | 심볼릭 링크 대상 일치 시 `ok` |
