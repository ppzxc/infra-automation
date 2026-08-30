# OpenBao SSH CA Role Task Specification

`openbao_ssh_ca` 역할은 중앙 OpenBao의 SSH Certificate Authority(CA) 공개키를 타겟 노드에 등록하고, 단기 서명 인증서 기반의 제로트러스트 SSH 접근 환경을 구성합니다.

---

## 1. 개요 및 구현 기능 (What)

- **OpenBao SSH CA 공개키 배포**: 중앙 OpenBao 컨트롤 플레인의 SSH CA 서명용 공개키를 타겟 노드의 `/etc/ssh/trusted-user-ca-keys.pem`에 배포.
- **권한 주체(Authorized Principals) 매핑**: 관리자 계정별로 허용할 서명 Principal(예: `admin`, `infra-admin`)을 정의하는 파일 구성.
- **OpenSSH 데몬 서명 인증서 신뢰 구성**: `sshd_config`에 `TrustedUserCAKeys` 및 `AuthorizedPrincipalsFile` 지시어를 추가하여 OpenBao 서명 인증서 유효성을 자동 검증.
- **레거시 OpenSSH 호환성 검사**: OpenSSH 5.4 이상(RHEL/CentOS 7+)에서만 CA 기능이 동작하므로, 레거시 환경(CentOS 6 등)에서는 조건부로 스킵 및 안전 경고 처리.

---

## 2. 왜 구현해야 하는가? (Why)

1. **정적 SSH 키의 유출 및 라이프사이클 관리 한계 극복**:
   - 수십~수백 대의 서버에 엔지니어들의 정적 SSH 공개키(`authorized_keys`)를 수동 배포하거나 관리하는 방식은 키 분실/유출, 퇴사자 권한 미회수 등 심각한 보안 취약점을 유발합니다.
2. **단기 임시 자격증명(Short-Lived Certificates) 기반 제로트러스트**:
   - 엔지니어는 OpenBao에 로그인하여 짧은 유효기간(예: 30분~4시간)의 SSH 인증서를 서명받아 접속합니다.
   - 서버마다 사용자를 일일이 수정할 필요 없이, 중앙에서 인증서 발급 정책을 통해 즉각적인 권한 회수 및 세션 감사가 가능해집니다.
3. **감사 추적성(Audit Trail) 향상**:
   - 누가 어떤 Principal 권한으로 언제 인증서를 발급받았는지 OpenBao 감사 로그에 중앙 집중식으로 기록됩니다.

---

## 3. 무엇을 변경하는가? (What Changes)

- 📁 **설정 파일 및 디렉토리**:
  - `/etc/ssh/trusted-user-ca-keys.pem` : OpenBao SSH CA 공개키 배포
  - `/etc/ssh/auth_principals/` : Principals 디렉토리 생성
  - `/etc/ssh/auth_principals/<admin_user>` : 허용 Principal 목록 파일 생성
  - `/etc/ssh/sshd_config` : `TrustedUserCAKeys` 및 `AuthorizedPrincipalsFile` 라인 추가 (`validate: sshd -t`)
- ⚙️ **데몬 및 서비스**:
  - `sshd` : 설정 변경 시 검증 후 리로드

---

## 4. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `BAO-001` | `Skip OpenBao SSH CA if disabled or key is empty` | `ansible.builtin.debug` | All | `when` 조건부 스킵 |
| `BAO-002` | `Check OpenSSH CA capability (requires OpenSSH >= 5.4, RHEL/CentOS 7+)` | `ansible.builtin.debug` | CentOS 6 | `when` 조건부 경고 출력 |
| `BAO-003` | `Ensure SSH configuration directory exists` | `ansible.builtin.file` | All | 디렉토리 존재 시 `ok` |
| `BAO-004` | `Deploy OpenBao SSH CA Public Key` | `ansible.builtin.copy` | RHEL 7+, Debian | Checksum 일치 시 `ok` |
| `BAO-005` | `Ensure AuthorizedPrincipals directory exists` | `ansible.builtin.file` | RHEL 7+, Debian | 디렉토리 존재 시 `ok` |
| `BAO-006` | `Create admin user principals file` | `ansible.builtin.copy` | RHEL 7+, Debian | 내용 일치 시 `ok` |
| `BAO-007` | `Configure sshd to trust OpenBao CA Keys and AuthorizedPrincipals` | `ansible.builtin.lineinfile` | RHEL 7+, Debian | 라인 일치 시 `ok` (`validate: sshd -t`) |
