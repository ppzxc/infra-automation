# Access Security Role Task Specification

`access_security` 역할은 온프레미스 IDC 인프라의 모든 타겟 노드에 OpenBao SSH CA 기반 단기 인증서 신뢰 및 HashiCorp Boundary 접속 메타데이터를 통합 구성하는 심화(Deep) 보안 모듈입니다.

---

## 1. 개요 및 구현 기능 (What)

- **OpenBao SSH CA 신뢰 구성**: OpenBao 중앙 컨트롤 플레인에서 발급한 SSH CA 공개키를 타겟 노드에 안전하게 배포하고 `sshd_config`의 `TrustedUserCAKeys`로 등록.
- **사용자별 접근 주체(Authorized Principals) 매핑**: `/etc/ssh/auth_principals` 디렉토리에 관리자별 인가 주체(`admin`, `{{ admin_user }}`) 파일 생성 및 `sshd` 연동.
- **HashiCorp Boundary 노드 메타데이터 등록**: `/etc/boundary/node-metadata.json` 파일에 호스트 IP, 타겟 프로토콜(SSH), 포트, 워커 태그 및 프로비저닝 타임스탬프 기록.
- **레거시 OS(CentOS 6) 호환성 격리**: OpenSSH 5.3의 `TrustedUserCAKeys` 미지원 한계를 자동 감지하여 사전 검증 및 안전한 폴백 처리.

---

## 2. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `ACC-001` | `Skip Access Security if disabled` | `ansible.builtin.debug` | All | `enable_access_security: false` 시 건너뜀 |
| `ACC-002` | `Check OpenSSH CA capability (requires OpenSSH >= 5.4, RHEL/CentOS 7+)` | `ansible.builtin.debug` | CentOS 6 | 조건 감지 시 경고 및 안전 우회 |
| `ACC-003` | `Ensure SSH configuration directory exists` | `ansible.builtin.file` | RHEL 7+, Debian | 디렉토리 상태 및 권한(`0755`) 일치 시 `ok` |
| `ACC-004` | `Deploy OpenBao SSH CA Public Key` | `ansible.builtin.copy` | RHEL 7+, Debian | Checksum 비교 및 변경 시 `Restart sshd for Access Security` 호출 |
| `ACC-005` | `Ensure AuthorizedPrincipals directory exists` | `ansible.builtin.file` | RHEL 7+, Debian | 디렉토리 상태 및 권한(`0755`) 일치 시 `ok` |
| `ACC-006` | `Create admin user principals file` | `ansible.builtin.copy` | RHEL 7+, Debian | Principals 목록 일치 시 `ok` |
| `ACC-007` | `Configure sshd to trust OpenBao CA Keys and AuthorizedPrincipals` | `ansible.builtin.lineinfile` | RHEL 7+, Debian | 정규식 매칭 및 `sshd -t` 사전 검증 |
| `ACC-008` | `Create Boundary target metadata directory` | `ansible.builtin.file` | All | 디렉토리 상태 및 권한(`0755`) 일치 시 `ok` |
| `ACC-009` | `Write Boundary Target Node Metadata` | `ansible.builtin.copy` | All | JSON 내용 일치 시 `ok` |
