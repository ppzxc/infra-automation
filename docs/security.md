# Security Role Task Specification

`security` 역할은 온프레미스 노드의 핵심 보안 계층인 OpenSSH 서버 하드닝, OS 계열별 호스트 방화벽(UFW, Firewalld, iptables), 그리고 무차별 대입 공격 차단 도구(Fail2ban)를 구성합니다.

---

## 1. 개요 및 구현 기능 (What)

- **OpenSSH 서버 보안 하드닝**:
  - `root` 계정의 원격 직접 로그인 차단 (`PermitRootLogin no`)
  - 비밀번호 기반 인증 비활성화 제어 (`PasswordAuthentication no`, 사전 검증 후 적용)
  - 최대 인증 시도 횟수 제한 (`MaxAuthTries 4`)
  - 빈 비밀번호 접속 금지 (`PermitEmptyPasswords no`)
  - SSH 설정 유효성 사전 검증 (`sshd -t`)
- **OS 패밀리별 자동 호스트 방화벽 구성**:
  - **Debian / Ubuntu**: `UFW` 패키지 설치, 기본 인바운드 차단(`default deny incoming`), 허용 포트 등록 및 활성화
  - **RHEL / CentOS 7+ / Rocky**: `firewalld` 패키지 설치, 데몬 활성화, 영구 허용 포트(`permanent`) 등록 및 리로드
  - **CentOS 6 레거시**: `iptables` INPUT 체인에 허용 포트 룰 적용
- **침입 방지 시스템 (Fail2ban) 구성**:
  - `fail2ban` 패키지 설치 및 서비스 활성화를 통한 SSH 무차별 대입 공격(Brute-force) IP 자동 격리/차단.

---

## 2. 왜 구현해야 하는가? (Why)

1. **무차별 공격 및 횡적 이동(Lateral Movement) 차단**:
   - IDC 사내망 또는 외부에 노출된 서버는 상시적인 SSH Brute-force 공격에 노출됩니다. 루트 로그인 및 패스워드 인증을 차단함으로써 공격 표면(Attack Surface)을 최소화합니다.
2. **심층 방어(Defense in Depth) 구현**:
   - 상단 L3/L4 네트워크 방화벽이 존재하더라도, 내부망 침해 사고 시 횡적 이동을 차단하기 위해 모든 개별 호스트 레벨에서 기본 차단(Default Deny) 정책의 호스트 방화벽이 필수적입니다.
3. **SSH 락아웃(Lockout) 방지 및 안전한 형상 관리**:
   - `sshd -t` 문법 검증 및 핸들러를 통한 안전한 서비스 리로드로 엔지니어의 접속 차단 사고를 원천 방지합니다.

---

## 3. 무엇을 변경하는가? (What Changes)

- 📁 **설정 파일 및 디렉토리**:
  - `/etc/ssh/sshd_config` : SSH 보안 설정 파라미터 적용
  - `/etc/fail2ban/fail2ban.conf` / `/etc/fail2ban/jail.local` : Fail2ban 룰 구성
- ⚙️ **데몬 및 서비스**:
  - `sshd` : 설정 변경 시 검증 후 리로드
  - `ufw` (Debian/Ubuntu) / `firewalld` (RHEL/Rocky) / `fail2ban` : 데몬 활성화 및 자동 기동
- 🌐 **네트워크 및 방화벽 규칙**:
  - 기본 인바운드 정책: `DENY` / `DROP`
  - 허용 인바운드 TCP 포트: SSH(`22`), 사용자 정의 포트(`firewall_allowed_tcp_ports`) (※ Node Exporter는 로컬 `127.0.0.1` 바인딩 및 Otel Collector 아웃바운드 푸시 구조로 인바운드 포트 불필요)

---

## 4. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `SEC-001` | `Configure SSH Hardening parameters` | `ansible.builtin.lineinfile` | All | 정규식 매칭 및 상태 일치 시 `ok` (`validate: sshd -t`) |
| `SEC-002` | `Ensure UFW is installed (Debian)` | `ansible.builtin.apt` | Debian, Ubuntu | 패키지 기설치 시 `ok` |
| `SEC-003` | `Allow incoming TCP ports via UFW (Debian)` | `community.general.ufw` | Debian, Ubuntu | 룰 기등록 시 `ok` |
| `SEC-004` | `Enable UFW with default deny incoming (Debian)` | `community.general.ufw` | Debian, Ubuntu | UFW 활성화 상태면 `ok` |
| `SEC-005` | `Ensure firewalld is installed and running (RHEL/Rocky 7+)` | `ansible.builtin.package` | RHEL 7+, Rocky | 패키지 기설치 시 `ok` |
| `SEC-006` | `Ensure firewalld service is started and enabled (RHEL/Rocky 7+)` | `ansible.builtin.service` | RHEL 7+, Rocky | 서비스 기동 상태면 `ok` |
| `SEC-007` | `Allow incoming TCP ports via firewalld (RHEL/Rocky 7+)` | `ansible.posix.firewalld` | RHEL 7+, Rocky | 포트 기등록 시 `ok` |
| `SEC-008` | `Allow incoming TCP ports via iptables (CentOS 6)` | `ansible.builtin.iptables` | CentOS 6 | iptables 체인 룰 확인 후 적용 |
| `SEC-009` | `Install fail2ban package if available` | `ansible.builtin.package` | All | 패키지 기설치 시 `ok`, `failed_when: false` |
| `SEC-010` | `Ensure fail2ban is running and enabled (if installed)` | `ansible.builtin.service` | All | 서비스 기동 상태면 `ok`, `failed_when: false` |
| `SEC-011` | `Configure SELinux in permissive mode (RHEL/Rocky 7+)` | `ansible.posix.selinux` | RHEL 7+, Rocky | SELinux 상태가 permissive면 `ok` |
| `SEC-012` | `Deploy Auditd security audit rules` | `ansible.builtin.template` | RHEL / Rocky | Checksum 비교 (`audit.rules.j2`) |
| `SEC-013` | `Ensure Auditd service is running and enabled` | `ansible.builtin.service` | RHEL / Rocky | 서비스 기동 상태면 `ok` |
| `SEC-014` | `Configure Sudo timestamp timeout and log file` | `ansible.builtin.copy` | All | Checksum 비교 (`validate: visudo`) |
| `SEC-015` | `Deploy Fail2ban SSH jail configuration` | `ansible.builtin.template` | All | Checksum 비교 (`fail2ban-sshd.local.j2`) |
| `SEC-016` | `Deploy firewalld-docker management CLI` | `ansible.builtin.copy` | RHEL 7+, Rocky | Checksum 비교 (`firewalld-docker.sh`) |
| `SEC-017` | `Create firewalld-docker.sh symlink` | `ansible.builtin.file` | RHEL 7+, Rocky | 심볼릭 링크 일치 시 `ok` |
| `SEC-018` | `Initialize firewalld DOCKER-USER direct rules (optional auto-init)` | `ansible.builtin.command` | RHEL 7+, Rocky | 룰 기등록 시 `ok`, `changed_when: false` |
| `SEC-019` | `Configure custom firewall ingress rules with source IP restrictions (UFW)` | `community.general.ufw` | Debian, Ubuntu | 룰 기등록 시 `ok` |
| `SEC-020` | `Configure custom firewall ingress rules with source IP restrictions (firewalld)` | `ansible.posix.firewalld` | RHEL 7+, Rocky | Rich Rule 기등록 시 `ok` |
| `SEC-021` | `Configure custom firewall ingress rules with source IP restrictions (iptables)` | `ansible.builtin.iptables` | CentOS 6 | iptables 체인 룰 확인 후 적용 |
| `SEC-022` | `Add IPSet source IPs via firewalld-docker` | `ansible.builtin.command` | RHEL 7+, Rocky | IPSet 멤버 기등록 시 `ok`, `changed_when: false` |
| `SEC-023` | `Allow ports for IPSet whitelists via firewalld-docker` | `ansible.builtin.command` | RHEL 7+, Rocky | 포트 Direct Rule 기등록 시 `ok`, `changed_when: false` |



