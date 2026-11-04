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
  - 허용 인바운드 TCP 포트: SSH(`22`), 사용자 정의 포트(`firewall_allowed_tcp_ports`)
  - **SSH IP 기반 접근 제어 (`ssh_allowed_source_ips`)**: 인가된 공인 IP/서브넷에 한해 22/tcp 허용(Firewalld Rich Rule / UFW from_ip), 미지정 시 0.0.0.0/0 개방 (※ Node Exporter는 로컬 `127.0.0.1` 바인딩 및 Otel Collector 아웃바운드 푸시 구조로 인바운드 포트 불필요)

---

## 4. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `SEC-001` | `Configure SSH Hardening parameters` | `ansible.builtin.lineinfile` | All | 정규식 매칭 및 상태 일치 시 `ok` (`validate: sshd -t`) |
| `SEC-002` | `Ensure UFW is installed (Debian)` | `ansible.builtin.apt` | Debian, Ubuntu | 패키지 기설치 시 `ok` |
| `SEC-003` | `Allow incoming TCP ports via UFW (Debian)` | `community.general.ufw` | Debian, Ubuntu | 룰 기등록 시 `ok` |
| `SEC-004` | `Enable UFW with default deny incoming (Debian)` | `community.general.ufw` | Debian, Ubuntu | UFW 활성화 상태면 `ok` |
| `SEC-005` | `Ensure firewalld is installed and running (RHEL/Rocky 7+)` | `ansible.builtin.package` | RHEL 7+, Rocky | 패키지 기설치 시 `ok` |
| `SEC-006` | `Ensure firewalld service is started and enabled (RHEL/Rocky 7+)` | `ansible.builtin.service` | RHEL 7+, Rocky | 서비스 기동 상태면 `ok`. 서비스가 없는(audit 미설치) 호스트만 건너뛰고 그 밖의 실패는 드러낸다 |
| `SEC-007` | `Allow incoming TCP ports via firewalld (RHEL/Rocky 7+)` | `ansible.posix.firewalld` | RHEL 7+, Rocky | 포트 기등록 시 `ok` |
| `SEC-008` | `Allow incoming TCP ports via iptables (CentOS 6)` | `ansible.builtin.iptables` | CentOS 6 (`_raw_path_effective=false`) | iptables 체인 룰 확인 후 적용 |
| `SEC-009` | `Install fail2ban package if available` | `ansible.builtin.package` | All (`_raw_path_effective=false`) | 패키지 기설치 시 `ok`, `failed_when: false` |
| `SEC-010` | `Ensure fail2ban is running and enabled (if installed)` | `ansible.builtin.service` | All (`_raw_path_effective=false`) | 서비스 기동 상태면 `ok`, `failed_when: false` |
| `SEC-011` | `Configure SELinux in permissive mode (RHEL/Rocky 7+)` | `ansible.posix.selinux` | RHEL 7+, Rocky | SELinux 상태가 permissive면 `ok` |
| `SEC-012` | `Deploy Auditd security audit rules` | `ansible.builtin.template` | RHEL / Rocky (`_raw_path_effective=false`) | Checksum 비교 (`audit.rules.j2`). 규칙 디렉터리가 없는(audit 미설치) 호스트만 건너뛰고 그 밖의 실패는 드러낸다 |
| `SEC-013` | `Ensure Auditd service is running and enabled` | `ansible.builtin.service` | RHEL / Rocky (`_raw_path_effective=false`) | 서비스 기동 상태면 `ok`. 서비스가 없는(audit 미설치) 호스트만 건너뛰고 그 밖의 실패는 드러낸다 |
| `SEC-014` | `Configure Sudo timestamp timeout and log file` | `ansible.builtin.copy` | All (`_raw_path_effective=false`) | Checksum 비교 (`validate: visudo`) |
| `SEC-015` | `Deploy Fail2ban SSH jail configuration` | `ansible.builtin.template` | All (`_raw_path_effective=false`) | Checksum 비교 (`fail2ban-sshd.local.j2`) |
| `SEC-016` | `Configure dmz zone for monitoring sources (RHEL/Rocky 7+)` | `ansible.posix.firewalld` | RHEL 7+, Rocky | DMZ 서브넷 기등록 시 `ok` |
| `SEC-017` | `Configure internal zone for private VPC subnets (RHEL/Rocky 7+)` | `ansible.posix.firewalld` | RHEL 7+, Rocky | Internal 서브넷 기등록 시 `ok` |
| `SEC-018` | `Ensure egress policy allows forwarding from docker to physical interface zone (RHEL 9+)` | `ansible.builtin.shell` | RHEL 9+ | 방화벽 정책 일치 시 `ok` |
| `SEC-019` | `Configure custom firewall ingress rules with source IP restrictions (UFW)` | `community.general.ufw` | Debian, Ubuntu | 룰 기등록 시 `ok` |
| `SEC-020` | `Configure custom firewall ingress rules with source IP restrictions (firewalld)` | `ansible.posix.firewalld` | RHEL 7+, Rocky | Rich Rule 기등록 시 `ok` |
| `SEC-021` | `Configure custom firewall ingress rules with source IP restrictions (iptables)` | `ansible.builtin.iptables` | CentOS 6 (`_raw_path_effective=false`) | iptables 체인 룰 확인 후 적용 |
| `SEC-022` | `Remove conflicting sshd_config.d drop-in files (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 파일 존재 시에만 삭제 후 `changed` |
| `SEC-023` | `Read current sshd_config (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 조회 전용 (`changed_when: false`) |
| `SEC-024` | `Probe sshd_config hash and mode (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 조회 전용 (`changed_when: false`) |
| `SEC-025` | `Configure SSH Hardening parameters via write-temp/validate/move (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 로컬 해시·모드가 원격 `sha256sum`/`stat`과 같으면 `ok` (`sshd -t -f` 검증 실패 시 임시 파일 삭제 후 실패) |
| `SEC-026` | `Probe sudo policy hash and mode (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 조회 전용 (`changed_when: false`) |
| `SEC-027` | `Configure Sudo timestamp timeout and log file via write-temp/validate/move (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 해시·모드·소유자가 같으면 `ok` (`visudo -cf` 검증 실패 시 임시 파일 삭제 후 실패, 원본 보존) |
| `SEC-028` | `Install fail2ban package if available (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 기설치 시 `ok`, 설치 불가여도 `failed_when: false` |
| `SEC-029` | `Check whether fail2ban is installed (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 조회 전용 (`changed_when: false`) |
| `SEC-030` | `Ensure fail2ban is running and enabled (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 설치된 경우에만, 기동·부팅 활성 상태면 `ok` (실패 시 fail) |
| `SEC-031` | `Probe fail2ban jail hash and mode (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 조회 전용 (`changed_when: false`) |
| `SEC-032` | `Deploy Fail2ban SSH jail configuration via write-temp/validate/move (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 설치된 경우에만, 해시·모드·소유자가 같으면 `ok` (`fail2ban-sshd.local.j2`) |
| `SEC-033` | `Check whether auditd is installed (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 조회 전용 (`changed_when: false`) |
| `SEC-034` | `Probe auditd rules hash and mode (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 조회 전용 (`changed_when: false`) |
| `SEC-035` | `Deploy Auditd security audit rules via write-temp/validate/move (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 설치된 경우에만, 해시·모드·소유자가 같으면 `ok` (`audit.rules.j2`; CentOS 7 `rules.d/overseer.rules`, CentOS 6 `audit.rules`) |
| `SEC-036` | `Ensure Auditd service is running and enabled (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 설치된 경우에만, 기동·부팅 활성 상태면 `ok` |
| `SEC-037` | `Probe iptables INPUT rules for allowed TCP ports (raw)` | `ansible.builtin.raw` | CentOS 6 (`_raw_path_effective`) | 조회 전용 (`iptables -S INPUT`), 응답 불가 시 fail |
| `SEC-038` | `Allow incoming TCP ports via iptables (raw)` | `ansible.builtin.raw` | CentOS 6 (`_raw_path_effective`) | probe에서 룰이 없을 때만 `iptables -I INPUT 1`, 이미 있으면 스킵(`ok`) |
| `SEC-039` | `Probe iptables INPUT rules for source-restricted ingress (raw)` | `ansible.builtin.raw` | CentOS 6 (`_raw_path_effective`) | 조회 전용 (`iptables -S INPUT`), 응답 불가 시 fail |
| `SEC-040` | `Allow source-restricted ingress via iptables (raw)` | `ansible.builtin.raw` | CentOS 6 (`_raw_path_effective`) | probe에서 룰이 없을 때만 삽입, 이미 있으면 스킵(`ok`) |
| `SEC-041` | `Configure SELinux in permissive mode (CentOS 7, raw)` | `ansible.builtin.raw` | CentOS 7 (`_raw_path_effective`) | config·실행 모드가 이미 같으면 `ok` (`/etc/selinux/config` 없으면 건너뜀) |
| `SEC-042` | `Ensure firewalld is installed (CentOS 7, raw)` | `ansible.builtin.raw` | CentOS 7 (`_raw_path_effective`) | 기설치 시 `ok` (`rpm -q` 확인 후에만 `yum install`) |
| `SEC-043` | `Ensure firewalld service is started and enabled (CentOS 7, raw)` | `ansible.builtin.raw` | CentOS 7 (`_raw_path_effective`) | 기동·부팅 활성 상태면 `ok` |
| `SEC-044` | `Detect default network interface (CentOS 7, raw)` | `ansible.builtin.raw` | CentOS 7 (`_raw_path_effective`) | 조회 전용 (`ip -4 route show default`, `changed_when: false`) |
| `SEC-045` | `Disable masquerade on all zones except external (CentOS 7, raw)` | `ansible.builtin.raw` | CentOS 7 (`_raw_path_effective`) | `external` 외 존에서 masquerade가 켜져 있을 때만 제거 후 `changed` |
| `SEC-046` | `Probe firewalld permanent rules (CentOS 7, raw)` | `ansible.builtin.raw` | CentOS 7 (`_raw_path_effective`) | 조회 전용 (`firewall-cmd --permanent --query-*` 종료코드), 응답 불가 시 fail |
| `SEC-047` | `Apply firewalld permanent rules only where they differ (CentOS 7, raw)` | `ansible.builtin.raw` | CentOS 7 (`_raw_path_effective`) | probe와 원하는 상태가 다를 때만 `--add-*`/`--remove-*` 후 `Reload firewalld`, 같으면 스킵(`ok`) |
| `SEC-048` | `Detect firewalld runtime drift from the rule plan (CentOS 7, raw)` | `ansible.builtin.raw` | CentOS 7 (`_raw_path_effective`) | 실행 중 방화벽이 규칙 계획과 같으면 `ok`, 다르면 `changed` 후 `Reload firewalld` |
| `SEC-049` | `Record detected default network interface (CentOS 7, raw)` | `ansible.builtin.set_fact` | CentOS 7 (`_raw_path_effective`) | 팩트 설정 전용 (`ansible_default_ipv4` 미정의 시에만) |
| `SEC-050` | `Build firewalld rule plan (CentOS 7, raw)` | `ansible.builtin.set_fact` | CentOS 7 (`_raw_path_effective`) | 팩트 설정 전용 (`raw_firewalld_plan`, 제거 규칙 우선 정렬) |
| `SEC-051` | `Apply firewall configuration tasks unless the host is in firewall_unmanaged` | `block` (`when: security_firewall_managed`) | All | 인벤토리 그룹 `firewall_unmanaged` 소속이면 UFW·firewalld·iptables·CentOS 6/7 raw 방화벽 태스크 전체를 건너뜀(`skipping`) |
| `SEC-052` | `Apply custom firewall ingress rules unless the host is in firewall_unmanaged` | `block` (`when: security_firewall_managed`) | All | 소스 IP 제한 인그레스 규칙(UFW·firewalld·iptables·raw iptables)도 같은 그룹이면 건너뜀 |
| `SEC-053` | `Create persistent journal directory and journald drop-in directory` | `ansible.builtin.file` | systemd 호스트 (`_raw_path_effective=false`) | 디렉터리·모드(`/var/log/journal` `2755`, `journald.conf.d` `0755`)·그룹(`/var/log/journal`은 `systemd-journal`이 있으면 `root:systemd-journal`, 없으면 `root:root`) 일치 시 `ok` |
| `SEC-054` | `Deploy journald persistent storage drop-in` | `ansible.builtin.template` | systemd 호스트 (`_raw_path_effective=false`) | Checksum 비교 (`journald-persistent.conf.j2`, `Storage=persistent`), 변경 시 `Restart systemd-journald` → `Restart rsyslog after journald` → `Restart fail2ban after journald`(둘 다 `systemctl try-restart`라 실행 중일 때만) → `Verify rsyslog still writes the auth log after journald restart`(rsyslog 실행 중이고 `/var/log/secure`가 있으면 시험 줄이 10초 안에 나타나는지 확인, #391) |
| `SEC-055` | `Check which audit_watch_paths exist` | `ansible.builtin.stat` | All (`_raw_path_effective=false`) | 조회 전용 (없는 시크릿 경로는 감사 규칙 적재를 실패시키므로 먼저 거른다) |
| `SEC-056` | `Keep only existing audit watch paths` | `ansible.builtin.set_fact` | All (`_raw_path_effective=false`) | 팩트 설정 전용 (`_audit_watch_paths_effective`) |
| `SEC-080` | `Look up the systemd-journal group` | `ansible.builtin.getent` | systemd 호스트 (`_raw_path_effective=false`) | 조회 전용 (`changed_when: false`, 그룹이 없어도 실패하지 않음. 결과는 `SEC-053`의 그룹 결정에 쓴다) |
| `SEC-081` | `Set auditd log rotation limits (max_log_file, num_logs)` | `ansible.builtin.lineinfile` | RedHat 계열 (`_raw_path_effective=false`) | `/etc/audit/auditd.conf` 두 줄(기본 `max_log_file = 50`, `num_logs = 10`, 변수 `audit_max_log_file`·`audit_num_logs`) 일치 시 `ok`, 변경 시 `Reload auditd`. 파일이 없는 호스트(audit 미설치)만 건너뜀 |
| `SEC-070` | `Validate the sshd source restriction list` | `ansible.builtin.assert` | All (`_raw_path_effective=false`) | 검사 전용 (`ssh_source_restriction_allowed_sources`가 IP/CIDR 목록인지) |
| `SEC-071` | `Apply the sshd Match Address source restriction block` | `ansible.builtin.blockinfile` | All (`_raw_path_effective=false`) | 마커 블록 일치 시 `ok` (`sshd -t` 검증, 변경 시 `Restart sshd`, 목록이 비면 블록 제거) |
| `SEC-072` | `Verify the connecting source is still allowed by sshd -T -C` | `ansible.builtin.command` | All (`_raw_path_effective=false`) | 조회 전용 (`changed_when: false`, 접속 중인 출발지가 막히면 실패) |
| `SEC-073` | `Remove the sshd source restriction block after a failed guard` | `ansible.builtin.blockinfile` | All (`_raw_path_effective=false`) | rescue 전용 (가드 실패 시 블록 제거, 이미 없으면 `ok`). Molecule은 컨테이너에 `SSH_CONNECTION`이 없어 가드를 건너뛰므로 pytest `tests/test_security_ssh_source.py`가 구조를 검증한다(`INTEGRATED`) |
| `SEC-074` | `Abort because the sshd source restriction would lock out this connection` | `ansible.builtin.fail` | All (`_raw_path_effective=false`) | rescue 전용 (롤백 뒤 중단). 검증은 `SEC-073`과 같다(pytest) |

> **Raw Provisioning Path (ADR-0005)**: CentOS 6/7 호스트는 `/etc/redhat-release` 자동 판별(`_raw_path_effective`, 인벤토리 `raw_provisioning_path`로 명시하면 그 값이 우선)에 따라 `SEC-001`/`SEC-001-DROPIN` 대신 `SEC-022`~`SEC-025`가, `SEC-009`/`SEC-010`/`SEC-012`/`SEC-013`/`SEC-014`/`SEC-015` 대신 `SEC-026`~`SEC-036`이 실행되고 (CentOS 7은 `SEC-011` 대신 `SEC-041`이 실행되고, CentOS 6는 `SEC-008`/`SEC-021` 대신 `SEC-037`~`SEC-040` iptables probe+mutate 쌍이 추가로 실행되며, CentOS 7은 firewalld 모듈/`firewall-cmd` 폴백 태스크(`SEC-005`~`SEC-007`, `SEC-016`/`SEC-017`/`SEC-020` 등) 대신 `SEC-042`~`SEC-050` firewalld probe+mutate 쌍(런타임 drift 감지 포함)이 실행된다(제거 규칙을 먼저 적용해 존 충돌을 피하고, 변경은 `permanent`에만 쓰고 raw `Reload firewalld` 핸들러로 반영). 룰 영속화(`service iptables save`)는 기존 모듈 경로와 같이 수행하지 않는다), `site.yml`은 `setup` 대신 raw로 OS 팩트를 확보한다. 헬퍼: `filter_plugins/raw_provisioning.py`. `--check`에서는 스킵된다.

> **방화벽 관리 제외 (`firewall_unmanaged`, #220)**: Semaphore 인벤토리에서 `servers`에 두면서 그룹 `firewall_unmanaged`에도 넣은 호스트는 `SEC-051`/`SEC-052` 게이트가 방화벽 태스크(UFW·firewalld·iptables, CentOS 7 raw 경로 포함)를 모두 건너뛴다. sshd·SELinux·fail2ban·auditd·sudo 정책은 그대로 적용한다. 기본값 `security_firewall_managed`는 그룹 소속에서 파생한다(Semaphore 인벤토리는 static이라 group_vars를 쓰지 않음). Host Audit 드리프트는 같은 인벤토리로 `site.yml`을 check 실행하므로 같은 규칙을 따른다. docker daemon이 관리하는 체인(`docker_iptables`)은 이 그룹과 무관하다. 프로비저닝 전에 `--check --diff`로 방화벽 태스크가 하나도 나오지 않는지 확인한다.

> **탐지 복구 (#372, Spec #364)**: 두 서버(방화벽 비관리 그룹)에서 방화벽을 건드리지 않고 탐지·감사·로그 보존만 적용한다.
> - **auditd**: `SEC-012`/`SEC-035` 규칙은 전체 `execve` 추적을 없애고 인증(`identity`, `auth_config`)·권한(`sudo_config`)·sshd 설정·컨테이너 설정(`container_config`, 기본 `/etc/docker/`, 호스트별 추가는 `audit_container_config_paths`)·시크릿 파일 접근(`secret_access`, `audit_watch_paths`)만 기록한다. 시크릿 경로 값은 저장소에 두지 않고 Semaphore Environment/인벤토리 변수로 받으며 `SEC-055`/`SEC-056`이 없는 경로를 걸러 규칙 적재 실패를 막는다. 규칙 잠금(`-e 2`)은 재부팅이 필요해 쓰지 않는다.
> - **auditd syscall 규칙 (#431, Spec #433 / Ticket-5)**: `SEC-012`/`SEC-035`의 규칙 파일(`audit.rules.j2` 6.)에 로그인 사용자만 기록하는 syscall 규칙 두 묶음이 있다. 아래 표가 규칙 ↔ 알림 ↔ 검증의 1:1 대응이다. 배포는 Host Provisioning 경로(`SEC-012`/`SEC-035`)로만 가므로 에이전트만 설치된 호스트의 감사 규칙은 그대로다. 규칙 적재 효과는 RHEL 계열 규칙 적재 버그(#424)가 고쳐진 뒤에 난다.
>
> | 묶음 | 규칙(b64·b32 모두) | 키 | 알림 | `verify.yml` 검증 |
> |---|---|---|---|---|
> | `/var/log` 삭제·이름 변경·자르기 | `-S unlink,unlinkat,rename,renameat,truncate,ftruncate,creat -F dir=/var/log` | `var_log_delete` | `infra-var-log-delete` (P1 Event) | 규칙 파일에 두 arch 줄이 있고, `auditctl -l`에 `-k var_log_delete`가 있다(규칙이 올라와 있을 때) |
> | 〃 (O_TRUNC 열기) | `-S open -F dir=/var/log -F a1&0x200`, `-S openat -F dir=/var/log -F a2&0x200` | `var_log_delete` | 〃 | 〃 |
> | 커널 모듈 적재·제거 | `-S init_module,finit_module,delete_module` (EL6는 커널에 없는 `finit_module` 제외) | `kernel_module` | `infra-kernel-module` (P2 Event) | 규칙 파일에 두 arch 줄이 있고, `auditctl -l`에 `-k kernel_module`이 있다(규칙이 올라와 있을 때) |
>
> 모든 줄은 `-F auid>=1000 -F auid!=4294967295`(`audit_login_uid_min`·`audit_auid_unset`)를 갖는다. `4294967295`는 audit.rules(7)의 `unset`과 같은 값이다. `unset` 별칭을 EL6·7 auditd(2.4·2.8)가 읽는지 확인하지 못해(문서는 최신 auditd 기준) 어느 버전에서나 읽히는 숫자로 썼다. 로그인 없이 시작한 서비스·logrotate는 auid가 이 값이라 규칙에 걸리지 않는다. 규칙은 `login_user_syscall_rule` 매크로 한 곳에서 만들고, 새 syscall 규칙(예: 증적 전용 키)은 이 매크로를 한 줄 더 부르면 된다. 알림이 읽는 키(`var_log_delete`·`kernel_module`)는 감시 키·증적 전용 키와 겹치지 않게 짓는다.
>
> **규칙 순서와 전제**: ① 커널은 첫 번째로 맞는 규칙의 키 하나만 기록한다(audit.rules(7)·auditctl(8): first match wins). 그래서 `-w /var/log/sudo.log … -k sudo_logs` 감시는 `var_log_delete` 규칙 **뒤**에 있다(앞이면 sudo 로그를 지운 기록이 `sudo_logs`로만 남아 P1이 울리지 않는다). `/var/log` 경로를 다루는 새 감시·증적 규칙(Ticket-8 등)도 6-1 뒤에 더하고, 렌더링 테스트가 이 순서를 지킨다. 1~5 감시는 6의 syscall 줄이 거부돼도 올라가도록 6보다 앞에 둔다. ② 로그인 사용자 기준은 `audit_login_uid_min`(기본 1000)이다. EL6의 `UID_MIN`은 500이라 EL6 호스트의 500~999 일반 계정은 걸리지 않는다(그 호스트는 변수를 500으로 둔다). ③ syscall 이름은 x86_64 기준이다. aarch64에는 `open`·`creat`·`unlink`·`rename`과 b32가 없어 auditctl이 규칙을 거부한다. 이 역할의 프로비저닝 대상은 x86_64라는 전제이고(인벤토리·역할에 aarch64 분기가 없다), arm64 호스트를 프로비저닝 대상에 넣으면 이 규칙을 아키텍처별로 나눠야 한다.
>
> **`/var/log` 규칙 문법의 근거 (카나리 실험 미실시)**: 인수 조건은 "`O_TRUNC` 열기를 넣을지를 카나리 실험으로 정한다"이지만 호스트 실험은 사용자 승인이 필요해 하지 못했다. 아래는 auditd 공식 문서(audit.rules(7)·auditctl(8))와 CIS 형태에서 정한 **설계이며 호스트에서 확인한 사실이 아니다**.
> - 경로 필터는 CIS가 쓰는 `-F path=`(파일 하나) 대신 `-F dir=/var/log`를 쓴다. auditctl(8)은 `-S openat,truncate -F dir=/etc`처럼 syscall 규칙에 디렉터리 필터를 붙이는 것을 "파일시스템 감사로 성능을 높이는 방법"으로 설명한다. 하위 전체를 보는 재귀 필터다.
> - `O_TRUNC` 열기를 **넣었다**. `> /var/log/secure`·`: > file`·`tee`(덧붙이지 않는 모드)는 `unlink`·`truncate` 없이 `open(O_TRUNC)`만 호출하므로, 넣지 않으면 가장 흔한 로그 비우기가 빠진다. 값 `0x200`은 리눅스 `O_TRUNC`(8진수 01000)이고 `open`은 flags가 a1, `openat`은 a2다. `&`(bit mask) 연산자는 auditctl(8)의 연산자 목록에 있다. 인자 필터가 붙은 열기 규칙은 O_TRUNC가 없는 열기(읽기·덧붙이기)를 걸러 소음을 막는다.
> - 알려진 한계: `openat2`는 flags가 구조체 안이라 거를 수 없고, `renameat2`는 `rename*` 목록에 없다(EL7 auditd가 이름을 모를 수 있어 CIS 목록을 따랐다). `ftruncate`가 파일 기술자로 부르는 경우 경로(PATH 기록)가 남는지는 커널 구현에 달려 있어 확인하지 못했다.
> - **카나리에서 확인할 것(미실시, Ticket-9·#436)**: ① `auditctl -R`로 규칙이 오류 없이 올라오는지(특히 `-F a1&0x200`, EL6의 `finit_module` 제외, EL6·7의 `auid!=4294967295`) ② 로그인 사용자의 `rm`·`> file`·`truncate -s0`가 각각 `var_log_delete` SYSCALL을 남기는지와 PATH 기록의 이름 ③ `tee`·`vim`·`logger` 등 정상 작업이 남기는 양(적용 1주 뒤 키별 증가량, #414 추정과 비교). 결과가 이 설계와 다르면 이 절과 `audit.rules.j2`를 고친다.
> - **fail2ban**: `SEC-015`/`SEC-032` jail은 `fail2ban_banaction`을 받는다. 기본값은 빈 값이라 배포판 기본 동작을 그대로 쓴다(방화벽 그룹과 무관). 이미 방화벽 연동 방식으로 차단 중인 호스트의 방어를 낮추지 않기 위해서다. `dummy`(방화벽을 건드리지 않고 탐지와 로그만 남김)는 운영자가 `fail2ban_banaction: dummy`로 명시할 때만 쓰며, 이때 네트워크 차단은 없고 실제 차단은 sshd 출발지 제한(#371)이 맡는다. 이 역할이 방화벽 체인·규칙을 직접 만들거나 바꾸지 않는 원칙(`SEC-051`)과 fail2ban 데몬이 런타임에 자체 규칙을 넣고 빼는 것은 다른 문제다. 전자는 Ansible 태스크의 원칙이고 후자는 배포판 기본 banaction이 하는 정상 동작이라, `dummy`를 쓰지 않아도 역할이 체인을 조작하는 것은 아니다. 절차와 한계는 `docs/runbooks/detection-recovery.md`.
> - **journald**: `SEC-053`/`SEC-054`가 `Storage=persistent`를 켜 재부팅 뒤에도 이전 부팅의 시스템 로그가 남는다. 용량·보존 한도는 `common`의 `COMMON-017`(`journald_max_use`, `journald_max_retention`)이 정한다. `/var/log/journal`의 그룹은 `SEC-080`이 `systemd-journal` 존재를 확인해 시스템 기본(`root:systemd-journal`)에 맞추고 그룹이 없는 환경은 `root`로 둔다. CentOS 6/7 raw 경로는 대상이 아니다.
> - **auditd 로테이션**: `SEC-081`이 `auditd.conf`의 `max_log_file`(MB)·`num_logs`를 변수 `audit_max_log_file`(기본 50)·`audit_num_logs`(기본 10)로 맞춰 감사 로그 디스크 상한을 둔다. 반영은 reload(HUP)다.
> - **중앙 수집·적용 절차**: [docs/runbooks/detection-recovery.md](runbooks/detection-recovery.md).

> **sshd 출발지 제한 (#371, Spec #364)**: 방화벽 체인을 건드리지 않고 sshd `Match Address` 블록(`DenyUsers *`)으로 허용 출발지 밖의 로그인을 거부한다(`SEC-070`~`SEC-074`). 허용 목록은 변수 `ssh_source_restriction_allowed_sources`(IP/CIDR 목록, 기본 빈 목록 = 제한 없음)로 받고 값은 저장소에 두지 않는다. 루프백은 항상 허용한다. 기존 `ssh_allowed_source_ips`는 방화벽 규칙(`SEC-019` 등)용이라 `firewall_unmanaged` 호스트에는 적용되지 않으며, 이 변수는 그것을 대체하지 않고 방화벽 밖 수단으로 따로 둔다(두 변수를 함께 정의해도 서로 읽지 않는다). `SEC-072` 가드는 Ansible이 접속한 출발지(`SSH_CONNECTION`)가 `sshd -T -C`로 막히면 `SEC-073`이 블록을 되돌리고 `SEC-074`가 중단해 스스로 잠기지 않게 한다. CentOS 6/7 raw 경로는 대상이 아니다. 적용 절차(별도 세션, 임시→영구, 롤백): [docs/runbooks/ssh-source-restriction.md](runbooks/ssh-source-restriction.md).
