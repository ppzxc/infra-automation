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
| `SEC-012` | `Deploy Auditd security audit rules` | `ansible.builtin.template` | RHEL / Rocky (`_raw_path_effective=false`) | Checksum 비교 (`audit.rules.j2`). 규칙 디렉터리가 없는(audit 미설치) 호스트만 건너뛰고 그 밖의 실패는 드러낸다. 바뀌면 `Restart auditd` 핸들러(`augenrules --load`, #424)를 부른다 |
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
| `SEC-082` | `Check which audit watch key paths exist` | `ansible.builtin.stat` | RedHat 계열 (`_raw_path_effective=false`) | 조회 전용 (후보 경로 `audit_watch_key_paths`를 모두 조회, `~계정`은 stat이 그 계정의 홈으로 바꾼다. 없는 경로에 watch를 걸면 규칙 적재가 실패하므로 먼저 거른다) |
| `SEC-083` | `Keep only existing audit watch key paths` | `ansible.builtin.set_fact` | RedHat 계열 (`_raw_path_effective=false`) | 팩트 설정 전용 (`_audit_watch_key_paths_effective`: 있는 경로만 `{key, path}`로, 홈은 stat이 돌려준 실제 경로) |
| `SEC-084` | `Probe which audit watch key paths exist (raw, read-only)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 조회 전용 (`changed_when: false`, `--check`에서도 실행. 고정 경로는 `[ -e ]`, 계정은 `getent passwd`의 홈에서 `.ssh/authorized_keys`를 확인) |
| `SEC-085` | `Keep only existing audit watch key paths (raw)` | `ansible.builtin.set_fact` | CentOS 6/7 (`_raw_path_effective`) | 팩트 설정 전용 (`SEC-083`과 같은 `_audit_watch_key_paths_effective`) |
| `SEC-080` | `Look up the systemd-journal group` | `ansible.builtin.getent` | systemd 호스트 (`_raw_path_effective=false`) | 조회 전용 (`changed_when: false`, 그룹이 없어도 실패하지 않음. 결과는 `SEC-053`의 그룹 결정에 쓴다) |
| `SEC-081` | `Set auditd log rotation limits (max_log_file, num_logs)` | `ansible.builtin.lineinfile` | RedHat 계열 (`_raw_path_effective=false`) | `/etc/audit/auditd.conf` 두 줄(기본 `max_log_file = 50`, `num_logs = 10`, 변수 `audit_max_log_file`·`audit_num_logs`) 일치 시 `ok`, 변경 시 `Reload auditd`. 파일이 없는 호스트(audit 미설치)만 건너뜀 |
| `SEC-082` | `Check whether the audit tools are installed (read-only)` | `ansible.builtin.shell` | RedHat 계열 (`_raw_path_effective=false`) | 조회 전용 (`command -v auditctl && command -v augenrules`, `changed_when: false`, `failed_when: false`, `check_mode: false`). audit 도구가 없는 호스트는 적재 단계(`SEC-083`과 `Restart auditd` 핸들러)를 건너뛴다. Molecule은 이미지에 audit이 없어 이 건너뜀을 `VERIFY-SEC-082`가 확인한다 |
| `SEC-083` | `Compare the loaded audit rules with the declared rules (read-only)` | `ansible.builtin.shell` | RedHat 계열 (`_raw_path_effective=false`) | 조회 전용 (`auditctl -l`과 이 역할 밖 `rules.d/*.rules` 내용을 읽는 스크립트 `security_audit_loaded_probe_cmd`, `check_mode: false`). 적재된 규칙이 렌더링한 `audit.rules.j2`와 다르면 `changed`이고 `Restart auditd`를 부른다. 불일치로 실패하지 않는다(--check Drift 판정이 막히지 않게). 필터 `audit_rules_probe_drift`(`filter_plugins/audit_rules.py`). 적용 실행의 판정·실패는 핸들러가, --check의 Drift 표시는 이 태스크가 맡는다 |
| `SEC-070` | `Validate the sshd source restriction list` | `ansible.builtin.assert` | All (`_raw_path_effective=false`) | 검사 전용 (`ssh_source_restriction_allowed_sources`가 IP/CIDR 목록인지) |
| `SEC-071` | `Apply the sshd Match Address source restriction block` | `ansible.builtin.blockinfile` | All (`_raw_path_effective=false`) | 마커 블록 일치 시 `ok` (`sshd -t` 검증, 변경 시 `Restart sshd`, 목록이 비면 블록 제거) |
| `SEC-072` | `Verify the connecting source is still allowed by sshd -T -C` | `ansible.builtin.command` | All (`_raw_path_effective=false`) | 조회 전용 (`changed_when: false`, 접속 중인 출발지가 막히면 실패) |
| `SEC-073` | `Remove the sshd source restriction block after a failed guard` | `ansible.builtin.blockinfile` | All (`_raw_path_effective=false`) | rescue 전용 (가드 실패 시 블록 제거, 이미 없으면 `ok`). Molecule은 컨테이너에 `SSH_CONNECTION`이 없어 가드를 건너뛰므로 pytest `tests/test_security_ssh_source.py`가 구조를 검증한다(`INTEGRATED`) |
| `SEC-074` | `Abort because the sshd source restriction would lock out this connection` | `ansible.builtin.fail` | All (`_raw_path_effective=false`) | rescue 전용 (롤백 뒤 중단). 검증은 `SEC-073`과 같다(pytest) |

> **Raw Provisioning Path (ADR-0005)**: CentOS 6/7 호스트는 `/etc/redhat-release` 자동 판별(`_raw_path_effective`, 인벤토리 `raw_provisioning_path`로 명시하면 그 값이 우선)에 따라 `SEC-001`/`SEC-001-DROPIN` 대신 `SEC-022`~`SEC-025`가, `SEC-009`/`SEC-010`/`SEC-012`/`SEC-013`/`SEC-014`/`SEC-015` 대신 `SEC-026`~`SEC-036`이 실행되고 (CentOS 7은 `SEC-011` 대신 `SEC-041`이 실행되고, CentOS 6는 `SEC-008`/`SEC-021` 대신 `SEC-037`~`SEC-040` iptables probe+mutate 쌍이 추가로 실행되며, CentOS 7은 firewalld 모듈/`firewall-cmd` 폴백 태스크(`SEC-005`~`SEC-007`, `SEC-016`/`SEC-017`/`SEC-020` 등) 대신 `SEC-042`~`SEC-050` firewalld probe+mutate 쌍(런타임 drift 감지 포함)이 실행된다(제거 규칙을 먼저 적용해 존 충돌을 피하고, 변경은 `permanent`에만 쓰고 raw `Reload firewalld` 핸들러로 반영). 룰 영속화(`service iptables save`)는 기존 모듈 경로와 같이 수행하지 않는다), `site.yml`은 `setup` 대신 raw로 OS 팩트를 확보한다. 헬퍼: `filter_plugins/raw_provisioning.py`. `--check`에서는 스킵된다.

> **방화벽 관리 제외 (`firewall_unmanaged`, #220)**: Semaphore 인벤토리에서 `servers`에 두면서 그룹 `firewall_unmanaged`에도 넣은 호스트는 `SEC-051`/`SEC-052` 게이트가 방화벽 태스크(UFW·firewalld·iptables, CentOS 7 raw 경로 포함)를 모두 건너뛴다. sshd·SELinux·fail2ban·auditd·sudo 정책은 그대로 적용한다. 기본값 `security_firewall_managed`는 그룹 소속에서 파생한다(Semaphore 인벤토리는 static이라 group_vars를 쓰지 않음). Host Audit 드리프트는 같은 인벤토리로 `site.yml`을 check 실행하므로 같은 규칙을 따른다. docker daemon이 관리하는 체인(`docker_iptables`)은 이 그룹과 무관하다. 프로비저닝 전에 `--check --diff`로 방화벽 태스크가 하나도 나오지 않는지 확인한다.

> **탐지 복구 (#372, Spec #364)**: 두 서버(방화벽 비관리 그룹)에서 방화벽을 건드리지 않고 탐지·감사·로그 보존만 적용한다.
> - **auditd**: `SEC-012`/`SEC-035` 규칙은 전체 `execve` 추적을 없애고 인증(`identity`, `auth_config`)·권한(`sudo_config`)·sshd 설정·컨테이너 설정(`container_config`, 기본 `/etc/docker/`, 호스트별 추가는 `audit_container_config_paths`)·시크릿 파일 접근(`secret_access`, `audit_watch_paths`)만 기록한다. 시크릿 경로 값은 저장소에 두지 않고 Semaphore Environment/인벤토리 변수로 받으며 `SEC-055`/`SEC-056`이 없는 경로를 걸러 규칙 적재 실패를 막는다. 규칙 잠금(`-e 2`)은 재부팅이 필요해 쓰지 않는다.
> - **fail2ban**: `SEC-015`/`SEC-032` jail은 `fail2ban_banaction`을 받는다. 기본값은 빈 값이라 배포판 기본 동작을 그대로 쓴다(방화벽 그룹과 무관). 이미 방화벽 연동 방식으로 차단 중인 호스트의 방어를 낮추지 않기 위해서다. `dummy`(방화벽을 건드리지 않고 탐지와 로그만 남김)는 운영자가 `fail2ban_banaction: dummy`로 명시할 때만 쓰며, 이때 네트워크 차단은 없고 실제 차단은 sshd 출발지 제한(#371)이 맡는다. 이 역할이 방화벽 체인·규칙을 직접 만들거나 바꾸지 않는 원칙(`SEC-051`)과 fail2ban 데몬이 런타임에 자체 규칙을 넣고 빼는 것은 다른 문제다. 전자는 Ansible 태스크의 원칙이고 후자는 배포판 기본 banaction이 하는 정상 동작이라, `dummy`를 쓰지 않아도 역할이 체인을 조작하는 것은 아니다. 절차와 한계는 `docs/runbooks/detection-recovery.md`.
> - **journald**: `SEC-053`/`SEC-054`가 `Storage=persistent`를 켜 재부팅 뒤에도 이전 부팅의 시스템 로그가 남는다. 용량·보존 한도는 `common`의 `COMMON-017`(`journald_max_use`, `journald_max_retention`)이 정한다. `/var/log/journal`의 그룹은 `SEC-080`이 `systemd-journal` 존재를 확인해 시스템 기본(`root:systemd-journal`)에 맞추고 그룹이 없는 환경은 `root`로 둔다. CentOS 6/7 raw 경로는 대상이 아니다.
> - **Audit Watch Key 4개 (Spec #433 / Ticket-4, #430)**: `SEC-012`/`SEC-035`가 배포하는 규칙 파일의 6번 구역이 감시 키 4개를 더한다. 용어는 `CONTEXT.md`의 Audit Watch Key. 알림은 기존 감시 키 변경 알림(`infra-audit-watch-change`, P2 Event)이 읽는다(키 목록 `o2c_audit_watch_keys`, 정상 변경 구분과 한계는 `docs/openobserve_config.md`).
>   | 감시 키 | 경로(역할 기본 변수) | 의미 |
>   |---|---|---|
>   | `audit_config` | `/etc/audit/` (`audit_config_watch_paths`) | auditd 설정·감사 규칙 파일이 바뀜(로그를 끄거나 돌리는 은폐 시도) |
>   | `syslog_config` | `/etc/rsyslog.conf`, `/etc/rsyslog.d/` (`audit_syslog_watch_paths`) | syslog 설정이 바뀜(로그 은폐) |
>   | `ssh_keys` | root와 `audit_ssh_key_accounts` 계정 홈의 `.ssh/authorized_keys` | 백도어 키 심기 |
>   | `firewall_config` | `/etc/firewalld/` (`audit_firewall_watch_paths`) | 방화벽 영구 설정이 바뀜 |
>
>   모두 `-p wa`(변경·속성)다. 읽기(`r`)는 sshd가 늘 하므로 보지 않는다. `SEC-082`~`SEC-085`가 실제로 있는 경로만 규칙에 싣고, 하나도 없거나 탐지가 건너뛰어진 호스트는 6번 구역이 비어 규칙 적재가 깨지지 않는다(예: firewalld가 없는 호스트). 계정 목록 `audit_ssh_key_accounts`는 비어 있어도 root는 늘 감시한다. 홈 디렉터리는 `/home/<이름>`으로 가정하지 않고 시스템(`~계정` 확장, raw는 `getent passwd`)이 알려준 값을 쓰며, 시스템에 없는 계정은 건너뛴다.
>   - **`authorized_keys` 감시 방식 결정(존재하는 파일만 감시)**: `.ssh/` 디렉터리 감시와 존재하는 파일만 감시 중에서 후자를 골랐다. 근거는 문서·설계상의 추론이다. (1) 디렉터리 감시는 `known_hosts`·개인 키 갱신 같은 같은 디렉터리의 다른 파일 변경도 같은 감시 키로 남기는데, 감사 기록의 SYSCALL 줄에는 파일 이름이 없어(이름은 별도 `PATH` 줄에만 있다) 알림이 둘을 구분할 수 없다. 그래서 운영자가 `ssh`를 쓸 때마다 P2 알림이 울릴 수 있다. (2) 파일 감시는 부모 디렉터리 안의 이름을 따라가므로 편집기·Ansible처럼 임시 파일을 만들어 이름을 바꿔 덮는 변경도 같은 감시가 이어서 본다(커널 감사 감시가 부모 디렉터리와 이름을 따라가는 설계라는 문서상의 근거이며 실험 ②로 확인해야 한다). (3) 없는 파일에 감시를 걸 수 있는지는 확인하지 못했으므로 기대지 않고, 존재하는 파일만 렌더링해 규칙 적재 실패를 피한다. **한계(받아들임)**: 감시 규칙을 적용한 뒤에 새로 생긴 `authorized_keys`(해당 계정에 파일이 없었던 경우)는 다음 프로비저닝 때 후보에 들어오기 전까지 감시되지 않는다. `.ssh/`가 없는 계정도 마찬가지다.
>   - **카나리 실험 미실시, 확인 필요(호스트 실험은 사용자 승인이 필요해 하지 않았다)**: 위 결정은 다음을 실험으로 확인하지 않은 추론이다. 카나리 한 대에서 확인한다(티켓 #436의 서버 적용 단계 포함). ① **삭제가 기록되는가**: `authorized_keys`를 지우고 `ausearch -k ssh_keys`에 `nametype=DELETE` 기록과 `syscall=unlink` SYSCALL이 남는지, 지운 뒤 같은 이름으로 다시 만들면 감시가 이어지는지. ② **임시 파일을 만든 뒤 이름을 바꿔 덮는 변경(Ansible `authorized_key`, 편집기)이 기록되는가**. ③ **없는 파일에 `-w`를 걸면 적재가 실패하는가**(실패하면 지금 방식이 필수이고, 성공하면 파일 생성 감시까지 넓힐 수 있다). ④ **디렉터리 감시의 잡음량**(`known_hosts` 갱신 빈도)과 키별 하루 증가량. ⑤ `auditctl -l`에서 4개 키가 모두 적재되는가(컨테이너 Molecule은 규칙을 적재할 수 없어 파일 내용만 검증한다). 결과가 위 추론과 다르면 이 항목과 `SEC-082`~`SEC-085`를 고친다.
>   - 방화벽은 영구 설정만 감시한다. `--permanent` 없이 바꾼 런타임 규칙은 놓친다(받아들인 한계). 에이전트만 설치된 호스트는 `security` 역할을 쓰지 않으므로(Host Agents 전용 playbook과 `provision_excluded` 사전 검증) 이 규칙은 들어가지 않는다. 규칙 적재 자체가 되려면 #424가 먼저 반영돼야 한다.
> - **auditd 로테이션**: `SEC-081`이 `auditd.conf`의 `max_log_file`(MB)·`num_logs`를 변수 `audit_max_log_file`(기본 50)·`audit_num_logs`(기본 10)로 맞춰 감사 로그 디스크 상한을 둔다. 반영은 reload(HUP)다.
> - **auditd 규칙 적재 (#424)**: 규칙 파일(`SEC-012`)이 바뀌어도 커널에 적재된 규칙은 그대로이던 결함을 고쳤다. RHEL 계열 systemd의 auditd 유닛은 `RefuseManualStop=yes`라 `ansible.builtin.service: state=restarted`를 거부하는데, 옛 `Restart auditd` 핸들러는 `failed_when: false`로 그 거부를 가려 재부팅 전까지 새 규칙이 들어가지 않았다(#372 이전의 `execve` 전수 규칙이 남은 호스트가 있었다).
>   - **방식**: 핸들러 `Restart auditd`(이름은 다른 태스크의 notify 때문에 유지)가 `augenrules --load`로 `/etc/audit/rules.d/*.rules`를 합쳐 서비스 재시작 없이 적재한다. 근거(Context7로 읽은 audit-userspace 문서, 2026-11-04): (1) `README`가 유닛의 `RefuseManualStop=yes`를 명시한다(서비스 재시작 거부). (2) `augenrules(8)`의 `--load`는 "load old or newly built rules into the kernel"이라 이미 합쳐 둔 옛 규칙도 다시 적재한다(파일 변경 여부와 무관하게 적재된다). (3) auditd는 멈추지 않으므로 적재 중 감사 이벤트 공백이 없다. (4) 규칙을 바꾼 뒤 `augenrules --load`로 적재하는 것이 이 프로젝트의 수동 런북([detection-recovery.md](runbooks/detection-recovery.md) 8절)이다. `augenrules --load`의 종료 코드 의미는 문서에 없고(`auditctl -c` 설명에는 규칙 하나가 실패하면 종료 코드가 성공이 아니라고 한다), 이 저장소를 만든 머신에는 auditd가 없어 실행해 보지 못했다. 그래서 종료 코드만 믿지 않고 적재 뒤 `auditctl -l`을 다시 읽어 비교하는 핸들러를 이어 둔다(적재가 0으로 끝나도 낡은 규칙이 남으면 플레이가 실패한다). 규칙 잠금(`-e 2`)이 걸려 있으면 적재가 거부될 것으로 보고 이 확인이 실패로 드러내게 했다(재부팅 필요). 이 동작은 실측하지 않았다(아래 '미실측 한계'). `service auditd restart` 래퍼를 택하지 않은 이유: 적재 실패가 종료 코드로 드러나지 않을 수 있다고 알려져 있어(유닛의 `ExecStartPost`가 실패를 무시하는 배포판이 있다) 호스트에서 확인하기 전에는 쓰지 않는다. 호스트 실측은 미실시(승인 필요).
  - **트리거**: 파일이 바뀔 때(`SEC-012`)뿐 아니라, 파일은 최신인데 적재 상태만 낡은 호스트를 위해 `SEC-083`이 `auditctl -l`과 렌더링한 규칙을 비교해 다르면 같은 핸들러를 부른다. 그래서 고친 역할로 다시 프로비저닝하면 파일 갱신과 적재가 함께 일어난다. audit 도구가 없는 호스트(`SEC-082`)만 건너뛰고, 적재 실패와 적재 뒤 불일치는 플레이 실패다.
>   - **적재 drift(수용 기준 3)는 프로비저닝 검증과 Host Audit Configuration Drift 두 곳에서 드러낸다**: 적용 실행에서는 위 핸들러의 재확인이 실패로, `--check --diff` Drift 하위 실행에서는 `SEC-083`이 `changed` 태스크 행으로 나온다(`docs/host_audit.md`). 별도의 Host Audit 항목은 만들지 않았다: 선언 호스트의 감사 규칙 키 점검(`EXP-DET-4`~`EXP-DET-6`)이 이미 있고, Drift 경로는 `site.yml`과 같은 선언을 쓰므로 새 수집 구조 없이 같은 표에 오른다.
>   - **비교 기준(근사)**: `auditctl -l`은 문자열이 그대로 같지 않다. watch는 (경로, 권한, 키)로, 그 밖의 규칙은 키로만 비교한다(`-w`/`-F path=`/`-F dir=` 표기 차이와 디렉터리 끝 `/`는 같게 본다). 시스템 호출 목록·arch는 비교하지 않는다(정규화 표기 차이로 매번 오탐이 나기 쉬워서다). 규칙 파일의 `-b`·`-f` 같은 제어 줄도 보지 않는다. 같은 키의 다른 syscall로 바뀐 경우는 못 잡는다. `augenrules`는 `rules.d/*.rules`를 모두 합쳐 적재하므로(`augenrules(8)`), 이 역할의 `overseer.rules` 밖 `.rules` 파일(하드닝 프로파일, 수동 파일)의 규칙은 선언으로 함께 본다. 안 그러면 그런 호스트는 정상인데도 매 실행 drift·재적재·확인 실패가 반복된다.
  - **미실측 한계**: (1) 잠금(`-e 2`) 상태에서 `augenrules --load`가 어떻게 끝나는지, 그때 `auditctl -l`이 무엇을 보여 주는지 실측하지 않았다. 어느 쪽이든 적재 뒤 확인이 선언과 다르면 실패하므로 낡은 규칙이 남은 채 성공으로 끝나지는 않지만, 실패 메시지의 원인 추정(재부팅 필요)은 틀릴 수 있다. (2) Molecule `VERIFY-SEC-083`은 `auditctl`이 없는 이미지(rc 127)에서는 통과로 건너뛴다. 컨테이너에서는 규칙 적재를 재현할 수 없어 적재 결과 자체는 pytest(`tests/test_security_audit_reload.py`, 가짜 `auditctl`/`augenrules`)만 검증한다. (3) 적재 실패 메시지에는 watch 경로를 싣지 않고 건수와 키 이름만 싣는다(시크릿 파일 경로가 실행 로그에 남지 않게). 어떤 경로가 어긋났는지는 호스트에서 `auditctl -l`로 본다.
  - **범위 밖**: 비 raw 경로인데 주 버전이 7 미만이면(규칙 경로가 `audit.rules`) `augenrules`가 없어 `SEC-082`가 적재 단계를 건너뛴다. CentOS 6/7 raw 경로(`SEC-035`)는 기존 `service auditd restart`(raw 핸들러)를 그대로 쓰며 적재 확인과 Drift 점검이 없다(raw 태스크는 `--check`에서 스킵, ADR-0005). 로테이션 `Reload auditd`(`SEC-081`)의 `failed_when: false`도 이번 범위가 아니다.
> - **중앙 수집·적용 절차**: [docs/runbooks/detection-recovery.md](runbooks/detection-recovery.md).

> **sshd 출발지 제한 (#371, Spec #364)**: 방화벽 체인을 건드리지 않고 sshd `Match Address` 블록(`DenyUsers *`)으로 허용 출발지 밖의 로그인을 거부한다(`SEC-070`~`SEC-074`). 허용 목록은 변수 `ssh_source_restriction_allowed_sources`(IP/CIDR 목록, 기본 빈 목록 = 제한 없음)로 받고 값은 저장소에 두지 않는다. 루프백은 항상 허용한다. 기존 `ssh_allowed_source_ips`는 방화벽 규칙(`SEC-019` 등)용이라 `firewall_unmanaged` 호스트에는 적용되지 않으며, 이 변수는 그것을 대체하지 않고 방화벽 밖 수단으로 따로 둔다(두 변수를 함께 정의해도 서로 읽지 않는다). `SEC-072` 가드는 Ansible이 접속한 출발지(`SSH_CONNECTION`)가 `sshd -T -C`로 막히면 `SEC-073`이 블록을 되돌리고 `SEC-074`가 중단해 스스로 잠기지 않게 한다. CentOS 6/7 raw 경로는 대상이 아니다. 적용 절차(별도 세션, 임시→영구, 롤백): [docs/runbooks/ssh-source-restriction.md](runbooks/ssh-source-restriction.md).
