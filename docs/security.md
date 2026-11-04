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
| `SEC-080` | `Look up the systemd-journal group` | `ansible.builtin.getent` | systemd 호스트 (`_raw_path_effective=false`) | 조회 전용 (`changed_when: false`, 그룹이 없어도 실패하지 않음. 결과는 `SEC-053`의 그룹 결정에 쓴다) |
| `SEC-081` | `Set auditd log rotation limits (max_log_file, num_logs)` | `ansible.builtin.lineinfile` | RedHat 계열 (`_raw_path_effective=false`) | `/etc/audit/auditd.conf` 두 줄(기본 `max_log_file = 50`, `num_logs = 10`, 변수 `audit_max_log_file`·`audit_num_logs`) 일치 시 `ok`, 변경 시 `Reload auditd`. 파일이 없는 호스트(audit 미설치)만 건너뜀 |
| `SEC-082` | `Check whether the audit tools are installed (read-only)` | `ansible.builtin.shell` | RedHat 계열 (`_raw_path_effective=false`) | 조회 전용 (`command -v auditctl && command -v augenrules`, `changed_when: false`, `failed_when: false`, `check_mode: false`). audit 도구가 없는 호스트는 적재 단계(`SEC-083`과 `Restart auditd` 핸들러)를 건너뛴다. Molecule은 이미지에 audit이 없어 이 건너뜀을 `VERIFY-SEC-082`가 확인한다 |
| `SEC-083` | `Compare the loaded audit rules with the declared rules (read-only)` | `ansible.builtin.shell` | RedHat 계열 (`_raw_path_effective=false`) | 조회 전용 (`auditctl -l`과 이 역할 밖 `rules.d/*.rules` 내용을 읽는 스크립트 `security_audit_loaded_probe_cmd`, `check_mode: false`). 적재된 규칙이 렌더링한 `audit.rules.j2`와 다르면 `changed`이고 `Restart auditd`를 부른다. 불일치로 실패하지 않는다(--check Drift 판정이 막히지 않게). 필터 `audit_rules_probe_drift`(`filter_plugins/audit_rules.py`). 적용 실행의 판정·실패는 핸들러가, --check의 Drift 표시는 이 태스크가 맡는다 |
| `SEC-100` | `Check which audit_evidence_watch_paths exist` | `ansible.builtin.stat` | All (`_raw_path_effective=false`) | 조회 전용 (Evidence-Only Watch Key의 감시 경로 `audit_evidence_watch_paths`(로그인 기록 파일·`/etc/localtime`) 중 없는 경로는 `-w`가 규칙 적재를 실패시킬 수 있어 먼저 거른다, #435) |
| `SEC-101` | `Keep only existing evidence watch paths` | `ansible.builtin.set_fact` | All (`_raw_path_effective=false`) | 팩트 설정 전용 (`_audit_evidence_watch_paths_effective`, 렌더링 테스트가 있는 경로만 `-w`로 나오는지 본다) |
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
> **순서의 트레이드오프(sudo_logs)**: `sudo_logs` 감시를 6. 뒤로 옮긴 대가로, 6의 syscall 줄 하나라도 `auditctl -R`에서 거부되면(문법·syscall 이름 오류) 그 뒤에 있는 `sudo_logs` 감시도 함께 적재되지 않는다. 1~5 감시는 앞에 있어 영향이 없다. 적재 실패는 #424의 적재 확인(`SEC-082`·`SEC-083`과 핸들러)이 드러내지만 `sudo_logs`만 빠진 상태는 키 이름을 봐야 알 수 있어, 카나리(#436)에서 `sudo_logs` 적재 여부를 확인한다.
>
> **`/var/log` 규칙 문법의 근거 (카나리 실험 미실시)**: 인수 조건은 "`O_TRUNC` 열기를 넣을지를 카나리 실험으로 정한다"이지만 호스트 실험은 사용자 승인이 필요해 하지 못했다. 아래는 auditd 공식 문서(audit.rules(7)·auditctl(8))와 CIS 형태에서 정한 **설계이며 호스트에서 확인한 사실이 아니다**.
> - 경로 필터는 CIS가 쓰는 `-F path=`(파일 하나) 대신 `-F dir=/var/log`를 쓴다. auditctl(8)은 `-S openat,truncate -F dir=/etc`처럼 syscall 규칙에 디렉터리 필터를 붙이는 것을 "파일시스템 감사로 성능을 높이는 방법"으로 설명한다. 하위 전체를 보는 재귀 필터다.
> - `O_TRUNC` 열기를 **넣었다**. `> /var/log/secure`·`: > file`·`tee`(덧붙이지 않는 모드)는 `unlink`·`truncate` 없이 `open(O_TRUNC)`만 호출하므로, 넣지 않으면 가장 흔한 로그 비우기가 빠진다. 값 `0x200`은 리눅스 `O_TRUNC`(8진수 01000)이고 `open`은 flags가 a1, `openat`은 a2다. `&`(bit mask) 연산자는 auditctl(8)의 연산자 목록에 있다. 인자 필터가 붙은 열기 규칙은 O_TRUNC가 없는 열기(읽기·덧붙이기)를 걸러 소음을 막는다.
> - 알려진 한계: `openat2`는 flags가 구조체 안이라 거를 수 없고, `renameat2`는 `rename*` 목록에 없다(EL7 auditd가 이름을 모를 수 있어 CIS 목록을 따랐다). `ftruncate`가 파일 기술자로 부르는 경우 경로(PATH 기록)가 남는지는 커널 구현에 달려 있어 확인하지 못했다.
> - **카나리에서 확인할 것(미실시, Ticket-9·#436)**: ① `auditctl -R`로 규칙이 오류 없이 올라오는지(특히 `-F a1&0x200`, EL6의 `finit_module` 제외, EL6·7의 `auid!=4294967295`) ② 로그인 사용자의 `rm`·`> file`·`truncate -s0`가 각각 `var_log_delete` SYSCALL을 남기는지와 PATH 기록의 이름 ③ `tee`·`vim`·`logger` 등 정상 작업이 남기는 양(적용 1주 뒤 키별 증가량, #414 추정과 비교). ④ **sudo_logs 적재 여부**(`auditctl -l`에 `sudo_logs`가 있는지, 위 순서 트레이드오프) ⑤ **EL6 init 스크립트 데몬의 auid 상속 오탐**: EL6에서 로그인한 사용자가 init 스크립트로 띄운 데몬은 그 사용자의 auid를 물려받아 `/var/log`를 `O_TRUNC`로 열면 로그인 사용자의 작업으로 기록돼 `var_log_delete`가 오탐할 수 있다(한계, 실측 전 가정). 작업자는 사람인데 도구가 데몬인 기록이 나오는지 본다 ⑥ `ftruncate`가 PATH 기록 없이 `dir=` 필터에 걸리지 않을 가능성(위 한계)이 실제로 나타나는지. 결과가 이 설계와 다르면 이 절과 `audit.rules.j2`를 고친다.
> - **Evidence-Only Watch Key (#435, Spec #433 / Ticket-8)**: `SEC-012`/`SEC-035`의 규칙 파일(`audit.rules.j2` 8.)에 알림 없이 사후 조사와 ISMS 증적으로만 남는 기록 다섯 묶음이 있다. 정상 작업에서도 늘 생기는 기록이라 알림을 붙이면 소음뿐이다(CONTEXT.md의 **Evidence-Only Watch Key**). 키는 모두 `evidence_` 접두어라 이름만 보고 알림이 없는 키임을 알 수 있고, 어떤 알림 정의·키 목록에도 넣지 않는다(렌더링 테스트가 알림 정의에 `evidence_`가 없음과 이 키 기록이 어떤 알림도 울리지 않음을 합성 행으로 고정한다). 알림을 붙이는 것은 수정이 아니라 새 결정이다. 배포는 Host Provisioning 경로(`SEC-012`/`SEC-035`)로만 가므로 에이전트만 설치된 호스트의 감사 규칙은 그대로다.
>
> | 묶음 | 규칙 | 키 | 알림 | `verify.yml` 검증 |
> |---|---|---|---|---|
> | 특권 명령 실행(setuid·setgid) | `-S execve -C uid!=euid`, `-S execve -C gid!=egid` (b64·b32, 로그인 사용자만) | `evidence_privileged_exec` | 알림 없음, 증적 전용 | 규칙 파일에 두 arch·두 비교 줄이 있고 `auditctl -l`에 키가 있다(규칙이 올라와 있을 때) |
> | 로그인 사용자의 파일 삭제 | `-S unlink,unlinkat,rename,renameat` (b64·b32, 로그인 사용자만, 경로 필터 없음) | `evidence_file_delete` | 알림 없음, 증적 전용 | 〃 |
> | 로그인 기록 파일 | `-w /var/log/wtmp`, `/var/log/btmp`, `/var/run/utmp`, `/var/log/lastlog` (`-p wa`, 있는 경로만) | `evidence_login_records` | 알림 없음, 증적 전용 | 있는 경로는 규칙 파일에 있고 없는 경로는 없다(`VERIFY-SEC-100`) |
> | 시간 변경 | `-S adjtimex,settimeofday`, `-S clock_settime -F a0=0x0` (b64·b32, 로그인 사용자만), `-w /etc/localtime -p wa` | `evidence_time_change` | 알림 없음, 증적 전용 | 규칙 파일에 두 arch 줄이 있다 |
> | mount | `-S mount` (b64·b32, 로그인 사용자만) | `evidence_mount` | 알림 없음, 증적 전용 | 규칙 파일에 두 arch 줄이 있다 |
>
> syscall 규칙은 위 #431의 `login_user_syscall_rule` 매크로로만 만들고(`auid>=1000`·`auid!=4294967295`, b64·b32), 규칙은 6.의 알림 키 규칙과 `sudo_logs` 감시 **뒤**(8.)에 있다. 8. 안에서는 감시(8-1)가 syscall 규칙보다 **앞**이다: 경로 필터 없는 `evidence_file_delete`가 앞에 있으면 `/etc/localtime`·`/var/run/utmp`를 지우거나 바꾼 기록이 그 키로만 남아 시간 변경·로그인 기록 키를 잃고(첫 매치만 기록), syscall 줄이 오래된 auditctl에서 거부돼도 앞의 감시는 이미 올라간다(렌더링 테스트가 순서를 지킨다). 첫 매치만 기록되므로 `/var/log` 아래 삭제는 `evidence_file_delete`가 아니라 `var_log_delete`로 남아 P1 알림이 울리고, `/var/log/wtmp` 등을 로그인 사용자가 지우거나 자르면 그 알림 키가 우선한다(`-w` 감시는 사용자 구분이 없어 로그인 기록을 쓰는 서비스의 기록도 남는다).
>
> **특권 명령 규칙 방식의 결정과 근거**: `setuid 파일 목록`(CIS 형태, 파일마다 `-F path=<파일> -F perm=x`)이 아니라 execve의 자격 전환 필터(`-C uid!=euid`, `-C gid!=egid`)로 정했다.
> - 파일 목록 방식(`perm=x`)은 setuid·setgid 파일 목록이 호스트·패키지마다 달라 규칙 파일이 호스트 상태에 의존한다. 목록을 만들려면 파일시스템 전체를 찾는 태스크가 새로 필요하고, 패키지가 setuid 파일을 더하거나 바꿔도 다음 프로비저닝까지 반영되지 않으며, 렌더링이 호스트마다 달라 렌더링 테스트·Molecule·적재 drift 비교(`SEC-083`)가 호스트 의존이 된다.
> - 자격 전환 필터는 목록이 없고 호스트와 무관하며 새 setuid 파일이 자동으로 포함된다. 규칙은 두 묶음(b64·b32)이라 렌더링이 결정적이다. 전수 execve 추적이 아니라 자격이 바뀐 실행만 남는다(`sudo`·`su`·`passwd`·`ping` 같은 setuid 파일 실행).
> - **한계**: 이미 `uid==euid`인 프로세스의 실행은 자격 전환이 없어 남지 않는다. 그래서 root 셸 안에서 setuid-root 파일을 실행하거나 사용자가 자기 소유 setuid 파일을 실행하는 기록은 이 키에 없다(`perm=x` 방식은 이것도 잡는다). 이 키의 목적은 "로그인 사용자가 권한을 얻은 시점"의 증적이고, 얻은 뒤 root 셸 안의 행위를 전수로 남기지 않는다는 위 원칙(execve 전수 기록 금지)을 지킨다. `-C`의 문법은 auditctl(8)이 `-C [f=f | f!=f]`(필드 간 비교, 로그인 사용자 필드 `auid, uid, euid, suid, fsuid`끼리나 `gid, egid, sgid, fsgid`끼리만 비교할 수 있고 두 묶음은 섞을 수 없다)로 정의한다(Context7로 읽은 audit-userspace 문서, 2026-11-05). `uid!=euid`와 `gid!=egid`는 각각 같은 묶음이라 유효하다. 모든 execve가 필터 비교를 거치는 성능 영향과 EL6 auditctl이 `-C`를 받는지는 **미실시**다(#436에서 확인).
>
> **한계와 미실시**:
> - 시간 변경: 32비트 전용 `stime`은 x86_64 커널에 없어 `login_user_syscall_rule`(b64·b32에 같은 목록)로는 넣지 못했다. 32비트 프로그램이 `stime`을 직접 부르는 경우만 빠진다(`settimeofday`·`clock_settime`이 일반 경로). `/etc/localtime`은 심볼릭 링크라 감시가 링크 이름의 생성·교체를 본다.
> - 감시 경로: `-w`는 없는 경로에서 적재를 실패시킬 수 있어 `SEC-100`·`SEC-101`이 있는 경로만 규칙에 넘긴다(이야기 26). CentOS 6/7 raw 경로(`SEC-035`)에는 이 거르기가 없고 기본 목록 그대로 렌더링한다(이 경로에서 기본 다섯 경로는 모두 존재하는 것이 보통이나 확인하지 못했다). 없는 경로를 `-w`로 걸었을 때 auditd가 실제로 거부하는지는 문서(auditctl(8)의 `-w` 설명)에 없고 호스트에서도 확인하지 못했다(**미실시, #436**). 같은 문서가 `-w`를 성능 문제로 deprecated 형식이라고 적지만, 이 파일의 기존 감시(1~5, `sudo_logs`)와 같은 형식을 따랐다.
> - 적재 drift 비교(`SEC-083`)는 watch를 경로·권한·키로 비교한다. `/etc/localtime`·`/var/run/utmp`가 `auditctl -l`에 선언과 같은 경로 문자열로 나오는지(심볼릭 링크 해석) 확인하지 못했다. 다르게 나오면 매 실행 drift로 보인다(**미실시, #436**).
> - 규칙 문법(`-C uid!=euid`, `-F a0=0x0`, `mount`·`clock_settime` 이름)은 audit.rules(7)·auditctl(8) 기준의 설계이며 호스트에서 `auditctl -R`로 적재해 확인하지 못했다(**미실시, #436**).
> - **한계: 사용자 지정 `audit_watch_paths`가 `/var/log` 아래이면 `var_log_delete` P1을 가로챈다.** 시크릿 감시(1~5절)가 syscall 규칙(6절)보다 앞이라, 그 파일을 로그인 사용자가 지우거나 자르면 첫 매치 키가 `secret_access`가 되어 P1이 울리지 않는다(첫 매치만 기록). `/var/log` 아래는 시크릿 경로로 넣지 않는 것을 전제로 하고, 순서는 렌더링 테스트가 고정한다.
> - **양은 추정이다**(#414: 증적 키 합계가 호스트당 하루 수 MB 이하). 특히 로그인 사용자 자격으로 도는 `sudo` 아래 작업(패키지 갱신·정리 스크립트, 프로비저닝)은 `evidence_file_delete`·`evidence_privileged_exec`를 크게 늘릴 수 있다. 호스트에서 확인하지 못했다. 가장 큰 이상치 후보는 둘이다. (1) `-w /var/log/btmp`는 사용자 구분(auid 필터)이 없어 인터넷에서 오는 SSH 로그인 실패마다 `evidence_login_records`가 늘어난다. (2) EL6에서 로그인한 사용자가 init 스크립트로 띄운 데몬은 그 사용자의 auid를 물려받아(위 #431 한계와 같은 이유) ntpd의 잦은 `adjtimex` 호출이 `evidence_time_change`를 채울 수 있다.
> - **에이전트만 설치된 호스트**: 감사 규칙 파일(`audit.rules.j2`)은 `security` 역할만 배포하고, 에이전트만 설치된 호스트를 다루는 Host Agents 플레이북(`host_agents.yml`·`host_agents_maintenance.yml`)은 이 역할을 포함하지 않는다. 테스트(`tests/test_security_render.py`)가 이를 지킨다.
> - **적용 뒤 키별 증가량 확인 절차(이야기 28, 실행은 미실시이며 #436 몫)**: 카나리 호스트에 적용하기 전과 적용 1주 뒤에 같은 방법으로 다섯 키의 기록 수와 `audit.log` 증가량을 비교한다. 키별 기록 수는 `sudo ausearch -k <키> --start <시각> --raw | grep -c '^type=SYSCALL'`(로그인 기록 감시는 `type=PATH`도 같이 본다)나 `sudo aureport --key --summary --start <시각>`으로 센다. 수치는 비공개 경로에 둔다(공개 저장소). 판단 기준: 합계가 추정(호스트당 하루 수 MB)을 넘는 호스트가 있으면 가장 큰 묶음부터 다시 판단한다(예: `evidence_file_delete`에 경로 필터를 더하거나 묶음을 뺀다). 절차는 `docs/runbooks/detection-recovery.md` 8절에도 있다.
> - **fail2ban**: `SEC-015`/`SEC-032` jail은 `fail2ban_banaction`을 받는다. 기본값은 빈 값이라 배포판 기본 동작을 그대로 쓴다(방화벽 그룹과 무관). 이미 방화벽 연동 방식으로 차단 중인 호스트의 방어를 낮추지 않기 위해서다. `dummy`(방화벽을 건드리지 않고 탐지와 로그만 남김)는 운영자가 `fail2ban_banaction: dummy`로 명시할 때만 쓰며, 이때 네트워크 차단은 없고 실제 차단은 sshd 출발지 제한(#371)이 맡는다. 이 역할이 방화벽 체인·규칙을 직접 만들거나 바꾸지 않는 원칙(`SEC-051`)과 fail2ban 데몬이 런타임에 자체 규칙을 넣고 빼는 것은 다른 문제다. 전자는 Ansible 태스크의 원칙이고 후자는 배포판 기본 banaction이 하는 정상 동작이라, `dummy`를 쓰지 않아도 역할이 체인을 조작하는 것은 아니다. 절차와 한계는 `docs/runbooks/detection-recovery.md`.
> - **journald**: `SEC-053`/`SEC-054`가 `Storage=persistent`를 켜 재부팅 뒤에도 이전 부팅의 시스템 로그가 남는다. 용량·보존 한도는 `common`의 `COMMON-017`(`journald_max_use`, `journald_max_retention`)이 정한다. `/var/log/journal`의 그룹은 `SEC-080`이 `systemd-journal` 존재를 확인해 시스템 기본(`root:systemd-journal`)에 맞추고 그룹이 없는 환경은 `root`로 둔다. CentOS 6/7 raw 경로는 대상이 아니다.
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
