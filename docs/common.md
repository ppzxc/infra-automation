# Common Role Task Specification

`common` 역할은 온프레미스 IDC 인프라의 모든 리눅스 노드에 공통적으로 적용되는 기본 시스템 베이스라인 환경(타임존, 패키지 저장소 복구, 필수 및 현대적 진단 유틸리티, NTP 시간 동기화, 커널 튜닝, 관리자 계정)을 구성합니다.

---

## 1. 개요 및 구현 기능 (What)

- **표준 타임존 동기화**: 전 노드의 타임존을 표준 시간대(`Asia/Seoul`)로 통일.
- **레거시 OS 저장소 복구 (CentOS 6/7)**: 공식 EOL로 인해 중단된 yum 미러를 `vault.centos.org` 아카이브 저장소로 자동 치환.
- **필수 시스템 패키지 및 EPEL 설치**: OS 패밀리(Debian/Ubuntu, RHEL 6/7/8/9/10, Rocky)별 적합한 패키지 관리자(APT, YUM, DNF)를 사용하여 기본 도구(`wget`, `git`, `vim`, `net-tools`, `jq`, `ca-certificates`, `tar`, `gzip` 등) 및 EPEL 저장소, 네트워크 소켓 도구(`nc`, `netcat-openbsd`) 설치. `curl`은 Debian/Ubuntu 및 RHEL/CentOS 6-7에서는 명시적으로 설치하고, RHEL/Rocky 8+에서는 기본 선탑재된 `curl-minimal`(Depsolve 충돌 방지를 위해 교체하지 않음)에 의존.
- **현대적 진단/분석 도구 (Modern Diagnostics)**: `htop`, `iotop`, `bat`, `ripgrep` (`rg`) 설치 및 Debian 계열 `batcat` -> `bat` 심볼릭 링크 자동 생성.
- **NTP 시간 동기화 데몬 구성**: 최신 OS에서는 `Chrony`, 레거시 CentOS 6에서는 `NTP`를 구성하여 지정된 사내/공용 NTP 서버와 지속 동기화. 한국 표준시(KRISS: `time.kriss.re.kr`, `time2.kriss.re.kr`), 국내 전용 NTP Pool(`kr.pool.ntp.org`), 글로벌 Anycast(`time.cloudflare.com`)를 조합한 Standard UTC(Leap Smear 미적용) 소스 분리(`ntp_pools`, `ntp_servers`) 구성 지원.
- **커널 파라미터(sysctl) 최적화**: 10GbE+ IDC 고대역폭 TCP 소켓 버퍼(16MB), Window Scaling, 패킷 큐(`netdev_max_backlog=30000`), TIME_WAIT 소켓 관리(`tcp_max_tw_buckets=1800000`), 파일 디스크립터 한도 확장 및 메모리 스왑 동작 최적화. 선택적 IPv6 비활성화(`disable_ipv6`) 및 추가 확장(`sysctl_extra_settings`) 지원.
- **시스템 자원 보안 한도 (Ulimit)**: `nofile` 및 `nproc` 한도를 65,535로 상향하여 고부하 분산 애플리케이션 및 데몬 병목 제거.
- **표준 3계층 사용자 계정 및 SSH 접근 환경 (Accounts)**: 관리자(`admin`), 서비스 운영자(`operator`), 일반 사용자(`user`) 3계층 역할 모델 기반 계정 생성, 계층별 패스워드리스 `sudoers` 권한 부여 및 SSH 공개키 배포.
- **시스템 전역 쉘 별칭 (Custom Shell Aliases)**: 모든 사용자가 대화형 셸에서 공통으로 사용할 수 있는 Docker, Compose, Firewalld 단축 명령어(`/etc/profile.d/99-aliases.sh`) 배포.
- **노드 식별 및 시스템 환경변수 배포**: `NODE_NAME`(단축 관리번호), `NODE_HOSTNAME`(FQDN), `NODE_INTERNAL_HOSTNAME`, `NODE_WILDCARD_HOSTNAME`, `NODE_PRIMARY_IPV4`, `NODE_INTERFACE`, `NODE_GATEWAY`, `NODE_ENV`, `NODE_IDC`, `NODE_ROLE`, `NODE_ADMIN_USER` 등을 `/etc/profile.d/98-node-env.sh` 및 `/etc/environment`에 자동 주입.

---

## 2. 왜 구현해야 하는가? (Why)

1. **분산 시스템 정합성 및 보안 감사 (시간 동기화)**:
   - 서버 간 시간이 어긋나면 분산 환경에서 다중 노드 로그 분석이 불가능해집니다.
   - HCP Vault의 단기 토큰(Token TTL) 및 단기 서명 SSH 인증서(SSH Certificate)의 시간 검증이 오차로 인해 실패하는 문제를 예방합니다.
2. **파편화된 온프레미스 레거시 자동 복구**:
   - CentOS 6 및 7은 공식 지원 종료(EOL)로 기본 미러 주소가 비활성화되어, 사전 복구 없이는 신규 패키지 설치 및 보안 도구 배포가 전면 중단됩니다. 이를 자동으로 감지하여 아카이브 미러로 전환합니다.
3. **고부하 IDC 서버 안정성 및 네트워크 처리량 확보 (커널 튜닝 & Ulimit)**:
   - 기본 리눅스 커널 설정은 서버 워크로드에 비해 파일 디스크립터(`fs.file-max`)나 TCP 소켓 버퍼(기본 212KB)가 협소하여 대량 트래픽 처리 시 소켓 고갈(Connection Refused) 및 Throughput 저하가 발생할 수 있습니다. 16MB 버퍼 및 백로그/TIME_WAIT 확장을 통해 고성능 통신을 보장합니다.
4. **Zero-Trust 접근 및 최소 권한 원칙 (3계층 계정 모델)**:
   - 직접적인 `root` SSH 로그인을 원천 차단(`PermitRootLogin no`)하고, Admin/Operator/User 권한을 격리하여 직무에 필요한 최소 권한(Least Privilege)만 부여합니다.

---

## 3. 무엇을 변경하는가? (What Changes)

- 📁 **설정 파일 및 디렉토리**:
   - `/etc/localtime`, `/etc/timezone` : 표준 타임존 심볼릭 링크 및 설정
   - `/etc/yum.repos.d/*.repo` : CentOS 6/7의 미러 주소를 `vault.centos.org` 아카이브 주소로 교체
   - `/etc/chrony.conf` 또는 `/etc/chrony/chrony.conf` : NTP 서버 풀 템플릿 적용
   - `/etc/sysctl.d/99-ansible.conf` (또는 `/etc/sysctl.conf`) : 커널 튜닝 및 하드닝 파라미터(`fs.file-max`, `net.core.rmem_max`, `net.ipv4.tcp_rmem`, `net.core.netdev_max_backlog`, `vm.swappiness`, `fs.protected_hardlinks`, `fs.protected_symlinks`, `kernel.randomize_va_space` 등)
   - `/etc/security/limits.d/99-limits.conf` : 시스템 보안 리소스 한도 (`nofile=65535`, `nproc=65535`)
   - `/etc/sudoers.d/90-<account>` : Admin 계층 패스워드리스 sudo 권한 파일 (`validate: visudo -cf %s`)
   - `/home/<account>/.ssh/authorized_keys` : 계정별 SSH 공개키 등록
   - `/usr/local/bin/bat` : Debian/Ubuntu 환경 `batcat` 심볼릭 링크
   - `/etc/profile.d/99-aliases.sh` : 시스템 전역 커스텀 쉘 별칭 파일
   - `/etc/profile.d/98-node-env.sh` : 로그인 셸 전용 노드 식별 환경변수 파일
   - `/etc/environment` : 시스템 전역 환경변수 파일
- ⚙️ **데몬 및 서비스**:
   - `chronyd` (또는 레거시 `ntpd`) : 서비스 활성화 및 자동 재시작
- 👤 **사용자 및 그룹**:
   - `accounts` 목록의 사용자 계정 및 전용 기본 그룹 생성, 계층별 보조 그룹(`sudo`/`wheel`, `docker`, `dockermgmt`) 등록

---

## 4. 태스크 매트릭스 (Task Matrix)

| Spec ID | 태스크 명칭 (Task Name) | Ansible 모듈 | 지원 OS | 멱등성 보장 방식 |
|---|---|---|---|---|
| `COMMON-001` | `Set timezone` | `community.general.timezone` | Linux All (RHEL 7+, Debian) | 내부 상태 비교 후 일치 시 건너뜀 |
| `COMMON-002` | `Fix EOL CentOS 6 / 7 Vault Repositories` | `ansible.builtin.shell` | CentOS 6, 7 | `changed_when: false` |
| `COMMON-003` | `Install common packages (Debian/Ubuntu)` | `ansible.builtin.apt` | Debian, Ubuntu | 패키지 기설치 시 `ok` |
| `COMMON-004` | `Install EPEL repository (RedHat/CentOS 7, Rocky 8, 9)` | `ansible.builtin.package` | RHEL 7, 8, 9, 10 | 기설치 시 `ok`, `failed_when: false` |
| `COMMON-005` | `Install common packages (RedHat/CentOS 6, 7 via YUM)` | `ansible.builtin.yum` | RHEL/CentOS 6, 7 | 패키지 기설치 시 `ok` |
| `COMMON-006` | `Install common packages (RHEL/Rocky 8, 9, 10 via DNF)` | `ansible.builtin.dnf` | RHEL 8, 9, 10, Rocky | 패키지 기설치 시 `ok` |
| `COMMON-007` | `Install optional diagnostic tools (htop, iotop, bat, ripgrep)` | `ansible.builtin.package` | All | `failed_when: false` |
| `COMMON-007-BAT` | `Ensure bat symlink exists for Debian/Ubuntu (batcat -> bat)` | `ansible.builtin.file` | Debian, Ubuntu | 심볼릭 링크 존재 시 `ok`, `failed_when: false` |
| `COMMON-008` | `Configure Chrony NTP servers (Modern OS)` | `ansible.builtin.template` | RHEL 7+, Debian | Checksum 비교 후 변경 시만 수정 및 핸들러 호출 |
| `COMMON-009` | `Ensure Chrony service is running (Modern OS)` | `ansible.builtin.service` | RHEL 7+, Debian | 서비스 기동 상태면 `ok` |
| `COMMON-010` | `Ensure NTP service is running (CentOS 6 legacy)` | `ansible.builtin.service` | CentOS 6 (`_raw_path_effective=false`) | 서비스 기동 상태면 `ok` |
| `COMMON-011` | `Apply sysctl kernel tuning` | `ansible.posix.sysctl` | All | sysctl 값 일치 시 `ok` |
| `COMMON-011-IPV6` | `Disable IPv6 via sysctl` | `ansible.posix.sysctl` | All | `disable_ipv6: true` 시 적용 |
| `COMMON-011-EXTRA` | `Apply extra sysctl kernel tuning` | `ansible.posix.sysctl` | All | `sysctl_extra_settings` 정의 시 적용 |
| `COMMON-012` | `Ensure account primary groups exist` | `ansible.builtin.group` | All | 그룹 존재 시 `ok` |
| `COMMON-013` | `Ensure accounts exist with tier-specific permissions` | `ansible.builtin.user` | All | 사용자 존재 및 속성 일치 시 `ok` |
| `COMMON-014` | `Configure passwordless sudoers for admin accounts` | `ansible.builtin.copy` | All | Checksum 비교 (`validate: visudo`) |
| `COMMON-015` | `Deploy SSH public keys for accounts` | `ansible.posix.authorized_key` | All | 공개키 등록되어 있으면 `ok` |
| `COMMON-016` | `Configure system security limits (nofile/nproc)` | `community.general.pam_limits` | All | `/etc/security/limits.d/99-limits.conf` 한도 일치 시 `ok` |
| `COMMON-017` | `Configure Systemd Journald retention limits` | `ansible.builtin.copy` | Systemd OS | 파일 내용 일치 시 `ok` |
| `COMMON-018` | `Deploy system-wide custom shell aliases` | `ansible.builtin.template` | All | Checksum 비교 (`aliases.sh.j2`) |
| `COMMON-019` | `Deploy node environment variables drop-in (/etc/profile.d/98-node-env.sh)` | `ansible.builtin.template` | All | Checksum 비교 (`node-env.sh.j2`) |
| `COMMON-020` | `Deploy system-wide environment variables (/etc/environment)` | `ansible.builtin.template` | All | Checksum 비교 (`environment.j2`) |
| `COMMON-021` | `Ensure tzdata package is installed before timezone configuration (Debian/Ubuntu)` | `ansible.builtin.apt` | Debian, Ubuntu | 패키지 기설치 시 `ok` |
| `COMMON-022` | `Revoke SSH public keys listed in accounts[].revoked_keys` | `ansible.posix.authorized_key` | All | 키가 이미 제거되어 있으면 `ok` |
| `COMMON-023` | `Remove passwordless sudoers drop-in for removed accounts` | `ansible.builtin.file` | All | 파일이 이미 없으면 `ok` |
| `COMMON-024` | `Read current sysctl.conf (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 조회 전용 (`changed_when: false`) |
| `COMMON-025` | `Probe sysctl.conf hash and mode (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 조회 전용 (`changed_when: false`) |
| `COMMON-026` | `Apply sysctl kernel tuning via write-temp/validate/move (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 로컬 해시·모드가 원격 `sha256sum`/`stat`과 같으면 `ok` |
| `COMMON-027` | `Ensure account primary groups exist (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 그룹·gid 일치 시 `ok` (`getent` probe 후 필요할 때만 `groupadd`/`groupmod`) |
| `COMMON-028` | `Ensure accounts exist with tier-specific permissions (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 계정 속성·보조 그룹 일치 시 `ok` (드리프트 시에만 `useradd`/`usermod`/`userdel`) |
| `COMMON-029` | `Probe sudoers drop-in hash and mode (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 조회 전용 (`changed_when: false`) |
| `COMMON-030` | `Configure passwordless sudoers via write-temp/validate/move (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 해시·모드 일치 시 `ok` (`visudo -cf` 검증 실패 시 원본 보존, 임시 파일 삭제 후 실패) |
| `COMMON-031` | `Deploy SSH public keys for accounts (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 키 blob이 이미 있으면 `ok` |
| `COMMON-032` | `Revoke SSH public keys listed in accounts[].revoked_keys (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 키가 이미 없으면 `ok` |
| `COMMON-033` | `Remove passwordless sudoers drop-in for removed accounts (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 파일이 이미 없으면 `ok` |
| `COMMON-034` | `Probe security limits file hash and mode (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 조회 전용 (`changed_when: false`) |
| `COMMON-035` | `Configure system security limits via write-temp/validate/move (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 기존 줄을 보존한 채 병합, 해시·모드·소유자 일치 시 `ok` |
| `COMMON-036` | `Read current security limits file (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 조회 전용 (`changed_when: false`) |
| `COMMON-037` | `Fix EOL CentOS 6 / 7 Vault Repositories (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | `changed_when: false` |
| `COMMON-038` | `Install common packages (CentOS 6, 7 via YUM, raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | `rpm -q --whatprovides` 확인 후 미설치 패키지만 설치 |
| `COMMON-039` | `Install optional diagnostic tools (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 미설치·설치 가능한 패키지만 설치, 실패 무시 |
| `COMMON-040` | `Align live sysctl values with the desired settings (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 실행 중 커널 값이 다를 때만 `sysctl -w` |
| `COMMON-041` | `Install ntp package (CentOS 6, raw)` | `ansible.builtin.raw` | CentOS 6 (`_raw_path_effective`) | 패키지 기설치 시 `ok` |
| `COMMON-042` | `Probe ntp.conf hash and mode (raw)` | `ansible.builtin.raw` | CentOS 6 (`_raw_path_effective`) | 조회 전용 |
| `COMMON-043` | `Configure ntpd servers via write-temp/validate/move (raw)` | `ansible.builtin.raw` | CentOS 6 (`_raw_path_effective`) | 해시·모드·소유자가 같으면 `ok` (`ntp.conf.j2`, `Restart ntpd` 핸들러) |
| `COMMON-044` | `Ensure ntpd service is running and enabled (raw)` | `ansible.builtin.raw` | CentOS 6 (`_raw_path_effective`) | 기동·부팅 활성 상태면 `ok` |
| `COMMON-045` | `Set timezone (CentOS 7, raw)` | `ansible.builtin.raw` | CentOS 7 (`_raw_path_effective`) | 현재 타임존이 같으면 `ok` (`timedatectl set-timezone`) |
| `COMMON-046` | `Install EPEL repository (CentOS 7, raw)` | `ansible.builtin.raw` | CentOS 7 (`_raw_path_effective`) | 기설치 시 `ok`, `failed_when: false` |
| `COMMON-047` | `Probe chrony.conf hash and mode (CentOS 7, raw)` | `ansible.builtin.raw` | CentOS 7 (`_raw_path_effective`) | 조회 전용 |
| `COMMON-048` | `Configure Chrony NTP servers via write-temp/validate/move (CentOS 7, raw)` | `ansible.builtin.raw` | CentOS 7 (`_raw_path_effective`) | 해시·모드·소유자가 같으면 `ok` (`chrony.conf.j2`, `Restart chrony` 핸들러) |
| `COMMON-049` | `Ensure Chrony service is running and enabled (CentOS 7, raw)` | `ansible.builtin.raw` | CentOS 7 (`_raw_path_effective`) | 기동·부팅 활성 상태면 `ok` |
| `COMMON-050` | `Probe journald retention drop-in hash and mode (CentOS 7, raw)` | `ansible.builtin.raw` | CentOS 7 (`_raw_path_effective`) | 조회 전용 |
| `COMMON-051` | `Configure Systemd Journald retention limits via write-temp/validate/move (CentOS 7, raw)` | `ansible.builtin.raw` | CentOS 7 (`_raw_path_effective`) | 해시·모드·소유자가 같으면 `ok` |
| `COMMON-052` | `Probe custom shell aliases hash and mode (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 조회 전용 (`custom_shell_aliases`가 있을 때만) |
| `COMMON-053` | `Deploy system-wide custom shell aliases via write-temp/validate/move (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 해시·모드·소유자가 같으면 `ok` (`aliases.sh.j2`, `COMMON-018` 대체) |
| `COMMON-054` | `Probe node environment drop-in hash and mode (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 조회 전용 |
| `COMMON-055` | `Deploy node environment variables drop-in via write-temp/validate/move (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 해시·모드·소유자가 같으면 `ok` (`node-env.sh.j2`, `COMMON-019` 대체) |
| `COMMON-056` | `Probe /etc/environment hash and mode (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 조회 전용 |
| `COMMON-057` | `Deploy system-wide environment variables via write-temp/validate/move (raw)` | `ansible.builtin.raw` | CentOS 6/7 (`_raw_path_effective`) | 해시·모드·소유자가 같으면 `ok` (`environment.j2`, `COMMON-020` 대체) |

> **Raw Provisioning Path (ADR-0005)**: `/etc/redhat-release` 자동 판별(`_raw_path_effective`; 인벤토리 `raw_provisioning_path` 명시 시 우선)로 raw 경로가 된 CentOS 6/7 호스트에서는 `COMMON-001`/`002`/`004`/`005`/`007`/`008`/`009`/`011*`/`012`/`013`/`014`/`015`/`016`/`017`/`018`/`019`/`020`/`022`/`023`이 스킵되고(`COMMON-001`/`004`/`008`/`009`/`017`은 CentOS 7 raw 블록이 대신하며 CentOS 6에서는 실행되지 않는다) `COMMON-024`~`COMMON-040`, `COMMON-052`~`COMMON-057`이 대신 실행된다(CentOS 6는 `COMMON-010` 대신 `COMMON-041`~`COMMON-044` ntpd 경로 추가, CentOS 7은 `COMMON-001`/`004`/`008`/`009`/`017` 대신 `COMMON-045`~`COMMON-051` 추가; CentOS 6는 Upstart라 journald 없음)(sysctl은 CentOS 6에 `/etc/sysctl.d`가 없어 `/etc/sysctl.conf`를 갱신). 헬퍼: `filter_plugins/raw_provisioning.py`. `--check`에서는 스킵된다.

