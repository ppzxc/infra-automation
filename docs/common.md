# Common Role Task Specification

`common` 역할은 온프레미스 IDC 인프라의 모든 리눅스 노드에 공통적으로 적용되는 기본 시스템 베이스라인 환경(타임존, 패키지 저장소 복구, 기본 유틸리티, NTP 시간 동기화, 커널 튜닝, 관리자 계정)을 구성합니다.

---

## 1. 개요 및 구현 기능 (What)

- **표준 타임존 동기화**: 전 노드의 타임존을 표준 시간대(`Asia/Seoul`)로 통일.
- **레거시 OS 저장소 복구 (CentOS 6/7)**: 공식 EOL로 인해 중단된 yum 미러를 `vault.centos.org` 아카이브 저장소로 자동 치환.
- **필수 시스템 패키지 및 EPEL 설치**: OS 패밀리(Debian/Ubuntu, RHEL 6/7/8/9/10, Rocky)별 적합한 패키지 관리자(APT, YUM, DNF)를 사용하여 기본 도구(`curl`, `vim`, `net-tools`, `tar` 등) 및 EPEL 저장소, 진단 도구(`htop`, `iotop`) 설치.
- **NTP 시간 동기화 데몬 구성**: 최신 OS에서는 `Chrony`, 레거시 CentOS 6에서는 `NTP`를 구성하여 지정된 사내/공용 NTP 서버와 지속 동기화. 한국 표준시(KRISS: `time.kriss.re.kr`, `time2.kriss.re.kr`), 국내 전용 NTP Pool(`kr.pool.ntp.org`), 글로벌 Anycast(`time.cloudflare.com`)를 조합한 Standard UTC(Leap Smear 미적용) 소스 분리(`ntp_pools`, `ntp_servers`) 구성 지원.
- **커널 파라미터(sysctl) 최적화**: 10GbE+ IDC 고대역폭 TCP 소켓 버퍼(16MB), Window Scaling, 패킷 큐(`netdev_max_backlog=30000`), TIME_WAIT 소켓 관리(`tcp_max_tw_buckets=1800000`), 파일 디스크립터 한도 확장 및 메모리 스왑 동작 최적화. 선택적 IPv6 비활성화(`disable_ipv6`) 및 추가 확장(`sysctl_extra_settings`) 지원.
- **시스템 자원 보안 한도 (Ulimit)**: `nofile` 및 `nproc` 한도를 100,000으로 상향하여 고부하 분산 애플리케이션 및 데몬 병목 제거.
- **표준 관리자 계정 및 SSH 접근 환경**: 비루트 표준 관리자(`admin_user`) 계정 생성, 패스워드리스 `sudoers` 권한 부여 및 관리자 SSH 공개키 배포.

---

## 2. 왜 구현해야 하는가? (Why)

1. **분산 시스템 정합성 및 보안 감사 (시간 동기화)**:
   - 서버 간 시간이 어긋나면 분산 환경에서 다중 노드 로그 분석이 불가능해집니다.
   - HCP Vault의 단기 토큰(Token TTL) 및 단기 서명 SSH 인증서(SSH Certificate)의 시간 검증이 오차로 인해 실패하는 문제를 예방합니다.
2. **파편화된 온프레미스 레거시 자동 복구**:
   - CentOS 6 및 7은 공식 지원 종료(EOL)로 기본 미러 주소가 비활성화되어, 사전 복구 없이는 신규 패키지 설치 및 보안 도구 배포가 전면 중단됩니다. 이를 자동으로 감지하여 아카이브 미러로 전환합니다.
3. **고부하 IDC 서버 안정성 및 네트워크 처리량 확보 (커널 튜닝 & Ulimit)**:
   - 기본 리눅스 커널 설정은 서버 워크로드에 비해 파일 디스크립터(`fs.file-max`)나 TCP 소켓 버퍼(기본 212KB)가 협소하여 대량 트래픽 처리 시 소켓 고갈(Connection Refused) 및 Throughput 저하가 발생할 수 있습니다. 16MB 버퍼 및 백로그/TIME_WAIT 확장을 통해 고성능 통신을 보장합니다.
4. **Zero-Trust 접근의 첫 단계 (루트 계정 분리)**:
   - 직접적인 `root` 계정 사용을 배제하고, `sudo` 권한을 가진 전용 관리자 계정을 통해 비대화식 자동화와 작업 감사 추적성을 확보합니다.

---

## 3. 무엇을 변경하는가? (What Changes)

- 📁 **설정 파일 및 디렉토리**:
   - `/etc/localtime`, `/etc/timezone` : 표준 타임존 심볼릭 링크 및 설정
   - `/etc/yum.repos.d/*.repo` : CentOS 6/7의 미러 주소를 `vault.centos.org` 아카이브 주소로 교체
   - `/etc/chrony.conf` 또는 `/etc/chrony/chrony.conf` : NTP 서버 풀 템플릿 적용
   - `/etc/sysctl.d/99-ansible.conf` (또는 `/etc/sysctl.conf`) : 커널 튜닝 파라미터(`fs.file-max`, `net.core.rmem_max`, `net.ipv4.tcp_rmem`, `net.core.netdev_max_backlog`, `vm.swappiness` 등)
   - `/etc/security/limits.d/99-limits.conf` : 시스템 보안 리소스 한도 (`nofile=100000`, `nproc=100000`)
   - `/etc/sudoers.d/90-admin-user` : 관리자 패스워드리스 sudo 권한 파일 (`validate: visudo -cf %s`)
   - `/home/<admin_user>/.ssh/authorized_keys` : 관리자 SSH 공개키 등록
- ⚙️ **데몬 및 서비스**:
   - `chronyd` (또는 레거시 `ntpd`) : 서비스 활성화 및 자동 재시작
- 👤 **사용자 및 그룹**:
   - `<admin_user>` 계정 생성, 기본 셸(`/bin/bash`) 지정, `sudo` 또는 `wheel` 보조 그룹 등록

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
| `COMMON-007` | `Install optional diagnostic tools (htop, iotop)` | `ansible.builtin.package` | All | `failed_when: false` |
| `COMMON-008` | `Configure Chrony NTP servers (Modern OS)` | `ansible.builtin.template` | RHEL 7+, Debian | Checksum 비교 후 변경 시만 수정 및 핸들러 호출 |
| `COMMON-009` | `Ensure Chrony service is running (Modern OS)` | `ansible.builtin.service` | RHEL 7+, Debian | 서비스 기동 상태면 `ok` |
| `COMMON-010` | `Ensure NTP service is running (CentOS 6 legacy)` | `ansible.builtin.service` | CentOS 6 | 서비스 기동 상태면 `ok` |
| `COMMON-011` | `Apply sysctl kernel tuning` | `ansible.posix.sysctl` | All | sysctl 값 일치 시 `ok` |
| `COMMON-011-IPV6` | `Disable IPv6 via sysctl` | `ansible.posix.sysctl` | All | `disable_ipv6: true` 시 적용 |
| `COMMON-011-EXTRA` | `Apply extra sysctl kernel tuning` | `ansible.posix.sysctl` | All | `sysctl_extra_settings` 정의 시 적용 |
| `COMMON-012` | `Ensure admin user group exists` | `ansible.builtin.group` | All | 그룹 존재 시 `ok` |
| `COMMON-013` | `Ensure admin user exists with sudo privileges` | `ansible.builtin.user` | All | 사용자 존재 및 속성 일치 시 `ok` |
| `COMMON-014` | `Enable passwordless sudo for admin user` | `ansible.builtin.copy` | All | Checksum 비교 (`validate: visudo`) |
| `COMMON-015` | `Deploy admin SSH public keys` | `ansible.posix.authorized_key` | All | 공개키 등록되어 있으면 `ok` |
| `COMMON-016` | `Configure system security limits (nofile/nproc)` | `community.general.pam_limits` | All | `/etc/security/limits.d/99-limits.conf` 한도 일치 시 `ok` |
| `COMMON-017` | `Configure Systemd Journald retention limits` | `ansible.builtin.copy` | Systemd OS | 파일 내용 일치 시 `ok` |

