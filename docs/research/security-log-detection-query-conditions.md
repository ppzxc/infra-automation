# 높은 신호 탐지의 업계 쿼리 조건

- 질문: 로그 은폐, `authorized_keys` 수정·삭제, 특권 그룹 추가, 비밀번호 스프레이, 공개키 첫 사용·낯선 사용자/IP, sshd 치명 오류, 방화벽 규칙 수정·서비스 중지를 업계 규칙은 정확히 어떤 조건(조건, 시간창, 임계, 등급, 알려진 오탐)으로 잡는가. 우리 `security_logs`로 같은 조건을 쓸 수 있는가.
- 날짜: 2026-11-04
- 관련: #417 (지도 #411)

## 출처

규칙 원문을 저장소에서 직접 읽었다(`gh api .../contents/<path>?ref=<SHA>`).

| 저장소 | 기준 | 커밋 SHA |
|---|---|---|
| SigmaHQ/sigma | `master` | `26a2c3810a4878caec599563f972a8c39587b154` |
| elastic/detection-rules | `main` | `cde6b55f46ace0b21d0c1ad95aa9cd8a24ec72be` |
| splunk/security_content | `develop` | `4c1652e36f137c83d2279f455a4911ee5bd76305` |
| wazuh/wazuh | 태그 `v4.14.9` | `bed556db3f4f535cb3a585f3d9e7f35a6acf0f58` |

- Wazuh `main`(`bbd1cea999dd661483c3e5f51345385caa853319`)에는 `ruleset/rules/`가 없다. 그래서 최신 릴리스 태그 `v4.14.9`의 `ruleset/rules/0095-sshd_rules.xml`, `0020-syslog_rules.xml`, `0015-ossec_rules.xml`, `0085-pam_rules.xml`, `0280-attack_rules.xml`, `0290-firewalld_rules.xml`, `0365-auditd_rules.xml`을 읽었다.
- Wazuh `frequency`·`timeframe` 뜻은 wazuh/wazuh-documentation 브랜치 `4.14`(`ea471550a31d883cfa669407fdaf30f99c08ad5d`)의 `source/user-manual/ruleset/ruleset-xml-syntax/rules.rst`를 따랐다. `frequency`는 "경보 전에 규칙이 일치해야 하는 횟수", `timeframe`은 초 단위 구간이다. 이 문서는 `timeframe`의 기본값을 적지 않는다. 또 `global_frequency`가 없으면 같은 에이전트(호스트)의 이벤트만 센다. 아래 Wazuh 행의 "N초에 M회"는 이 정의대로 읽은 것이다.
- 우리 쪽 맥락: `docs/openobserve_config.md`, `roles/security/templates/audit.rules.j2`, `roles/openobserve_config/defaults/main.yml`, `roles/openobserve_config/files/vrl/security_semantics.vrl`. `docs/research/security-log-alert-industry-baseline.md`는 이 시점에 저장소에 없었다.

### 등급 표기

출처마다 원래 값을 그대로 적는다. P1~P3로 바꾼 값은 **제안**이라고 따로 표시한다.

- Elastic: `severity`(low·medium·high)와 `risk_score`(21·47·73)
- Sigma: `level`(medium·high)
- Splunk: 탐지 `type`(Anomaly·TTP)과 RBA 점수
- Wazuh: 규칙 `level`(0~15)

### 우리 데이터 판정 기준

- **예**: 지금 수집하는 필드나 원문(`body`)만으로 같은 조건을 SQL로 쓸 수 있다.
- **부분**: 일부 경로만 잡히거나(예: sudo로 실행한 명령만), 원문 파싱이 더 필요하다.
- **아니오**: 필요한 이벤트가 수집되지 않는다.

## 판정을 좌우하는 세 가지 사실

1. **명령 실행(execve) 기록이 없다.** `audit.rules.j2`에 있던 `-a always,exit -F arch=b64 -S execve -k exec_log`는 #364/#372 커밋(`87cad21`, 2026-10-27)에서 소음 때문에 일부러 뺐다. 그래서 Elastic·Sigma·Splunk의 `process_creation`/EXECVE 규칙은 그대로 옮길 수 없다. 이번에 읽은 Elastic·Sigma·Splunk 규칙 45개 중 19개가 이런 규칙이다(Sigma 9, Elastic 8, Splunk 2). 로그 은폐, 방화벽 규칙 변경, 특권 그룹 쪽에 몰려 있다. 엔드포인트 파일 이벤트를 쓰는 Elastic 규칙 4개(`authorized_keys` 2개, 로그 파일 삭제, SSH 백도어 로그)도 같은 이유로 옮길 수 없다. Wazuh 규칙은 모두 로그 원문이나 auditd 기록 유형을 본다. 대신 쓸 수 있는 길은 sudo 줄의 `COMMAND=`(VRL `process_command_line`)뿐이다. root 셸이나 `sudo -i` 안에서 친 명령은 보이지 않는다. 그 전에 프로비저닝한 호스트에 옛 규칙이 남아 `exec_log` 기록이 아직 들어오는지는 **미확인**이다(알림 픽스처에는 실제 `exec_log` 줄이 있다).
2. **감시 규칙 없이 auditd가 스스로 남기는 기록은 들어온다.** `SERVICE_STOP`(systemd 서비스 중지), `CONFIG_CHANGE`(감사 규칙·설정 변경, `audit_enabled=`), `DAEMON_END`/`DAEMON_ABORT`, `ADD_USER`·`USER_MGMT` 같은 계정 관리 기록이 그렇다. 기존 알림 `infra-auditd-stopped`·`infra-account-change`가 이미 이 기록을 읽는다.
3. **감시 규칙은 프로비저닝 대상 호스트에만 들어간다.** `audit.rules.j2`는 `security` 역할이 프로비저닝 대상에만 배포한다. 에이전트만 설치한 호스트는 바꾸지 않는다는 운영 원칙이 있다. 그래서 "감시 규칙을 더하면 된다"는 판정(auditd 설정, syslog 설정, `authorized_keys`, 로그 삭제 syscall 규칙)은 프로비저닝 대상 호스트에서만 성립한다. 기존 키 `identity`·`sudo_config`·`sshd_config`도 마찬가지다. 반대로 `secure`/`auth.log` 원문으로 하는 탐지(스프레이, sshd 치명 오류, 낯선 사용자·IP)는 로그를 보내는 모든 호스트에 적용된다. 에이전트만 설치한 호스트에서 auditd가 돌고 그 기록이 수집되는지는 **미확인**이다. 그래서 1·2번의 기록 유형 탐지가 그 호스트들에도 적용되는지도 미확인이다.

`new_terms`(Elastic)는 ML이 아니다. "지난 5일 동안 처음 보는 값"을 찾는 규칙이라 긴 조회 구간의 SQL로 흉내 낼 수 있다. 이 저장소는 이미 조회 구간 11520분(8일) 알림을 쓴다.

## 1. 로그 은폐

### 1-1. auditd 설정 변경·감사 규칙 삭제·auditd 중지

| 출처 | 조건 | 시간창·임계 | 등급 | 오탐 주의 | 우리 데이터 |
|---|---|---|---|---|---|
| Sigma `lnx_auditd_auditing_config_change` | auditd `type=PATH`, `name`이 `/etc/audit/*`, `/etc/libaudit.conf`, `/etc/audisp/*` | 1건 | high | 정상 관리 작업 | **아니오.** 이 경로를 감시하지 않는다. 필요: `-w /etc/audit/ -p wa -k <키>`. Sigma는 PATH `name`으로 맞추지만 우리 `infra-audit-watch-change`는 SYSCALL `key=`로 맞추므로 키 목록에 더하면 된다 |
| Sigma `proc_creation_lnx_auditctl_clear_rules` | `auditctl` 실행 + 인자 `-D`(규칙 전체 삭제) | 1건 | high | 관리자 문제 해결. "모든 시도를 조사" | **부분.** 실행 기록은 없다. 대신 커널이 규칙 변경마다 `CONFIG_CHANGE`를 남긴다. 단 우리 `audit.rules.j2` 첫 줄이 `-D`라서 규칙을 다시 읽을 때마다(프로비저닝, 재부팅) 같은 기록이 나온다. 정확한 `op=` 값은 **미확인**(실로그 확인 필요) |
| Elastic `defense_evasion_attempt_to_disable_auditd_service` | 실행: `service … stop`, `chkconfig … off`, `update-rc.d … remove/disable`, `systemctl disable/stop/kill/mask` 중 하나 + 인자 `auditd`/`auditd.service`. 부모가 `auditd.prerm`이면 제외 | 1건, `from: now-9m` | medium, 47 | 패키지 제거 스크립트 | **예(다른 방식).** 기존 `infra-auditd-stopped`가 `DAEMON_END`·`DAEMON_ABORT`·`audit_enabled=0` 뒤 시작 기록이 없는 경우를 잡는다. sudo 명령은 `infra-sudo-risky-command`(`o2c_sudo_protected_services`에 auditd 포함) |
| Splunk `linux_auditd_auditd_service_stop` | `type=SERVICE_STOP unit=auditd` | 1건 | Anomaly, RBA 20 | 자동화 도구 | **예.** `SERVICE_STOP` 수집됨 |
| Wazuh 80703 / 80704 / 80705 | `DAEMON_END`(res=success) / `DAEMON_ABORT` / `CONFIG_CHANGE` 또는 `DAEMON_CONFIG` | 1건 | 10 / 10 / 3 | 설정 변경(80705)은 낮은 등급 | **예** |

### 1-2. syslog 설정 변경·syslog 중지

| 출처 | 조건 | 시간창·임계 | 등급 | 오탐 주의 | 우리 데이터 |
|---|---|---|---|---|---|
| Sigma `lnx_auditd_logging_config_change` | `type=PATH`, `name`이 `/etc/syslog.conf`, `/etc/rsyslog.conf`, `/etc/syslog-ng/syslog-ng.conf` | 1건 | high | 정상 관리 작업 | **아니오.** 감시 규칙이 없다. 필요: `-w /etc/rsyslog.conf`·`-w /etc/rsyslog.d/ -p wa -k <키>`(`rsyslog.d/`는 Sigma 목록에 없지만 RHEL·Debian 모두 쓰는 위치라 함께 넣는 것을 제안) |
| Elastic `defense_evasion_attempt_to_disable_syslog_service` | 1-1과 같은 중지 명령 4종 + 인자 `syslog`, `rsyslog`, `syslog-ng`(및 `.service`). 부모가 `rsyslog-rotate`이거나 인자 `HUP`이면 제외 | 1건 | medium, 47 | 로그 순환 스크립트의 재시작 | **부분.** sudo 명령은 `infra-sudo-risky-command`가 이미 잡는다(rsyslog 포함). `SERVICE_STOP unit=rsyslog`도 들어오지만 재부팅 중 오탐이 나서 `infra-auditd-stopped`에서 뺐다(`defaults/main.yml` 주석). 쓰려면 "중지 뒤 일정 시간 시작 없음"으로 판정해야 한다 |
| Wazuh 1004 / 1005·1006 | `^exiting on signal` / syslogd 재시작 | 1건 | 5 / 5 | 재시작 | **미확인.** rsyslog의 종료 줄 형식과 그 줄이 `security_logs`가 아니라 `system_logs`로 가는지 확인하지 않았다 |
| Sigma `lnx_syslog_security_tools_disabling_syslog` | syslog 키워드 `stopping iptables`, `stopping ip6tables`, `stopping firewalld`, `stopping cbdaemon`, `stopping falcon-sensor` | 1건 | medium | 정상 관리 작업 | 1-5 방화벽 항목 참고 |

### 1-3. 로그 파일 삭제·비우기

| 출처 | 조건 | 시간창·임계 | 등급 | 오탐 주의 | 우리 데이터 |
|---|---|---|---|---|---|
| Elastic `defense_evasion_log_files_deleted` | 파일 삭제 이벤트, 경로가 `/var/run/utmp`, `/var/log/wtmp`, `btmp`, `lastlog`, `faillog`, `syslog`, `messages`, `secure`, `auth.log`, `boot.log`, `kern.log`, `dmesg` 중 하나. 프로세스 `gzip`·`executor`·`dockerd`, podman의 `lastlog`는 제외 | 1건 | medium, 47 | 압축·컨테이너 런타임 | **아니오.** 파일 삭제 이벤트가 없다. `-w /var/log/secure -p wa`는 rsyslog가 계속 쓰므로 쓸 수 없다. 필요한 것은 `/var/log` 아래 `unlink`·`unlinkat`·`rename`·`truncate` 계열 syscall 규칙이고 logrotate를 제외해야 한다(규칙 문법·소음은 **미검증**) |
| Sigma `proc_creation_lnx_clear_logs` | `rm`·`rmdir`·`shred`·`unlink` 실행 + 인자에 `/var/log` 또는 `/var/spool/mail`. `rm -f /var/log/sysstat/…`, `rm -f -- /var/log//dmesg`는 제외 | 1건 | medium (stable) | 정상 관리 작업 | **부분.** sudo `COMMAND=`로만 |
| Sigma `proc_creation_lnx_clear_syslog` | (`/var/log/syslog` + `rm -r/-f`·`unlink`·`mv`·`truncate -s 0`·`ln -sf /dev/null`·`cp /dev/null`·`shred -u`) 또는 리다이렉션 `> /var/log/syslog` 류, 또는 `journalctl --vacuum`·`journalctl --rotate` | 1건 | high | 로그 순환, 유지보수 | **부분.** sudo `COMMAND=`로만. 리다이렉션(`>`)은 셸 문법이라 sudo 줄에도 보이지 않는다 |
| Sigma `lnx_clear_syslog`(builtin) | 원문 키워드 `rm /var/log/syslog`, `rm -rf …`, `mv /var/log/syslog`, `> /var/log/syslog`. `/syslog.` 포함 줄은 제외 | 1건 | high | 로그 순환 | **부분.** 원문 키워드 검색이라 sudo 줄에 남으면 걸린다 |
| Wazuh 591 / 592 | 자체 수집기의 `File rotated` / `File size reduced` | 1건 | 3 / 8 | 순환 | **아니오(대체 있음).** 우리 수집기는 이런 메시지를 내지 않는다. 대신 `infra-auth-silent-p1/p2`가 `auth` 수집 중단을 잡는다 |

### 1-4. `journalctl`로 로그 지우기

| 출처 | 조건 | 시간창·임계 | 등급 | 오탐 주의 | 우리 데이터 |
|---|---|---|---|---|---|
| Elastic `defense_evasion_journalctl_clear_logs` | `journalctl` 실행 + 인자 `--vacuum-time=*`, `--vacuum-size=*`, `--vacuum-files=*`. 부모 인자가 `/etc/cron.daily/clean-journal-logs`이면 제외 | 1건 | medium, 47 | 정리 cron | **부분.** sudo `COMMAND=`로만. 지금 `o2c_sudo_risky_commands`에는 없다 |
| Sigma `proc_creation_lnx_clear_syslog` | `journalctl --vacuum`, `journalctl --rotate` 포함 | 1건 | high | 유지보수 | 위와 같음 |

### 1-5. 셸 히스토리 지우기

| 출처 | 조건 | 시간창·임계 | 등급 | 오탐 주의 | 우리 데이터 |
|---|---|---|---|---|---|
| Elastic `defense_evasion_shell_history_clearing_via_environment_variables` | 프로세스 환경 변수 `HISTSIZE=0`, `HISTFILESIZE=0`, `HISTCONTROL=ignorespace`, `HISTFILE=/dev/null` | 1건 | high, 73 | — | **아니오.** 프로세스 환경 변수는 Elastic Defend(`logs-endpoint.events.process*`)만 수집한다 |
| Elastic `defense_evasion_deletion_of_bash_command_line_history` | (`rm`·`echo`·`ln -sf /dev/null`·`truncate -s0` + `.bash_history`/`.zsh_history`) 또는 `history -c`, `export HISTFILE=/dev/null`·`HISTFILESIZE=0`, `unset HISTFILE`, `set +o history`. `timeout`·`kubectl`·`psql`·`bazel`·`git`·`jq`·`grep`, `stat -c %s history`는 제외 | 1건 | medium, 47 | 위 도구 | **부분.** `rm`·`truncate`를 sudo로 실행한 경우만 |
| Sigma `lnx_shell_clear_cmd_history` | 키워드 `history -c`, `history -w`, `export HISTFILESIZE=0`, `shopt -ou history`, `cat /dev/null >*sh_history`, `rm *sh_history`, `shred *sh_history`, `truncate -s0 *sh_history`, `chattr +i*sh_history` 등. `unset HISTFILE`은 오탐이 많아 주석 처리됨 | 1건 | high | Unknown | **아니오.** 셸 안 명령을 담은 로그가 없다 |
| Sigma `lnx_auditd_susp_histfile_operations` | `type=EXECVE` + 인자에 `.bash_history`, `.zsh_history`, `.zhistory`, `.history`, `.sh_history`, `fish_history` | 1건 | medium | 히스토리를 정리하는 정상 소프트웨어 | **아니오.** EXECVE 없음 |
| Sigma `proc_creation_lnx_susp_history_delete` | `rm`·`unlink`·`shred` + 히스토리 파일 경로 | 1건 | high | 정상 관리 작업 | **부분.** sudo로만 |

**기존 설정의 빈 패턴:** `o2c_sudo_risky_commands`의 `history -c`는 사실상 걸리지 않는다. `history`는 셸 내장 명령이라 sudo `COMMAND=`에 나오지 않는다(`sudo bash -c '… history -c'`처럼 셸을 거칠 때만 문자열로 보인다).

## 2. `authorized_keys` 수정·삭제

| 출처 | 조건 | 시간창·임계 | 등급 | 오탐 주의 | 우리 데이터 |
|---|---|---|---|---|---|
| Elastic `persistence_ssh_authorized_keys_modification`(cross-platform) | 파일 변경·생성, 이름 `authorized_keys`/`authorized_keys2`. **new_terms**: (`host.id`, `process.executable`) 조합이 지난 5일 처음. 제외: `vim`, `scp`, `touch`, `bsdtar`, `/var/lib/docker/*`, `google_guest_agent`, `jumpcloud-agent`, `puppet`, `chef-client` 등 | 1건(새 조합) | medium, 47 | 위 도구 | **아니오(지금).** 감시 규칙이 없다. 필요한 규칙은 이미 `docs/openobserve_config.md` "잡을 수 없는 신호"에 정리돼 있다(`-w … -p wa -k ssh_keys`, root·사용자 홈 경로 목록). 규칙이 생기면 "호스트+`exe` 첫 등장"은 5일 조회 SQL로 쓸 수 있다 |
| Elastic `defense_evasion_authorized_keys_file_deletion` | 파일 삭제, 이름 `authorized_keys`/`authorized_keys2`. 제외: `google_guest_agent`, `dockerd`, `containerd`, `/nix/store/*`, 경로에 `backup`·`ansible`·`puppet` | 1건 | low, 21 | 백업·Ansible·Puppet | **아니오(지금).** 파일 감시(`-w`)가 삭제도 남기는지는 **미확인**(감시 규칙 추가 때 시험 필요) |
| Splunk `linux_ssh_authorized_keys_modification` | 프로세스 `bash` 또는 `cat` + 명령줄에 `*/authorized_keys*` | 1건 | Anomaly, RBA 20 | 관리자가 키를 더하고 뺌, `echo` 필터 권장 | **아니오.** 실행 기록 없음 |
| Sigma | `rules/linux` 아래에서 `authorized_keys` 이름의 규칙을 찾지 못했다(파일 이름 기준, 본문 검색은 **미확인**) | — | — | — | — |
| Wazuh 5755 | sshd `bad ownership or modes for file`(권한 문제로 키 인증 거부) | 1건 | 3 | — | **예.** 수정 탐지는 아니고 참고용. Wazuh는 키 파일 변경을 syscheck(FIM)로 보며 규칙 파일에는 없다 |

오탐 주의(우리 환경): 우리 프로비저닝은 Ansible로 `authorized_keys`를 쓴다. Elastic이 경로 `*ansible*`을 빼는 것처럼, 우리도 실행 주체(AUID·`exe`)로 프로비저닝 쓰기를 구분해야 한다.

## 3. 특권 그룹에 사용자 추가

| 출처 | 조건 | 시간창·임계 | 등급 | 오탐 주의 | 우리 데이터 |
|---|---|---|---|---|---|
| Elastic `persistence_linux_user_added_to_privileged_group` | `usermod`·`adduser` 실행, 또는 `gpasswd` + `-a/--add/-M/--members`. 인자 중 하나가 `root`, `admin`, `wheel`, `staff`, `sudo`, `disk`, `video`, `shadow`, `lxc`, `lxd`. 구글 게스트 에이전트·`platform-python`·salt-minion 부모는 제외 | 1건 | low, 21 | 구성 관리 도구 | **예(다른 기록으로).** 기존 `infra-account-change`(P2)가 auditd 계정 관리 기록(`USER_MGMT`·`GRP_MGMT` 등)에서 `grp="<그룹>"`·`ID="<그룹>"`으로 특권 그룹 변경을 따로 표시한다 |
| Sigma `proc_creation_lnx_usermod_susp_group` | `usermod` + `-aG root` 또는 `-aG sudoers` | 1건 | medium | 정상 관리 작업 | 위와 같음 |
| Sigma `lnx_privileged_user_creation` | `secure`/`auth.log` 줄에 `new user` + `GID=0,`·`UID=0,`·`GID=10,`·`GID=27,` 중 하나 | 1건 | high | 관리 작업 | **예.** 원문 줄이 수집된다. 우리 알림은 같은 사건을 auditd로 세고 shadow-utils syslog 줄은 중복이라 세지 않는다. GID 10(wheel)·27(sudo)은 배포판마다 다르다 |
| Sigma `lnx_auditd_create_account` | `SYSCALL` + `exe`가 `/useradd`로 끝남, 또는 `type=ADD_USER` | 1건 | medium | 관리 작업 | **예**(`infra-account-change`) |
| Splunk `linux_auditd_add_user_account_type` | `type=ADD_USER` | 1건 | Anomaly (RBA 점수 **미확인**) | 자동화 | **예** |
| Wazuh 2960 / 2961 / 5901 / 5902 | gpasswd `added by` / 그 중 그룹 `sudo` / `new group` / `new user` | 1건 | 2 / 5 / 8 / 8 | — | **예** |

**목록 차이:** 우리 `o2c_privileged_groups`는 `wheel`, `sudo`, `docker`, `root`다. Elastic은 `admin`, `staff`, `disk`, `video`, `shadow`, `lxc`, `lxd`도 특권 그룹으로 본다. `docker`는 우리만 넣었다(docker 그룹은 root와 같은 권한이라 맞는 선택이다). `disk`·`shadow`는 우리 호스트에서도 의미가 있다(원시 디스크 읽기, `/etc/shadow` 읽기). 더할지는 결정 대상이다.

## 4. 비밀번호 스프레이 (한 출발지, 여러 계정)

| 출처 | 조건 | 시간창·임계 | 등급 | 오탐 주의 | 우리 데이터 |
|---|---|---|---|---|---|
| Elastic `credential_access_potential_password_spraying_attack` (ES\|QL) | `event.action in (ssh_login, user_login)`, `event.outcome == failure`, `source.ip` 있음. **출발지별**(호스트 구분 없음) | 5분 버킷, 서로 다른 `user.name` **> 10** 이고 실패 **≥ 30** | low, 21 | 문서화된 오탐 없음 | **예.** `event_action='ssh_login' AND event_outcome='failure'`를 `source_address`로 묶고 `count(DISTINCT user_name) > 10 AND count(*) >= 30` |
| Splunk `detect_password_spray_attempts` | Authentication 데이터모델 실패, `src`별 5분 구간 | 서로 다른 계정 **> 30** 이고 출발지 평균 + 3σ 이상(이상치) | TTP, RBA user 50 | 문서상 "없음". 데이터 소스는 Windows 4625 | **부분.** 3σ 기준선은 출발지별 과거 분포가 필요하다. 고정 임계는 Elastic 쪽이 단순하다 |
| Wazuh 5712 | `invalid user`(5710)가 같은 출발지에서 | 120초에 8회, `ignore=60` | 10 | — | **예** |
| Wazuh 5763 / 5720 / 40111 | 인증 실패(5760: `Failed password` 등)가 같은 출발지에서 / 5716 실패 같은 출발지 / `authentication_failed` 그룹 같은 출발지 | 120초 8회 / `frequency="8"`(timeframe 속성 없음, 기본값 **미확인**) / 160초 12회 | 10 / 10 / 10 | — | **예** |

주의:
- 우리 VRL은 `Invalid user X from …` 줄에 `user_name`·`event_reason='invalid user'`를 넣지만 **`event_outcome`은 넣지 않는다**(같은 시도의 `Failed password for invalid user` 줄과 이중으로 세지 않으려고). 비밀번호 인증을 끈 sshd는 `Failed password` 줄 없이 `Invalid user` 줄과 `Connection closed by invalid user … [preauth]` 줄만 남길 수 있다. 그런 호스트에서는 `event_outcome='failure'`만 세면 스프레이를 놓친다. 우리 호스트의 sshd 인증 설정 분포는 **미확인**이다. 스프레이 SQL은 `event_reason='invalid user'` 줄도 세는 쪽으로 두는 것이 안전하다. 같은 시도를 두 번 세도 서로 다른 계정 수는 그대로다. 하지만 `count(*) >= 30`은 부풀려진다. 실패 수는 (`user_name`, `source_port`) 조합을 중복 없이 세는 것을 제안한다(**미검증**).
- 기존 `infra-ssh-login-failures-per-source`(출발지별 5분 10회)는 계정 수와 무관하게 이미 울린다. 스프레이 규칙의 가치는 새 탐지라기보다 "여러 계정"이라는 성격을 알려 주는 데 있다.

### 참고: 무차별 대입 뒤 성공

| 출처 | 조건 | 시간창·임계 | 등급 | 우리 데이터 |
|---|---|---|---|---|
| Elastic `credential_access_potential_successful_linux_ssh_bruteforce` | EQL `sequence by host.id, source.ip, user.name`: 실패 `runs=25` 다음 성공 | `maxspan=15s` | high, 73 | **예(근사).** 기존 `infra-ssh-bruteforce-success`(P1, 같은 출발지·서버 15분 안 실패 ≥ 10 + 성공 ≥ 1). SQL은 순서(실패 **다음** 성공)를 표현하지 못하고 개수로 근사한다 |
| Elastic `…ssh_bruteforce_external` / `_internal` | 같은 `sequence`, 실패 `runs=60`. 출발지가 공인/사설 대역인지로 나눔 | `maxspan=30s` | low 21 / medium 47 | **예(근사)** |
| Wazuh 40112 | `authentication_success` 직전에 같은 출발지의 `authentication_failures`(40111 등) | `timeframe=240` | 12 | **예(근사)** |

## 5. 공개키 첫 사용·낯선 사용자/IP의 SSH 성공

| 출처 | 조건 | 시간창·임계 | 등급 | 오탐 주의 | 우리 데이터 |
|---|---|---|---|---|---|
| Elastic `initial_access_first_time_public_key_authentication` | `ssh_login` 성공, `system.auth.ssh.method: publickey`. **new_terms** `system.auth.ssh.signature`(키 지문) | 지난 5일 처음, 실행 구간 `now-9m` | low, 21 | 드물게 접속하는 사용자 | **부분.** `Accepted publickey for <user> from <ip> port <port> ssh2: <type> SHA256:<지문>` 줄에 지문이 있지만 VRL이 추출하지 않는다. SQL 정규식이나 VRL 필드 추가가 필요하다 |
| Elastic `initial_access_successful_ssh_authentication_by_unusual_ip` | `ssh_login` 성공. **new_terms** `related.ip` | 지난 5일 처음 | low, 21 | — | **예.** `source_address`별 첫 등장 시각이 최근 구간 안인지(조회 5일+). 스캔 비용은 **미확인** |
| Elastic `initial_access_successful_ssh_authentication_by_unusual_user` | `ssh_login` 성공. **new_terms** `related.user` | 지난 5일 처음 | low, 21 | 드물게 접속하는 사용자 | **예.** `user_name`으로 같은 방식 |
| Wazuh 10100 | `authentication_success` 그룹 + `if_fts`(처음 보는 값) | 첫 등장 | 4 | — | **예.** fts가 어떤 필드 조합을 쓰는지는 **미확인** |

- Elastic new_terms는 필드 하나(`related.ip` 또는 `related.user`)만 보므로 **호스트 구분 없이** 전체에서 처음인지를 본다.
- 기존 `infra-ssh-login-unregistered-source`와 다르다. 그것은 고정 허용 목록(`normal_sources`)으로 비교하고 학습이 없다. 새 정상 출발지는 등록 전까지 계속 울린다. 반면 "아는 출발지에서 처음 보는 사용자"나 "처음 보는 키"는 잡지 못한다. new_terms 방식은 그 둘을 잡지만, 5일 안에 한 번 본 값은 다시 알리지 않는다.

## 6. sshd 치명 오류

| 출처 | 조건 | 시간창·임계 | 등급 | 오탐 주의 | 우리 데이터 |
|---|---|---|---|---|---|
| Sigma `lnx_sshd_susp_ssh` | sshd 원문 키워드: `unexpected internal error`, `unknown or unsupported key type`, `invalid certificate signing key`, `invalid elliptic curve value`, `incorrect signature`, `error in libcrypto`, `unexpected bytes remain after decoding`, `fatal: buffer_get_string: bad string`, `Local: crc32 compensation attack`, `bad client public DH value`, `Corrupted MAC on input` | 1건 | medium | Unknown | **예.** `process_executable_name IN ('sshd','sshd-session')`(OpenSSH 9.8+) + `body LIKE` |
| Wazuh 5707 / 5714 | `fatal: buffer_get_string: bad string` / `Corrupted check bytes on`(5713) 뒤 `Local: crc32 compensation attack` | 1건 / 120초에 3회 | 14 / 14 | — | **예** |
| Wazuh 5701 / 5758 | `Bad protocol version identification` / `error: maximum authentication attempts exceeded` | 1건 | 8 / 8 | 스캐너 | **예** |
| Wazuh 5747 / 5748 / 5713 | `bad client public DH value` / `Corrupted MAC on input.` / `Corrupted check bytes on` | 1건 | 6 / 6 / 6 | 스캐너·깨진 클라이언트 | **예** |
| Wazuh 5704 → 5705 | `fatal: Timeout before authentication for` | 360초에 6회 | 4 → 10 | 스캔 | **예** |
| Wazuh 5706 | `Did not receive identification string from` | 1건 | 6 | 스캔 | **예** |
| Wazuh 5709·5750 등 | 소켓 오류, 협상 실패(`Unable to negotiate`, `no matching …`) | — | 0~2(무시) | 소음 | 참고: 업계도 협상 실패는 알리지 않는다 |
| Elastic `credential_access_ssh_backdoor_log` | `ssh`/`sshd` 프로세스가 수상한 파일(`/tmp/*`, `/dev/shm/*`, 숨김 파일 등)을 만듦 | 1건 | low, 21 | SSH 바이너리 정상 업데이트 | **아니오.** 파일 생성 이벤트가 없다. 오류 로그 탐지가 아니다 |

오탐 주의(우리 환경): 인터넷에 열린 sshd는 스캐너 때문에 `Corrupted MAC on input`, `Bad protocol version`, `Did not receive identification`이 자주 나올 수 있다. Wazuh가 이들을 6~8로 낮게 두는 이유다. 우리 7일 빈도는 **미확인**이므로 임계를 정하기 전에 세어 봐야 한다.

## 7. 방화벽 규칙 수정·방화벽 서비스 중지

| 출처 | 조건 | 시간창·임계 | 등급 | 오탐 주의 | 우리 데이터 |
|---|---|---|---|---|---|
| Sigma `lnx_auditd_disable_system_firewall` | `type=SERVICE_STOP`, `unit`이 `firewalld`, `iptables`, `ufw` | 1건 | high | 관리 작업 | **예.** `SERVICE_STOP` 수집됨. 재시작·재부팅의 중지 기록이 오탐이므로 `infra-auditd-stopped`처럼 "중지 뒤 일정 시간 시작 없음"으로 판정해야 한다 |
| Splunk `linux_auditd_disable_or_modify_system_firewall` | `type=SERVICE_STOP unit IN (firewalld, ufw)` | 1건 | Anomaly, RBA 20 | 자동화 | **예** |
| Elastic `defense_evasion_attempt_to_disable_iptables_or_firewall` | `ufw disable`; `iptables -F/--flush/-X/--delete-chain`(인자 정확히 2개); 부모가 `force-stop`인 iptables; 서비스 중지 명령 4종 + `firewalld`/`iptables`/`ip6tables`(`.service`) | 1건 | medium, 47 | — | **부분.** sudo로 실행한 것만. `o2c_sudo_risky_commands`가 이미 `iptables -F/--flush`, `nft flush ruleset`, `firewall-cmd --panic-on`, firewalld 중지를 본다 |
| Elastic `defense_evasion_linux_firewall_rule_creation_or_modification` | iptables 계열 + `-A/-I/-R/-P` + `DROP/ACCEPT/REJECT`; `nft add/insert/replace rule` + 같은 동작(`-c` 제외); `ufw deny/allow/reject`(`delete`·`--dry-run` 제외). 부모 제외: `firewalld`, `libvirtd`, `dockerd`, podman `netavark`, `cilium-agent`, **`fail2ban-server`**, `NetworkManager`, `tailscaled`, `kubelet` | 1건 | low, 21 | 컨테이너 런타임·fail2ban | **부분.** sudo로만. 우리 호스트는 Docker와 fail2ban을 쓰므로 실행 기록이 생겨도 이 두 부모 제외가 필수다 |
| Sigma `lnx_auditd_modify_system_firewall` | `type=EXECVE`: `iptables` + `a1`에 `DROP`; `firewall-cmd` + `remove`; `ufw` + `delete`; `nft` + `delete`/`flush` | 1건 | medium | 정상 관리 작업 | **아니오.** EXECVE 없음 |
| Sigma `proc_creation_lnx_disable_ufw` / `proc_creation_lnx_iptables_flush_ufw` | `ufw-init` + `stop`/`force-stop`/`flush` 또는 `ufw … disable` / iptables + `-F`·`-Z`·`-X` + `ufw-logging-*` 체인 | 1건 | medium / medium | 관리자 | **부분.** sudo로만 |
| Sigma `lnx_syslog_security_tools_disabling_syslog` | syslog 원문 `stopping iptables`, `stopping ip6tables`, `stopping firewalld` | 1건 | medium | 관리 작업 | **미확인.** 이 문구가 systemd 환경에서 실제로 찍히는지와 어느 스트림으로 가는지 확인하지 않았다 |
| Splunk `linux_iptables_firewall_modification` | `iptables … --dport … ACCEPT … &>/dev/null … tcp`, 부모 경로가 시스템 경로가 아님, 포트 3269·636·989·994·995·8443 중 **3개 이상** | 같은 부모·호스트 묶음 | Anomaly, RBA 20 | 감사·시험 | **아니오.** 특정 악성코드 패턴이라 우리에게 맞지 않는다 |
| Wazuh 40900~40903 | firewalld 오류 줄(` ERROR: `, 잘못된 체인, 이미 설정된 zone) | 1건 | 1~3 | — | 참고: Wazuh 기본 규칙에는 방화벽 규칙 변경 탐지가 없다 |

참고: 커널은 netfilter 테이블 변경 때 `NETFILTER_CFG` 감사 기록을 남길 수 있다. 이번에 읽은 규칙 중 이 기록을 쓰는 것은 없었다. Docker가 iptables를 자주 바꾸므로 소음이 클 것으로 보이며, 우리 스트림에 실제로 들어오는지는 **미확인**이다.

## 요약

| 탐지 | 업계 대표 조건 | 우리 데이터 | 이미 있는 알림 |
|---|---|---|---|
| auditd 설정 변경 | PATH `/etc/audit/*` (Sigma high) | 아니오(감시 규칙 필요, 프로비저닝 대상만) | — |
| 감사 규칙 삭제·auditd 중지 | `auditctl -D`, 서비스 중지, `DAEMON_END` | 예/부분(`CONFIG_CHANGE`, `-D` 재적재 오탐) | `infra-auditd-stopped` |
| syslog 설정 변경 | PATH `rsyslog.conf` 등 (Sigma high) | 아니오(감시 규칙 필요, 프로비저닝 대상만) | — |
| syslog 중지 | 중지 명령 + rsyslog (Elastic medium) | 부분(sudo, `SERVICE_STOP`) | `infra-sudo-risky-command` |
| 로그 파일 삭제 | 파일 삭제 이벤트 (Elastic medium) | 아니오(syscall 규칙 필요, `-w`는 불가, 프로비저닝 대상만) | `infra-auth-silent-*`(간접) |
| `journalctl --vacuum` | 실행 인자 (Elastic medium, Sigma high) | 부분(sudo만, 패턴 없음) | — |
| 셸 히스토리 지우기 | 환경 변수·셸 명령 (Elastic high/medium) | 아니오(`history -c` 패턴은 걸리지 않음) | — |
| `authorized_keys` 변경·삭제 | 파일 변경 + new_terms (Elastic medium/low) | 아니오(감시 규칙 필요, 프로비저닝 대상만, 이미 문서화) | — |
| 특권 그룹 추가 | `usermod`·`gpasswd` + 그룹 목록 (Elastic low, Sigma medium/high) | 예 | `infra-account-change` |
| 비밀번호 스프레이 | 5분, 계정 > 10, 실패 ≥ 30, 출발지별 (Elastic low) | 예(`Invalid user` 줄도 세야 함) | 출발지별 실패 알림이 간접 포함 |
| 공개키 첫 사용 | new_terms 키 지문 5일 (Elastic low) | 부분(지문 파싱 필요) | — |
| 낯선 사용자·IP 성공 | new_terms 5일 (Elastic low) | 예(긴 조회 SQL) | `infra-ssh-login-unregistered-source`(허용 목록 방식) |
| sshd 치명 오류 | 키워드 11개 (Sigma medium, Wazuh 6~14) | 예 | — |
| 방화벽 서비스 중지 | `SERVICE_STOP` firewalld/iptables/ufw (Sigma high) | 예(재시작 오탐 처리 필요) | sudo 중지 명령만 |
| 방화벽 규칙 수정 | 실행 인자 (Elastic low, Sigma medium) | 부분(sudo만) | `infra-sudo-risky-command`(flush·panic만) |

핵심:

1. 로그 은폐, 방화벽 규칙 변경, 특권 그룹 쪽 규칙은 대부분 **프로세스 실행 기록**을 전제로 한다(Elastic·Sigma·Splunk 45개 중 19개). 우리는 execve 기록을 일부러 껐으므로 이 규칙들은 sudo `COMMAND=` 경로로만 부분 대체된다. root 셸 안의 행위는 보이지 않는다.
2. 감시 규칙을 더하면 쓸 수 있는 것: auditd 설정(`/etc/audit/`), syslog 설정(`/etc/rsyslog.conf`, `/etc/rsyslog.d/`), `authorized_keys`. 세 가지 모두 기존 `infra-audit-watch-change`의 키 목록에 더하는 방식으로 이어진다. 단 **프로비저닝 대상 호스트에서만** 그렇다(에이전트만 설치한 호스트는 바꾸지 않는다).
3. 로그 파일 삭제는 파일 감시(`-w`)로는 안 되고 syscall 규칙이 필요하다.
4. 지금 데이터로 바로 만들 수 있는 새 알림: 비밀번호 스프레이, sshd 치명 오류, 방화벽 서비스 중지(`SERVICE_STOP`), 낯선 사용자·IP 성공(5일 첫 등장).
5. 업계 등급은 대부분 low~medium(Elastic 21~47, Splunk Anomaly)이다. high는 셸 히스토리 환경 변수, 무차별 대입 뒤 성공(Elastic 73)과 Sigma의 설정 변경·로그 지우기 규칙이다. **제안:** 무차별 대입 뒤 성공과 로그 은폐는 P1, 설정 변경·방화벽 중지·sshd 치명 오류·스프레이는 P2, 낯선 사용자·IP·첫 공개키는 P3. 이 등급은 업계 값이 아니라 우리 제안이다.

## 미확인 목록

- 옛 `exec_log` execve 규칙이 남은 호스트가 있는지
- `auditctl -D`·규칙 재적재 때 `CONFIG_CHANGE`의 `op=` 값
- 파일 감시(`-w … -p wa`)가 `authorized_keys` 삭제를 기록하는지
- 우리 호스트 sshd의 비밀번호 인증 설정 분포(스프레이 계수 방식에 영향)
- sshd 치명 오류 키워드의 우리 7일 빈도
- rsyslog 종료 줄과 `stopping firewalld` 같은 문구가 어느 스트림에 어떤 모양으로 들어오는지
- `NETFILTER_CFG` 기록 수집 여부
- Wazuh `timeframe` 기본값(5720처럼 생략된 경우)과 `if_fts` 키 필드
- 에이전트만 설치한 호스트에서 auditd가 돌고 수집되는지
- 5일 조회 SQL의 OpenObserve 스캔 비용
- Splunk `linux_auditd_add_user_account_type`의 RBA 점수

## 출처의 특이점

- Splunk `linux_auditd_possible_access_or_modification_of_sshd_config_file`은 이름과 달리 정규식이 `/etc/ssh/ssh_config.*`라서 클라이언트 설정에만 맞고 `sshd_config`에는 맞지 않는다. 설명 문장도 "ssh_config file"이라고 쓴다.
- Splunk `detect_password_spray_attempts`의 데이터 소스는 Windows 4625다. 리눅스 SSH용 고정 임계는 Elastic 규칙이 유일하다.
- Wazuh 5720은 `frequency="8"`만 있고 `timeframe` 속성이 없다.
- Sigma `lnx_shell_clear_cmd_history`는 `unset HISTFILE`을 오탐이 많다며 주석 처리했지만, Elastic `deletion_of_bash_command_line_history`는 이를 조건에 넣는다.
