# OpenObserve 알림 런북

> OpenObserve 알림(`roles/openobserve_config/defaults/main.yml`의 `o2c_alerts`)을 받았을 때의 대응 절차다. 네이버웍스 알림 메시지의 `▶ 런북` 링크가 이 문서의 각 절로 연결된다.
> 알림 정의와 전송 구조는 [openobserve_config.md](../openobserve_config.md), 로그 필드는 [ADR-0008](../adr/0008-log-structuring-edge-envelope-central-semantics.md)을 본다.

## 심각도

| 심각도 | 의미 | 응답 목표 |
|---|---|---|
| 🔴 P1 긴급 | 침해 또는 장애가 진행 중일 수 있다 | 즉시 확인 (업무 시간 외 포함) |
| 🟠 P2 경고 | 공격 시도나 이상 징후. 아직 피해는 확인되지 않았다 | 당일 확인 |
| 🟡 P3 주의 | 탐지·수집 품질 문제. 직접 피해는 없다 | 업무 시간에 처리 |

## 공통 절차

1. 메시지의 `▶ 로그 보기`로 OpenObserve에서 원문 로그를 연다. 시각은 UTC다(KST = UTC+9).
2. `■ 대상`의 호스트·출발지·사용자를 작업 일정, 배포 기록(Semaphore Task 이력)과 대조한다. Semaphore(39.116.31.43)와 사무실(59.25.177.53)에서 시작된 접속은 대부분 운영 작업이다.
3. 대응하면 결과(원인, 조치, 담당자)를 기록한다. ISMS 2.11.5(사고 대응) 증적이 된다.
4. 같은 알림이 반복되고 원인이 정상 작업이면 임계값이나 예외 조건을 고치는 PR을 낸다. 알림을 끄지 않는다.

---

<a id="root-login-success"></a>
## 🔴 root 계정 원격 로그인 성공 (`infra-root-login-success`)

**조건**: `security_logs`에서 `user_name = 'root'`인 SSH 로그인 성공이 5분 안에 1건 이상.

**왜 중요한가**: root 직접 접속은 누가 접속했는지 식별할 수 없고, 프로비저닝 이후에는 막혀야 한다(`PermitRootLogin`, KISA U-01). 성공 기록은 침해이거나 설정이 우회된 것이다.

**확인**
```bash
# 대상 서버에서
sudo grep -E "Accepted .* for root" /var/log/secure | tail      # Debian 계열: /var/log/auth.log
sudo sshd -T | grep -i permitrootlogin
last -i root | head
```

**대응**
- 출발지가 Semaphore·사무실이고 작업 시각과 맞으면 정상 작업이다. 부트스트랩 모드(아직 site.yml로 프로비저닝되지 않은 호스트)에서는 root 접속이 정상이다.
- 확인되지 않은 접속이면: 해당 세션 종료(`pkill -KILL -t <tty>`), root 비밀번호 변경, OpenBao 값 갱신, 보안 담당에게 보고한다.
- `PermitRootLogin`이 `yes`로 되어 있으면 site.yml(`security` 역할)을 다시 적용한다.

**격상**: 출발지가 외부 IP이고 작업자가 확인되지 않으면 즉시 침해 대응으로 전환한다.

---

<a id="kernel-disk-errors"></a>
## 🔴 커널·디스크 오류 발생 (`infra-kernel-disk-errors`)

**조건**: `system_logs`에 `Out of memory: Killed process`, `I/O error`, `EXT4-fs error`, `XFS ... Corruption` 패턴이 5분 안에 1건 이상.

**왜 중요한가**: OOM은 서비스 프로세스가 강제 종료됐다는 뜻이고, I/O·파일시스템 오류는 디스크 고장이나 데이터 손상의 전조다.

**확인**
```bash
sudo dmesg -T | grep -iE "out of memory|i/o error|ext4-fs error|xfs" | tail
free -h; ps aux --sort=-%mem | head -5          # OOM
sudo smartctl -H /dev/sdX; df -h; mount | grep ro, # 디스크
```

**대응**
- OOM: 종료된 프로세스가 서비스면 재기동 상태를 확인하고, 메모리 상위 프로세스와 한도(JVM 힙, 컨테이너 limit)를 점검한다.
- I/O·FS 오류: 먼저 백업 상태를 확인한다(RustFS snapshot, `restic snapshots`). 파일시스템이 읽기 전용으로 바뀌었으면 서비스 영향을 판단하고 디스크 교체·fsck 일정을 잡는다.

**격상**: 파일시스템이 읽기 전용으로 바뀌었거나 같은 디스크 오류가 반복되면 하드웨어 장애로 IDC에 연락한다.

---

<a id="ssh-login-failures-per-source"></a>
## 🟠 한 출발지에서 SSH 로그인 실패 급증 (`infra-ssh-login-failures-per-source`)

**조건**: 같은 `source_address`에서 5분 동안 SSH 로그인 실패 10회 이상.

**왜 중요한가**: 무차별 대입 공격의 전형적인 형태다. fail2ban이 동작하면 이 정도로 쌓이기 전에 차단돼야 한다.

**확인**
```bash
sudo fail2ban-client status sshd
sudo grep "<출발지IP>" /var/log/secure | tail
```

**대응**
- 사내·작업자 IP면 해당 자동화(Semaphore 작업 등)의 자격증명을 확인한다. 오늘 사례처럼 OpenBao 비밀번호가 실제와 다르면 같은 실패가 반복된다.
- 외부 IP면 fail2ban이 차단했는지 확인하고, 안 됐으면 방화벽에서 차단한다.

**격상**: 같은 출발지에서 로그인 **성공** 기록이 있으면 P1로 다룬다.

---

<a id="ssh-login-failures-per-host"></a>
## 🟠 한 서버에 SSH 로그인 실패 급증 (`infra-ssh-login-failures-per-host`)

**조건**: 한 서버에서 5분 동안 SSH 로그인 실패 50회 이상(출발지 무관).

**왜 중요한가**: 여러 출발지에서 오는 분산 공격이라 출발지별 알림과 fail2ban에 잡히지 않을 수 있다.

**대응**
- `▶ 로그 보기`에서 출발지 분포를 본다. 출발지가 많고 외부면 SSH 포트를 인터넷에 노출할 필요가 있는지 검토하고, 방화벽 허용 범위를 줄인다.
- 한두 개 내부 출발지면 자격증명이 틀린 자동화 작업이다. 해당 작업을 멈추고 자격증명을 고친다.

---

<a id="sudo-escalation-failure"></a>
## 🟠 sudo/su 권한 상승 실패 (`infra-sudo-escalation-failure`)

**조건**: sudo/su 인증 실패 또는 `NOT in sudoers` 기록이 5분 안에 1건 이상. 성공은 알리지 않고 기록만 한다.

**왜 중요한가**: 탈취한 일반 계정으로 권한 상승을 시도하는 단계일 수 있다. 단순 비밀번호 오입력도 같은 기록을 남긴다.

**확인**
```bash
sudo grep -E "(sudo|su)(\[[0-9]+\])?: .*(authentication failure|NOT in sudoers|FAILED SU)" /var/log/secure | tail
last -i <사용자> | head
```

**대응**
- 해당 사용자에게 시도 여부를 확인한다.
- 본인이 아니면 계정을 잠그고(`usermod -L`), 비밀번호를 바꾸고, 그 계정의 접속 출발지를 추적한다.

---

<a id="log-parse-errors"></a>
## 🟡 로그 해석 실패율 상승 (`infra-log-parse-errors-security-logs`, `infra-log-parse-errors-system-logs`)

**조건**: 30분 동안 20줄 이상 들어온 서버에서 `log_parse_error = true` 비율이 10% 이상.

**왜 중요한가**: 해석되지 않은 로그에는 `event_action`, `user_name`, `source_address` 같은 필드가 없어서 위 보안·장애 알림에 잡히지 않는다. 탐지 공백이다.

**대응**
- 해당 서버에서 최근 패키지 업데이트(openssh, sudo, rsyslog)로 로그 형식이 바뀌었는지 확인한다.
- OpenObserve에서 `log_parse_error = true`인 원문을 몇 줄 뽑아, 수집기 설정(`roles/monitoring/templates/otelcol-contrib.yaml.j2`)이나 VRL 함수(`roles/openobserve_config/files/vrl/`)를 고치는 PR을 낸다.

---

<a id="openobserve-health"></a>
## 🔴 OpenObserve 응답 없음 (ns0266 `openobserve-health.timer`)

**조건**: ns0266이 5분마다 OpenObserve `/healthz`를 확인해, 실패하면 OpenObserve를 거치지 않고 네이버웍스 webhook으로 직접 P1을 보낸다. 같은 장애는 60분마다만 다시 통지하고 복구 통지는 없다(통지가 멈추면 복구). ns0266·ns0332 동시 장애는 감수한다.

**왜 중요한가**: OpenObserve가 죽으면 이 문서의 모든 알림이 동작하지 않는다.

**확인**
```bash
# ns0332
systemctl status openobserve; df -h; free -m
# ns0266 (확인 쪽)
systemctl list-timers openobserve-health.timer
journalctl -u openobserve-health.service -n 20
```

**대응**: ns0332의 OpenObserve 서비스·디스크·메모리를 복구한다. 복구 뒤 Silent Host 알림이 남아 있으면 수집 재개를 확인한다. ns0266에서 타이머 자체가 안 돌면 `Host Agents — Config`를 다시 실행한다.

**수동 검증 절차** (배포 후 한 번, 또는 webhook 값을 바꾼 뒤): ns0266에서 대상 URL을 틀린 값으로 한 번 실행해 통지가 도착하는지 본다.
```bash
sudo rm -f /var/lib/openobserve-health/notified
sudo O2_HEALTH_URL_OVERRIDE=http://127.0.0.1:1/healthz /usr/local/sbin/openobserve-health-check
```
네이버웍스에 `[P1 긴급] OpenObserve 응답 없음`이 도착하면 정상이다(종료코드 0). 통지 뒤 60분 동안은 같은 장애로 보고 재통지하지 않으므로, 이 시험 뒤에는 위 첫 줄처럼 상태 파일을 지운다(실제 장애가 아니므로 상태가 남지 않게 한다).
