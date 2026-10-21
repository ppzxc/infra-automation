# OpenObserve 알림 런북

> OpenObserve 알림(`roles/openobserve_config/defaults/main.yml`의 `o2c_alerts`)을 받았을 때의 대응 절차다. 네이버웍스 알림 메시지의 `▶ 런북` 링크가 이 문서의 각 절로 연결된다.
> 알림 정의와 전송 구조는 [openobserve_config.md](../openobserve_config.md), 로그 필드는 [ADR-0008](../adr/0008-log-structuring-edge-envelope-central-semantics.md)을 본다.

## 심각도

| 심각도 | 의미 | 응답 목표 |
|---|---|---|
| 🔴 P1 긴급 | 장애·데이터 손실·침해가 진행 중이거나 수 시간 내 임박 | 즉시 확인 (업무 시간 외 포함) |
| 🟠 P2 경고 | 방치하면 하루~며칠 내 P1이 된다 | 당일 확인 |
| 🟡 P3 주의 | 탐지·수집 품질 문제. 직접 피해는 없다 | 업무 시간에 처리 |

### 재통지 원칙 (Event Alert / State Alert)

- **Event Alert**: 사건이 일어났다는 알림. silence가 조회 구간과 같아 구간마다 1번만 온다.
- **State Alert**: 어떤 상태가 계속된다는 알림. 상태가 이어지는 동안 P1은 60분, P2·P3은 1440분(하루 1번)마다 다시 온다. 복구 통지는 없다(통지가 멈추면 복구).
- 이중 등급 알림(디스크·inode·메모리)은 P2가 "P2 이상 P1 미만" 구간만 잡아 같은 대상에 P1·P2가 동시에 오지 않는다.

## 공통 절차

1. 메시지의 `▶ 로그 보기`로 OpenObserve에서 원문 로그를 연다. 시각은 UTC다(KST = UTC+9).
2. `■ 대상`의 호스트·출발지·사용자를 작업 일정, 배포 기록(Semaphore Task 이력)과 대조한다. Semaphore와 사무실에서 시작된 접속은 대부분 운영 작업이다(정상 출발지 목록은 OpenBao `normal_sources`).
3. 대응하면 결과(원인, 조치, 담당자)를 기록한다. ISMS 2.11.5(사고 대응) 증적이 된다.
4. 같은 알림이 반복되고 원인이 정상 작업이면 임계값이나 예외 조건을 고치는 PR을 낸다. 알림을 끄지 않는다.

---

<a id="root-login-success"></a>
## 🔴 root 계정 원격 로그인 성공 — 외부 출발지 (`infra-root-login-success`)

**조건**: `security_logs`에서 `user_name = 'root'`인 SSH 로그인 성공이 5분 안에 1건 이상이고, 출발지가 **정상 출발지 목록에도 사설 대역에도 없을 때**(진짜 외부 출발지). 목록의 출발지(kind 무관)와 미등록 사설 대역은 아래 P2(알고 있는 출발지)로 간다. 출발지 값이 없는 로그인은 알 수 없는 출발지라 이 P1이다.

**정상 출발지 목록**: OpenBao `agents/openobserve`의 `normal_sources`(`[{"address": "<IP>", "kind": "semaphore|office"}]`)에만 둔다. 저장소에는 주소를 두지 않는다. 바꾼 뒤 `OpenObserve — Config`를 다시 실행하면 반영된다. `kind`는 구분용 표시이고 판정은 같다(semaphore·office 모두 P1에서 빠지고 P2로 간다). 사설 대역은 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16이다. 목록이 비어 있으면 모든 공인 출발지 root 로그인이 이 P1로 오고 사설 대역은 P2로 간다. SSH 로그인 실패 급증 알림에는 이 목록을 적용하지 않는다(정상 출발지의 실패 급증도 신호다).

**왜 중요한가**: root 직접 접속은 누가 접속했는지 식별할 수 없고, 프로비저닝 이후에는 막혀야 한다(`PermitRootLogin`, KISA U-01). 등록되지도 사내도 아닌 곳의 성공 기록은 침해이거나 설정이 우회된 것이다.

**확인**
```bash
# 대상 서버에서
sudo grep -E "Accepted .* for root" /var/log/secure | tail      # Debian 계열: /var/log/auth.log
sudo sshd -T | grep -i permitrootlogin
last -i root | head
```

**대응**
- 출발지가 새로 편입된 Semaphore·사무실 주소로 확인되면 `normal_sources`에 추가하고 Config를 다시 실행한다. 부트스트랩 모드(아직 site.yml로 프로비저닝되지 않은 호스트)에서는 root 접속이 정상이지만 출발지는 보통 Semaphore 목록에 있다.
- 확인되지 않은 접속이면: 해당 세션 종료(`pkill -KILL -t <tty>`), root 비밀번호 변경, OpenBao 값 갱신, 보안 담당에게 보고한다.
- `PermitRootLogin`이 `yes`로 되어 있으면 site.yml(`security` 역할)을 다시 적용한다.

**격상**: 출발지가 외부 IP이고 작업자가 확인되지 않으면 즉시 침해 대응으로 전환한다.

---

<a id="root-login-known"></a>
## 🟠 root 계정 원격 로그인 성공 — 알고 있는 출발지 (`infra-root-login-known`)

**조건**: `user_name = 'root'`인 SSH 로그인 성공이 5분 안에 1건 이상이고, 출발지가 `normal_sources`에 있거나(kind 무관: semaphore·office) 목록에 없는 사설 대역(10/8, 172.16/12, 192.168/16, 127/8, 169.254/16)일 때. 재통지 간격은 기본 60분이고 역할 변수 `o2c_root_known_silence_minutes`로 바꾼다. 이전의 하루 요약 알림(`infra-root-login-office-daily`, P3)을 대체하며 기존 알림은 기본 폐기 목록(`o2c_retired_alerts`)에 있어 반영 때 삭제된다.

**왜 중요한가**: 알고 있는 출발지여도 정책상 금지된 root 직접 접속(`PermitRootLogin`)이 일어났다는 뜻이다. 등록된 출발지면 작업·배포일 가능성이 높고, 미등록 사설 출발지면 내부 이동(횡적 이동) 가능성을 확인해야 한다.

**대응**
- 등록된 출발지면 작업·배포 일정과 대조하고, 일반 계정 + sudo로 전환하도록 안내한다. 배포 자동화가 root로 접속하면 접속 계정을 바꾸는 PR을 낸다.
- 미등록 사설 출발지면 그 장비의 소유자와 접속 경위를 확인한다. 정상 출발지로 확정되면 `normal_sources`에 추가하고 Config를 다시 실행한다.
- 확인되지 않으면 세션 종료, root 비밀번호 변경 후 위 P1 절차(외부 출발지)로 격상한다.

---

<a id="oom-kill"></a>
## 🟠 OOM kill로 프로세스 강제 종료 (`infra-oom-kill`)

**조건**: `system_logs`에 `Killed process`, `Out of memory: Kill process`, `invoked oom-killer`가 대소문자와 상관없이 5분 안에 1건 이상. 컨테이너 cgroup OOM(`Memory cgroup out of memory: Killed process`)과 CentOS 6/7 형식을 포함한다. 같은 상태는 조회 구간(5분)마다 다시 통지된다(Event Alert).

**왜 중요한가**: 서비스 프로세스가 강제 종료됐다는 뜻이다. 반복되면 다른 서비스와 서버 전체로 번진다.

**확인**
```bash
sudo dmesg -T | grep -iE "out of memory|killed process|oom-killer" | tail
free -h; ps aux --sort=-%mem | head -5
docker stats --no-stream        # 컨테이너 한도(cgroup) OOM이면
```

**대응**
- `■ 대상`의 종료된 프로세스가 서비스면 재기동 상태를 확인한다.
- 메모리 상위 프로세스와 한도(JVM 힙, 컨테이너 limit)를 점검하고, 반복되면 증설이나 한도 조정을 계획한다.

**격상**: 같은 호스트에서 OOM이 반복되며 핵심 서비스가 계속 죽으면 P1로 다룬다.

---

<a id="disk-fs-errors"></a>
## 🔴 디스크 I/O·파일시스템 오류 발생 (`infra-disk-fs-errors`)

**조건**: `system_logs`에 `I/O error`, `EXT4-fs error`, `XFS ... Corruption`, `blk_update_request`, `Buffer I/O error`가 대소문자와 상관없이 5분 안에 1건 이상(Event Alert).

**왜 중요한가**: 디스크 고장이나 데이터 손상의 전조다. 프로세스 종료(OOM)와 달리 데이터 손실 위험이 있어 P1로 따로 통지한다.

**확인**
```bash
sudo dmesg -T | grep -iE "i/o error|ext4-fs error|xfs|blk_update_request" | tail
sudo smartctl -H /dev/sdX; df -h; mount | grep "ro,"
```

**대응**
- 먼저 백업 상태를 확인한다(RustFS snapshot, `restic snapshots`).
- 파일시스템이 읽기 전용으로 바뀌었으면 서비스 영향을 판단하고 디스크 교체·fsck 일정을 잡는다.

**격상**: 파일시스템이 읽기 전용으로 바뀌었거나 같은 디스크 오류가 반복되면 하드웨어 장애로 IDC에 연락한다.

---

<a id="app-log-errors"></a>
## 🟠 컨테이너 로그에 ERROR 이상 기록 (`infra-app-log-errors`)

**조건**: `app_logs`에서 수집기가 올린 `severity`가 error 이상(`error`·`err`·`severe`·`fatal`·`critical`·`panic`·`dpanic`, 대소문자 무시)인 줄이 호스트·컨테이너별로 5분 안에 1건 이상(Event Alert).

**레벨이 올라오는 형식**: JSON 한 줄 로그의 `level` 또는 `log.level`(앱·Caddy), valkey 텍스트 로그의 레벨 문자. keepalived처럼 레벨이 없는 로그와 JSON이 아닌 줄(스택 트레이스 이어지는 줄 등)은 알림 대상이 아니다(키워드로 추정하지 않는다). WARN은 알리지 않고 검색용으로만 남는다.

**왜 중요한가**: 앱 장애, 요청 실패, DB·큐·캐시 연결 문제의 첫 신호일 수 있다.

**확인**
```bash
# OpenObserve에서: app_logs, host_name=<행의 호스트>, container_name=<행의 컨테이너>, severity가 error 이상
# 노드에서 직접 볼 때
docker logs --since 10m <컨테이너 이름> 2>&1 | grep -iE '"level":"(error|fatal)"' | tail
```

**대응**
- ERROR 원문과 직전 줄로 원인을 좁힌다(DB·RabbitMQ·valkey 연결, 설정 오류).
- 같은 시각의 VIP 전환, valkey 알림, Silent Host가 있는지 대조한다.
- 서비스 영향이 있으면 해당 노드를 서비스에서 뺀다(valkey 수동 페일오버 → keepalived 정지).

**격상**: 여러 노드에서 동시에 오거나 앱 헬스가 DOWN이면 서비스 장애로 처리한다.

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

**대응**: ns0332의 OpenObserve 서비스·디스크·메모리를 복구한다. 복구 뒤 Silent Host 알림이 남아 있으면 수집 재개를 확인한다. ns0266에서 타이머 자체가 안 돌면 `Host Agents — Config All`를 다시 실행한다.

**수동 검증 절차** (배포 후 한 번, 또는 webhook 값을 바꾼 뒤): ns0266에서 대상 URL을 틀린 값으로 한 번 실행해 통지가 도착하는지 본다.
```bash
sudo rm -f /var/lib/openobserve-health/notified
sudo O2_HEALTH_URL_OVERRIDE=http://127.0.0.1:1/healthz /usr/local/sbin/openobserve-health-check
```
네이버웍스에 `[P1 긴급] OpenObserve 응답 없음`이 도착하면 정상이다(종료코드 0). 통지 뒤 60분 동안은 같은 장애로 보고 재통지하지 않으므로, 이 시험 뒤에는 위 첫 줄처럼 상태 파일을 지운다(실제 장애가 아니므로 상태가 남지 않게 한다).

<a id="silent-host"></a>
## 🟠/🔴 Silent Host — 메트릭 하트비트 끊김 (`infra-silent-host-p2`, `infra-silent-host-p1`)

수집 로스터 호스트(인벤토리 `servers` − Host Agents Exclusion − Host Agents Backup Only, ns0266·ns0332 포함)에서 `system_memory_usage` 하트비트가 15분 넘게 끊기면 P2(3시간 미만), 3시간 넘게 끊기면 P1이다. 같은 호스트에 P2와 P1이 동시에 오지 않는다. 서버가 내려가도(서버 응답 없음) 수집기가 멈춰도 같이 걸린다.

**왜 중요한가**: OpenObserve는 약 5시간보다 오래된 로그를 받지 않는다. 이 시간이 지나면 이 구간 로그는 OpenObserve로 복구되지 않음 — ISMS 로그 증거가 중앙에서 영구히 빠진다(2026-10 CentOS 6 수집기 중단 사고, #161).

**확인**
1. 같은 호스트의 서버 응답 없음(Unreachable Host) 알림이 있으면 그쪽이 원인이다. 서버·네트워크부터 복구한다.
2. 서버가 살아 있으면 호스트에서 `systemctl status otelcol-contrib`(CentOS 6은 `service otelcol-contrib status`)와 최근 로그를 본다.

**대응**: 수집기를 재기동하고 하트비트가 돌아오는지 본다. P1이면 끊긴 구간 로그가 5시간 한도 안에 들어오는지 확인하고, 넘었다면 호스트의 원본 로그를 보존한다. 며칠 이상 계획 정지하는 호스트는 OpenBao `silent_host_exceptions`에 만료일과 함께 등록하고 `OpenObserve — Config`를 다시 실행한다. 호스트를 편입·폐기했다면 같은 Config 재실행이 필요하다.

---

<a id="app-telemetry-silent"></a>
## 🟠 앱 텔레메트리 무소식 — funa JVM 메트릭 끊김 (`infra-app-telemetry-silent`)

OpenBao `hosts/<host>/agents`의 `otel_app_telemetry`가 켜진 호스트에서 funa JVM 메트릭(`jvm_memory_used`, `service_name=funa`)이 15분 넘게 오지 않으면 온다. 스위치가 꺼진 호스트는 대상이 아니다. 대상 목록은 `OpenObserve — Config`를 실행할 때 만들어지므로 스위치를 바꾸면 Config를 다시 실행한다.

**왜 중요한가**: 2026-10-01처럼 앱 텔레메트리(트레이스, 앱 메트릭)가 알림 없이 버려질 수 있다.

**확인**
1. 같은 호스트의 Silent Host 알림이 있으면 수집기 전체가 원인이다. 그쪽부터 복구한다.
2. 호스트에서 `systemctl status otelcol-contrib`와 OTLP 수신기 설정(스위치가 렌더링에 반영됐는지)을 본다.
3. funa 컨테이너가 떠 있는지, OTLP exporter 환경 변수가 맞는지 본다.

**대응**: 원인을 고치고 메트릭이 돌아오는지 본다. 의도적으로 끈 것이면 `otel_app_telemetry`를 끄고 Config를 다시 실행한다.

---

<a id="unreachable-host"></a>
## 🔴 서버 응답 없음 — Unreachable Host (`infra-unreachable-host`)

Semaphore 호스트(ns0266)의 수집기가 `servers` 전체(Host Agents Backup Only 포함)의 SSH 포트에 60초마다 접속을 시도하고, `tcpcheck.status`가 5분 연속 0(접속 실패)이면 P1이다. 통지 행에 대상 `<주소>:<포트>`가 나온다. P1이라 해소될 때까지 60분마다 다시 온다.

**왜 중요한가**: 서버·네트워크가 내려갔을 가능성이 크다. 접속이 된다고 OS가 건강하다는 뜻은 아니며 이 알림은 도달성만 본다.

**Silent Host와의 구분**
| 알림 | 의미 | 보는 곳 |
|---|---|---|
| 서버 응답 없음 | 서버의 SSH 포트에 접속이 안 됨(서버·네트워크 다운) | ns0266이 외부에서 확인 |
| Silent Host | 서버가 보내던 메트릭 하트비트가 끊김(수집기 중단 또는 서버 다운) | 서버 안의 수집기가 보냄 |

서버가 다운이면 두 알림이 같은 호스트에 함께 올 수 있다(수집 로스터 호스트). 이때는 서버 응답 없음이 원인이므로 서버·네트워크부터 복구하고, 복구되면 수집기도 돌아와 Silent Host가 멈춘다. Backup Only 호스트는 로그를 보내지 않아 Silent Host 대상이 아니며 이 알림으로만 감시된다. 서버 응답 없음 없이 Silent Host만 오면 서버는 살아 있고 수집기만 멈춘 것이다.

**확인**
```bash
# ns0266에서 해당 주소·포트로 직접
nc -vz -w 5 <주소> <포트>
```
1. 접속이 안 되면 서버 전원·콘솔·네트워크 경로를 확인한다. 서버가 계획 정지라면 그대로 둔다(정지 중에는 계속 온다).
2. 접속이 되는데 알림이 온다면 ns0266 수집기(`otelcol-contrib`) 상태, ns0266에서 대상까지의 방화벽 경로, OpenBao `hosts/<호스트>`의 `ansible_port`·`public_ip`가 실제 SSH 포트·주소와 같은지 본다(대상은 OpenBao 값으로 만든다).
3. ns0266이 죽으면 `tcpcheck` 메트릭 전체가 끊긴다. 이는 ns0266의 Silent Host 알림으로 잡힌다.

**편입·폐기**: 대상 목록은 검사하는 쪽이 Host Agents 실행 때마다 `servers` 전체의 OpenBao `hosts/<호스트>`(주소 `public_ip`, 비표준 SSH 포트 `ansible_port`)에서 만든다. 실행 범위(`target_hosts`)와 무관하다. 호스트를 편입·폐기하면 `Host Agents — Deploy All`(또는 Config)를 ns0266에 다시 반영해야 한다.
**제외**: 검사하는 쪽에서 도달할 수 없는 것이 정상인 서버는 Semaphore 인벤토리(`hosts`)의 `tcpcheck_excluded` 그룹에 넣는다(`host_agents_excluded`와 같은 방식). 현재 `ns0229`·`ns0246`이 들어 있다: 순수 내부 IP(10.10.10.x)만 할당된 서버라 공인 `218.234.206.79`의 포트 2002·2001 포워딩으로만 접근하고, ns0266에서는 이 경로가 막혀 있다(`connect: no route to host`). 그래서 서버 도달성 감시의 사각지대다. 접속 못 하는 이유가 없어지면 그룹에서 뺀다. 목록에서 빠진 서버는 도달성 알림을 받지 못한다. Extra variables `host_agents_tcpcheck_excluded`로도 지정할 수 있다. 저장소의 `inventory/group_vars`는 Semaphore에서 읽히지 않으니 거기에 두지 않는다.
<a id="backup-failure"></a>
## 🟠 백업 실패 (`infra-backup-failure`)

`backup_logs`에서 `job=backup`, `success=false` 이벤트가 오면 발생 즉시 P2로 한 번 알린다(Event Alert). 호스트는 `host` 필드다.

**왜 중요한가**: 복구 지점이 늘지 않는다. 방치하면 26시간 뒤 백업 누락으로 이어진다.

**확인**: 행의 호스트에서 `tail -1 /var/log/host-agents/backup.jsonl`의 `error`, 저장소(RustFS) 접속·자격증명·디스크 여유.

**대응**: 원인을 고친 뒤 호스트에서 백업을 수동 실행해 성공을 확인한다.

<a id="integrity-check-failure"></a>
## 🟠 백업 저장소 무결성 검사 실패 (`infra-integrity-check-failure`)

Repo Maintenance의 `job=maintenance`, `command=check`, `success=false` 이벤트를 즉시 P2로 알린다(Event Alert).

**왜 중요한가**: 저장소 손상 가능성이 있고, 실패한 호스트는 prune이 차단된다.

**확인·대응**: Semaphore Repo Maintenance 실행 로그에서 해당 호스트의 check 오류를 보고 `restic check`로 손상 범위를 확인한다. 손상이면 복구·재초기화와 백업 재실행을 계획한다.

<a id="backup-missing"></a>
## 🟠 백업 누락 (`infra-backup-missing`)

수집 로스터 호스트(Backup Only 제외, ns0266·ns0332 포함)의 마지막 성공 `job=backup`이 26시간을 넘으면 하루 1번 P2로 알린다(State Alert). 배포만 되고 한 번도 백업하지 않은 호스트도 걸린다.

**확인**
1. **같은 호스트의 Silent Host 알림이 있는지 먼저 확인한다.** 수집기가 멈췄다면 백업은 돌았어도 이벤트만 빠진 것일 수 있다.
2. 호스트의 `/etc/cron.d/host-agents-backup`(또는 systemd timer)과 `/var/log/host-agents/backup.jsonl` 마지막 줄을 본다. 놓친 실행은 보정되지 않는다.
3. 신규 편입 호스트면 Host Agents Deploy가 실행됐는지 확인한다.

**구분**: 서버 다운은 Unreachable Host(서버 응답 없음), 수집기 중단은 Silent Host, 백업 이벤트만 없는 것이 백업 누락이다.

<a id="maintenance-missing"></a>
## 🟠 유지보수 누락 (`infra-maintenance-missing`)

유지보수 로스터(Backup Only 포함) 호스트의 마지막 `command=check`가 8일을 넘으면 하루 1번 P2로 알린다(State Alert). Backup Only 호스트는 백업 이벤트를 보내지 않으므로 백업 누락이 아니라 이 알림과 무결성 검사 실패로만 감시된다.

**확인·대응**: Semaphore Repo Maintenance 템플릿의 최근 실행과 스케줄, 해당 호스트가 제외·접속 실패로 건너뛰어졌는지 확인한 뒤 수동으로 Repo Maintenance를 실행한다.

---

## 스위치 syslog 알림 (Spec #277)

스위치 syslog는 수신 서버(#276)를 거쳐 `system_logs`에 `service_name=switch-syslog`로 들어오고, `switch_syslog_semantics` 함수가 로그 한 줄에 장비와 Cisco 메시지 필드를 붙인다. `host_name`은 스위치가 아니라 로그를 받는 서버이고 `severity`는 항상 0이므로, 스위치로 거를 때는 아래 필드를 쓴다. 원문 `body`는 바뀌지 않는다.

| 필드 | 뜻 |
|---|---|
| `device_id` | 관리번호(`ns0347`). 장비 이름 앞부분의 `ns` + 숫자이며 인벤토리 호스트명과 같다. 이름에 없으면 필드가 없다 |
| `device_name` | 원문의 장비 이름을 소문자로 바꾸고 도메인을 뗀 값(`ns0347-3560x`). 알림은 `device_id`가 없으면 이 값으로 장비를 센다 |
| `cisco_facility`, `cisco_mnemonic` | `%SW_MATM-4-MACFLAP_NOTIF`의 `SW_MATM`, `MACFLAP_NOTIF` |
| `event_name` | 메시지 코드 전체(`SW_MATM-4-MACFLAP_NOTIF`, `%` 제외). 잡음·알림 목록은 이 값으로 적는다 |
| `log_syslog_severity_code`, `log_syslog_severity_name` | 메시지 코드의 심각도 0~7과 이름(emergency, alert, critical, error, warning, notice, informational, debug) |

**한계**: 장비 시각은 연도가 없고 시간대가 장비 설정에 달려 있어 `_timestamp`(수신 시각)가 기준이다. 장비 시각은 원문에 그대로 있다. 알림은 일부 메시지에만 생기는 필드를 쓰지 않고 `body`에서 뽑는다(그 메시지가 한 번도 오지 않은 동안 컬럼이 없어 알림이 `unknown field`로 오류가 나지 않게).

**목록 갱신 절차**: 아래 목록은 모두 역할 기본 변수(`roles/openobserve_config/defaults/main.yml`)이며 Semaphore의 `OpenObserve — Config` 템플릿 Environment(`-e`)나 저장소 기본값을 고쳐 반영한다. 고친 뒤 **`OpenObserve — Config`를 다시 실행**해야 알림 SQL이 바뀐다.
- `o2c_switch_syslog_roster`(수신 중단 감시 장비, 관리번호 목록): 새 스위치에 syslog 전송을 설정하고 로그가 `switch-syslog`로 도착하는 것을 확인한 **뒤에** 추가한다. 철거·교체한 장비는 뺀다. 전송을 설정하지 않은 장비를 넣으면 허위 알림이 온다.
- `o2c_switch_uplinks`(업링크 포트 다운 감시, `[{device: ns0250, port: Gi1/0/49}]`): 포트는 약어(`Gi1/0/49`)와 전체 이름(`GigabitEthernet1/0/49`) 어느 쪽이든 쓴다(링크 다운 메시지는 전체 이름, MAC 플랩 메시지는 약어로 찍힌다). **목록이 비어 있으면 규칙 자체가 만들어지지 않는다.** 링크 다운은 심각도 3이라 미사용 포트 다운까지 전부 알림이 되므로 핵심 연결만 넣는다. 용어 `Watched Port`(CONTEXT.md)는 SNMP 감시(#175)의 라벨 기반 개념이며 이 로그 기반 목록과 별개다.
- `o2c_switch_noise_events`(잡음 메시지 코드): 반복되는 의미 없는 메시지를 `FACILITY-SEVERITY-MNEMONIC`로 추가한다. 기본값은 ARP 해소 실패(`ADJ-3-RESOLVE_REQ`)다. 잡음으로 뺀 줄도 검색은 그대로 되고 수신 중단 판단에는 수신으로 센다. 설정 변경·로그인 실패·MAC 플랩 메시지 코드를 잡음에 넣으면 그 알림도 꺼지므로 넣지 않는다.
- 임계값: `o2c_switch_login_fail_threshold`(기본 5회/5분), `o2c_switch_macflap_threshold`(기본 2회/10분), `o2c_switch_severity_max`(기본 2), `o2c_switch_silent_hours`(기본 24시간).

**수신 중단 판정**: `device_id` 필드가 있거나 원문에 장비 이름(관리번호)이 있으면 수신 중으로 센다. 파이프라인을 반영한 직후에도, 새 장비를 목록에 더한 직후에도 이전 로그 때문에 오탐이 나지 않는다. 원문에서 찾으므로 다른 장비 메시지가 이 장비 이름을 본문에 언급하면 조용한 장비를 놓칠 수 있다(관리번호는 보통 본문에 나오지 않는다).

**수신 중단 알림의 한계**: 스위치 syslog는 이벤트가 있을 때만 전송되므로 조용한 장비와 고장난 전송을 구분하지 못한다. 그래서 기준 시간을 24시간으로 길게 두었다. 2주 관찰한 뒤 오탐이 있으면 `o2c_switch_silent_hours`를 늘리고, 놓치는 것이 있으면 줄인다. 장비 자체가 내려간 것은 이 알림이 아니라 SNMP 알림(#175)이 맡는다.

<a id="switch-config-change"></a>
### 🟠 스위치 설정 변경 감지 (`infra-switch-config-change`)

**조건**: `SYS-5-CONFIG_I`(설정 모드를 마칠 때 장비가 남기는 메시지) 1건부터 5분 구간마다 한 번(Event Alert). 대상 행에 장비와 원문의 변경 주체(`Configured from console by <사용자> on vty0 (<주소>)`)가 나온다.

**왜 중요한가**: 승인되지 않은 설정 변경은 장애나 침해의 시작이다. 변경 이력은 ISMS 변경 관리 증적이다.

**확인**: 행의 사용자·접속 방식·주소를 작업 일정(Semaphore 이력, 작업 요청)과 대조한다. 로그 보기에서 같은 장비의 직전 로그인 기록을 본다. Cisco Backup의 직전 설정과 비교하면 바뀐 줄을 알 수 있다.

**대응**: 승인되지 않은 변경이면 해당 계정·접속 경로를 막고 직전 설정으로 되돌린 뒤 보안 담당에게 보고한다. 승인된 작업이면 작업 기록에 남긴다.

<a id="fortigate-config-change"></a>
### 🟠 포티게이트 설정 변경 감지 (`fortigate_backup` 역할)

**조건**: 포티게이트 설정 백업(매일 03:30)이 같은 대상의 직전 백업과 다를 때 한 번(Event Alert). 이 알림은 OpenObserve가 아니라 백업 역할이 같은 webhook으로 직접 보낸다. 헤더 줄(빌드·사용자·시각)만 다르면 오지 않고, 첫 백업에도 오지 않는다. 같은 변경은 다시 오지 않는다. 대상 행에 장비(관리번호), 응답 멤버, 바뀐 섹션·항목 이름과 설정 키 이름만 나온다(값 없음).

**왜 중요한가**: 승인되지 않은 방화벽 정책·관리자·VPN 변경은 접근 통제 약화나 침해의 시작이다. 변경 이력은 ISMS 변경 관리 증적이다.

**확인**: 변경 시각 전후(전날 백업~이번 백업)의 작업 요청·변경 기록과 대조한다. 바뀐 값은 알림에 없으므로 컨트롤러의 백업 디렉터리에서 직전 파일과 이번 파일을 `diff`로 비교한다(두 파일명은 알림의 직전 백업 이름과 같은 대상의 최신 파일). 출력에 VPN 키·관리자 해시가 들어 있으니 화면·채팅·이슈에 붙이지 않는다. 같은 시간대의 방화벽 관리자 로그인 기록(`security_logs`, `fortigate-syslog`)에서 변경 주체를 찾는다.

**대응**: 승인되지 않은 변경이면 해당 관리자 계정·접속 경로를 막고 직전 백업으로 되돌린 뒤 보안 담당에게 보고한다. 승인된 작업이면 변경 기록에 남긴다. 알림에 멤버 변경 비교라고 되어 있으면 장애 전환이 있었던 것이니 멤버 고유 설정은 변경으로 세지 않았음을 감안한다.

**알림이 오지 않을 때**: Semaphore 백업 작업이 `FORTIGATE-ALERT`로 실패했다면 변경은 감지했으나 webhook이 없거나 전송이 실패한 것이다. 같은 변경은 다시 알리지 않으므로 작업 로그의 변경 항목을 직접 확인하고 webhook(`fortigate_backup_alert_webhook_url`) 설정을 고친다.

<a id="switch-login-failures"></a>
### 🟠 스위치 로그인 실패 반복 (`infra-switch-login-failures`)

**조건**: 한 장비에서 `SEC_LOGIN-4-LOGIN_FAILED`가 5분 안에 5회 이상(Event Alert, 기본값은 `o2c_switch_login_fail_threshold`).

**확인**: 로그 보기에서 실패 줄의 `[user: ...] [Source: ...]`를 본다. 출발지가 사내(작업자·Semaphore)인지 외부인지 구분한다.

**대응**: 외부·미확인 출발지면 스위치의 관리 접속 ACL과 방화벽을 점검해 막는다. 작업자의 반복 오입력이면 기록만 남긴다. 같은 출발지의 로그인 성공이 이어졌으면 설정 변경 알림도 함께 확인한다.

<a id="switch-severity-critical"></a>
### 🔴 스위치 중요 장애 메시지 (`infra-switch-severity-critical`)

**조건**: 메시지 코드의 심각도가 0~2(emergency·alert·critical)인 줄이 5분 안에 1건 이상(Event Alert). 잡음 목록의 코드는 제외한다.

**왜 중요한가**: 하드웨어·전원·스택·메모리 같은 중대한 장애이며 그 스위치 아래 서버가 함께 끊길 수 있다.

**확인**: 행의 `event_name`과 로그 보기의 원문을 읽는다. 장비 콘솔 또는 다른 경로로 `show logging`, `show environment`, `show switch`(스택)를 본다.

**대응**: 하드웨어 문제면 이중화 경로로 서비스를 옮기고 교체 일정을 잡는다. 이미 알려진 무해한 반복 메시지면 `o2c_switch_noise_events`에 추가하는 PR을 낸다.

<a id="switch-uplink-down"></a>
### 🔴 스위치 업링크 포트 다운 (`infra-switch-uplink-down`)

**조건**: `o2c_switch_uplinks`에 적은 (장비, 포트)에 대해 `LINK-3-UPDOWN`·`LINEPROTO-5-UPDOWN`·`LINK-5-CHANGED`가 `down` 또는 `administratively down`으로 바뀐 줄이 5분 안에 1건 이상(Event Alert). **목록이 비어 있으면 이 알림은 없다.**

**확인**: 행의 장비·포트와 반대편 장비의 포트 상태, 케이블·광모듈을 확인한다. `administratively down`이면 누군가 shutdown한 것이므로 설정 변경 알림과 대조한다.

**대응**: 복구되지 않으면 우회 경로를 확보하고 회선·장비 담당에게 연락한다. 이중화로 이미 우회되고 있으면 복구 일정을 잡는다.

<a id="switch-mac-flap"></a>
### 🟠 스위치 MAC 플랩 감지 (`infra-switch-mac-flap`)

**조건**: 한 장비에서 `SW_MATM-4-MACFLAP_NOTIF`가 10분 안에 2회 이상(기본값은 `o2c_switch_macflap_threshold`). 플랩이 계속되면 60분(`o2c_switch_macflap_silence_minutes`)마다 다시 온다.

**왜 중요한가**: 같은 MAC이 두 포트 사이를 오가는 것은 L2 루프나 장비 이동·이중 연결의 신호다. 방치하면 VLAN 통신이 불안정해진다.

**확인**: 로그 보기에서 원문의 MAC, VLAN, 두 포트(`Gi0/13`, `Gi0/14`)를 읽는다. 그 두 포트에 무엇이 연결됐는지 본다(서버 이중화 본딩, 가상 스위치, 루프 케이블, 무선 AP).

**대응**: 서버의 이중화 구성이면 본딩 모드(active-backup/LACP)와 스위치 쪽 EtherChannel 설정이 맞는지 본다. 루프면 케이블을 분리한다. 의도된 구성이라면 스위치 설정을 고치거나 임계값을 조정한다.

<a id="switch-syslog-silent"></a>
### 🟠 스위치 syslog 수신 중단 (`infra-switch-syslog-silent`)

**조건**: `o2c_switch_syslog_roster`의 스위치가 24시간(`o2c_switch_silent_hours`) 넘게 `switch-syslog` 로그를 보내지 않음(State Alert, 하루 1번 재통지). 목록에 없는 장비는 보지 않는다.

**왜 중요한가**: 전송 설정이나 수신 경로가 끊기면 그동안의 설정 변경·로그인 이력이 중앙에 남지 않는다. 스위치는 이벤트가 있을 때만 보내므로 오래 조용한 정상 장비일 수도 있다.

**확인**: 스위치에서 `show running-config | include logging`으로 `logging host`와 `logging trap` 수준을 본다. 수신 서버의 방화벽과 수신 서비스 상태(#276)를 본다. 해당 장비의 `ns` 번호와 `device_id`가 같은지 로그 보기에서 확인한다.

**대응**: 설정이 사라졌으면 복구한다. 원래 조용한 장비면 기준 시간을 늘린다. 철거·교체한 장비면 목록에서 뺀다.

---

## 방화벽(포티게이트) 알림 (Spec #282 / Ticket-3)

방화벽 syslog는 [수신 경로](fortigate-syslog.md)를 거쳐 `security_logs`에 `service_name=fortigate-syslog`로 들어온다. 알림 6개는 스위치 알림과 같은 통지 경로·메시지 형식(등급, 무슨 일, 왜 중요, 대상, 조치, 런북 링크)을 쓴다.

> **실로그 샘플로 검증됨**(검증 범위: 관리자 로그인 성공/실패, 정책·로그 설정 변경(GUI·jsconsole·ha_daemon), 로컬·포워드 트래픽(정책 0 포함), IPsec 터널 통계, UTM(ips·virus·dlp·anomaly), HA 인터페이스 실패, FSSO, 엔드포인트. 검증되지 않은 종류: HA 전환(상태 변경) 실제 줄, SSL VPN 사용자 로그인/로그아웃·로그인 실패 줄, 실제 장비가 만든 웹필터·앱제어 줄, IPv6 주소). 실장비 줄을 가짜 값으로 치환한 `tests/fixtures/fortigate_real_lines.tsv`(합성이 아닌 실장비 모양)를 알림 SQL에 넣어 발화·미발화를 확인한다. 실측으로 고친 점: 실제 바이러스 로그에는 `severity` 키가 없어 `subtype=virus`·`eventtype=infected`를 중대 탐지로 함께 센다. 로그 전송 설정 변경(`log.syslogd.*`, `log.setting`)은 기본 감시 대상이 아니다(`o2c_fortigate_policy_cfgpaths`에 더하면 알린다). 검증되지 않은 종류의 줄이 처음 들어오면 `subtype`/`action`/`status`, `cfgpath`·`user`·`time`, `logdesc`, `severity`·`attack`, `devname`을 샘플과 다시 대조하고, 다르면 알림 SQL(`roles/openobserve_config/defaults/main.yml`)과 검증 레코드(`files/alert_fixtures.yml`)를 함께 고친다.

| 알림 | 등급 | 조건 (기본값) | 재통지 |
|---|---|---|---|
| `infra-fortigate-admin-login-failures` | 🟠 P2 | 한 출발지에서 관리자 로그인 실패가 5분 안에 5회 이상 | 30분 |
| `infra-fortigate-change-unapproved` | 🔴 P1 | 정책·계정 변경이 승인 시간(기본 9~18시) 밖 | 5분(구간과 같음) |
| `infra-fortigate-change-approved` | 🟡 P3 | 정책·계정 변경이 승인 시간 안, 하루 1번 요약 | 하루 |
| `infra-fortigate-ha-failover` | 🟠 P2 | HA 로그(`subtype=ha`) 1건부터 | 30분 |
| `infra-fortigate-critical-detection` | 🔴 P1 | UTM 탐지(`type=utm`) 중 `severity=critical` 또는 바이러스 감염(`subtype=virus`·`eventtype=infected`) 1건부터 | 60분 |
| `infra-fortigate-syslog-silent` | 🟠 P2 | 감시 목록의 방화벽이 120분 넘게 로그 없음 | 하루 |

**중복 알림 방지**: 모든 알림이 재통지 간격(silence)을 가진다. 같은 공격·같은 HA 전환 반복은 위 간격마다 한 번만 알리고, 변경 알림은 조회 구간(5분)과 같아 같은 줄을 두 번 알리지 않는다. 승인 시간 안의 변경은 하루 1번 요약으로만 가므로 정상 작업이 P1을 만들지 않는다.

**공통 한계**: 알림 SQL은 `service_name`과 원문 `body`의 `key=value`만 읽는다. `security_logs`에는 첫 방화벽 줄이 들어오기 전까지 방화벽 필드(`device_id` 등) 컬럼이 없어서, 그 컬럼을 참조하면 알림 평가가 매번 오류가 나고 Config 실행(`O2C-036`)이 막히기 때문이다. 필드 추출([OpenObserve 구성](../openobserve_config.md), #285)과 별개로 동작한다. 따옴표 있는 값(`subtype="ha"`)과 없는 값(`subtype=ha`)을 모두 받는다.

**목록 갱신 절차**: 아래 값은 모두 역할 기본 변수(`roles/openobserve_config/defaults/main.yml`)이며 Semaphore의 `OpenObserve — Config` 템플릿 Environment(`-e`)나 저장소 기본값을 고친 뒤 **`OpenObserve — Config`를 다시 실행**해야 반영된다. 잘못된 형식(장비 이름, 경로 문자, 승인 시간)은 요청 전에 실패한다.
- `o2c_fortigate_syslog_roster`(수신 중단 감시 장비): **기본값은 비어 있다.** 전송을 시작하기 전 장비(`ns0380`, `ns0381`, `ns0399`)를 넣으면 허위 알림이 계속 오기 때문이다. 장비가 로그를 보내기 시작하고 `security_logs`에 도착하는 것을 확인한 **뒤에** 관리번호를 더한다(사무실 `ns0399`가 먼저). IDC HA 쌍은 대기 멤버가 평소 조용하고 장애 전환 뒤에는 반대가 되므로 `ns0380+ns0381`처럼 `+`로 묶어 한 항목으로 쓴다(어느 한 멤버라도 보내면 수신 중). **hostname을 관리번호로 바꾸지 못한 장비는 관리번호가 아닌 원래 이름(`devname` 그대로, 대소문자 무관)으로도 목록에 넣을 수 있다**(예: `Example_Branch_FW`). 이 장비의 `device_id`(관리번호)를 채우려면 `o2c_fortigate_device_aliases`에 `{example_branch_fw: ns0000}`처럼 소문자 정규화한 이름 → 관리번호를 넣는다(표에 없으면 `ns`+숫자 추출). 공개 저장소라 실제 이름과 값은 저장소에 쓰지 않고 Semaphore `OpenObserve — Config` 템플릿의 Environment(Extra variables)로 넣는다. 목록에 없는 장비는 로그가 없어도 알리지 않는다. 목록이 비면 규칙은 있지만 행을 돌려주지 않는다.
- `o2c_fortigate_approved_start_hour`, `o2c_fortigate_approved_end_hour`(승인 시간, 기본 9, 18, 끝 미포함): 변경 로그 원문의 `time=`(장비 시계)을 읽는다. **장비 시간대가 운영 시간대(KST)여야 한다.** 시각이 없는 줄은 승인 시간 밖으로 본다. 요일은 구분하지 않는다.
- `o2c_fortigate_policy_cfgpaths`, `o2c_fortigate_account_cfgpaths`(변경을 알릴 `cfgpath`): 기본은 정책(`firewall.policy`, `firewall.policy6`, `firewall.proxy-policy`)과 계정(`system.admin`, `system.accprofile`, `system.api-user`, `user.local`, `user.group`)이다.
- `o2c_fortigate_detection_severities`(기본 `critical`), `o2c_fortigate_login_fail_threshold`(기본 5), `o2c_fortigate_silent_minutes`(기본 120, 스위치 24시간보다 짧다. 방화벽은 로그가 계속 나오므로), 재통지 간격 `o2c_fortigate_*_silence_minutes`.

<a id="fortigate-admin-login-failures"></a>
### 🟠 방화벽 관리자 로그인 연속 실패 (`infra-fortigate-admin-login-failures`)

**조건**: `subtype=system`, `action=login`, `status=failed`인 줄이 같은 출발지에서 5분 안에 5회 이상(`o2c_fortigate_login_fail_threshold`). VPN 사용자 로그인 실패는 관리자 로그인이 아니라 대상이 아니다.

**왜 중요한가**: 방화벽 관리자 계정이 뚫리면 모든 통신 정책을 바꿀 수 있다(무차별 대입의 전형).

**확인**: 행의 출발지가 사내 작업자·Semaphore인지 본다. 로그 보기에서 실패한 계정과 접속 방식(`ui`: GUI/ssh)을 읽는다. 같은 출발지의 로그인 성공이 이어졌는지 본다.

**대응**: 외부·미확인 출발지면 관리 접속 허용 주소(trusted host)와 관리 인터페이스 노출 범위를 점검해 막는다. 성공이 이어졌으면 계정 변경 알림(아래)과 함께 보고 계정을 잠근다. 작업자의 오입력이면 기록만 남긴다.

<a id="fortigate-change-unapproved"></a>
### 🔴 방화벽 정책·계정 변경, 승인 시간 밖 (`infra-fortigate-change-unapproved`)

**조건**: `cfgpath`가 정책·계정 목록에 있는 변경이 승인 시간(장비 시계 기준 9~18시) 밖에 기록됨. 시각을 읽을 수 없는 줄도 포함한다. 행에 장비, 변경 대상(`cfgpath`), 관리자가 나온다.

**왜 중요한가**: 승인되지 않은 정책·계정 변경은 차단 해제나 백도어 계정 생성일 수 있다. 변경 이력은 ISMS 변경 관리 증적이다.

**확인**: 행의 관리자와 `cfgpath`를 작업 요청·Semaphore 이력과 대조한다. 로그 보기에서 `cfgattr`(바뀐 값)과 접속 방식·출발지(`ui`)를 읽는다. 직전 [FortiGate Backup](../fortigate_backup.md)과 비교하면 바뀐 설정을 알 수 있다.

**대응**: 승인된 긴급 작업이 아니면 해당 관리자 계정을 잠그고 직전 설정으로 되돌리며 보안 담당에게 보고한다. 승인된 작업이면 작업 기록에 남긴다.

<a id="fortigate-change-approved"></a>
### 🟡 방화벽 정책·계정 변경, 승인 시간 안 하루 요약 (`infra-fortigate-change-approved`)

**조건**: 위와 같은 변경이 승인 시간 안에 기록됨. 하루에 한 번 요약한다.

**왜 중요한가**: 정상 작업이 대부분이지만 변경 관리 증적으로 그날의 작업 요청과 대조해야 한다. 대응 작업이 없는 변경은 계정 도용일 수 있다.

**확인·대응**: 행의 관리자·변경 대상을 그날의 작업 요청과 대조해 결과를 작업 기록에 남긴다. 대응 작업이 없는 변경이면 승인 시간 밖 변경 절차(P1)로 격상한다.

<a id="fortigate-ha-failover"></a>
### 🟠 방화벽 HA 전환·이상 (`infra-fortigate-ha-failover`)

**조건**: `subtype=ha` 로그 1건부터. 행에 장비 이름과 `logdesc`(HA 이벤트 종류)가 나온다. 정보성 동기화 로그(secondary가 주기적으로 남기는 동기화 상태 줄, logid `0108037903`)는 제외한다. 제외 목록은 변수 `o2c_fortigate_ha_ignored_logids`(숫자 문자열 목록, 빈 목록이면 HA 로그 전부)로 조정한다. 실장비에서 다른 정보성 줄이 알림을 일으키면 그 logid를 목록에 더한다(실제 HA 전환 줄은 아직 검증되지 않았다).

**왜 중요한가**: 통신은 이어지더라도 이중화가 깨져 다음 장애에서 서비스가 끊길 수 있다. 전환이 반복되면 세션이 끊긴다.

**확인**: 장비 이름으로 지금 주 장비가 어느 멤버인지 본다(IDC 쌍은 멤버마다 장비 이름이 다르다). 전환 직전의 인터페이스·전원·하트비트 로그를 본다. **IDC 쌍은 secondary가 직접 로그를 보내지 못하는 수용 위험이 있으므로**([수신 런북](fortigate-syslog.md) 2절) 대기 멤버 쪽 사정은 장비 접속이나 다른 경로로 확인해야 한다.

**대응**: 멤버가 복구되지 않으면 교체·점검 일정을 잡는다. 계획된 작업(재부팅, 펌웨어)이면 작업 기록에 남긴다.

<a id="fortigate-critical-detection"></a>
### 🔴 방화벽 중대 보안 탐지 (`infra-fortigate-critical-detection`)

**조건**: `type=utm` 로그 중 `severity`가 `critical`(`o2c_fortigate_detection_severities`)인 것 1건부터. 행에 장비와 탐지 이름(`attack`)이 나온다.

**왜 중요한가**: 알려진 취약점 공격이나 악성코드가 방화벽을 지나가려 했다. 차단됐더라도 공격 대상에 이미 닿았는지 확인해야 한다.

**확인**: 로그 보기에서 출발지·목적지·조치(`action`: 차단 `dropped`/`blocked`, 통과 `pass`/`monitor`)를 본다. 출발지가 내부 호스트인지 본다.

**대응**: 통과였거나 내부 호스트가 출발지면 그 호스트를 격리하고 점검한다. 외부의 반복 공격이면 차단 정책 추가를 검토한다. 결과를 사고 기록(ISMS 2.11.5)에 남긴다.

<a id="fortigate-syslog-silent"></a>
### 🟠 방화벽 syslog 수신 중단 (`infra-fortigate-syslog-silent`)

**조건**: `o2c_fortigate_syslog_roster`의 방화벽이 120분(`o2c_fortigate_silent_minutes`) 넘게 `fortigate-syslog` 로그를 보내지 않음(State Alert, 하루 1번 재통지). 목록이 기본값(빈 목록)이면 어떤 장비도 보지 않는다. 장비 이름은 원문의 `devname`으로 찾는다.

**왜 중요한가**: 전송 설정이나 수신 경로가 끊기면 그동안의 관리자 접속·정책 변경 이력이 중앙에 남지 않는다(ISMS 로그 1년 보관의 공백).

**확인**: 장비의 로그 전송 설정(대상, 형식, 출발지 고정)이 그대로인지 본다. 수신 서버의 허용 목록과 syslog-ng 상태를 [수신 런북 3절](fortigate-syslog.md)대로 확인한다. HA 쌍은 장애 전환 뒤 새 primary 이름으로 이어지는지 본다.

**대응**: 설정이 사라졌으면 복구한다. 철거·교체한 장비면 목록에서 뺀다. 로그가 원래 적은 장비(정책별 로그를 최소화)면 기준 시간을 늘린다. IDC 쌍에서 secondary가 조용한 것은 정상이다(쌍을 `+`로 묶어 감시).

---

## 리소스 알림 (디스크·inode·메모리)

사용률은 `_timestamp`별로 묶은 값의 **조회 구간 최솟값**으로 판정한다(구간 내내 높아야 발화). 디스크·inode는 15분, 메모리는 10분. 90% 이상 95% 미만은 P2(재통지 1440분), 95% 이상은 P1(재통지 60분). 통지 행에 호스트·마운트·사용률이 나온다. squashfs·iso9660·tmpfs·devtmpfs·overlay는 감시하지 않고 `/boot`·`/boot/efi`는 감시한다. 항상 높게 쓰는 볼륨은 OpenBao `agents/openobserve`의 `alert_resource_exclusions`(호스트·마운트 예외)나 `alert_resource_thresholds`(임계값 덮어쓰기)에 넣고 `OpenObserve — Config`를 다시 실행한다.

<a id="disk-usage"></a>
### 🟠/🔴 디스크 사용률 (`infra-disk-usage-p2`, `infra-disk-usage-p1`)

**왜 중요한가**: 가득 차면 로그·DB·백업 쓰기가 실패한다.

**확인**
```bash
df -hT <마운트>
sudo du -xh <마운트> --max-depth=2 | sort -h | tail -20
docker system df   # Docker 사용 호스트
```

**대응**: 큰 파일·오래된 로그·Docker 이미지/볼륨을 정리하거나 증설한다. 원래 가득 차게 쓰는 볼륨이면 OpenBao 예외를 등록한다.

<a id="inode-usage"></a>
### 🟠/🔴 inode 사용률 (`infra-inode-usage-p2`, `infra-inode-usage-p1`)

**왜 중요한가**: 용량이 남아도 inode가 다하면 파일을 만들 수 없다(작은 파일 폭증).

**확인**
```bash
df -i <마운트>
sudo du -x --inodes <마운트> --max-depth=3 | sort -n | tail -20
```

**대응**: 작은 파일이 몰린 디렉터리(세션·캐시·메일 큐 등)를 정리하고 원인 프로세스를 고친다.

<a id="memory-usage"></a>
### 🟠/🔴 메모리 사용률 (`infra-memory-usage-p2`, `infra-memory-usage-p1`)

사용률 = `1 − system.linux.memory.available / system.memory.limit`(`system_linux_memory_available`·`system_memory_limit`). 회수 가능한 캐시·버퍼는 사용량에 들어가지 않는다.

**확인**
```bash
free -m
ps aux --sort=-%mem | head
docker stats --no-stream   # Docker 사용 호스트
```

**대응**: 메모리를 많이 쓰는 프로세스·컨테이너의 누수와 한도를 점검하고 재기동하거나 증설한다. OOM kill이 이미 있었는지 시스템 로그에서 확인한다.
