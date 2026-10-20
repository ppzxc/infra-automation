# 스위치 syslog 수신 경로 런북

> Cisco 스위치 syslog가 OpenObserve까지 가는 경로와 점검 방법이다(#276). 필드 추출과 알림은 [#277](https://github.com/ppzxc/infra-automation/issues/277)과 [openobserve_config.md](../openobserve_config.md)를 본다. 공개 저장소라 IP·포트 등 인프라 상세는 적지 않는다.

## 1. 경로

```text
스위치 ──syslog──▶ LibreNMS의 syslog-ng 컨테이너 ─┬─▶ LibreNMS (syslog.php, 화면·검색 30일)
                                                   └─▶ 장비별·일별 파일 ──▶ 호스트 otelcol(filelog) ──▶ OpenObserve system_logs
```

| 구간 | 내용 |
|---|---|
| 수신 | LibreNMS compose의 `syslog-ng` 컨테이너가 TCP/UDP로 받는다. |
| LibreNMS 저장 | LibreNMS 설정 `enable_syslog`가 켜져 있어야 쌓인다(꺼져 있으면 받아도 화면에 안 보인다). 보관은 `syslog_purge`(기본 30일). |
| 파일 보관 | 같은 메시지를 `/var/log/remote/<송신 장비>/<날짜>.log`로 쓴다. 호스트 logrotate가 365일 보관한다. |
| 중앙 수집 | 호스트 otelcol이 파일을 읽어 `system_logs`에 `service.name=switch-syslog`로 보낸다. 장비 구분은 파일 경로 속성과 원문에 있다(`host_name`은 수집 서버). |
| 보관 | OpenObserve 서버 전역 365일(ISMS 로그 1년). |

## 2. 설정 위치와 함정

- **syslog-ng 사용자 설정은 컨테이너의 `/data/syslog-ng/*.conf`에 둔다.** 메인 설정이 이 경로만 `@include`한다. `conf.d`에 마운트한 파일은 읽히지 않는다(과거 보관 설정이 한 번도 로드되지 않은 원인). 파일을 둔 뒤 컨테이너를 재생성하지 말고 `syslog-ng-ctl reload`로 설정만 다시 읽힌다.
- **OpenObserve 전송은 호스트 KV `otel_extra_logs`로 한다.** OpenBao의 해당 호스트 `agents` 항목에 `path=/var/log/remote/*/*.log`, `stream=system_logs`, `service=switch-syslog`를 넣고 Semaphore **Host Agents — Config**를 그 호스트에만 실행한다. KV는 PATCH가 막혀 있어 전체를 읽어 합친 뒤 `cas`로 쓴다. 시크릿 키가 같은 항목에 있으니 값을 출력하지 않는다.
- 추가 경로에는 파서가 적용되지 않는다(ADR-0006 §2.3). 장비·심각도 필드는 #277의 중앙 변환이 만든다.

## 3. 점검 절차

1. **LibreNMS 설정**: `enable_syslog`가 `true`인지 확인한다.
2. **수신**: syslog-ng 컨테이너의 통계에서 `s_net` 처리 건수가 늘어나는지 본다. 늘지 않으면 스위치 쪽 `logging host` 설정이나 경로 문제다.
3. **파일**: `/var/log/remote/` 아래에 장비별 디렉터리와 오늘 날짜 파일이 생기는지 본다. 없으면 사용자 설정이 로드되지 않은 것이다(2절).
4. **OpenObserve**: `system_logs`에서 `service_name='switch-syslog'`의 최신 레코드 시각을 본다. 없으면 호스트 otelcol 설정에 경로가 있는지와 서비스 상태를 본다.
5. **장비 확인**: 새 스위치는 `logging host`가 설정돼 있어야 한다. 설정 변경 전에는 `cisco_backup`으로 설정을 먼저 받는다.

## 4. 알려진 한계

- 원문 시각에는 연도가 없고 시간대가 장비 설정에 의존한다. 증적 기준 시각은 수집 시각이다.
- 스위치 syslog는 이벤트가 있을 때만 전송된다. 조용한 것과 끊긴 것은 로그만으로 구분되지 않는다(#277의 수신 중단 알림 기준 시간이 길다).
- 보내는 장비가 늘면 LibreNMS의 장비 목록과 #277의 수신 중단 감시 목록을 같이 갱신한다.
