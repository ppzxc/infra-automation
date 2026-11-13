# 스위치 syslog 수신 경로 런북

> Cisco 스위치 syslog가 OpenObserve까지 가는 경로와 점검 방법이다(#276). 필드 추출과 알림은 [#277](https://github.com/ppzxc/infra-automation/issues/277)과 [openobserve_config.md](../openobserve_config.md)를 본다. 공개 저장소라 IP·포트 등 인프라 상세는 적지 않는다.

## 1. 경로

```text
스위치 ──RFC3164/UDP syslog──▶ Telegraf syslog 수신기 ──JSON HTTP──▶ OpenObserve system_logs
```

| 구간 | 내용 |
|---|---|
| 수신 | Telegraf `inputs.syslog`가 Cisco RFC3164/UDP를 받고, `allowed_sources`에 등록된 출발지만 처리한다. Cisco sequence number 등 비표준 변형은 `best_effort`로 부분 파싱한다. |
| OpenObserve 전송 | Telegraf `outputs.http`가 메시지를 JSON 로그로 만들어 `system_logs`에 전송한다. `service_name=switch-syslog`, `host_name`은 수집 서버이며 원문 호환 형식의 `body`를 보존한다. |
| 보관 | OpenObserve 서버 전역 365일(ISMS 로그 1년). |

## 2. 설정 위치와 함정

- Telegraf 설정 템플릿은 [`configs/telegraf/cisco-switch-syslog.conf`](../../configs/telegraf/cisco-switch-syslog.conf)에 있다. 수신 주소, 관측한 출발지 IP 허용 목록, OpenObserve JSON ingest URL, 인증값은 저장소에 넣지 않고 런타임 환경/시크릿으로 주입한다.
- Telegraf의 syslog 입력은 메트릭 형태로 파싱하므로, `outputs.http`의 JSON 변환이 이를 OpenObserve 로그 스키마(`_timestamp`, `service_name`, `host_name`, `severity`, `body`)로 바꾼다. HTTP 출력에서 오류가 없어야 OpenObserve ingest 성공으로 본다.
- RFC3164는 UDP 입력만 사용한다. 스위치가 TCP syslog를 보내면 이 수신 설정으로 처리되지 않는다.

## 3. 점검 절차

1. **수신기**: `app-telegraf-syslog`가 실행 중이고 UDP 수신 포트가 게시됐는지 확인한다.
2. **허용 목록**: Telegraf 설정의 `allowed_sources`가 수신기에서 관측한 출발지 주소를 포함하는지 확인한다. Docker 포트 전달 전후에 수신기가 보는 출발지가 달라질 수 있다.
3. **파싱·전송**: Telegraf 컨테이너 로그에서 syslog 파싱 경고와 HTTP 출력 오류를 구분한다. Cisco sequence number 경고는 best-effort 파싱으로 레코드가 만들어질 수 있으나, HTTP 오류는 OpenObserve 전송 실패다.
4. **OpenObserve**: `system_logs`에서 `service_name='switch-syslog'`의 최신 레코드 시각을 확인한다.
5. **장비 확인**: 새 스위치는 `logging host`가 설정돼 있어야 한다. 설정 변경 전에는 `cisco_backup`으로 설정을 먼저 받는다.

## 4. 알려진 한계

- 원문 시각에는 연도가 없고 시간대가 장비 설정에 의존한다. 증적 기준 시각은 수집 시각이다.
- 스위치 syslog는 이벤트가 있을 때만 전송된다. 조용한 것과 끊긴 것은 로그만으로 구분되지 않는다(#277의 수신 중단 알림 기준 시간이 길다).
- 보내는 장비가 늘면 비공개 런타임 허용 목록과 #277의 수신 중단 감시 목록을 같이 갱신한다.
