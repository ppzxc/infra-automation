---
status: accepted
date: 2026-10-06
---

# 8. 로그 구조화: 엣지 Envelope Parsing + 중앙 의미 해석(코드 관리)

Host Agents가 로그를 원문 그대로만 보내서 severity 필터, 필드 기반 집계, 알림이 모두 정규식에 기대고 있었다. 그래서 **원문 `body`는 바이트 단위로 바꾸지 않고**, 로그 포맷이 정해 둔 필드만 수집기(otelcol operator)에서 꺼내 `attributes`·`Timestamp`·`severity`에 붙이기로 한다(**Envelope Parsing**). 메시지가 무슨 뜻인지(sshd 사용자·IP, sudo 명령, OCSF 정규화) 해석하는 일은 OpenObserve VRL ingest function에서 하며, 그 함수·알림·통지 대상은 이 저장소에서 코드로 관리해 OpenObserve API로 반영한다. ADR-0006 §2.3의 "파싱 없음"을 이 결정으로 대체한다.

## Considered Options

- **엣지 전부 파싱**: 규칙 하나 고칠 때마다 전 호스트(CentOS 6 포함)에 다시 배포해야 하고, 메시지 해석이 바이너리 두 버전(0.119.0/0.161.0)에 묶인다.
- **중앙 전부 파싱(UI 관리)**: 다시 배포할 필요는 없지만 규칙이 Git 밖에 있어서 엣지와 필드 계약이 어긋나도 알 수 없다.
- **검색 시 파싱(schema-on-read)**: 알림 쿼리마다 정규식이 중복되고 무거워진다.
- **본문을 파싱 결과로 교체**: ISMS 2.9.4 증거인 원문이 사라진다.

## Consequences

- 필드 이름은 OTel semantic conventions(`process.executable.name`, `process.pid`, `user.name`, `source.address`, `severity_*`)를 따른다. OCSF가 필요해지면 중앙에서 매핑한다.
- severity는 **포맷이 실제로 갖고 있을 때만** 채운다(journald `PRIORITY`, fail2ban·dnf 레벨 등). rsyslog 기본 파일 포맷은 PRI를 남기지 않으므로 syslog 파일의 severity는 비어 있고, 이런 로그의 오류 알림은 패턴 기반으로 만든다. 키워드로 severity를 추정하지 않는다.
- 이벤트 시각은 `Timestamp`, 수집 시각은 `ObservedTimestamp`에 둔다. RFC3164 줄에는 타임존이 없으므로 Probe가 읽은 **호스트의 실제 타임존**으로 해석한다(읽지 못하면 `timezone` 변수로 대체하고 WARN). 연도는 수집 시점 기준으로 추정한다.
- 파싱에 실패한 줄도 버리지 않고 원문 그대로 보내며 `log.parse_error=true`를 붙인다. 파싱 실패율도 알림 대상이다.
  - (2026-10-12 개정) 파싱에 성공한 줄에는 `log.parse_error=false`를 명시한다. 실패가 한 번도 없으면 OpenObserve 스트림에 컬럼이 생기지 않아 파싱 실패율 알림 SQL이 `unknown field`로 계속 오류였다.
- `app_logs`는 포맷을 알 수 없으므로 파싱하지 않는다.
  - (2026-10-19 개정, Spec #236) 컨테이너 로그(`filelog/containers`)에 한해 **레벨만** 올린다. JSON 한 줄 로그의 `level`·`log.level`과 valkey의 레벨 문자처럼 포맷이 실제로 레벨을 가진 줄만 `severity`로 올리고, 해당 없는 줄은 비운다(추정 금지). 본문은 그대로고 `log.parse_error`는 붙이지 않는다. 사용자가 추가한 `app_logs` 파일 경로는 여전히 파싱하지 않는다.
- JSON 로그의 trace context 필드도 Envelope Parsing에 속한다(Spec #253). 컨테이너 JSON 줄의 trace id 필드(funa `trace_id`/`span_id`/`trace_flags`, Caddy `traceID`/`spanID`)를 LogRecord의 TraceID/SpanID/flags로 올리고, 없거나 전부 0인 id는 건너뛰며 본문은 그대로 둔다.
- 이 변경 이전 레코드에는 새 필드가 없으므로 쿼리와 알림은 null을 견뎌야 한다.
- (2026-10-20 개정, Spec #277) 스위치 syslog(`system_logs`의 `service_name=switch-syslog`, #276)는 엣지에 해석할 곳이 없다(수신 서버가 원문만 보낸다). 중앙 VRL `switch_syslog_semantics`가 Cisco `%FACILITY-SEVERITY-MNEMONIC` 메시지에서 장비(`device_name`, 관리번호 `device_id`), facility, mnemonic, `event_name`, 심각도 0~7(`log_syslog_severity_code`·`_name`)을 **추가**한다. 이 메시지 형식은 심각도를 실제로 가지므로 "포맷이 가질 때만 채운다" 원칙에 맞다. 기존 `severity`(항상 0)·`host_name`(수집 서버)·`body`는 바꾸지 않고, 형식이 아닌 줄과 다른 서비스는 그대로 통과한다(서비스 검사는 함수 안에 둔다). 장비 시각은 연도·시간대가 불확실해 `_timestamp`로 승격하지 않는다.
- (2026-10-21 개정, Spec #282 / Ticket-2) 포티게이트 방화벽 syslog(`security_logs`의 `service_name=fortigate-syslog`, #283)도 엣지에 해석할 곳이 없어 중앙 VRL `fortigate_semantics`가 같은 원칙으로 장비(`device_name`, 관리번호 `device_id`), 유형·하위 유형(`fortigate_log_type`·`_subtype`), 동작(`event_action`), 출발지(`source_address`), 사용자(`user_name`), 정책 식별자(`fortigate_policy_id`)를 **추가**한다. 방화벽 줄은 심각도를 `level=`로 갖지만 이 개정은 심각도 필드를 만들지 않는다. 소스 스트림당 파이프라인이 하나라 보안 로그 파이프라인에 `security_semantics` 다음 함수로 잇고, 서비스 검사는 함수 안에 둔다. 규칙은 합성 입력으로만 검증됐으므로 실장비 샘플로 재검증한다.
