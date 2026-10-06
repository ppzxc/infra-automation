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
- `app_logs`는 포맷을 알 수 없으므로 파싱하지 않는다.
- 이 변경 이전 레코드에는 새 필드가 없으므로 쿼리와 알림은 null을 견뎌야 한다.
