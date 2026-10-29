# Uptime Kuma 모니터 태그 규칙 런북

Uptime Kuma 모니터에 붙이는 태그의 키·값 규칙과 적용 방법이다. 모니터를 만들거나 바꿀 때 이 규칙을 따른다.

모니터 이름·심각도·알림 제목 규칙과 이전 절차는 `kuma-migration.md`에 있고, 이 문서는 그 위에 태그 키·값 규칙과 적용 방법을 더한다. 공개 저장소이므로 IP·도메인 값·호스트별 모니터 목록은 쓰지 않는다. 호스트별 적용 기록은 비공개 경로(`~/.local/share/infra-automation/`)에 둔다.

## 1. 태그 키

| 키 | 의미 | 값 규칙 | 예 |
|---|---|---|---|
| `host` | 모니터가 보는 호스트 | Inventory Hostname(관리번호) 소문자. 호스트가 없는 모니터(VIP 등)는 붙이지 않는다 | `ns0325` |
| `service` | 서비스 | 소문자 서비스 이름 | `funa` |
| `component` | 감시 대상 구성요소 | `app`, `caddy`, `keepalived`, `valkey-master`, `valkey-replica`, `vip` 중 하나 | `caddy` |
| `env` | 환경 | `prod` | `prod` |
| `node_domain` | 노드(호스트) 도메인 | 호스트의 `<관리번호>.nanoit.kr`. `host`가 있을 때만 붙인다 | `ns0325.nanoit.kr` |
| `service_domain` | 서비스 도메인 | 서비스 공통 도메인. VIP가 여러 개여도 같은 이름 하나다 | `funa.nanoit.kr` |
| `P1` / `P2` / `P3` | 심각도 | **태그 이름 자체가 심각도**이고 값은 비운다. 모니터마다 하나만 붙인다. 의미는 `alerts.md`, 구성요소별 등급과 알림 제목 규칙은 `kuma-migration.md`를 따른다 | `P1` |

- 키는 위 6개와 심각도 태그로 고정한다. 새 키가 필요하면 이 표를 먼저 바꾼다.
- **심각도는 `priority:P1` 같은 키·값 태그로 바꾸지 않는다.** Kuma 알림 채널의 템플릿이 모니터 태그 중 이름이 `P1`·`P2`·`P3`인 것을 찾아 알림 제목의 `[심각도]`에 쓰고, 없으면 P3으로 표시한다. 태그 이름을 바꾸면 알림이 계속 가지만 심각도가 모두 `[P3]`으로 나간다(2026-10-29 한 번 바꿨다가 되돌렸다).
- 값은 철자를 인벤토리·OpenObserve `host_name`과 같게 쓴다. 그래야 알림과 모니터를 같은 호스트로 대응시킬 수 있다.
- 구성요소별 심각도는 `kuma-migration.md`의 "모니터 이름·심각도·알림 제목"을 따른다(P1: `app`·`caddy`·`valkey-master`·`vip`, P2: `valkey-replica`·`keepalived`).

## 2. IP는 태그가 아니라 설명(description)에 쓴다

공인·VIP·사설 IP를 태그로 넣으면 다른 호스트의 값이 복사돼 틀린 채 남기 쉽다(실제로 두 모니터에서 다른 호스트의 IP·도메인이 붙어 있었다). 모니터 설명에 `공인 … / VIP master … / 사설 …` 형식으로 적고, 기준은 인벤토리와 OpenBao로 한다. 서버 쪽 값은 `keepalived` 설정(VIP)과 `ip addr`(사설)에서 읽는다.

## 3. 적용 방법

- **권장: Kuma UI.** Kuma는 공식 쓰기 REST API가 없고 `.env`의 API 키는 `/metrics` 읽기 전용이다. UI 로그인 계정으로 태그를 편집한다.
- DB를 직접 수정할 수도 있다(Kuma가 내장 MariaDB `embedded-mariadb`를 쓰는 경우, 컨테이너 안에서 `mariadb -S /app/data/run/mariadb.sock -u root kuma`). 이때 다음을 지킨다.
  1. 먼저 `tag`, `monitor_tag` 테이블을 덤프해 root 전용 파일로 보관한다.
  2. 태그 변경은 한 트랜잭션으로 한다.
  3. **Kuma 컨테이너를 재시작한다**(`docker stop -t 120` 후 시작, `kuma-migration.md`와 같다). 태그 이름이 Prometheus 메트릭 라벨이라 시작 때 정해진 라벨 집합에 없는 새 태그가 생기면 `Added label "…" is not included in initial labelset` 오류가 난다(`/metrics` 갱신 실패). 재시작하면 새 태그로 다시 만들어진다.
  4. 재시작 뒤 활성 모니터가 모두 UP인지, `PROMETHEUS` 오류가 더 없는지 확인한다.
- UI 화면에 바로 반영되지 않으면 새로고침한다.

## 4. 확인

모니터별 태그는 `monitor`·`monitor_tag`·`tag`를 조인해 읽는다.

```sql
select m.id, m.name, group_concat(concat(t.name, ':', mt.value) order by t.id separator ' | ') tags
from monitor m join monitor_tag mt on mt.monitor_id = m.id join tag t on t.id = mt.tag_id
group by m.id order by m.id;
```

- 호스트 모니터는 `host`·`service`·`component`·`env`·`node_domain`·`service_domain`과 심각도 태그 하나, 호스트 없는 모니터(VIP)는 `host`와 `node_domain`을 뺀 나머지가 있어야 한다.
- 알림이 쓰는 심각도는 태그 이름 `P1`·`P2`·`P3` 중 하나다. 심각도 태그가 없는 모니터는 `[P3]`으로 나간다.
- `host`와 `node_domain` 값이 서로 같은 호스트를 가리키는지, 모니터 이름의 호스트와도 같은지 본다.
- 모니터 URL이 있다면 노드 도메인(`<관리번호>.nanoit.kr`) 또는 서비스 도메인을 쓴다. 더 이상 쓰지 않는 호스트 이름(옛 호스트네임)을 보는 모니터가 없어야 한다.
