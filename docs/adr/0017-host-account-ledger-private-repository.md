---
status: accepted
date: 2026-11-20
---

# 17. Host Account는 비공개 원장 저장소를 정본으로 두고, 직원 신원은 GWS에서 읽으며, 정기 비교로 Account Drift를 보고한다

리눅스 서버의 계정은 두 경로로 생긴다. 하나는 프로비저닝(`common` 롤 `accounts`, 실제로는 관리 계정만)이고, 다른 하나는 손 작업이다. 어떤 직원이 어느 서버에 어떤 권한으로 들어갈 수 있는지 한곳에서 볼 수 없다. 접속 요청과 승인 이력이 남지 않고, 퇴사자 계정과 출처를 모르는 키를 찾아낼 방법도 없다. 지금 관측은 Host Audit Asset Inventory 하나뿐이다. 이 관측은 월 1회 이름만 비교하고, 보조 그룹·만료·키 지문은 보지 않는다. 이 저장소는 공개라서 계정 이름과 직원 정보를 둘 수 없다. 그래서 **Host Account와 Access Grant의 정본을 별도 비공개 저장소(`idc-access`)에 둔다**. 추적은 이 저장소의 지도 #618과 스펙 이슈 #630에서 한다. 형식의 정본은 비공개 저장소의 `docs/FORMAT.md`와 `schemas/`다.

1. **정본은 셋이고 서로 겹치지 않는다.** 직원 신원·조직·그룹의 정본은 Google Workspace(GWS)다. Host Account, Access Grant, 공개키의 정본은 `idc-access`다. 시크릿(서비스 계정 키, 비밀번호, 개인키, 토큰)은 OpenBao에만 둔다. 원장 대상은 리눅스 서버의 모든 계정이다(`person`·`service`·`automation`). 시스템 계정은 개수만 본다.
2. **역할 분담.** 스케줄링과 실행은 모두 Semaphore(Ansible)가 한다. 서버 접속이나 시크릿이 필요한 일도 Semaphore만 한다. Forgejo는 두 가지만 한다. 웹훅으로 실행을 트리거하고, Actions로 저장소 내용만 읽는 정적 PR 검증을 돌린다. 트리거는 ADR-0016과 같다. `main` push 웹훅이 Semaphore Integration을 부르고, 서명은 HMAC-SHA256으로 검증한다. 템플릿은 체크아웃한 커밋을 웹훅의 커밋과 대조한다. 서명 비밀은 integration마다 따로 두고, 봇의 push는 매처에서 제외한다.
3. **GWS 동기화.** Semaphore가 GWS Directory API에서 users·orgunits·groups·members 전체를 정기적으로 읽어 `snapshots/directory/`에 커밋한다. 읽기 전용 서비스 계정에 읽기 전용 커스텀 역할을 직접 부여하고, 도메인 전체 위임은 쓰지 않는다. 키와 고객 ID는 OpenBao `secrets/`에 둔다. Host Account는 GWS 불변 id로 Employee에 연결한다. 이메일은 표시용이다.
4. **원장 형식.** 계정마다 `accounts/<username>/account.yml` 파일 하나를 두고, 공개키는 키 하나당 `keys/<라벨>.pub` 파일 하나를 둔다. Access Grant는 계정 파일 안의 `grants:` 목록이다. 대상은 Asset, 이름 붙인 호스트 묶음(`hostsets.yml`), 또는 그 목록이다. sudo는 `none | all | <프로필>`이고, 프로필은 `sudo_profiles.yml`에 둔다. `service`와 `automation`은 책임자 Employee가 반드시 있어야 한다. GWS에 없는 사람은 '외부 인원'으로 두고 만료일과 내부 책임자를 필수로 한다. 새 `person` 계정의 이름은 이메일 앞부분이다. 이름은 생성 때 고정하고, 규칙에 맞지 않는 기존 이름은 '예외 이름'으로 인정한다. UID는 새 계정에만 원장이 예약 범위에서 배정한다.
5. **변경은 PR로만 한다.** `main`은 보호하고, 병합에는 인프라 담당 1명의 승인과 필수 상태 검사가 필요하다. 봇만 push 허용 목록에 넣는다. 봇 커밋에는 의미 비교로 '봇 범위 검사'를 돌린다. 봇이 바꿀 수 있는 범위는 `snapshots/**`, `observed/**`, `README.md`, 계정 파일의 `email` 필드다. 직원이 자기 계정 파일에 키를 넣는 PR을 직접 여는 것이 기본이다.
6. **Account Drift는 원장 대 관측의 차이다.** Host Audit과 분리한 읽기 전용 수집기가 매일 1회 전체 서버를 수집한다. 수집 범위는 `/etc/passwd`, 보조 그룹, 셸, 비밀번호 상태, sudo 수준, `authorized_keys` 지문이다. 지문은 러너에서 SHA256으로 계산하고, 저장소에는 키 본문을 남기지 않는다. 수집 결과를 원장과 비교해 드리프트 10종과 '정보'로 나누고, 심각도는 높음·중간·정보다. 무시 목록과 확인 표시는 두지 않는다. 드리프트는 원장 PR이나 호스트 수정으로만 없앤다. 알람은 드리프트가 새로 생기거나 사라졌을 때만 보내고, 계정 이름과 서버 이름을 넣지 않는다.
7. **첫 원장은 관측에서 만든다.** bootstrap 템플릿이 관측과 GWS 스냅샷으로 초안을 만들어 PR로 연다. 이메일 앞부분과 정확히 일치하는 계정만 `person`으로 연결한다. 나머지는 '미분류'로 두고, 미분류는 bootstrap PR에서만 새로 만들 수 있다. 병합 직후 남는 드리프트는 받아들이면 안 되는 위험(퇴사자 계정 활성, 빈 비밀번호, 셸 불일치, root 비허용 키)뿐이다. 나중에 편입하는 호스트도 같은 템플릿의 호스트 단위 모드로 받는다.
8. **단계.** 1단계는 원장 생성, GWS 동기화, 드리프트 보고만 하고 서버를 바꾸지 않는다. 병합이 부르는 템플릿은 모의 실행으로 바뀔 계정 목록만 보고한다. 계정 생성·잠금·삭제(적용), 기존 경로 전환, 퇴사자 회수 자동화, 기한부 접속은 다음 단계다.

## Considered Options

- **기존 경로 확장(`common` 롤 `accounts` + OpenBao `inventory/operators/`)**: 이 저장소가 공개라 계정 이름과 직원 연결을 둘 수 없다. OpenBao는 시크릿 저장소라 PR 승인 이력과 검토 흐름이 없다.
- **CMDB 제품이나 OpenBao를 원장으로 쓰기**: 접속 요청·승인·이력이 Git PR만큼 단순하지 않다. 정적 검증과 리뷰를 따로 만들어야 한다.
- **GWS를 Host Account의 정본으로 쓰기(`posixAccounts`·`sshPublicKeys` 필드)**: 현재 GWS에는 SSH 키·UID·사번이 한 명도 없다. 서버별 권한(Access Grant)을 담을 곳도 없다. GWS는 신원만 맡는다.
- **Host Audit 수집기 재사용**: 증적의 `schema_version`, 3년 잠금 보관, 월 1회 주기에 묶여 있다. 매일 비교하는 드리프트 관측을 같은 증적에 넣으면 둘 다 흔들린다. 읽기 전용 정의와 접속 규약만 같이 쓴다.
- **Semaphore REST API를 Forgejo Actions에서 호출**: 커밋 고정과 상태 표시는 되지만, 토큰 범위를 좁힐 수 없고 같은 저장소 브랜치 push로 우회할 수 있다.
- **Grant를 받는 호스트별 파일로 두기(ADR-0016 방식)**: 본인 키 PR, 퇴사 회수 PR, 계정별 검토가 여러 파일에 흩어진다. 호스트 소유자 승인이 필요해지면 생성 뷰로 해결한다.
- **직전 실행 대비 드리프트**: 처음 본 차이가 다음 날 기준값이 되어 사라진다. 원장과 비교하고, 알람만 직전 실행과 비교한다.

## Consequences

- **ADR-0009 개정**: "결과를 Git에 보관하지 않는다"는 공개 저장소에 계정·포트가 남는 것을 막는 결정이었다. 비공개 `idc-access`에 계정 이름과 관측 요약을 두는 것은 그 결정과 부딪히지 않는다. Host Audit 증적은 그대로 Host Audit이 보관한다.
- **ADR-0014와 `docs/openbao_integration.md` 부분 대체(다음 단계)**: 원장이 Operator 공개키와 관리 계정의 정본이 되면, `inventory/operators/<계정>`과 `common` 롤 `accounts`는 원장에서 값을 받도록 바뀐다. 전환 전까지 기존 경로는 그대로 동작한다. 저장 구조(`inventory/`·`secrets/`)와 계열별 접근 정책은 바뀌지 않는다.
- **CONTEXT.md 개정**: Operator는 "Asset 위의 계정이 아님"이었다. 앞으로는 Employee 중 인프라를 운영하는 사람을 뜻하고, 그 사람의 로그인 계정은 Host Account다. Host Account, Employee, Access Grant, Account Drift를 새 용어로 둔다.
- Asset 목록은 봇이 `snapshots/assets/`에 스냅샷으로 둔다. 원천은 잠정으로 OpenBao `inventory/`이고, Semaphore static 인벤토리 함정은 정기 태스크의 호스트 목록을 정할 때 함께 다룬다.
- PR 검증은 저장소 파일만 읽으므로 서버와 시크릿 없이 돌고, 병합 뒤 대시보드가 어떻게 바뀌는지 미리 보여 줄 수 있다. 그 대신 스냅샷이 오래되면 검증도 오래된 값으로 판정한다.
- 네트워크 장비와 NAS의 계정은 다루지 않는다.
