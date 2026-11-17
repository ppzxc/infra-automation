---
status: accepted
date: 2026-11-17
---

# 14. OpenBao 저장 구조와 접근 정책: `infra` 1단, 마운트 두 개, 소유 대상별 저장, 작업 계열별 정책

OpenBao의 거의 모든 데이터가 `infra/prod/host` 네임스페이스의 `hosts/<ns>` 한 문서에 쌓여 있었다. ISMS 메타데이터, 접속 주소, 계정 이름, 에이전트 설정, API 토큰이 섞였고, 키 이름은 도구 이름(`ansible_host`)과 별칭(`ip`, `host`, `public_ip`)으로 갈라졌다. 네임스페이스·마운트·접두사를 정하는 손잡이가 역할마다 복사돼 기본값도 서로 달랐고, 모든 Semaphore 템플릿이 Environment 하나와 AppRole 하나를 같이 썼다. 웹훅 감시 작업도 모든 호스트의 root 비밀번호를 읽을 수 있었다. 등록은 UI·CLI로 직접 해서 형식 검증이 없었고, 정책은 손으로 바꾸고 이력이 없었다. 이 구조로는 Host Audit 유형 확장(네트워크 장비·웹·DB)을 받을 수 없었다. 서버가 아닌 Asset, 경유 접속, 여러 Endpoint를 표현할 자리가 없기 때문이다.

이 결정은 Map #500(#501~#510)에서 정했고 Spec #511이 구현한다. 용어는 `CONTEXT.md`의 Asset·Endpoint·Credential·Automation Identity·Service·Operator를 따른다. 일괄 전환은 한 번 하는 절차라 ADR이 아니라 런북이다([openbao-cutover](../runbooks/openbao-cutover.md)).

## Decision

1. **네임스페이스는 `infra` 1단이고 그 안에 KV v2 마운트를 둘 둔다.** 비밀이 아닌 값은 `inventory/`, 비밀만 담는 곳은 `secrets/`다. 네임스페이스·마운트는 공용 읽기 지점 한 곳에서만 설정하고, 역할마다 복사된 접두사 변수와 대체 읽기 체인은 없앤다. 필수 문서나 필수 키가 없으면 대체값 없이 실패한다.
2. **저장은 소유 대상별로, 접근은 작업 계열별로 나눈다.** 소유 대상은 Asset, Service, Operator, Automation Identity다. 같은 Asset의 정보도 비밀이 아닌 값은 `inventory/`, 비밀은 `secrets/`에 두고, 무엇을 읽을 수 있는지는 정책이 정한다. 문서 종류별 경로 골격은 스키마와 `index.yml`이 원본이다.
3. **스키마를 강제하고 쓰기는 등록 도구로만 한다.** 문서 종류마다 JSON Schema(2020-12)를 저장소에 두고, 경로 패턴 → 스키마 대응표는 `index.yml` 한 파일로 한다. `validate`·`put`·`check`가 같은 검증 코드를 쓰고, `put`은 `cas`로 동시 수정을 막는다. 모든 객체는 `additionalProperties: false`다. 매일 정기 점검(Periodic Check)이 전체를 스키마·참조·Semaphore 인벤토리와 대조한다. "등록은 도구로만"은 정책으로 강제할 수 없는 운영 규칙이다.
4. **정책·AppRole·마운트·userpass는 OpenTofu 코드로 관리한다.** `hashicorp/vault` provider(버전 고정)를 쓰고 Semaphore 템플릿으로 Auto Approve 없이 적용한다. state는 S3 호환 저장소에 두고 `pbkdf2`로 state·plan을 암호화한다. AppRole `secret_id`는 state에 남지 않도록 OpenTofu로 발급하지 않고 response-wrapping 수동 런북으로 발급한다([openbao-operations](../runbooks/openbao-operations.md)).
5. **AppRole은 작업 계열마다 하나다.** 정책은 경로 묶음 단위의 작은 정책이고 AppRole이 `token_policies`로 조합한다. 계열 × 경로 매트릭스의 원본은 정책 HCL이며 문서에 복사하지 않는다. 정책 경로는 `+`와 끝자리 `*`만 쓰므로 "이번 실행 Asset만 읽기" 제한은 만들 수 없고 문서 종류로 나눈다. 기계 계열 중 list 권한은 `periodic_check`에만 준다.
6. **사람은 일상용 `operator`와 비상용 `admin`으로 나눈다.** `operator`는 `infra` 안 userpass 사용자로 전체 읽기(list 포함, 등록 도구의 `check`와 참조 확인에 필요)와 create/update만 하고 delete·destroy·`sys/`는 없다. 삭제·영구 삭제·정책 수동 변경은 루트 네임스페이스의 `admin`으로만 한다. 에이전트 세션(`agent_session`)은 `inventory/` 전체와 `secrets/`의 메타데이터(키 이름·버전)만 읽고 비밀 값은 읽지 못한다.
7. **전환은 이중 읽기 없이 한 번에 한다.** 운영에 영향 없는 준비 PR을 먼저 병합하고, 동결 창에서 이전 스크립트로 적재한 뒤 전환 PR 하나를 병합한다. 옛 `infra/prod/host`는 읽기 전용으로 남겨 되돌리기를 코드 revert와 Environment 복귀로 끝낸다.

## Considered Options

| 대안 | 결과 | 이유 |
|---|---|---|
| 현행 유지(`hosts/<ns>` 한 문서) | 기각 | 기각 이유: 소유 대상이 다른 값이 한 문서에 섞여 한 계열에 필요한 만큼만 열 수 없다. 웹훅 감시가 root 비밀번호를 읽는 문제가 그대로 남고, 서버가 아닌 Asset을 표현할 자리가 없다. |
| 다단 네임스페이스(`infra/prod/host` 유지·확장) | 기각 | 기각 이유: 네임스페이스를 건너는 identity는 기본으로 꺼져 있고 문서도 켜지 말라고 한다. OpenTofu도 사람 인증도 네임스페이스 하나(`infra`)만 다루면 되고, 분리는 마운트와 정책으로 충분하다. |
| 작업별 저장(작업 이름 문서에 그 작업의 값을 모음) | 기각 | 기각 이유: 작업 이름 문서가 실제로는 Service 권한(예: RustFS 쓰기 자격)인데 작업 이름 뒤에 숨고, 같은 자격을 쓰는 작업이 늘면 복제된다. 소유 대상별로 저장하고 작업별로는 접근만 나눈다. |
| 이중 읽기 전환(옛 구조와 새 구조를 함께 읽는 기간) | 기각 | 기각 이유: 대체 읽기 체인이 영구히 남고 어느 쪽이 원본인지 흐려진다. 일괄 전환하고 옛 구조를 읽기 전용으로 두면 되돌리기가 데이터 복원 없이 끝난다. |
| 문서 버전 표기(`schema_version`) | 기각 | 기각 이유: 소비자가 여러 버전을 동시에 읽어야 해 대체 읽기가 되살아난다. 스키마를 바꾸는 PR에 데이터 이전 절차를 함께 넣고, Periodic Check가 옛 문서를 잡는다. |

이 ADR에서 정하지 않음: 동적 자격증명(SSH 서명 인증서, DB 시크릿 엔진)과 감사 장치(audit device).

## Consequences

- 새 Asset 유형(네트워크 장비·웹·DB)은 구조 변경 없이 Endpoint와 Credential을 추가해 받는다.
- 정책 변경은 저장소 코드 리뷰와 `plan`을 거친다. `plan`은 state 밖에서 손으로 만든 객체를 보지 못하므로 Periodic Check가 OpenTofu 밖 객체를 탐지한다.
- 운영 부담이 늘어난다. 두 번째 도구(OpenTofu)와 state 저장소, 180일마다 하는 수동 `secret_id` 교체가 생기고, 교체를 놓치면 작업이 멈춘다. 만료 30일 전 알림이 이를 완화한다.
- applier AppRole은 사실상 관리자 권한이다. secret_id를 짧게 두고 러너 CIDR로 묶어 노출을 줄인다.
- 이 ADR로 ADR-0006 §2.2(OpenBao KV 스키마)·ADR-0009·ADR-0012의 OpenBao 위치 서술이 대체된다. 개정 줄은 전환 PR에서 붙인다.
