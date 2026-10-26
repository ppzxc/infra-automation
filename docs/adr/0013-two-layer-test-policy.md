---
status: accepted
date: 2026-10-26
---

# 13. 테스트를 두 층으로 나눈다: 통합 테스트는 소수, 필터 직접 테스트는 다수. 커밋은 빠른 검사, 전체는 PR

커밋 hook의 `pytest`가 커밋마다 약 11~12분(`-n 6`) 걸렸고, 전체 테스트(문제 정의 시점 1,485개)는 `-n 4`로 약 19분이었다. 에이전트가 시간 초과로 끊기거나 hook을 우회하게 되어 검증이 사실상 지켜지지 않았다. 원인은 `ansible-playbook`을 실행하는 테스트 파일이 19개이고, 특히 `tests/test_openobserve_config.py`가 알림 정의만 읽는 테스트에도 `_apply()`로 전체 play(약 8초)를 매번 새로 띄운다는 점이었다. callback·gathering·fact cache 설정으로는 줄지 않았다(측정함). 이 결정은 Spec #348(#349~#353)에서 구현했다.

## Decision

1. **두 층으로 나눈다.**
   - **통합 테스트(소수)**: `ansible-playbook`을 실제로 실행해서 멱등성, 계획·반영 순서, check 모드, `no_log`, 실패 경로, 검증 단계처럼 실행해 봐야 알 수 있는 동작만 검증한다.
   - **필터 직접 테스트(다수)**: 알림 SQL·행 템플릿·길이·시각 렌더링처럼 정의만 읽는 검사는 렌더링 play를 한 번 돌려 얻은 결과(`o2c_render_dump`)를 공유하는 `tests/test_openobserve_render.py`에서 한다. 같은 렌더링을 쓰는 테스트는 `xdist_group`으로 한 워커에 모이고 `--dist loadgroup`으로 실행한다.
   - 두 입력이 같다는 것은 다리 테스트 `test_apply_sends_exactly_what_the_render_play_shows`(통합)가 지킨다. 이 테스트가 깨지면 필터 직접 테스트는 운영 동작을 대변하지 못한다.
2. **`slow`는 자동으로 표시한다.** `tests/conftest.py`가 `ansible-playbook` 문자열을 쓰는 함수와 그것을 헬퍼·fixture·다른 테스트 모듈 별칭으로 부르는 테스트를 `slow`로 표시한다. 손으로 단 marker에 기대지 않으므로 표시를 잊어서 hook이 다시 느려지지 않는다.
3. **검증 시점을 나눈다.**

   | 시점 | 무엇을 | 실행 |
   |---|---|---|
   | 커밋(pre-commit) | 시크릿 검사(gitleaks), 3-Way 스펙 검증, 빠른 테스트 `-m "not slow and not heavy_harness"` | `lefthook.yml` → `scripts/run-fast-tests.sh` (`-n 4 --dist loadgroup`, `--durations=10`, 플러그인이 있으면 `--timeout=300`) |
   | 푸시(pre-push) | Molecule Fast Scenario (ADR-0007) | `scripts/run-molecule.sh fast` |
   | PR·`main` push(GitHub Actions) | `spec` job + 전체 `pytest`를 6분할 matrix(`TEST_SHARD`, nodeid crc32)로 실행 | `.github/workflows/tests.yml` |
   | 릴리스 전 | Molecule Full Matrix | `make test-full` |

   `make init-hooks`가 설치하는 `scripts/pre-commit.sh`(gitleaks가 없을 때 lefthook이 부르는 대체 검사 포함)도 같은 `scripts/run-fast-tests.sh`를 쓴다. `make test`(`make test-unit`)는 사람이 직접 전체를 돌리는 진입점이다.
4. **전환 기간 규칙.** 옛 통합 테스트는 새 필터 테스트가 자리 잡는 동안 `slow`로 남겨 CI가 둘 다 돌린다. 옛 테스트는 (a) 옛 이름과 새 이름의 **대응표**가 있고 (b) 새 테스트가 대상 동작을 **일부러 깼을 때 실패하는 것**을 확인한 뒤에만 지운다. 확인은 묶음마다 role·필터 코드를 임시로 바꿔 새 테스트를 돌려 실패한 테스트를 기록하고 원래대로 되돌리는 방식이다. 기록은 `docs/tests/openobserve_config_test_transition.md`에 있다.
5. **"모든 테스트가 통과한다"는 보장은 유지한다.** 커밋에서 빠진 `slow` 테스트는 PR에서 모두 돈다. 필수 체크(`spec`, `pytest (1/6)`~`(6/6)`)의 브랜치 보호 설정은 저장소 관리자가 한다.

## Evidence

서두의 1,485개는 #348 문제 정의 시점의 전체 테스트 수이고, 아래 1,530개는 #350~#353 작업 뒤 이 ADR을 쓴 시점의 수다. 서로 다른 시점의 수치라 값이 다르다.

| 항목 | 전 | 후 | 출처 |
|---|---|---|---|
| 커밋 hook의 pytest | 약 11~12분 | 약 32초(1,021개 통과, 2개 skip, `-n 4`; 렌더링 테스트 63개를 hook에 넣기 전 957개·약 31초) | #348 문제 정의, 렌더링 테스트를 fast로 옮긴 뒤 `scripts/run-fast-tests.sh` 재실행 |
| `slow`로 자동 분류된 테스트 | 해당 없음 | 509개(전체 1,533개 중; session fixture 경계 적용 전 572개) | `pytest -m slow --collect-only` |
| 전체 테스트 | `-n 4`로 약 19분 | 6분할 matrix에서 가장 느린 job 6분 36초(`spec` 39초) | #348, #352(PR #357) |
| `test_openobserve_config.py` 전체 | 360개, 532초 | 300개, 448초 | #351 |
| config + render 두 파일 합계 | 약 538초(532 + 6) | 439초(약 18%) | #351 |
| `_apply(o2)` 소스 호출 | 126 | 83 | #351 (grep) |
| `_apply(o2)` 실행 시 기본 호출 | 142 | 82 | #351 |
| 전환 테스트 | 알림 정의만 읽는 옛 테스트 44개 | `test_openobserve_render.py`(65개, 7초), 44개 모두 일부러 깬 변경에서 실패 확인 | #351 |

- 합계 감소가 크지 않은 이유: 남은 `_apply` 호출 대부분이 멱등성·변경 갱신·검증 단계처럼 서버와 주고받는 통합 테스트이거나 목록·임계를 바꿔 렌더링을 새로 해야 하는 테스트다(기본 호출이 아닌 호출 167개는 그대로).
- 속도의 대부분은 테스트를 줄여서가 아니라 **커밋에서 `slow`를 빼고 PR에서 병렬로 돌려서** 얻었다. 필터 직접 테스트로의 전환은 전체 시간을 약 100초 줄였고, 앞으로 커밋 hook으로 가져올 수 있는 기반이다(아래 미해결 항목).

## Consequences

- 커밋은 약 30초 안에 끝나므로 우회할 이유가 줄지만, 커밋 단계에서는 `ansible-playbook`을 테스트마다 실행하는 동작(약 509개)이 검증되지 않는다. 그 회귀는 PR에서 잡힌다. **푸시 전에 확인하려면 `pytest tests/ -n 4 --dist loadgroup`을 직접 돌린다.**
- 새 테스트가 `ansible-playbook`을 쓰면 자동으로 `slow`가 되어 커밋에서 빠진다. 커밋에서도 돌리고 싶으면 그 동작을 필터 함수 직접 테스트로 쓴다.
- 알림 SQL·행 템플릿 같은 정의 검사를 추가할 때는 `_apply()` 통합 테스트가 아니라 `tests/test_openobserve_render.py`의 `desired` fixture를 쓴다. 통합 테스트는 실행해야만 알 수 있는 동작에만 쓴다.
- 공개 저장소이므로 CI는 시크릿을 주입하지 않고 읽기 권한만 쓴다. Python·ansible-core·컬렉션 버전은 `requirements-test.txt`로 로컬과 맞춘다.
- `host_agents_legacy_*`와 `test_backup`은 필터 테스트로 바꾸지 않아 CI 시간에 남는다.

## Open items (미해결)

- **(해소) 렌더링 테스트가 커밋 hook에 들어가지 않던 문제.** `tests/conftest.py`의 자동 `slow` 전파가 session 범위 fixture(`rendered`)에서 멈추도록 바꿨다. 렌더링은 워커당 한 번이라 hook 비용이 작다(약 31초 → 약 32초). 그래서 `tests/test_openobserve_render.py` 65개가 모두 `-m "not slow"`에 들어간다. 테스트가 `ansible-playbook`을 직접 실행하거나 function 범위 fixture가 실행하면 여전히 `slow`다(`tests/test_conftest_sharding.py`가 지킨다).
- **(해소) CI 샤딩이 `xdist_group`을 쪼개던 문제.** 샤드를 nodeid의 crc32로만 나눠 같은 `xdist_group`이 여러 샤드에 흩어지고 샤드마다 렌더링했다. 지금은 `tests/conftest.py`가 `xdist_group`이 있으면 그룹 이름으로 샤드를 정해 같은 렌더링을 쓰는 테스트가 한 샤드에 모인다(`tests/test_conftest_sharding.py`가 지킨다).
- **Molecule `VERIFY-O2C-008`·`VERIFY-O2C-009`는 추가하지 않았다.** `O2C-008`·`O2C-009`는 문서와 코드에는 있지만 `molecule/*/verify.yml` 검증이 없어 `scripts/validate-ansible-specs.py`가 `INTEGRATED`(검증 없음)로 분류한다. 동작은 pytest(`tests/test_openobserve_render.py`)만 검증한다.
- **`pytest-timeout`이 없는 환경**에서는 `scripts/run-fast-tests.sh`가 시간 제한 없이 실행하고 안내 메시지만 낸다(`pytest-xdist`가 없으면 직렬 실행). `pip install -r requirements-test.txt`로 설치한다.

## Considered Options

- **hook에서 변경 경로와 관련된 테스트만 실행**: 빠른 테스트만으로 2분 이내(약 32초)가 되어 경로 매핑의 복잡도를 감수할 이유가 없었다. 공유 경로(`filter_plugins/`, `playbooks/`, `ansible.cfg`, `pytest.ini`, `lefthook.yml`, 테스트 헬퍼)를 건드릴 때 전체로 돌아가야 하는 규칙이 필요해지는 것도 단점이다.
- **전체 테스트를 hook에 그대로 두고 병렬도만 올리기**: 병렬 실패의 원인을 알 수 없고 여전히 10분대라 우회를 막지 못한다.
- **marker를 손으로 달기**: 표시를 잊으면 hook이 다시 느려진다. AST 기반 자동 표시로 대신한다.
- **옛 통합 테스트를 바로 삭제**: 대응표와 일부러 깨 보기 확인 없이 지우면 커버리지가 조용히 사라진다.
