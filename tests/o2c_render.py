"""OpenObserve Config의 기본 렌더링 결과를 한 번만 만들어 테스트가 나눠 쓰게 한다(Spec #348 / Ticket-2).

`defaults/main.yml`은 Jinja 템플릿이고 `o2c_desired` 입력(spec)은 role의 set_fact가 조립하므로, 실제 렌더링 경로(role 태스크)를
짧게 돌려야 한다. `o2c_render_dump`를 주면 role이 O2C-003까지만 실행하고 시크릿이 아닌 원하는 객체를 JSON으로 덤프한 뒤 끝난다
(OpenObserve에는 접속하지 않는다). 알림 정의만 읽는 테스트는 `_apply()`로 전체 play를 돌리는 대신 이 결과를 읽는다.

OpenBao는 공용 읽기 지점의 우회 변수 `openbao_fixture`(키 `<마운트>/<문서 경로>`)로만 흉내 낸다(Spec #511 / Ticket-16).
"""
import json
import os
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
PLAYBOOK = ROOT_DIR / "playbooks" / "openobserve_config.yml"
RENDER_LOG_ENV = "O2C_RENDER_LOG"   # 설정하면 렌더링마다 한 줄을 덧붙인다(워커당 한 번인지 확인하는 용도)

# 가짜 입력 — 렌더링도 반영도 OpenBao·OpenObserve 실서버에 접속하지 않는다. 두 테스트 파일이 같은 값을 쓰도록 여기에만 둔다.
WEBHOOK_URL = "https://hooks.example.internal/o2/SECRET-PATH-123"
ADMIN = {"username": "cfg@example.com", "password": "API-PASSWORD-xyz"}        # secrets/services/openobserve/admin
INGEST = {"username": "ingest@example.com", "password": "INGEST-TOKEN-qrs"}    # secrets/services/openobserve/ingest
NOTIFY = {"url": WEBHOOK_URL}                                                  # secrets/services/alert/notify
ADMIN_DOC, INGEST_DOC, NOTIFY_DOC = ("secrets/services/openobserve/admin", "secrets/services/openobserve/ingest",
                                     "secrets/services/alert/notify")
CONFIG_DOC = "inventory/config/openobserve_config"


def openbao_docs(endpoint, *, config=None, docs=None, assets=None, endpoints=None):
    """`openbao_fixture` 값. `config`는 inventory/config/openobserve_config 문서, `docs`는 `{경로: 문서}` 덮어쓰기(값이 None이면 그 문서를 뺀다),
    `assets`·`endpoints`는 `{관리번호: 문서}`(inventory/assets/<ns>, inventory/assets/<ns>/endpoints)다."""
    out = {"inventory/services/openobserve": {"url": endpoint}, ADMIN_DOC: dict(ADMIN), INGEST_DOC: dict(INGEST), NOTIFY_DOC: dict(NOTIFY)}
    if config is not None:
        out[CONFIG_DOC] = config
    for ns, doc in (assets or {}).items():
        out[f"inventory/assets/{ns}"] = doc
    for ns, doc in (endpoints or {}).items():
        out[f"inventory/assets/{ns}/endpoints"] = doc
    for path, doc in (docs or {}).items():
        if doc is None:
            out.pop(path, None)
        else:
            out[path] = doc
    return out


def fixture_args(endpoint, *, config=None, docs=None, assets=None, endpoints=None, extra=None):
    """`ansible-playbook`에 줄 `-e` 인자(`openbao_fixture`와 role 변수 덮어쓰기)."""
    fixture = openbao_docs(endpoint, config=config, docs=docs, assets=assets, endpoints=endpoints)
    return ["-e", json.dumps({"openbao_fixture": fixture, **(extra or {})})]


def render_desired(dump_path, *, endpoint="http://127.0.0.1:9", extra=None):
    """role을 O2C-003까지 돌려 비밀이 아닌 원하는 객체 목록(`[{kind, name, body, ...}]`)을 돌려준다.

    `endpoint`는 원문 링크에 들어가므로 반영(`_apply`)과 비교할 때 같은 주소를 줘야 한다. `extra`는 role 변수를 덮어쓴다(예: `{"o2c_tz_offset": 480}`).
    """
    cmd = ["ansible-playbook", "-i", "localhost,", str(PLAYBOOK),
           *fixture_args(endpoint, extra={**(extra or {}), "o2c_render_dump": str(dump_path)})]
    res = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300,
                         env=dict(os.environ, ANSIBLE_NOCOLOR="1"))
    assert res.returncode == 0, res.stdout + res.stderr
    if os.environ.get(RENDER_LOG_ENV):
        with open(os.environ[RENDER_LOG_ENV], "a", encoding="utf-8") as fh:
            fh.write(f"{os.getpid()}\n")
    return json.loads(Path(dump_path).read_text(encoding="utf-8"))
