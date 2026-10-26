"""OpenObserve Config의 기본 렌더링 결과를 한 번만 만들어 테스트가 나눠 쓰게 한다(Spec #348 / Ticket-2).

`defaults/main.yml`은 Jinja 템플릿이고 `o2c_desired` 입력(spec)은 role의 set_fact가 조립하므로, 실제 렌더링 경로(role 태스크)를
짧게 돌려야 한다. `o2c_render_dump`를 주면 role이 O2C-003까지만 실행하고 시크릿이 아닌 원하는 객체를 JSON으로 덤프한 뒤 끝난다
(OpenObserve에는 접속하지 않는다). 알림 정의만 읽는 테스트는 `_apply()`로 전체 play를 돌리는 대신 이 결과를 읽는다.
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
KV = {"api_user": "cfg@example.com", "api_password": "API-PASSWORD-xyz", "alert_webhook_plain_url": WEBHOOK_URL,
      "alert_webhook_token": "WEBHOOK-TOKEN-abc", "controller_ingest_token": "INGEST-TOKEN-qrs"}


def fixture_args(endpoint, *, kv=None, extra=None):
    """`ansible-playbook`에 줄 `-e` 인자. 기본은 "앱 텔레메트리·호스트 스위치를 아무 호스트도 안 켬" 픽스처이고, 값이 None인 키는 뺀다(픽스처 없음)."""
    extra = {"o2c_app_telemetry_kv_fixture": {}, "o2c_host_kv_fixture": {}, **(extra or {})}
    extra = {k: v for k, v in extra.items() if v is not None}
    return ["-e", f"o2_endpoint={endpoint}", "-e", json.dumps({"o2c_kv_fixture": kv or KV, **extra})]


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
