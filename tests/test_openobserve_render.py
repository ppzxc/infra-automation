"""기본 렌더링 결과를 공유하는 알림 정의 테스트(Spec #348 / Ticket-2).

`test_openobserve_config.py`의 같은 이름 테스트는 `_apply()`로 전체 play를 돌려 가짜 서버에 쌓인 알림을 읽는다.
여기서는 렌더링 play를 워커당 한 번만 돌리고(`rendered`) 그 결과를 읽는다. 옛 테스트의 정리는 #351 범위다.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from o2c_render import KV, RENDER_LOG_ENV, ROOT_DIR, render_desired
from test_openobserve_config import EXPECTED_ALERTS, PROMQL_ALERTS, RESOURCE_ALERTS, SELFTEST

# 같은 렌더링을 읽는 테스트는 한 워커에 묶는다(`--dist loadgroup`). 묶지 않으면 테스트가 흩어진 워커 수만큼 렌더링한다.
pytestmark = pytest.mark.xdist_group("o2c-render")


@pytest.fixture(scope="session")
def rendered(tmp_path_factory):
    """실제 렌더링 경로(role 태스크)로 만든 원하는 객체 목록."""
    return render_desired(tmp_path_factory.mktemp("o2c-render") / "desired.json")


@pytest.fixture(scope="session")
def rendered_alerts(rendered):
    return {o["name"]: o["body"] for o in rendered if o["kind"] == "alert"}


def test_render_returns_every_managed_alert(rendered_alerts):
    assert EXPECTED_ALERTS | set(PROMQL_ALERTS) | {SELFTEST} <= set(rendered_alerts)


def test_render_never_dumps_the_webhook_destination(rendered):
    assert "destination" not in {o["kind"] for o in rendered}
    text = str(rendered)
    assert KV["alert_webhook_plain_url"] not in text and KV["alert_webhook_token"] not in text and KV["api_password"] not in text


def test_resource_alerts_are_metric_state_alerts_with_grade_and_renotify_interval(rendered_alerts):
    for name, (sev, silence, period, stream) in RESOURCE_ALERTS.items():
        a = rendered_alerts[name]
        assert a["stream_type"] == "metrics" and a["stream_name"] == stream, name
        assert a["context_attributes"]["severity"] == sev, name
        assert a["trigger_condition"]["silence"] == silence and a["trigger_condition"]["period"] == period, name
        assert a["query_condition"]["type"] == "sql"
        assert {"host_name", "usage_pct"} <= set(re.findall(r"\{(\w+)\}", a["row_template"])), name
    assert "mountpoint" in rendered_alerts["infra-disk-usage-p1"]["row_template"]


def test_unreachable_host_is_a_p1_state_alert_on_tcpcheck_status_zero_for_5_minutes(rendered_alerts):
    a = rendered_alerts["infra-unreachable-host"]
    assert a["stream_type"] == "metrics" and a["stream_name"] == "tcpcheck_status"
    assert a["context_attributes"]["severity"] == "P1 긴급"
    assert a["trigger_condition"]["period"] == 5 and a["trigger_condition"]["silence"] == 60
    sql = a["query_condition"]["sql"]
    assert "max(value) = 0" in sql and "tcpcheck_endpoint" in sql
    assert "{tcpcheck_endpoint}" in a["row_template"]


def test_the_group_marker_and_loadgroup_option_keep_one_rendering_per_worker(request):
    assert request.node.get_closest_marker("xdist_group").args == ("o2c-render",)
    for path in ("scripts/run-fast-tests.sh", ".github/workflows/tests.yml", "Makefile"):
        text = (ROOT_DIR / path).read_text(encoding="utf-8")
        assert "--dist loadgroup" in text and "worksteal" not in text, path


def test_four_workers_render_once(tmp_path):
    """-n 4 --dist loadgroup에서 렌더링 fixture 테스트가 한 워커에 묶여 렌더링은 한 번만 일어난다."""
    log = tmp_path / "renders.log"
    env = dict(os.environ, **{RENDER_LOG_ENV: str(log)})
    res = subprocess.run([sys.executable, "-m", "pytest", str(Path(__file__)), "-n", "4", "--dist", "loadgroup", "-q",
                          "-p", "no:cacheprovider", "-k", "not four_workers", "-o", "addopts="],
                         capture_output=True, text=True, cwd=ROOT_DIR, env=env, timeout=600)
    assert res.returncode == 0, res.stdout + res.stderr
    assert len(log.read_text(encoding="utf-8").split()) == 1
