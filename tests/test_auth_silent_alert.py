"""인증 로그 수집 중단 알림(Spec #390): `o2c_absence_sql`의 선택 인자와 픽스처. 렌더링된 알림 정의 테스트는 test_openobserve_render.py에 있다(ADR-0013)."""
import re
import sys

import pytest

from o2c_render import ROOT_DIR

sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))
from openobserve_config import o2c_absence_sql  # noqa: E402

AUTH = "service_name = 'auth'"


def test_absence_sql_defaults_keep_the_silent_host_sql_unchanged():
    p2 = o2c_absence_sql(["ns1"], "system_memory_usage", "p2")
    p1 = o2c_absence_sql(["ns1"], "system_memory_usage", "p1")
    assert p2 == ("SELECT 'ns1' AS host_name, count(*) AS n FROM \"system_memory_usage\" WHERE host_name = 'ns1' "
                  "HAVING count(*) >= 1 AND sum(CASE WHEN _timestamp >= to_unixtime(now()) * 1000000 - 900000000 THEN 1 ELSE 0 END) < 1")
    assert p1 == ("SELECT 'ns1' AS host_name, count(*) AS n FROM \"system_memory_usage\" WHERE host_name = 'ns1' "
                  "HAVING count(*) < 1")


def test_absence_sql_condition_narrows_every_branch_to_one_source():
    sql = o2c_absence_sql(["ns1", "ns2"], "security_logs", "p1", AUTH)
    assert sql.count(" UNION ALL ") == 1
    for host in ("ns1", "ns2"):
        assert "WHERE host_name = '%s' AND %s HAVING count(*) < 1" % (host, AUTH) in sql


@pytest.mark.parametrize("recent, us", [(60, 3600000000), ("60", 3600000000), (15, 900000000)])
def test_absence_sql_p2_recent_window_is_configurable(recent, us):
    sql = o2c_absence_sql(["ns1"], "security_logs", "p2", AUTH, recent)
    assert "- %d THEN 1" % us in sql and AUTH in sql


@pytest.mark.parametrize("bad", [0, -5, "abc", True, 1.5e-9])
def test_absence_sql_rejects_a_non_positive_recent_window(bad):
    with pytest.raises(ValueError):
        o2c_absence_sql(["ns1"], "security_logs", "p2", AUTH, bad)


@pytest.mark.parametrize("cond", ["service_name = 'auth'; DROP", "a = 1 -- x", 5])
def test_absence_sql_rejects_an_unsafe_condition(cond):
    with pytest.raises(ValueError):
        o2c_absence_sql(["ns1"], "security_logs", "p1", cond)


def test_absence_sql_empty_roster_never_fires_and_keeps_the_condition_shape():
    assert o2c_absence_sql([], "security_logs", "p1", AUTH) == (
        "SELECT 'none' AS host_name, count(*) AS n FROM \"security_logs\" WHERE service_name = 'auth' HAVING count(*) < 0")
    assert o2c_absence_sql([], "system_memory_usage", "p2") == (   # 조건이 없으면 기존 SQL 그대로
        "SELECT 'none' AS host_name, count(*) AS n FROM \"system_memory_usage\" HAVING count(*) < 0")


def test_auth_silent_fixtures_cover_the_rsyslog_stall_case():
    from o2c_alert_helpers import FIXTURES
    for name in ("infra-auth-silent-p2", "infra-auth-silent-p1"):
        cases = FIXTURES[name]["cases"]
        stall = [c for c in cases if c["fires"] and any(r.get("service_name") == "audit" for r in c["records"])]
        assert stall, "%s: auth는 끊기고 audit만 오는 호스트가 발화하는 케이스가 있어야 한다" % name
