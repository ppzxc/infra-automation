"""보안 제품 로그 일일 보고(`infra-appsec-daily-report`, #450)의 알림 정의와 SQL.

렌더링 결과에서 정의를 읽고, 합성 app_logs 행에 렌더링된 SQL을 sqlite로 돌려 신호별로 울리는지·안 울리는지를 본다. 값은 모두 가짜다.
"""
import sys

import pytest

from o2c_render import ROOT_DIR, render_desired
from o2c_alert_helpers import _run_alert_on_sqlite

sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

pytestmark = pytest.mark.xdist_group("o2c-render")
NAME = "infra-appsec-daily-report"
P = "chakramax-"


def _alert(rendered):
    return next(o["body"] for o in rendered if o["kind"] == "alert" and o["name"] == NAME)


@pytest.fixture(scope="session")
def default(tmp_path_factory):
    return _alert(render_desired(tmp_path_factory.mktemp("o2c-appsec") / "desired.json"))


@pytest.fixture(scope="session")
def with_roster(tmp_path_factory):
    return _alert(render_desired(tmp_path_factory.mktemp("o2c-appsec-roster") / "desired.json",
                                 extra={"o2c_appsec_hosts": ["nsroster"]}))


def _rows(alert, records):
    return _run_alert_on_sqlite(alert["query_condition"]["sql"], [dict({"host_name": "h1"}, **r) for r in records], stream="app_logs")


def _signals(rows):
    return {(r["host_name"], r["signal"]) for r in rows}


def test_trigger_is_a_daily_cron_over_the_last_24_hours(default):
    trig = default["trigger_condition"]
    assert trig["frequency_type"] == "cron" and trig["cron"] == "0 17 * * *"
    assert trig["period"] == 1440 and default["tz_offset"] == 540


def test_other_alerts_keep_minute_frequency(tmp_path):
    rendered = render_desired(tmp_path / "desired.json")
    other = next(o["body"] for o in rendered if o["kind"] == "alert" and o["name"] == "infra-fortigate-change-approved")
    assert other["trigger_condition"]["frequency_type"] == "minutes" and "cron" not in other["trigger_condition"]


def test_a_quiet_day_returns_no_rows_so_nothing_is_sent(default):
    quiet = [{"service_name": P + "chad", "body": "Echo from: 2, Maxsvr Master: 2, Chad Master: -10"},
             {"service_name": P + "cgw-gw", "body": "11-06 10:00:00:000 [0x1]: [INFO] CHECKING timeout..."},
             {"service_name": P + "cgw-gw", "body": "[WARN] ssh_gw, extention packet error"},
             {"service_name": P + "maxsvr", "body": "[erro:Recv:RecvSend.cpp: 1:1] SSL_read() returns 0. Broken pipe."},
             {"service_name": P + "maxsvr", "body": "[erro:GetSession:SessionManage: 76:1] pool sessions : 0, using sessions : 2"},
             {"service_name": P + "rastracker", "body": "[crit:recvData:ClientPeer.cp: 1] - Failure : LocalIP=, SessionIP=1.2.3.4"},
             {"service_name": "other-service", "body": "[ERROR] unrelated"}]
    assert _rows(default, quiet) == []


@pytest.mark.parametrize("record,signal", [
    ({"service_name": P + "rastracker", "body": "x pid = 0"}, "rastracker 프로세스 중단(pid = 0)"),
    ({"service_name": P + "maxbackup", "body": "daily backup Failure"}, "일일 백업 실패"),
    ({"service_name": P + "cgw-sf", "body": "PCAP packets[0]"}, "DB 감시 중단(PCAP packets[0])"),
    ({"service_name": P + "run", "body": "Segmentation fault"}, "비정상 종료 흔적"),
    ({"service_name": P + "maxsvr", "body": "[crit:main: main.cpp: 1:1] ***** Chakra Max Server Start *****"}, "관리 서버 기동 기록"),
    ({"service_name": P + "cgw-gw", "body": "[ERROR] license check failed"}, "목록 밖 오류 줄: " + P + "cgw-gw"),
])
def test_each_signal_is_reported_once_per_host(default, record, signal):
    assert _signals(_rows(default, [record, dict(record)])) == {("h1", signal)}


def test_ha_master_change_needs_two_different_values(default):
    same = [{"service_name": P + "chad", "body": "Echo: Maxsvr Master: 2, Chad Master: -10"}] * 3
    changed = same + [{"service_name": P + "chad", "body": "Echo: Maxsvr Master: 1, Chad Master: -10"}]
    assert _rows(default, same) == []
    rows = _rows(default, changed)
    assert [(r["signal"], r["events"]) for r in rows] == [("HA Master 전환", 2)]


def test_known_noise_is_matched_case_insensitively_and_unknown_errors_survive(default):
    rows = _rows(default, [{"service_name": P + "maxsvr", "body": "[erro:X] SSL_ACCEPT(1.2.3.4:5) returns -1"},
                           {"service_name": P + "maxsvr", "body": "[erro:X] database connection refused"}])
    assert [(r["signal"], r["events"]) for r in rows] == [("목록 밖 오류 줄: " + P + "maxsvr", 1)]


def test_silence_check_is_absent_without_a_roster(default):
    assert "로그 공백" not in default["query_condition"]["sql"]


def test_roster_host_with_no_logs_is_reported_per_missing_service(with_roster):
    rows = _rows(with_roster, [{"host_name": "nsroster", "service_name": P + "chad", "body": "Maxsvr Master: 2"},
                               {"host_name": "nsroster", "service_name": P + "maxsvr", "body": "ok"},
                               {"host_name": "other", "service_name": P + "cgw-gw", "body": "ok"}])
    assert _signals(rows) == {("nsroster", "로그 공백: " + P + "cgw-gw"), ("nsroster", "로그 공백: " + P + "cgw-sf")}
    assert all(r["events"] == 0 for r in rows)


def test_roster_host_with_all_services_logging_is_not_reported(with_roster):
    records = [{"host_name": "nsroster", "service_name": P + s, "body": "ok"} for s in ("cgw-gw", "cgw-sf", "maxsvr", "chad")]
    assert _rows(with_roster, records) == []


def test_bad_cron_is_rejected(tmp_path):
    with pytest.raises(Exception):
        render_desired(tmp_path / "desired.json", extra={"o2c_appsec_report_cron": "every day"})
