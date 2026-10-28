"""기본 렌더링 결과를 공유하는 알림 정의 테스트(Spec #348 / Ticket-2).

`test_openobserve_config.py`는 `_apply()`로 전체 play를 돌려 가짜 서버와 주고받는 동작(멱등성·순서·check 모드·실패 경로)을 본다.
여기서는 렌더링 play를 워커당 한 번만 돌리고(`rendered`) 그 결과를 읽는다.

#351에서 알림 정의만 읽던 옛 테스트 44개를 이 파일로 옮겼다(대응표: docs/tests/openobserve_config_test_transition.md).
옮긴 테스트는 같은 이름이고, `desired`(렌더링 결과를 `FakeO2.store`와 같은 모양으로 보여 주는 fixture)를 읽는다.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from o2c_render import KV, RENDER_LOG_ENV, ROOT_DIR, render_desired
from o2c_alert_helpers import (
    COUNT_FIELDS, DEVICE_TIME_ALERTS, EXPECTED_ALERTS, FIXTURES, FORTIGATE_ALERTS, FORTIGATE_FN, LONGEST_ROW_VALUES,
    LONGEST_TEXT, MEM_ALERTS, PROMQL_ALERTS, PROMQL_DEFS, PROMQL_ROW_FIELDS, RAID_ALERTS, RESOURCE_ALERTS, ROLE, TIME_ALERTS,
    RUNBOOK, SECURITY_ALERTS, SECURITY_TIME_CASES, SELFTEST, SWITCH_ALERTS, SWITCH_FN, SYSTEM_TIME_CASES,
    TEXT_VALUE, _branch_devices, _decode_raw_url, _ev, _fail, _filters, _fixture_records, _kst_us, _raw_line,
    _raw_original, _rendered_message, _row_lines, _run_alert_on_sqlite, _run_memory_alert_on_sqlite, _sql,
)

# 같은 렌더링을 읽는 테스트는 한 워커에 묶는다(`--dist loadgroup`). 묶지 않으면 테스트가 흩어진 워커 수만큼 렌더링한다.
pytestmark = pytest.mark.xdist_group("o2c-render")


@pytest.fixture(scope="session")
def rendered(tmp_path_factory):
    """실제 렌더링 경로(role 태스크)로 만든 원하는 객체 목록 `[{kind, name, body, ...}]`(원본). 아래 `rendered_alerts`(알림 body만 이름으로)와 `desired`(`FakeO2.store` 모양)는 이것에서 파생한다."""
    return render_desired(tmp_path_factory.mktemp("o2c-render") / "desired.json")


@pytest.fixture(scope="session")
def rendered_alerts(rendered):
    """`rendered` 중 알림의 `{이름: body}`."""
    return {o["name"]: o["body"] for o in rendered if o["kind"] == "alert"}


class RenderedServer:
    """렌더링 결과를 `FakeO2`가 반영 뒤 들고 있는 모양(`store`, `shorts`)으로 보여 준다. 알림 정의를 읽는 기존 helper(`_sql` 등)가 그대로 쓴다.

    destination은 비밀이라 덤프에 없으므로 일부러 `store`에 두지 않는다(읽으면 KeyError — 비어 있는 척하지 않는다).
    반영이 서버에 보내는 것과 이 결과가 같다는 것은 `test_apply_sends_exactly_what_the_render_play_shows`가 지킨다.
    """

    def __init__(self, rendered):
        self.store = {kind: {o["name"]: o["body"] for o in rendered if o["kind"] == kind}
                      for kind in ("alert", "template", "function", "pipeline")}
        self.shorts = {o["short_link"]["short"].split("/web/short/")[1].split("?")[0]: o["short_link"]["original"]
                       for o in rendered if o.get("short_link")}


@pytest.fixture(scope="session")
def desired(rendered):
    """`rendered`를 `FakeO2.store`처럼 읽게 하는 `RenderedServer`(옮긴 테스트가 `o2.store` 대신 읽는다)."""
    return RenderedServer(rendered)


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
    env = {k: v for k, v in os.environ.items() if k != "TEST_SHARD"}   # CI 샤드 몫이 자식 pytest의 수집을 줄이지 않게 한다
    env[RENDER_LOG_ENV] = str(log)
    res = subprocess.run([sys.executable, "-m", "pytest", str(Path(__file__)), "-n", "4", "--dist", "loadgroup", "-q",
                          "-p", "no:cacheprovider", "-k", "returns_every_managed or never_dumps or metric_state_alerts or unreachable_host",
                          "-o", "addopts="],
                         capture_output=True, text=True, cwd=ROOT_DIR, env=env, timeout=600)
    assert res.returncode == 0, res.stdout + res.stderr
    assert len(log.read_text(encoding="utf-8").split()) == 1


# --- 전환된 테스트(#351) ---


def test_template_body_is_the_plain_text_message_without_a_json_wrapper(desired):
    """통지 본문은 사내 알림 플랫폼(Google Chat)의 text/plain 경로로 가는 알림 텍스트 그대로다(JSON 래퍼 없음, 본문 길이 제한 없음)."""
    text = desired.store["template"]["infra-automation-plain"]["body"]
    assert not text.lstrip().startswith("{\"content\"") and '"type": "text"' not in text
    # 행동 가능한 알림: 심각도·제목·무슨 일·왜 중요·조치·런북·대상 행·대시보드 링크·발생 구간
    for var in ("{severity_icon}", "{severity}", "{title}", "{what}", "{why}", "{action_1}", "{runbook}",
                "{rows:30}", "{alert_count}", "{link_label}", "{alert_url}", "{alert_trigger_time_str}", "{alert_name}"):
        assert var in text, var
    assert "\n" in text and "\\n" not in text   # 실제 줄바꿈
    # 시각 줄은 알림 평가 시각({alert_trigger_time_str})이고 KST다(OpenObserve 컨테이너가 호스트 /etc/localtime을 쓴다), 규칙은 다음 줄.
    # 결과 행 _timestamp 기반 변수는 최종 SELECT에 _timestamp가 없으면 비어 쓰지 않는다
    assert text.endswith("\n⏱ 평가: {alert_trigger_time_str} KST\n📋 규칙: {alert_name}")
    assert "alert_start_time" not in text and "alert_end_time" not in text and "(UTC)" not in text


def test_template_uses_the_new_labels_and_not_the_old_ones(desired):
    text = desired.store["template"]["infra-automation-plain"]["body"]
    for label in ("■ 현상: {what}", "■ 영향: {why}", "■ 대상 {alert_count}건:\n{rows:30}", "■ 조치:\n{action_1}\n{action_2}\n{action_3}\n{action_4}\n", "▶ 런북: ", "▶ {link_label}: {alert_url}", "⏱ 평가: ", "📋 규칙: {alert_name}"):
        assert label in text, label
    assert "무슨 일" not in text and "왜 중요" not in text


def test_rendered_body_puts_one_numbered_item_per_line_and_keeps_newlines_out_of_values(desired):
    """OpenObserve는 값 안의 개행을 `\\n` 두 글자로 이스케이프하므로 줄바꿈은 본문에만 있고 값에는 없다."""
    tpl = desired.store["template"]["infra-automation-plain"]["body"]
    items = _filters().o2c_action_items("① 하나 ② 둘 ③ 셋")
    rendered = tpl
    for key, value in items.items():
        rendered = rendered.replace("{%s}" % key, value)
    assert "■ 조치:\n1. 하나\n2. 둘\n3. 셋\n\n" in rendered
    for name, alert in desired.store["alert"].items():
        assert not any("\n" in str(v) for v in alert["context_attributes"].values()), name


def test_template_places_the_raw_log_line_right_after_the_alert_url(desired):
    text = desired.store["template"]["infra-automation-plain"]["body"]
    assert "▶ {link_label}: {alert_url}\n{raw_log_line}\n" in text


def test_every_alert_is_actionable(desired):
    """모든 알림은 심각도·제목·무슨 일·왜 중요·조치·런북 링크와 대상 행 템플릿을 갖는다(PagerDuty/Google SRE 원칙)."""
    runbook = RUNBOOK.read_text(encoding="utf-8")
    for name, alert in desired.store["alert"].items():
        if name == SELFTEST:
            continue
        ctx = alert["context_attributes"]
        assert ctx["severity"] in ("P1 긴급", "P2 경고", "P3 주의"), name
        assert ctx["severity_icon"] in ("🔴", "🟠", "🟡"), name
        for key in ("title", "what", "why"):
            assert ctx[key].strip() and '"' not in ctx[key] and "\n" not in ctx[key], (name, key)
        anchor = ctx["runbook"].split("#", 1)[1]
        assert ctx["runbook"].startswith("https://github.com/ppzxc/infra-automation/blob/main/docs/runbooks/alerts.md#")
        assert f'<a id="{anchor}"></a>' in runbook, (name, anchor)
        assert alert["row_template_type"] == "String" and alert["row_template"].startswith("• "), name
        # 행 템플릿의 {필드}는 모두 그 알림 SQL이 SELECT하는 컬럼이다
        import re as _re
        fields = set(_re.findall(r"\{(\w+)\}", alert["row_template"]))
        if alert["query_condition"]["type"] == "promql":   # 결과의 value와 시리즈 레이블
            assert fields and fields <= PROMQL_ROW_FIELDS and "value" in fields, (name, fields)
            continue
        assert fields and all(f in alert["query_condition"]["sql"] for f in fields), (name, fields)


def test_severity_mapping_follows_impact(desired):
    sev = {n: a["context_attributes"]["severity"] for n, a in desired.store["alert"].items()}
    assert sev["infra-root-login-success"] == sev["infra-disk-fs-errors"] == "P1 긴급"
    assert sev["infra-ssh-login-failures-per-source"] == sev["infra-sudo-escalation-failure"] == sev["infra-oom-kill"] == "P2 경고"
    assert sev["infra-log-parse-errors-security-logs"] == "P3 주의"
    assert sev["infra-app-log-errors"] == "P2 경고"


def test_selftest_notification_is_clearly_marked_as_a_test(desired):
    ctx = desired.store["alert"][SELFTEST]["context_attributes"]
    assert ctx["severity"] == "TEST"       # 통지 첫 줄이 "<아이콘> [TEST] <제목>"이 된다
    assert all(ctx[k].strip() and '"' not in ctx[k] and "\n" not in ctx[k] for k in ("title", "what", "why", "runbook"))
    assert ctx["action_1"].startswith("1. ") and '"' not in ctx["action_1"]
    assert "시험" in ctx["title"] and desired.store["alert"][SELFTEST]["row_template"].startswith("• ")


def test_every_alert_action_is_one_numbered_slot_per_item_after_rendering(desired):
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    source = {a["name"]: a["action"] for a in defaults["o2c_alerts"]}
    assert len(desired.store["alert"]) >= 36 + len(PROMQL_ALERTS)
    for name, alert in desired.store["alert"].items():
        ctx = alert["context_attributes"]
        items = [ctx[f"action_{n}"] for n in range(1, 5)]
        filled = [i for i in items if i]
        assert items[:len(filled)] == filled and filled, name
        assert [i.split(". ", 1)[0] for i in filled] == [str(n) for n in range(1, len(filled) + 1)], name
        assert not re.search("[①-⑳]", "".join(items)) and all(i.split(". ", 1)[1].strip() for i in filled), name
        if name in source:
            assert len(filled) == max(1, len(re.findall("[①-⑳]", source[name]))), name


def test_promql_alerts_are_created_as_promql_metrics_alerts_to_the_current_destination(desired):
    for name, (sev, period, freq, silence, op, value, stream, pending) in PROMQL_ALERTS.items():
        a = desired.store["alert"][name]
        assert a["pending_period_sec"] == pending * 60, name
        assert a["stream_type"] == "metrics" and a["stream_name"] == stream and a["is_real_time"] is False, name
        qc = a["query_condition"]
        assert qc["type"] == "promql" and qc["promql"].strip() and "sql" not in qc, name
        assert qc["promql_condition"] == {"column": "value", "operator": op, "value": value}, name
        assert a["trigger_condition"] == {"period": period, "operator": ">=", "threshold": 1, "frequency": freq,
                                          "frequency_type": "minutes", "silence": silence, "align_time": True}, name
        assert a["destinations"] == ["infra-automation-plain"] and a["row_template_type"] == "String" and a["enabled"] is True, name
        assert a["context_attributes"]["severity"] == sev and a["context_attributes"]["link_label"] == "상세 보기", name
        assert a["context_attributes"]["action_1"].startswith("1. "), name


def test_log_alerts_keep_the_sql_condition_and_the_link_label(desired):
    for name in EXPECTED_ALERTS:
        a = desired.store["alert"][name]
        assert a["query_condition"]["type"] == "sql" and "align_time" not in a["trigger_condition"], name
        # 원문 링크가 있으면 {alert_url}은 "상세 보기"로 두고 원문은 raw_log_line에 싣는다. 없으면 "로그 보기" 그대로
        has_raw = bool(a["context_attributes"]["raw_log_line"])
        assert a["context_attributes"]["link_label"] == ("상세 보기" if has_raw else "로그 보기"), name


def test_promql_row_templates_use_only_numbers_and_safe_labels(desired):
    """OpenObserve가 변수 값을 이스케이프해서 넣는지(평문 본문에 `\\"`로 보이는지)는 실서버에서만 알 수 있다(#346 시험).
    그래서 PromQL 행 템플릿은 숫자 value와 따옴표·역슬래시 없는 레이블만 쓴다."""
    for a in PROMQL_DEFS:
        assert not re.search(r'["\\]', a["row_template"]), a["name"]


def test_promql_alerts_round_the_value_so_notifications_carry_no_decimals(desired):
    defs = {a["name"]: a["promql"] for a in PROMQL_DEFS}
    for name, q in defs.items():
        assert desired.store["alert"][name]["query_condition"]["promql"] == "round(%s)" % q.replace("{{ o2c_disk_latency_min_iops }}", "5"), name


def test_existing_log_alerts_stay_logs(desired):
    for name in EXPECTED_ALERTS - set(RESOURCE_ALERTS) - {"infra-silent-host-p2", "infra-silent-host-p1", "infra-unreachable-host", "infra-app-telemetry-silent"}:
        assert desired.store["alert"][name]["stream_type"] == "logs", name


def test_resource_sql_groups_by_timestamp_uses_min_and_default_thresholds_and_fstype_exclusions(desired):
    p2, p1 = _sql(desired, "infra-disk-usage-p2"), _sql(desired, "infra-disk-usage-p1")
    for sql in (p2, p1):
        assert "GROUP BY host_name, mountpoint, device, _timestamp" in sql and "min(" in sql
        for t in ("squashfs", "iso9660", "tmpfs", "devtmpfs", "overlay"):
            assert f"'{t}'" in sql
        assert "/boot" not in sql   # /boot, /boot/efi는 제외하지 않는다
    assert ">= 90" in p2 and "< 95" in p2 and ">= 95" in p1
    mem = _sql(desired, "infra-memory-usage-p1")
    assert "GROUP BY host_name, _timestamp" in mem and "min(pct)" in mem


def test_app_log_error_alert_is_a_p2_event_alert_on_error_or_worse_per_host_and_container(desired):
    """컨테이너 로그 ERROR 알림(Spec #236): severity가 error 이상인 줄만, 호스트·컨테이너별 5분 1건부터. WARN 이하와 레벨 없는 줄은 알리지 않는다."""
    alert = desired.store["alert"]["infra-app-log-errors"]
    sql = alert["query_condition"]["sql"]
    assert alert["stream_name"] == "app_logs" and alert["stream_type"] == "logs"
    assert "lower(severity) IN (" in sql and "GROUP BY host_name, container_name" in sql
    for level in ("'error'", "'fatal'", "'critical'", "'panic'", "'dpanic'"):
        assert level in sql, level
    assert "'warn'" not in sql and "'info'" not in sql and "body" not in sql      # 키워드가 아니라 파싱된 레벨만 본다
    assert alert["trigger_condition"]["period"] == 5 and alert["trigger_condition"]["silence"] == 5
    assert alert["context_attributes"]["severity"] == "P2 경고"


def test_memory_alert_sql_uses_available_and_limit_streams_not_usage_states(desired):
    for name in MEM_ALERTS:
        sql = _sql(desired, name)
        assert '"system_linux_memory_available"' in sql and '"system_memory_limit"' in sql, name
        assert "system_memory_usage" not in sql and "slab_unreclaimable" not in sql and "state" not in sql, name


@pytest.mark.parametrize("name", MEM_ALERTS)
def test_memory_alert_fixtures_fire_as_expected_when_the_rendered_sql_runs(desired, name):
    sql = _sql(desired, name)
    for case in FIXTURES[name]["cases"]:
        fired = _run_memory_alert_on_sqlite(sql, case)
        assert (case["host"] in fired) == case["fires"], (name, case["name"])


def test_raid_alerts_are_p2_with_a_two_reading_window_and_a_runbook_entry(desired):
    runbook = RUNBOOK.read_text(encoding="utf-8")
    for name in RAID_ALERTS:
        alert = desired.store["alert"][name]
        assert alert["context_attributes"]["severity"] == "P2 경고", name
        assert alert["stream_name"] == "host_status_logs", name
        assert f"(`{name}`)" in runbook, name
    for name in set(RAID_ALERTS) - {"infra-raid-collection-error", "infra-host-status-silent"}:
        trigger = desired.store["alert"][name]["trigger_condition"]
        assert (trigger["period"], trigger["frequency"]) == (15, 5), name
        assert "HAVING count(*) >= 2" in desired.store["alert"][name]["query_condition"]["sql"], name


def test_time_sync_alerts_are_p2_on_host_status_logs_with_their_windows_and_a_runbook_entry(desired):
    runbook = RUNBOOK.read_text(encoding="utf-8")
    spec = (ROOT_DIR / "docs" / "openobserve_config.md").read_text(encoding="utf-8")
    for name, (period, frequency, marker) in TIME_ALERTS.items():
        alert = desired.store["alert"][name]
        assert alert["context_attributes"]["severity"] == "P2 경고", name
        assert alert["stream_name"] == "host_status_logs", name
        trigger = alert["trigger_condition"]
        assert (trigger["period"], trigger["frequency"]) == (period, frequency), name
        assert marker in alert["query_condition"]["sql"], name
        assert "kind = 'time_sync'" in alert["query_condition"]["sql"], name
        assert f"(`{name}`)" in runbook and f"`{name}`" in spec, name


def _host_status_records(case):
    """The records of one fixture case: every `ts` (seconds before now, one or a list) becomes one record of that case's host."""
    base = 1_792_767_302_000_000
    out = []
    for rec in case["records"]:
        rec = dict(rec)
        stamps = rec.pop("ts", 0)
        for stamp in (stamps if isinstance(stamps, list) else [stamps]):
            out.append(dict(rec, host_name=case["host"], _timestamp=base + int(stamp) * 1_000_000))
    return out


def test_raid_and_time_sync_alerts_never_fire_on_each_others_records_when_they_run_on_every_case(desired):
    """RAID and time sync share the host_status_logs stream: one family's records must never fire the other family's alerts."""
    raid = [n for n in sorted(RAID_ALERTS) if n != "infra-host-status-silent"]   # the roster alert needs the inventory
    time_sync = sorted(TIME_ALERTS)
    cases = {n: FIXTURES[n]["cases"] for n in raid + time_sync}
    records = [r for n in cases for case in cases[n] for r in _host_status_records(case)]
    time_hosts = {c["host"] for n in time_sync for c in cases[n]}
    for name in time_sync:      # a time alert fires on exactly its own firing cases, whatever RAID records sit in the stream
        fired = {row["host_name"] for row in _run_alert_on_sqlite(_sql(desired, name), records, "host_status_logs")}
        assert fired == {c["host"] for c in cases[name] if c["fires"]}, name
    for name in raid:           # a RAID alert never fires on a time sync record
        fired = {row["host_name"] for row in _run_alert_on_sqlite(_sql(desired, name), records, "host_status_logs")}
        assert not fired & time_hosts, name


def test_a_time_sync_record_does_not_count_for_the_raid_collector_silence_check(desired):
    """infra-host-status-silent waits for the RAID collector's tool_status line; a time_sync line must not satisfy it."""
    sql = _sql(desired, "infra-host-status-silent")
    assert "kind = 'tool_status'" in sql and "time_sync" not in sql


# --- 남은 보안 로그 알림 (Spec #322 / Ticket-8, #330) ---------------------------------------------------------------------------
REMAINING_SECURITY_ALERTS = ("infra-audit-watch-change", "infra-ssh-login-unregistered-source", "infra-root-crontab-change",
                             "infra-fortigate-admin-login-new-source")


def _case_records(name, case):
    """The records of one fixture case the way the verification step ingests them (fake host, repeat expanded, placeholder sources skipped)."""
    spec = FIXTURES[name]
    out = []
    for rec in case["records"]:
        rec = dict(rec)
        if str(rec.get("source_address", "")).startswith("@"):
            return None                       # a registered source only exists with OpenBao normal_sources: the integration test covers it
        omit = rec.pop("omit_host_field", False)
        rec.pop("ts", None)
        if isinstance(rec.get("body"), str):
            rec["body"] = rec["body"].replace("{host}", case["host"])
        if not omit:
            rec[spec.get("host_field", "host_name")] = case["host"]
        out += [dict(rec) for _ in range(rec.pop("repeat", 1))]
    return out


@pytest.mark.parametrize("name", REMAINING_SECURITY_ALERTS)
def test_remaining_security_alert_fixtures_fire_as_expected_when_the_rendered_sql_runs(desired, name):
    alert = desired.store["alert"][name]
    spec = FIXTURES[name]
    cases = [(c, _case_records(name, c)) for c in spec["cases"]]
    cases = [(c, recs) for c, recs in cases if recs is not None]
    assert {c["fires"] for c, _ in cases} == {True, False}, name
    records = [r for _, recs in cases for r in recs]
    rows = _run_alert_on_sqlite(alert["query_condition"]["sql"], records, alert["stream_name"])
    fired = {row[spec.get("row_key", "host_name")] for row in rows}
    assert fired == {c["host"] for c, _ in cases if c["fires"]}, name


def test_a_watched_file_change_made_by_an_account_tool_alerts_once_not_twice(desired):
    """useradd changes /etc/passwd (a watch-key SYSCALL) and also writes ADD_USER: only the existing account-change alert may fire."""
    watch, change = ("infra-audit-watch-change", "infra-account-change")
    cases = {c["host"]: c for c in FIXTURES[watch]["cases"]}
    for host in ("verify-watch-useradd", "verify-watch-passwd"):
        records = _case_records(watch, cases[host])
        watch_rows = _run_alert_on_sqlite(_sql(desired, watch), records, "security_logs")
        change_rows = _run_alert_on_sqlite(_sql(desired, change), records, "security_logs")
        assert watch_rows == [] and len(change_rows) == 1, host
    editor = _case_records(watch, cases["verify-watch-identity-vim"])
    assert len(_run_alert_on_sqlite(_sql(desired, watch), editor, "security_logs")) == 1
    assert _run_alert_on_sqlite(_sql(desired, change), editor, "security_logs") == []        # a hand edit leaves no ADD_USER record


def test_the_audit_watch_alert_covers_the_account_sudoers_and_sshd_keys_but_not_the_noisy_sudo_log_or_exec_keys(desired):
    sql = _sql(desired, "infra-audit-watch-change")
    for key in ("identity", "sudo_config", "sshd_config"):
        assert f'key="{key}"' in sql, key
    for key in ("sudo_logs", "exec_log"):
        assert f'key="{key}"' not in sql, key


def test_root_crontab_alert_reads_the_cron_log_not_the_audit_stream(desired):
    alert = desired.store["alert"]["infra-root-crontab-change"]
    assert alert["stream_name"] == "system_logs" and alert["context_attributes"]["severity"] == "P2 경고"
    trigger = alert["trigger_condition"]
    assert (trigger["period"], trigger["frequency"], trigger["silence"]) == (5, 1, 5)
    sql = alert["query_condition"]["sql"]
    assert "(root) REPLACE (root)" in sql and "(root) DELETE (root)" in sql and "LIST" not in sql


def test_the_unregistered_login_alerts_have_no_registered_condition_without_normal_sources(desired):
    """With an empty normal_sources list every source is unregistered (same rule as the root login alerts)."""
    for name in ("infra-ssh-login-unregistered-source", "infra-fortigate-admin-login-new-source"):
        assert "NOT IN" not in _sql(desired, name), name


def test_every_remaining_security_alert_has_a_runbook_entry_and_a_spec_mention_and_the_missing_collection_is_recorded(desired):
    runbook = RUNBOOK.read_text(encoding="utf-8")
    spec = (ROOT_DIR / "docs" / "openobserve_config.md").read_text(encoding="utf-8")
    for name in REMAINING_SECURITY_ALERTS:
        anchor = name.removeprefix("infra-")
        assert f'<a id="{anchor}"></a>' in runbook and f"(`{name}`)" in runbook and f"`{name}`" in spec, name
    # 잡을 수 없는 신호와 그 신호에 필요한 수집(#330)
    for token in ("authorized_keys", "SSL VPN", "필요한 수집", "ssh_keys"):
        assert token in spec, token


def test_switch_alerts_are_created_on_system_logs_with_the_specified_grades_and_windows(desired):
    for name, (sev, period, silence) in SWITCH_ALERTS.items():
        a = desired.store["alert"][name]
        assert a["stream_name"] == "system_logs" and a["stream_type"] == "logs", name
        assert a["context_attributes"]["severity"] == sev, name
        assert (a["trigger_condition"]["period"], a["trigger_condition"]["silence"]) == (period, silence), name
        assert a["destinations"] == ["infra-automation-plain"] and a["enabled"], name
        assert "switch-syslog" in a["query_condition"]["sql"], name


def test_switch_function_and_pipeline_are_added_beside_the_security_ones_and_the_security_pipeline_is_untouched(desired):
    assert set(desired.store["function"]) == {"security_semantics", SWITCH_FN, FORTIGATE_FN}
    fn = desired.store["function"][SWITCH_FN]
    assert fn["function"] == (ROLE / "files" / "vrl" / "switch_syslog_semantics.vrl").read_text().strip() and fn["params"] == "row"
    pl = desired.store["pipeline"][SWITCH_FN]
    assert pl["source"]["stream_name"] == "system_logs" and pl["source"]["source_type"] == "realtime" and pl["enabled"] is True
    node = next(n["data"] for n in pl["nodes"] if n["data"]["node_type"] == "function")
    assert node["name"] == SWITCH_FN and node["after_flatten"] is True
    # 서버 로그를 거르는 일은 함수 안의 service_name 검사가 한다(조건 노드는 쓰지 않는다)
    assert not [n for n in pl["nodes"] if n["data"]["node_type"] == "condition"]
    assert desired.store["pipeline"]["security_semantics"]["source"]["stream_name"] == "security_logs"


def test_firewall_function_runs_in_the_security_pipeline_right_after_the_security_function(desired):
    """Spec #282 / Ticket-2: one pipeline per source stream, so the firewall function is chained, not a second pipeline on security_logs."""
    fn = desired.store["function"][FORTIGATE_FN]
    assert fn["function"] == (ROLE / "files" / "vrl" / "fortigate_semantics.vrl").read_text().strip() and fn["params"] == "row"
    assert set(desired.store["pipeline"]) == {"security_semantics", SWITCH_FN}
    pl = desired.store["pipeline"]["security_semantics"]
    assert pl["source"]["stream_name"] == "security_logs" and pl["enabled"] is True
    functions = [n for n in pl["nodes"] if n["data"]["node_type"] == "function"]
    assert [(n["data"]["name"], n["data"]["after_flatten"]) for n in functions] == [("security_semantics", True), (FORTIGATE_FN, True)]
    # input -> security_semantics -> fortigate_semantics -> output, and no condition node (the service check lives in the function)
    edges = {(e["source"], e["target"]) for e in pl["edges"]}
    ids = {n["data"].get("name") or n["io_type"]: n["id"] for n in pl["nodes"]}
    assert edges == {(next(n["id"] for n in pl["nodes"] if n["io_type"] == "input"), ids["security_semantics"]),
                     (ids["security_semantics"], ids[FORTIGATE_FN]),
                     (ids[FORTIGATE_FN], next(n["id"] for n in pl["nodes"] if n["io_type"] == "output"))}
    assert not [n for n in pl["nodes"] if n["data"]["node_type"] == "condition"]


def test_default_noise_list_holds_the_arp_resolution_failure_and_every_alert_excludes_it(desired):
    for name in ("infra-switch-config-change", "infra-switch-login-failures", "infra-switch-severity-critical", "infra-switch-mac-flap"):
        assert "event_name NOT IN ('ADJ-3-RESOLVE_REQ')" in _sql(desired, name), name
    assert "NOT IN" not in _sql(desired, "infra-switch-syslog-silent")   # 잡음 줄도 수신으로 센다


def test_default_silent_roster_is_the_explicit_list_of_confirmed_senders_and_the_default_window_is_24_hours(desired):
    silent = desired.store["alert"]["infra-switch-syslog-silent"]
    assert _branch_devices(silent["query_condition"]["sql"]) == {"ns0250", "ns0347"}   # 인벤토리 전체가 아니라 명시 목록
    assert silent["trigger_condition"]["period"] == 24 * 60 and "HAVING count(*) < 1" in silent["query_condition"]["sql"]


def test_silent_alert_counts_a_record_that_only_names_the_device_in_its_raw_body(desired):
    """Records written before the switch pipeline existed have no device_id; they must still count as "received"."""
    sql = _sql(desired, "infra-switch-syslog-silent")
    for device in ("ns0250", "ns0347"):
        assert f"(device_id = '{device}' OR lower(body) LIKE '% {device}%')" in sql, device
    assert "HAVING count(*) < 1" in sql


def test_silent_alert_does_not_fire_right_after_the_pipeline_is_applied_when_old_logs_exist(desired):
    """The first evaluation after the pipeline change sees old records (raw body only) next to a few processed ones."""
    sql = _sql(desired, "infra-switch-syslog-silent").replace('"system_logs"', '"system_logs_alert_verify"')
    other = {"service_name": "switch-syslog", "device_id": "ns0999", "body": "Oct 20 17:50:00 203.0.113.9 ns0999-3560X: x"}   # device_id 컬럼이 있는 스키마
    old = [{"service_name": "switch-syslog", "body": "Oct 20 17:48:40 203.0.113.9 NS0347-3560X: Oct 20 17:48:39.702 KST: %SW_MATM-4-MACFLAP_NOTIF: x"},
           {"service_name": "switch-syslog", "body": "Oct 20 17:48:35 203.0.113.8 ns0250-3750X: Oct 20 17:48:34.411 KST: %ADJ-3-RESOLVE_REQ: x"}]
    assert _run_alert_on_sqlite(sql, old + [other]) == []   # 두 장비 모두 수신 중 → 발화 없음
    assert {row["device_id"] for row in _run_alert_on_sqlite(sql, old[:1] + [other])} == {"ns0250"}   # 한 장비만 조용하면 그 장비만 발화


def test_without_a_source_list_every_public_root_login_is_p1_and_private_ones_are_p2(desired):
    """normal_sources가 비어 있을 때: 공인 출발지는 모두 P1, 사설 대역은 P2, 등록 출발지 조건(IN)은 두지 않는다."""
    assert "NOT IN" not in _sql(desired, "infra-root-login-success")
    known = _sql(desired, "infra-root-login-known")
    assert " IN (" not in known and "source_address LIKE '10.%'" in known and "IN ('')" not in known


def test_firewall_alerts_are_created_on_security_logs_with_the_specified_grades_windows_and_silences(desired):
    for name, (sev, period, silence) in FORTIGATE_ALERTS.items():
        a = desired.store["alert"][name]
        assert a["stream_name"] == "security_logs" and a["stream_type"] == "logs", name
        assert a["context_attributes"]["severity"] == sev, name
        assert (a["trigger_condition"]["period"], a["trigger_condition"]["silence"]) == (period, silence), name
        assert a["destinations"] == ["infra-automation-plain"] and a["enabled"], name
        assert "fortigate-syslog" in a["query_condition"]["sql"], name
        for key in ("what", "why", "action_1", "runbook"):
            assert a["context_attributes"][key].strip(), (name, key)
        assert a["context_attributes"]["runbook"].endswith("#" + name.removeprefix("infra-")), name


def test_firewall_alert_sql_needs_no_firewall_column_so_it_is_valid_before_the_first_firewall_line_arrives(desired):
    """security_logs has no firewall column until a firewall line is ingested; a missing column would fail every evaluation (O2C-036)."""
    for name in FORTIGATE_ALERTS:
        sql = _sql(desired, name).replace("AS device_id", "")
        for column in ("device_id", "device_name", "fortigate_log_type", "fortigate_log_subtype", "fortigate_policy_id"):
            assert not re.search(rf"(?<![A-Za-z_'\"]){column}(?![A-Za-z_'\"])", sql), (name, column)


def test_firewall_alerts_do_not_break_the_existing_ones(desired):
    assert (EXPECTED_ALERTS - set(FORTIGATE_ALERTS)) <= set(desired.store["alert"])
    for name, (sev, period, silence) in SWITCH_ALERTS.items():
        trigger = desired.store["alert"][name]["trigger_condition"]
        assert (trigger["period"], trigger["silence"]) == (period, silence)
    assert FORTIGATE_FN in desired.store["function"]


def test_per_source_ssh_row_shows_one_time_for_one_event_and_first_to_last_for_a_range(desired):
    name = "infra-ssh-login-failures-per-source"
    one = [_fail("2026-10-23 08:59:14")] * 10
    assert _row_lines(desired, name, one, "security_logs") == ["• 203.0.113.10 → ns0272: 실패 10회 · 10-23 08:59:14"]
    two = [_fail("2026-10-23 08:55:02")] * 5 + [_fail("2026-10-23 08:59:14")] * 5
    assert _row_lines(desired, name, two, "security_logs") == ["• 203.0.113.10 → ns0272: 실패 10회 · 10-23 08:55:02~08:59:14"]


def test_event_time_range_across_midnight_keeps_both_dates(desired):
    recs = [_fail("2026-10-23 23:58:00")] * 5 + [_fail("2026-10-24 00:02:30")] * 5
    assert _row_lines(desired, "infra-ssh-login-failures-per-source", recs, "security_logs") == [
        "• 203.0.113.10 → ns0272: 실패 10회 · 10-23 23:58:00~10-24 00:02:30"]


def test_event_time_does_not_change_which_sources_fire(desired):
    recs = [_fail("2026-10-23 08:59:14", "203.0.113.11")] * 9 + [_fail("2026-10-23 08:59:14", "203.0.113.12")] * 10
    assert [r.split(" ")[1] for r in _row_lines(desired, "infra-ssh-login-failures-per-source", recs, "security_logs")] == ["203.0.113.12"]
    sql = _sql(desired, "infra-ssh-login-failures-per-source")
    assert "WHERE event_action = 'ssh_login' AND event_outcome = 'failure'" in sql
    assert "GROUP BY source_address, host_name HAVING count(*) >= 10" in sql


def test_per_source_rows_come_out_with_the_most_failures_first_so_the_row_cap_keeps_the_worst(desired):
    recs = [_fail("2026-10-23 08:59:14", "203.0.113.11")] * 11 + [_fail("2026-10-23 08:59:14", "203.0.113.12")] * 30
    rows = _row_lines(desired, "infra-ssh-login-failures-per-source", recs, "security_logs")
    assert [r.split(" ")[1] for r in rows] == ["203.0.113.12", "203.0.113.11"]


def test_raw_log_link_survives_the_event_time_column(desired):
    alert = desired.store["alert"]["infra-ssh-login-failures-per-source"]
    assert alert["context_attributes"]["raw_log_line"].startswith("▶ 로그 보기: http")
    from openobserve_config import o2c_raw_log_sql
    assert o2c_raw_log_sql(alert["query_condition"]["sql"], "security_logs") == (
        "SELECT * FROM \"security_logs\" WHERE event_action = 'ssh_login' AND event_outcome = 'failure' ORDER BY _timestamp DESC LIMIT 200")


def test_every_alert_with_an_event_time_column_fits_the_5000_character_limit_with_30_longest_rows(desired):
    with_time = [n for n, a in desired.store["alert"].items() if a["query_condition"]["type"] == "sql" and "event_time" in a["row_template"]]
    assert "infra-ssh-login-failures-per-source" in with_time
    for name in with_time:
        fields = set(re.findall(r"\{(\w+)\}", desired.store["alert"][name]["row_template"]))
        values = {f: LONGEST_ROW_VALUES.get(f, "999" if f in COUNT_FIELDS else LONGEST_TEXT.get(f, TEXT_VALUE)) for f in fields}
        assert len(_rendered_message(desired, name, values)) <= 5000, name


@pytest.mark.parametrize("name", sorted(SECURITY_TIME_CASES))
def test_security_server_alert_rows_show_one_time_for_one_instant_and_first_to_last_for_a_range(desired, name):
    fields, expected = SECURITY_TIME_CASES[name]
    n = len(fields)
    one = [_ev("2026-10-23 08:59:14", **f) for f in fields]
    assert _row_lines(desired, name, one, "security_logs") == [f"{expected} · 10-23 08:59:14"]
    two = [_ev("2026-10-23 08:55:02", **f) for f in fields[: max(n // 2, 1)]] + [_ev("2026-10-23 08:59:14", **f) for f in fields[max(n // 2, 1):] or fields[:1]]
    assert _row_lines(desired, name, two, "security_logs")[0].endswith(" · 10-23 08:55:02~08:59:14")


def test_parse_error_alerts_keep_the_raw_log_link_and_show_the_time(desired):
    for name, stream in (("infra-log-parse-errors-security-logs", "security_logs"), ("infra-log-parse-errors-system-logs", "system_logs")):
        alert = desired.store["alert"][name]
        assert alert["row_template"].endswith(" · {event_time}")
        recs = [_ev("2026-10-23 08:55:02", log_parse_error=True)] * 60 + [_ev("2026-10-23 08:59:14", log_parse_error=False)] * 40
        rows = _row_lines(desired, name, recs, stream)
        assert rows and rows[0].endswith(" · 10-23 08:55:02~08:59:14"), name
        assert alert["context_attributes"]["raw_log_line"].startswith("▶ 로그 보기: http")


@pytest.mark.parametrize("name", sorted(SYSTEM_TIME_CASES))
def test_system_app_backup_raid_and_reachability_rows_show_one_time_or_first_to_last(desired, name):
    stream, base, expected = SYSTEM_TIME_CASES[name]
    k = len(base)
    one = [_ev("2026-10-23 08:59:14", **f) for f in base]
    assert _row_lines(desired, name, one, stream) == [expected.format(n=k) + " · 10-23 08:59:14"]
    two = [_ev("2026-10-23 08:55:02", **f) for f in base] + [_ev("2026-10-23 08:59:14", **f) for f in base]
    rows = _row_lines(desired, name, two, stream)
    assert rows == [expected.format(n=2 * k) + " · 10-23 08:55:02~08:59:14"]


def test_backup_and_raid_missing_and_usage_alerts_keep_their_rows(desired):
    for name in ("infra-backup-missing", "infra-maintenance-missing", "infra-host-status-silent", "infra-disk-usage-p1"):
        assert "event_time" not in desired.store["alert"][name]["row_template"], name


@pytest.mark.parametrize("name", sorted(DEVICE_TIME_ALERTS))
def test_device_rows_show_one_time_or_first_to_last_and_keep_the_device_name(desired, name):
    stream = DEVICE_TIME_ALERTS[name]
    base = [dict({"device_name": "sw", "device_id": None} if stream == "system_logs" else {}, **r) for r in _fixture_records(name)]
    base = base * 2 if len(base) == 1 else base
    half = max(len(base) // 2, 1)
    one = [dict(r, _timestamp=_kst_us("2026-10-23 08:59:14")) for r in base]
    rows = _row_lines(desired, name, one, stream)
    assert len(rows) >= 1 and all(r.endswith(" · 10-23 08:59:14") for r in rows), rows
    two = [dict(r, _timestamp=_kst_us("2026-10-23 08:55:02" if i < half else "2026-10-23 08:59:14")) for i, r in enumerate(base)]
    two[-1]["_timestamp"] = _kst_us("2026-10-23 08:59:14")
    rows = _row_lines(desired, name, two, stream)
    assert rows and all(r.startswith("• ns0272") for r in rows) and any(r.endswith(" · 10-23 08:55:02~08:59:14") for r in rows), rows


def test_log_alerts_with_a_derivable_where_carry_the_raw_log_link_and_the_others_do_not(desired):
    alerts = desired.store["alert"]
    for name in ("infra-ssh-login-failures-per-source", "infra-root-login-success", "infra-oom-kill", "infra-disk-fs-errors",
                 "infra-switch-config-change", "infra-backup-failure"):
        ctx = alerts[name]["context_attributes"]
        path, qs, decoded = _decode_raw_url(_raw_original(desired, alerts[name]))
        assert path == "/web/logs" and qs["stream"] == alerts[name]["stream_name"], name
        assert decoded.startswith('SELECT * FROM "%s" WHERE ' % alerts[name]["stream_name"]), name
        assert decoded.endswith("ORDER BY _timestamp DESC LIMIT 200"), name
        assert not re.search(r"group by|having|count\(", decoded, re.I), name
        assert ctx["link_label"] == "상세 보기", name   # {alert_url}(알림 화면)은 상세, 원문은 별도 줄
    where = _decode_raw_url(_raw_original(desired, alerts["infra-ssh-login-failures-per-host"]))[2]
    assert "event_action = 'ssh_login' AND event_outcome = 'failure'" in where
    # raw_sql 직접 지정: HAVING만으로 거르는 집계
    for name, stream in (("infra-log-parse-errors-security-logs", "security_logs"), ("infra-log-parse-errors-system-logs", "system_logs")):
        assert _decode_raw_url(_raw_original(desired, alerts[name]))[2] == (
            'SELECT * FROM "%s" WHERE log_parse_error = true ORDER BY _timestamp DESC LIMIT 200' % stream)
    # 파생 불가·메트릭·PromQL·자가 시험은 기존 링크와 라벨을 그대로 둔다
    for name, alert in alerts.items():
        ctx = alert["context_attributes"]
        if name in ("infra-backup-missing", "infra-maintenance-missing", "infra-switch-syslog-silent", "infra-silent-host-p1", "infra-app-telemetry-silent", "infra-disk-usage-p1", SELFTEST) \
                or name in PROMQL_ALERTS:
            assert _raw_line(alert) == "", name
        assert ctx["link_label"] in ("로그 보기", "상세 보기"), name
        if _raw_line(alert) == "" and alert["stream_type"] == "logs" and name != SELFTEST:
            assert ctx["link_label"] == "로그 보기", name


def test_security_alerts_are_created_with_their_grades_windows_and_raw_log_links(desired):
    for name, (sev, period, silence, pending, _marker) in SECURITY_ALERTS.items():
        a = desired.store["alert"][name]
        assert a["stream_name"] == "security_logs" and a["query_condition"]["type"] == "sql", name
        assert a["context_attributes"]["severity"] == sev, name
        trigger = a["trigger_condition"]
        assert (trigger["period"], trigger["frequency"], trigger["silence"], a["pending_period_sec"]) == (period, 1, silence, pending * 60), name
        decoded = _decode_raw_url(_raw_original(desired, a))[2]   # 모두 WHERE에서 원문 조회를 파생한다
        assert decoded.startswith('SELECT * FROM "security_logs" WHERE ') and "count(" not in decoded, name


# --- infra-oom-kill 자기 증식 루프(알림 서버가 알림 본문·쿼리 계획을 로그로 남기면 같은 알림에 다시 걸림) ---

OOM_QUERY_PLAN_LOG = ("Oct 26 15:32:36 ns0217 bot-java[2513767]:              FilterExec: (lower(body@1) LIKE %killed process% OR "
                      "lower(body@1) LIKE %out of memory: kill process% OR lower(body@1) LIKE %invoked oom-killer%) AND _timestamp@0 >= 1792995720000000")
OOM_PREVIOUS_ALERT_LOG = ("Oct 26 16:59:05 ns0217 bot-java[2513767]: textToAll text=🟠 [P2 경고] OOM kill로 프로세스 강제 종료 "
                          "• ns0217 (39.116.31.229): 종료된 프로세스 " + OOM_QUERY_PLAN_LOG)


@pytest.mark.parametrize("body", [OOM_QUERY_PLAN_LOG, OOM_PREVIOUS_ALERT_LOG, OOM_QUERY_PLAN_LOG * 200])
@pytest.mark.parametrize("source", ["bot-java", "dockerd"])
def test_oom_kill_alert_ignores_logs_that_merely_quote_its_own_pattern(desired, body, source):
    """알림 서버(bot-java)·dockerd가 쿼리 계획이나 이전 알림 본문을 로그로 남겨도 OOM kill 알림이 다시 발화하지 않는다(커널 출처만 본다)."""
    rows = _run_alert_on_sqlite(_sql(desired, "infra-oom-kill"),
                                [dict(host_name="ns0217", process_executable_name=source, body=body)], "system_logs")
    assert rows == []


def test_oom_kill_row_value_stays_short_even_when_the_pattern_does_not_extract_a_name(desired):
    """커널 줄이라도 프로세스 이름을 못 뽑으면 원문 전체가 아니라 짧은 대체값이 행에 실린다(Google Chat 본문 50,000자 제한)."""
    body = "ns0217 kernel: Out of memory: Killed process 77 total-vm:1kB " + "x" * 60000
    rows = _run_alert_on_sqlite(_sql(desired, "infra-oom-kill"),
                                [dict(host_name="ns0217", process_executable_name="kernel", body=body)], "system_logs")
    assert [r["killed_process"] for r in rows] == ["알 수 없음"]


def test_oom_kill_alert_still_fires_for_the_kernel_lines_seen_in_production(desired):
    """운영에서 실제로 본 커널 OOM 줄(2026-10-12 ns0266)은 계속 발화하고 프로세스 이름이 행에 실린다."""
    lines = ["Oct 12 20:57:34 ns0266 kernel: Memory cgroup out of memory: Killed process 1663741 (ansible-playboo) total-vm:1264452kB, anon-rss:828164kB",
             "Oct 12 20:31:36 ns0266 kernel: semaphore invoked oom-killer: gfp_mask=0x100cca(GFP_HIGHUSER_MOVABLE), order=0, oom_score_adj=0"]
    rows = _run_alert_on_sqlite(_sql(desired, "infra-oom-kill"),
                                [dict(host_name="ns0266", process_executable_name="kernel", body=b) for b in lines], "system_logs")
    assert sorted(r["killed_process"] for r in rows) == ["ansible-playboo", "oom-killer 호출"]


# --- 행 값 길이 상한 가드(Spec #367): 알림 서버는 본문이 50,000자를 넘으면 통지를 통째로 버린다 ---

BODY_LIMIT = 50000
RAW_COLUMN_CALL = re.compile(r"\b(?:regexp_replace|(?:max|min)\(\s*(?:message|body|detail)\s*\))|\bbody\s+AS\b|\bmessage\s+AS\b|\bdetail\s+AS\b", re.I)


def _unbounded_raw_values(sql):
    """SELECT에 길이 상한(`substr(..., 1, N)`) 없이 실리는 로그 원문 표현식. 정수로 바꾸는 CAST는 원문이 행에 실리지 않으므로 뺀다."""
    found = []
    for m in RAW_COLUMN_CALL.finditer(sql):
        before = sql[:m.start()].rstrip()
        if before.endswith("substr(") or before.upper().endswith("CAST("):
            continue
        if re.match(r"\b(body|message|detail)\s+AS\b", m.group(0), re.I):
            found.append(m.group(0))   # 원문 컬럼을 그대로 별칭만 붙여 싣는 경우
        elif m.group(0).lower().startswith("regexp_replace") or m.group(0).lower().startswith(("max", "min")):
            found.append(sql[m.start():m.start() + 60])
    return found


def test_no_sql_alert_puts_raw_log_text_in_a_row_without_a_length_cap(desired):
    """행 값에 로그 원문(regexp_replace 결과, max(message) 등)이 substr 상한 없이 실리는 알림이 없다. 미매치 시 원문 전체가 되어 본문이 폭주한다(#365)."""
    offenders = {n: _unbounded_raw_values(_sql(desired, n)) for n, a in desired.store["alert"].items() if a["query_condition"]["type"] == "sql"}
    assert {n: v for n, v in offenders.items() if v} == {}


def test_the_guard_flags_an_uncapped_raw_value_and_accepts_a_capped_one():
    assert _unbounded_raw_values("SELECT regexp_replace(body, 'a', 'b') AS x FROM s")
    assert _unbounded_raw_values("SELECT max(message) AS message FROM s")
    assert not _unbounded_raw_values("SELECT substr(regexp_replace(body, 'a', 'b'), 1, 40) AS x, substr(max(message), 1, 100) AS message FROM s")
    assert not _unbounded_raw_values("SELECT CAST(regexp_replace(body, 'a', 'b') AS INT) AS h FROM s")


def _longest_value_per_sql(sql):
    """SQL의 substr 상한 중 가장 큰 값. 상한이 없으면 0."""
    return max([int(n) for n in re.findall(r"substr\([^;]*?,\s*1,\s*(\d+)\)", sql)] or [0])


def test_every_sql_alert_message_with_30_rows_of_capped_values_stays_under_the_notification_body_limit(desired):
    """행의 텍스트 필드가 SQL 상한만큼 길어도 `{rows:30}` 본문이 50,000자를 넘지 않는다(상한 없는 필드는 TEXT_VALUE)."""
    checked = 0
    for name, alert in desired.store["alert"].items():
        if alert["query_condition"]["type"] != "sql":
            continue
        cap = _longest_value_per_sql(_sql(desired, name))
        fields = set(re.findall(r"\{(\w+)\}", alert["row_template"]))
        values = {f: LONGEST_ROW_VALUES.get(f, "999" if f in COUNT_FIELDS else "가" * cap if cap else LONGEST_TEXT.get(f, TEXT_VALUE)) for f in fields}
        assert len(_rendered_message(desired, name, values)) <= BODY_LIMIT, name
        checked += 1
    assert checked >= 30


def test_raid_time_and_switch_alert_rows_cut_a_huge_raw_message(desired):
    """RAID 수집 실패·시각 미동기·스위치 설정 변경 알림은 원문이 6만 자여도 행 값이 상한(100·100·200자)을 넘지 않는다."""
    huge = "x" * 60000
    raid = _run_alert_on_sqlite(_sql(desired, "infra-raid-collection-error"),
                                [dict(host_name="ns0272", _timestamp=_kst_us("2026-10-23 08:5%d:02" % i), kind="tool_status", status="timeout", message=huge)
                                 for i in range(3)], "host_status_logs")
    assert [len(r["message"]) for r in raid] == [100]
    time_ = _run_alert_on_sqlite(_sql(desired, "infra-time-unsynced"),
                                 [dict(host_name="ns0272", _timestamp=_kst_us("2026-10-23 08:%02d:02" % i), kind="time_sync", sync_status="unsynced", message=huge)
                                  for i in range(6)], "host_status_logs")
    assert [len(r["message"]) for r in time_] == [100]
    event = sorted(re.findall(r"'([^']+)'", re.search(r"event_name IN \(([^)]*)\)", _sql(desired, "infra-switch-config-change")).group(1)))[0]
    sw = _run_alert_on_sqlite(_sql(desired, "infra-switch-config-change"),
                              [dict(host_name="ns0272", device_id=None, device_name="sw1", service_name="switch-syslog", event_name=event,
                                    body="%SYS-5-CONFIG_I: " + huge)], "system_logs")
    assert [len(r["detail"]) for r in sw] == [200]
