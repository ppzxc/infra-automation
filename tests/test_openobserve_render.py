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
    COUNT_FIELDS, DEVICE_TIME_ALERTS, EXPECTED_ALERTS, FIXTURES, FORTIGATE_ALERTS, FORTIGATE_FN, GITHUB_FN, LONGEST_ROW_VALUES,
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
    assert set(desired.store["function"]) == {"security_semantics", SWITCH_FN, FORTIGATE_FN, GITHUB_FN}
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
    assert [(n["data"]["name"], n["data"]["after_flatten"]) for n in functions] == [("security_semantics", True), (FORTIGATE_FN, True), (GITHUB_FN, True)]
    # input -> security_semantics -> fortigate_semantics -> github_audit_semantics -> output, and no condition node (the service check lives in the function)
    edges = {(e["source"], e["target"]) for e in pl["edges"]}
    ids = {n["data"].get("name") or n["io_type"]: n["id"] for n in pl["nodes"]}
    assert edges == {(next(n["id"] for n in pl["nodes"] if n["io_type"] == "input"), ids["security_semantics"]),
                     (ids["security_semantics"], ids[FORTIGATE_FN]),
                     (ids[FORTIGATE_FN], ids[GITHUB_FN]),
                     (ids[GITHUB_FN], next(n["id"] for n in pl["nodes"] if n["io_type"] == "output"))}
    assert not [n for n in pl["nodes"] if n["data"]["node_type"] == "condition"]


def test_github_audit_function_is_chained_last_and_the_existing_function_sources_are_unchanged(desired):
    """Spec #399 / Ticket-3: github_audit_semantics follows the existing functions in the security pipeline; the others keep their source."""
    fn = desired.store["function"][GITHUB_FN]
    assert fn["function"] == (ROLE / "files" / "vrl" / "github_audit_semantics.vrl").read_text().strip() and fn["params"] == "row"
    assert desired.store["function"]["security_semantics"]["function"] == (ROLE / "files" / "vrl" / "security_semantics.vrl").read_text().strip()
    assert "github" not in desired.store["function"][FORTIGATE_FN]["function"]


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
        assert (trigger["period"], trigger["frequency"], trigger["silence"], a["pending_period_sec"]) == (period, 5 if name == "infra-security-service-stopped" else 1, silence, pending * 60), name   # 중지 알림은 24시간 구간이라 5분마다
        decoded = _decode_raw_url(_raw_original(desired, a))[2]   # 모두 WHERE에서 원문 조회를 파생한다
        assert decoded.startswith('SELECT * FROM "security_logs" WHERE ') and "count(" not in decoded, name


# --- sshd 치명 오류와 낯선 사용자 SSH 성공 (Spec #433 / Ticket-2, #428) ---------------------------------------------------------
from o2c_alert_helpers import DEFAULTS   # noqa: E402  (이 절이 쓰는 역할 기본 변수 원본)

SSHD_FATAL, SSH_NEW_USER = "infra-sshd-fatal-error", "infra-ssh-login-new-user"

# 기대값은 정의 변수가 아니라 업계 규칙(Sigma lnx_sshd_susp_ssh에서 스캐너 소음을 뺀 10개, Wazuh 5707·5714와 겹침)에서 옮긴 글자다.
INDUSTRY_SSHD_FATAL = ("unexpected internal error", "unknown or unsupported key type", "invalid certificate signing key",
                       "invalid elliptic curve value", "incorrect signature", "error in libcrypto", "unexpected bytes remain after decoding",
                       "fatal: buffer_get_string: bad string", "Local: crc32 compensation attack", "bad client public DH value")
# 인터넷 스캐너·점검이 늘 만드는 줄(7일 실로그에서 이 중 하나가 호스트 24대에서 분당 1건씩 나왔다)
SCANNER_NOISE = ("Corrupted MAC on input.", "Bad protocol version identification 'GET / HTTP/1.1' from 203.0.113.9 port 4444",
                 "Did not receive identification string from 203.0.113.9 port 4444")


def _sshd_line(text, process="sshd", host="ns0272"):
    return {"host_name": host, "process_executable_name": process, "service_name": "auth", "body": text}


def _fatal_rows(desired, *records):
    return _run_alert_on_sqlite(_sql(desired, SSHD_FATAL), list(records), "security_logs")


def test_sshd_signal_alerts_are_security_log_event_alerts_with_a_grade_and_a_runbook_entry(desired):
    for name, severity in ((SSHD_FATAL, "P2 경고"), (SSH_NEW_USER, "P3 주의")):
        alert = desired.store["alert"][name]
        assert alert["stream_name"] == "security_logs" and alert["context_attributes"]["severity"] == severity, name
        assert name in EXPECTED_ALERTS, name
        anchor = name.removeprefix("infra-")
        assert alert["context_attributes"]["runbook"].endswith("alerts.md#" + anchor), name
    assert (desired.store["alert"][SSHD_FATAL]["trigger_condition"]["period"],
            desired.store["alert"][SSHD_FATAL]["trigger_condition"]["silence"]) == (5, 5)


@pytest.mark.parametrize("process", ["sshd", "sshd-session"])
@pytest.mark.parametrize("keyword", INDUSTRY_SSHD_FATAL)
def test_a_fatal_sshd_keyword_fires_for_both_sshd_processes(desired, keyword, process):
    rows = _fatal_rows(desired, _sshd_line(f"error: {keyword} [preauth]", process))
    assert [r["host_name"] for r in rows] == ["ns0272"]
    assert _fatal_rows(desired, _sshd_line(f"error: {keyword.upper()}", process))   # 대소문자를 가리지 않는다


@pytest.mark.parametrize("noise", SCANNER_NOISE)
def test_scanner_noise_never_fires_the_fatal_alert_even_in_bulk(desired, noise):
    assert _fatal_rows(desired, *[_sshd_line(noise, host=f"ns{n:04d}") for n in range(200)]) == []


def test_a_scanner_phrase_inside_a_fatal_line_is_still_noise(desired):
    """스캐너 목록은 치명 문구보다 먼저다(운영자가 겹치는 문구를 넣어도 소음이 울리지 않는다)."""
    assert _fatal_rows(desired, _sshd_line("fatal: buffer_get_string: bad string; Did not receive identification string from 203.0.113.9")) == []


@pytest.mark.parametrize("process", ["sudo", "bot-java", "dockerd", "sshd-keygen", ""])
def test_the_same_phrase_from_another_process_does_not_fire(desired, process):
    assert _fatal_rows(desired, _sshd_line("error: error in libcrypto", process)) == []


def test_fatal_rows_group_per_host_and_show_the_count(desired):
    rows = _fatal_rows(desired, _sshd_line("error: incorrect signature", host="ns0001"), _sshd_line("error: error in libcrypto", host="ns0001"),
                       _sshd_line("fatal: buffer_get_string: bad string", host="ns0001"), _sshd_line("error: error in libcrypto", host="ns0002"))
    assert sorted((r["host_name"], r["errors"]) for r in rows) == [("ns0001", 3), ("ns0002", 1)]
    lines = _row_lines(desired, SSHD_FATAL, [_sshd_line("error: error in libcrypto", host="ns0002")] * 2, "security_logs")
    assert len(lines) == 1 and lines[0].startswith("• ns0002: ") and " 2건 · " in lines[0]


def test_a_like_phrase_may_contain_a_colon_but_still_nothing_that_breaks_the_sql():
    o2c = _filters()
    assert o2c.o2c_valid_like_groups([{"label": "x", "patterns": ["fatal: buffer_get_string: bad string"]}])
    assert not o2c.o2c_valid_like_groups([{"label": "x", "patterns": ["a'; drop"]}])


def test_the_fatal_threshold_and_keyword_lists_are_role_defaults_with_the_documented_values():
    assert DEFAULTS["o2c_sshd_fatal_threshold"] == 1
    assert DEFAULTS["o2c_sshd_processes"] == ["sshd", "sshd-session"]   # sshd-auth(OpenSSH 10+)는 7일 실로그에 0건이라 기본에 넣지 않았다
    kept = {p for g in DEFAULTS["o2c_sshd_fatal_keywords"] for p in g["patterns"]}
    assert kept == {k.lower() for k in INDUSTRY_SSHD_FATAL}
    dropped = {p for g in DEFAULTS["o2c_sshd_scanner_noise"] for p in g["patterns"]}
    assert dropped == {"corrupted mac on input", "bad protocol version identification", "did not receive identification string"}
    assert not kept & dropped


def _now_us():
    import time
    return int(time.time() * 1_000_000)


def _ssh_success(user, ago_minutes, host="ns0272", source="203.0.113.5"):
    return {"event_action": "ssh_login", "event_outcome": "success", "user_name": user, "host_name": host, "source_address": source,
            "_timestamp": _now_us() - int(ago_minutes * 60 * 1_000_000)}


DAY = 24 * 60


def _new_user_rows(desired, *records):
    return _run_alert_on_sqlite(_sql(desired, SSH_NEW_USER), list(records), "security_logs")


def test_a_user_first_seen_in_the_evaluation_window_fires(desired):
    rows = _new_user_rows(desired, _ssh_success("newbie", 1))
    assert [(r["user_name"], r["host_name"]) for r in rows] == [("newbie", "ns0272")]


def test_a_user_who_succeeded_within_the_last_five_days_does_not_fire(desired):
    for ago in (30, 3 * DAY, 4 * DAY + 23 * 60):
        assert _new_user_rows(desired, _ssh_success("alice", ago), _ssh_success("alice", 1)) == [], ago


def test_the_earlier_success_may_be_on_another_host_because_hosts_are_not_told_apart(desired):
    assert _new_user_rows(desired, _ssh_success("alice", 2 * DAY, host="ns0001"), _ssh_success("alice", 1, host="ns0002")) == []


def test_only_successful_ssh_logins_count_as_seen_or_new(desired):
    failed = dict(_ssh_success("mallory", 2 * DAY), event_outcome="failure")
    assert [r["user_name"] for r in _new_user_rows(desired, failed, _ssh_success("mallory", 1))] == ["mallory"]   # 실패는 본 것이 아니다
    assert _new_user_rows(desired, dict(_ssh_success("mallory", 1), event_outcome="failure")) == []
    assert _new_user_rows(desired, dict(_ssh_success("mallory", 1), event_action="sudo")) == []


def test_a_user_first_seen_before_the_evaluation_window_is_left_to_the_earlier_evaluation(desired):
    """창 밖에서 처음 본 사용자는 이미 울렸거나 울린 뒤라 다시 울리지 않는다(이 알림이 한 번만 울리는 이유)."""
    assert _new_user_rows(desired, _ssh_success("carol", 3 * 60)) == []


def test_new_user_rows_name_the_user_the_server_and_the_source(desired):
    lines = _row_lines(desired, SSH_NEW_USER, [_ssh_success("newbie", 1, host="ns0003", source="198.51.100.7")], "security_logs")
    assert len(lines) == 1 and lines[0].startswith("• ns0003: newbie ← 198.51.100.7 (1회)")


def test_new_user_window_frequency_and_lookback_are_role_defaults_and_set_the_alert_timing(desired):
    d = DEFAULTS
    assert d["o2c_ssh_new_user_lookback_days"] == 5
    trigger = desired.store["alert"][SSH_NEW_USER]["trigger_condition"]
    assert trigger["period"] == 5 * DAY + int(d["o2c_ssh_new_user_window_minutes"])   # 조회 구간 = 5일 + 평가 구간
    assert trigger["frequency"] == int(d["o2c_ssh_new_user_frequency_minutes"])
    assert trigger["silence"] == int(d["o2c_ssh_new_user_window_minutes"])
    assert int(d["o2c_ssh_new_user_frequency_minutes"]) <= int(d["o2c_ssh_new_user_window_minutes"])   # 평가 사이에 틈이 없다


def test_sshd_signal_values_override_from_the_role_variables(tmp_path):
    rendered = render_desired(tmp_path / "desired.json", extra={
        "o2c_sshd_fatal_threshold": 3, "o2c_ssh_new_user_lookback_days": 2, "o2c_ssh_new_user_window_minutes": 20,
        "o2c_ssh_new_user_frequency_minutes": 10, "o2c_sshd_scanner_noise": [], "o2c_sshd_processes": ["sshd", "sshd-session", "sshd-auth"]})
    alerts = {o["name"]: o["body"] for o in rendered if o.get("kind") == "alert"}
    two = [_sshd_line("error: incorrect signature") for _ in range(2)]
    assert _run_alert_on_sqlite(alerts[SSHD_FATAL]["query_condition"]["sql"], two, "security_logs") == []
    assert len(_run_alert_on_sqlite(alerts[SSHD_FATAL]["query_condition"]["sql"], two + two[:1], "security_logs")) == 1
    overlap = [_sshd_line("error: error in libcrypto; Did not receive identification string from 203.0.113.9")] * 3
    assert len(_run_alert_on_sqlite(alerts[SSHD_FATAL]["query_condition"]["sql"], overlap, "security_logs")) == 1   # 소음 목록이 비면 제외 조건도 없다
    assert len(_run_alert_on_sqlite(alerts[SSHD_FATAL]["query_condition"]["sql"], [_sshd_line("error: error in libcrypto", "sshd-auth")] * 3, "security_logs")) == 1   # 프로세스 목록 변수
    trigger = alerts[SSH_NEW_USER]["trigger_condition"]
    assert (trigger["period"], trigger["frequency"], trigger["silence"]) == (2 * DAY + 20, 10, 20)
    sql = alerts[SSH_NEW_USER]["query_condition"]["sql"]
    assert [r["user_name"] for r in _run_alert_on_sqlite(sql, [_ssh_success("x", 15)], "security_logs")] == ["x"]   # 창 20분
    assert _run_alert_on_sqlite(sql, [_ssh_success("x", 25)], "security_logs") == []


def test_sshd_signal_fixtures_exist_for_the_verification_step():
    for name in (SSHD_FATAL, SSH_NEW_USER):
        cases = FIXTURES[name]["cases"]
        assert {c["fires"] for c in cases} == {True, False}, name


def test_sshd_signal_alerts_have_runbook_and_spec_entries_with_the_measured_basis():
    runbook = RUNBOOK.read_text(encoding="utf-8")
    spec = (ROOT_DIR / "docs" / "openobserve_config.md").read_text(encoding="utf-8")
    for name in (SSHD_FATAL, SSH_NEW_USER):
        anchor = name.removeprefix("infra-")
        assert f'<a id="{anchor}"></a>' in runbook and f"(`{name}`)" in runbook and f"`{name}`" in spec, name
    for token in ("lnx_sshd_susp_ssh", "5707", "5714", "Did not receive identification string", "7일", "스캔 비용"):
        assert token in spec, token


# --- /var/log 삭제·커널 모듈 syscall 규칙 알림 (Spec #433 / Ticket-5, #431) ----------------------------------------------------
VAR_LOG, KERNEL_MODULE = "infra-var-log-delete", "infra-kernel-module"

# 규칙(roles/security/templates/audit.rules.j2)이 만드는 SYSCALL 기록의 모양: 같은 호스트의 기존 audit 줄(exec_log·감시 키 SYSCALL)과 auditd 형식을 따랐다.
# key는 SYSCALL 줄에만 붙고 경로는 뒤따르는 PATH 줄(type=PATH ... name="/var/log/x")에 있다. 알림은 SYSCALL 줄만 읽는다.
_SYSCALL_NAMES = {263: "unlinkat", 257: "openat", 313: "finit_module", 175: "init_module", 176: "delete_module"}
# 줄 모양은 실로그(2026-11-04 security_logs의 audit SYSCALL 줄 하루치, 7대 호스트, 읽기 전용 조회)에서 확인했다: 키 바로 뒤에 \x1d(GS) 구분자가 오고 그 뒤에 auditd가 해석해
# 붙인 `ARCH=… SYSCALL=<이름> AUID="…" UID="…"`가 온다. 로그인 없는 줄은 `auid=4294967295`와 `AUID="unset"`이다.
_SYSCALL_BODY = ('type=SYSCALL msg=audit(1793000000.123:7001): arch=c000003e syscall=%d success=%s exit=0 a0=ffffff9c a1=55d2 a2=0 a3=0 items=2 '
                 'ppid=4000 pid=4900 auid=%s uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=313 comm="%s" exe="%s" '
                 'subj=kernel key="%s"\x1dARCH=x86_64 SYSCALL=%s AUID="%s" UID="root"')


def _sys_row(key, exe, comm, auid="1002", syscall=263, success="yes", host="ns0272", user="opsverify", service="audit"):
    return {"host_name": host, "service_name": service,
            "body": _SYSCALL_BODY % (syscall, success, auid, comm, exe, key, _SYSCALL_NAMES[syscall], "unset" if auid == "4294967295" else user)}


def _var_log_rows(desired, *records):
    return _run_alert_on_sqlite(_sql(desired, VAR_LOG), list(records), "security_logs")


def _module_rows(desired, *records):
    return _run_alert_on_sqlite(_sql(desired, KERNEL_MODULE), list(records), "security_logs")


def test_the_syscall_rule_alerts_are_security_log_event_alerts_in_the_expected_list_with_runbook_entries(desired):
    for name, severity in ((VAR_LOG, "P1 긴급"), (KERNEL_MODULE, "P2 경고")):
        alert = desired.store["alert"][name]
        assert alert["stream_name"] == "security_logs" and alert["context_attributes"]["severity"] == severity, name
        assert name in EXPECTED_ALERTS, name
        trigger = alert["trigger_condition"]
        assert (trigger["period"], trigger["frequency"], trigger["silence"]) == (5, 1, 5), name
        assert alert["context_attributes"]["runbook"].endswith("alerts.md#" + name.removeprefix("infra-")), name


def test_a_login_user_deleting_a_log_file_fires_the_p1_alert(desired):
    rows = _var_log_rows(desired, _sys_row("var_log_delete", "/usr/bin/rm", "rm"))
    assert [(r["host_name"], r["changes"]) for r in rows] == [("ns0272", 1)]


def test_a_truncation_by_a_login_user_fires_too(desired):
    """`> /var/log/secure` 같은 자르기는 openat(O_TRUNC)로 남고 같은 키를 쓴다."""
    assert len(_var_log_rows(desired, _sys_row("var_log_delete", "/usr/bin/bash", "bash", syscall=257))) == 1


def test_a_record_without_a_login_uid_never_fires_the_log_delete_alert_even_if_the_rule_let_it_through(desired):
    """logrotate·서비스는 auid가 비어(4294967295) 규칙이 거르지만, 알림도 같은 조건을 한 번 더 확인한다."""
    assert _var_log_rows(desired, *[_sys_row("var_log_delete", "/usr/sbin/logrotate", "logrotate", auid="4294967295") for _ in range(50)]) == []
    assert _var_log_rows(desired, _sys_row("var_log_delete", "/usr/bin/rm", "rm", auid="4294967295")) == []


def test_an_excluded_executable_does_not_fire_but_a_lookalike_does(desired):
    assert _var_log_rows(desired, _sys_row("var_log_delete", "/usr/sbin/logrotate", "logrotate")) == []        # 로그인 사용자가 손으로 돌린 logrotate
    assert len(_var_log_rows(desired, _sys_row("var_log_delete", "/tmp/logrotate", "logrotate"))) == 1          # 이름만 같고 경로가 다르면 제외가 아니다
    assert len(_var_log_rows(desired, _sys_row("var_log_delete", "/usr/sbin/logrotate-evil", "logrotate-evil"))) == 1


def _var_log_sql(rendered):
    return next(o["body"]["query_condition"]["sql"] for o in rendered if o["kind"] == "alert" and o["name"] == VAR_LOG)


def test_the_excluded_executable_list_is_a_role_variable_with_a_safe_path_check(tmp_path):
    assert DEFAULTS["o2c_var_log_excluded_exes"] == ["/usr/sbin/logrotate"]
    rendered = render_desired(tmp_path / "desired.json", extra={"o2c_var_log_excluded_exes": ["/usr/bin/cleanup-tool", "/usr/local/sbin/rotate"]})
    sql = _var_log_sql(rendered)
    assert _run_alert_on_sqlite(sql, [_sys_row("var_log_delete", "/usr/bin/cleanup-tool", "cleanup-tool")], "security_logs") == []
    assert _run_alert_on_sqlite(sql, [_sys_row("var_log_delete", "/usr/local/sbin/rotate", "rotate")], "security_logs") == []
    assert len(_run_alert_on_sqlite(sql, [_sys_row("var_log_delete", "/usr/sbin/logrotate", "logrotate")], "security_logs")) == 1   # 기본 목록을 덮었다
    empty = render_desired(tmp_path / "empty.json", extra={"o2c_var_log_excluded_exes": []})
    sql = _var_log_sql(empty)
    assert len(_run_alert_on_sqlite(sql, [_sys_row("var_log_delete", "/usr/sbin/logrotate", "logrotate")], "security_logs")) == 1   # 비면 제외 없음
    o2c = _filters()
    assert o2c.o2c_valid_exe_paths(["/usr/sbin/logrotate", "/opt/x-1.0/bin/yz"]) and o2c.o2c_valid_exe_paths([])
    for bad in ("logrotate", "/usr/bin/a_b", "/usr/bin/a b", "/usr/bin/a'b", '/usr/bin/a"b', "/usr/bin/%", "/usr/bin/a;b", ""):
        assert not o2c.o2c_valid_exe_paths([bad]), bad


def test_failed_attempts_other_keys_other_streams_and_non_syscall_lines_do_not_fire_the_log_delete_alert(desired):
    for row in (_sys_row("var_log_delete", "/usr/bin/rm", "rm", success="no"),                       # 권한 거부 — 지워지지 않았다
                _sys_row("delete", "/usr/bin/rm", "rm"),                                                # 증적 전용 키(#435)는 알림 대상이 아니다
                _sys_row("var_log_delete", "/usr/bin/rm", "rm", service="sshd"),
                _sys_row("kernel_module", "/usr/sbin/modprobe", "modprobe", syscall=313),
                {"host_name": "ns0272", "service_name": "audit", "body": 'type=PATH msg=audit(1793000000.123:7001): item=1 name="/var/log/secure" nametype=DELETE key="var_log_delete"'}):
        assert _var_log_rows(desired, row) == [], row


def test_log_delete_rows_group_by_host_actor_and_tool_and_name_them(desired):
    records = [_sys_row("var_log_delete", "/usr/bin/rm", "rm") for _ in range(3)] + [_sys_row("var_log_delete", "/usr/bin/bash", "bash", syscall=257, host="ns0001", user="alice")]
    rows = _var_log_rows(desired, *records)
    assert sorted((r["host_name"], r["actor"], r["tool"], r["changes"]) for r in rows) == [("ns0001", "alice", "bash", 1), ("ns0272", "opsverify", "rm", 3)]
    lines = _row_lines(desired, VAR_LOG, records[:3], "security_logs")
    assert len(lines) == 1 and lines[0].startswith("• ns0272: opsverify의 rm 3건") and " · " in lines[0]


def test_a_kernel_module_load_or_unload_by_a_login_user_fires_the_p2_alert(desired):
    for syscall, comm, exe, action in ((313, "modprobe", "/usr/sbin/modprobe", "적재"), (175, "insmod", "/usr/sbin/insmod", "적재"), (176, "rmmod", "/usr/sbin/rmmod", "제거")):
        rows = _module_rows(desired, _sys_row("kernel_module", exe, comm, syscall=syscall))
        assert [(r["host_name"], r["tool"], r["action"], r["changes"]) for r in rows] == [("ns0272", comm, action, 1)], comm


def test_a_kernel_module_row_without_the_enriched_syscall_name_still_fires_and_says_load_or_unload(desired):
    """EL6·7 auditd는 해석 필드(SYSCALL=)를 안 붙일 수 있다. 그때는 적재인지 제거인지 몰라 둘을 함께 적는다."""
    row = _sys_row("kernel_module", "/usr/sbin/modprobe", "modprobe", syscall=313)
    row["body"] = row["body"].split("\x1d")[0]
    assert [(r["tool"], r["action"]) for r in _module_rows(desired, row)] == [("modprobe", "적재·제거")]


def test_kernel_module_records_without_a_login_uid_failures_or_another_key_do_not_fire(desired):
    for row in (_sys_row("kernel_module", "/usr/sbin/modprobe", "modprobe", syscall=313, auid="4294967295"),
                _sys_row("kernel_module", "/usr/sbin/modprobe", "modprobe", syscall=313, success="no"),
                _sys_row("var_log_delete", "/usr/bin/rm", "rm"),
                _sys_row("kernel_module", "/usr/sbin/modprobe", "modprobe", syscall=313, service="sshd")):
        assert _module_rows(desired, row) == [], row


def test_kernel_module_rows_name_the_server_actor_and_tool(desired):
    lines = _row_lines(desired, KERNEL_MODULE, [_sys_row("kernel_module", "/usr/sbin/insmod", "insmod", syscall=175, host="ns0003", user="alice")], "security_logs")
    assert len(lines) == 1 and lines[0].startswith("• ns0003: alice의 insmod 커널 모듈 적재 1건") and " · " in lines[0]


@pytest.mark.parametrize("name", (VAR_LOG, KERNEL_MODULE))
def test_syscall_alert_fixtures_fire_as_expected_when_the_rendered_sql_runs_on_them(desired, name):
    """검증 단계가 쓰는 합성 행(fixtures)이 로그인 사용자 → 울림, auid 없음·제외 실행 파일·다른 키 → 안 울림 그대로 판정된다."""
    spec = FIXTURES[name]
    assert {c["fires"] for c in spec["cases"]} == {True, False}
    records = [r for c in spec["cases"] for r in _case_records(name, c)]
    fired = {row["host_name"] for row in _run_alert_on_sqlite(_sql(desired, name), records, "security_logs")}
    assert fired == {c["host"] for c in spec["cases"] if c["fires"]}


def _without_enriched_fields(row):
    """EL6·7 auditd 형식: 해석 필드(`\\x1d` 뒤의 ARCH=·SYSCALL=·AUID=)가 없는 줄."""
    return dict(row, body=row["body"].split("\x1d")[0])


def test_without_the_enriched_auid_name_the_actor_falls_back_to_the_raw_auid_number(desired):
    """AUID="이름" 해석 필드가 없는 형식에서도 작업자 자리에 `auid <번호>`가 나온다(알 수 없음이 아니다). 알림은 그대로 울린다."""
    row = _without_enriched_fields(_sys_row("var_log_delete", "/usr/bin/rm", "rm", auid="1002"))
    assert "AUID=" not in row["body"] and " auid=1002 " in row["body"]
    assert [(r["actor"], r["tool"]) for r in _var_log_rows(desired, row)] == [("auid 1002", "rm")]
    lines = _row_lines(desired, VAR_LOG, [row], "security_logs")
    assert len(lines) == 1 and lines[0].startswith("• ns0272: auid 1002의 rm 1건")
    mod = _without_enriched_fields(_sys_row("kernel_module", "/usr/sbin/insmod", "insmod", auid="1002", syscall=175))
    assert [(r["actor"], r["tool"]) for r in _module_rows(desired, mod)] == [("auid 1002", "insmod")]
    # 해석 이름이 있으면 이름이 우선이다
    assert [r["actor"] for r in _var_log_rows(desired, _sys_row("var_log_delete", "/usr/bin/rm", "rm"))] == ["opsverify"]


def test_the_default_exclusion_and_the_runbook_say_a_login_users_own_logrotate_run_is_not_alerted(desired):
    """제외 실행 파일은 exe 경로만 본다: 로그인 사용자가 `logrotate -f 내_설정`으로 로그를 지워도 알리지 않는다. 그 위험과 기본값 근거가 문서·변수 주석에 있어야 한다."""
    assert _var_log_rows(desired, _sys_row("var_log_delete", "/usr/sbin/logrotate", "logrotate")) == []
    runbook = RUNBOOK.read_text(encoding="utf-8")
    spec = (ROOT_DIR / "docs" / "openobserve_config.md").read_text(encoding="utf-8")
    comment = (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
    for doc in (runbook, spec, comment):
        assert "logrotate -f" in doc
    assert "기본 제외" in spec and "근거" in spec


def test_the_record_format_paragraph_agrees_with_the_actor_fallback():
    """"기록 형식의 근거" 단락은 작업자 칸 대체(`auid <번호>`)와 모순되면 안 된다: 해석 필드가 없을 때 작업자를 `알 수 없음`이라 쓰면 안 된다."""
    spec = (ROOT_DIR / "docs" / "openobserve_config.md").read_text(encoding="utf-8")
    para = next(ln for ln in spec.splitlines() if "기록 형식의 근거(2026-11-04" in ln)
    assert "작업자는 `auid <번호>`" in para and "작업자는 `알 수 없음`" not in para and "`적재·제거`" in para


def test_the_documents_state_the_syscall_rule_limits_found_in_review():
    sec = (ROOT_DIR / "docs" / "security.md").read_text(encoding="utf-8")
    runbook = RUNBOOK.read_text(encoding="utf-8")
    assert "sudo_logs 적재 여부" in sec                      # 카나리(#436) 확인 항목
    assert "auditctl -R" in sec and "sudo_logs" in sec and "6. 뒤" in sec   # 순서 트레이드오프
    for doc in (sec, runbook):                                 # EL6 init 스크립트 데몬이 auid를 물려받는 오탐
        assert "init 스크립트" in doc and "auid를 물려" in doc
    assert "#436" in sec and "ftruncate" in sec


def test_the_syscall_alerts_have_runbook_and_spec_entries_with_the_rule_basis():
    runbook = RUNBOOK.read_text(encoding="utf-8")
    spec = (ROOT_DIR / "docs" / "openobserve_config.md").read_text(encoding="utf-8")
    sec = (ROOT_DIR / "docs" / "security.md").read_text(encoding="utf-8")
    for name in (VAR_LOG, KERNEL_MODULE):
        anchor = name.removeprefix("infra-")
        assert f'<a id="{anchor}"></a>' in runbook and f"(`{name}`)" in runbook and f"`{name}`" in spec, name
    for token in ("var_log_delete", "kernel_module", "O_TRUNC", "카나리 실험", "미실시", "o2c_var_log_excluded_exes", "auditctl -l"):
        assert token in spec + sec + runbook, token


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


# --- 인증 로그 수집 중단 (Spec #390) ---
def test_auth_silent_alerts_are_state_alerts_on_security_logs_with_the_silent_host_timing(desired):
    for name in ("infra-auth-silent-p2", "infra-auth-silent-p1"):
        alert = desired.store["alert"][name]
        assert alert["stream_name"] == "security_logs", name
        assert alert["trigger_condition"]["period"] == 180 and alert["trigger_condition"]["frequency"] == 5, name
    assert desired.store["alert"]["infra-auth-silent-p2"]["trigger_condition"]["silence"] == 1440
    assert desired.store["alert"]["infra-auth-silent-p1"]["trigger_condition"]["silence"] == 60


def test_auth_silent_alerts_watch_only_the_auth_source_for_every_roster_host(tmp_path):
    roster = ["ns9001", "ns9002"]
    rendered = render_desired(tmp_path / "desired.json", extra={"o2c_roster_silent": roster, "o2c_auth_silent_p2_minutes": 45})
    alerts = {o["name"]: o["body"] for o in rendered if o.get("kind") == "alert"}
    p2 = alerts["infra-auth-silent-p2"]["query_condition"]["sql"]
    p1 = alerts["infra-auth-silent-p1"]["query_condition"]["sql"]
    for sql in (p2, p1):
        assert sql.count(" UNION ALL ") == len(roster) - 1
        for host in roster:
            assert "FROM \"security_logs\" WHERE host_name = '%s' AND service_name = 'auth' HAVING" % host in sql
    assert "- 2700000000 THEN 1" in p2 and "count(*) >= 1" in p2   # 변수로 바꾼 최근 구간(45분)이 SQL에 들어간다. 3시간 전체 없음은 P1 몫
    assert "HAVING count(*) < 1" in p1 and "THEN 1" not in p1


# --- GitHub 웹훅 전달 점검 (Spec #399 / Ticket-6) ---
GWW_ALERTS = {   # name -> (severity, period minutes, frequency, silence)
    "infra-github-webhook-watch-silent": ("P1 긴급", 13 * 60, 60, 360),
    "infra-github-webhook-hook-state": ("P2 경고", 15, 5, 60),
    "infra-github-webhook-redelivery-failed": ("P2 경고", 15, 5, 60),
    "infra-github-webhook-check-error": ("P2 경고", 15, 5, 60),
}


def test_github_webhook_alerts_keep_the_prefix_severity_runbook_link_and_timing(desired, rendered):
    for name, (sev, period, freq, silence) in GWW_ALERTS.items():
        assert name.startswith("infra-"), name
        alert = desired.store["alert"][name]
        assert alert["context_attributes"]["severity"] == sev, name
        assert alert["context_attributes"]["runbook"].endswith("#" + name.removeprefix("infra-")), name
        assert alert["stream_name"] == "security_logs", name
        tc = alert["trigger_condition"]
        assert (tc["period"], tc["frequency"], tc["silence"]) == (period, freq, silence), name
    names = [o["name"] for o in rendered if o["kind"] == "alert"]
    assert len(names) == len(set(names)) and set(GWW_ALERTS) <= set(names)   # 기존 알림 이름과 겹치지 않는다


def test_github_webhook_runbook_sections_exist_for_every_alert():
    text = (ROOT_DIR / "docs" / "runbooks" / "alerts.md").read_text(encoding="utf-8")
    for name in GWW_ALERTS:
        assert '<a id="%s"></a>' % name.removeprefix("infra-") in text and "`%s`" % name in text, name


def test_github_webhook_silence_threshold_covers_two_check_intervals_but_stays_inside_the_redelivery_window(desired):
    defaults = yaml.safe_load((ROOT_DIR / "roles" / "github_webhook_watch" / "defaults" / "main.yml").read_text(encoding="utf-8"))
    period_min = desired.store["alert"]["infra-github-webhook-watch-silent"]["trigger_condition"]["period"]
    assert period_min > 2 * int(defaults["gww_check_interval_hours"]) * 60   # 한 번 빠진 실행에는 울리지 않는다
    assert period_min < int(defaults["gww_redelivery_window_hours"]) * 60 / 2   # 재전송 가능 기간(3일)에 비해 충분히 일찍 알린다


def test_github_webhook_silent_alert_watches_only_the_heartbeat_record(desired):
    assert _sql(desired, "infra-github-webhook-watch-silent") == (
        "SELECT 'github-webhook-watch' AS service_name, count(*) AS n FROM \"security_logs\" "
        "WHERE service_name = 'github-webhook-watch' AND record_type = 'heartbeat' HAVING count(*) < 1")


HEARTBEAT = dict(service_name="github-webhook-watch", record_type="heartbeat", result="ok", error="", hook_status="ok", hook_problems="",
                 failed_count=0, expired_count=0, deliveries_truncated=False)


@pytest.mark.parametrize("name, change, fires", [
    ("infra-github-webhook-hook-state", dict(hook_status="missing", hook_problems="hook_missing"), True),
    ("infra-github-webhook-hook-state", dict(hook_status="inactive"), True),
    ("infra-github-webhook-hook-state", dict(hook_status="events_mismatch"), True),
    ("infra-github-webhook-hook-state", dict(hook_status="ok"), False),
    ("infra-github-webhook-redelivery-failed", dict(failed_count=1), True),
    ("infra-github-webhook-redelivery-failed", dict(expired_count=2), True),
    ("infra-github-webhook-redelivery-failed", dict(deliveries_truncated=True), True),
    ("infra-github-webhook-redelivery-failed", dict(), False),
    ("infra-github-webhook-redelivery-failed", dict(deliveries_truncated="true"), True),   # 불리언이 문자열로 들어와도 판정이 같다
    ("infra-github-webhook-redelivery-failed", dict(deliveries_truncated="false"), False),
    ("infra-github-webhook-check-error", dict(result="error", error="credential_missing"), True),
    ("infra-github-webhook-check-error", dict(result="error", error="api_http_401", hook_status="unknown"), True),
    ("infra-github-webhook-check-error", dict(result="ok", error=""), False),
])
def test_github_webhook_event_alerts_fire_on_the_documented_heartbeat_fields(desired, name, change, fires):
    rows = _run_alert_on_sqlite(_sql(desired, name), [dict(HEARTBEAT, **change)], stream="security_logs")
    assert bool(rows) is fires


def test_github_webhook_rows_fit_the_message_limit_in_the_worst_case(desired):
    values = {"hook_status": "events_mismatch", "hook_problems": "hook_inactive,events_mismatch", "event_time": LONGEST_ROW_VALUES["event_time"],
              "failed_count": "9999", "expired_count": "9999", "truncated": "1", "error": "api_unexpected_response", "service_name": "github-webhook-watch"}
    for name in GWW_ALERTS:
        assert len(_rendered_message(desired, name, values)) <= BODY_LIMIT, name


def test_github_webhook_truncated_flag_is_read_without_a_boolean_aggregate_or_comparison(desired):
    sql = _sql(desired, "infra-github-webhook-redelivery-failed")
    assert "max(deliveries_truncated)" not in sql and "deliveries_truncated = true" not in sql   # 엔진마다 불리언 max·비교가 다르다
    rows = _run_alert_on_sqlite(sql, [dict(HEARTBEAT, deliveries_truncated=True)], stream="security_logs")
    assert rows[0]["truncated"] == 1


def test_github_webhook_check_error_alert_names_every_documented_error_code_in_its_runbook():
    text = (ROOT_DIR / "docs" / "runbooks" / "alerts.md").read_text(encoding="utf-8")
    section = text.split('<a id="github-webhook-check-error"></a>')[1].split("\n---\n")[0]
    for code in ("credential_missing", "api_unreachable", "api_http_401", "api_http_403", "api_unexpected_response"):
        assert code in section, code
    silent = text.split('<a id="github-webhook-watch-silent"></a>')[1].split("\n---\n")[0]
    assert "오류 코드가 있어도 하트비트는 남" in silent   # 오류 하트비트로는 침묵 알림이 울리지 않는다


# --- GitHub 조직 관리 변경 알림 (Spec #399 / Ticket-4) --- 등급은 2026-11-03 사용자가 확정했다.
GHA_ALERTS = {   # name -> (severity, 알림이 잡아야 할 (event, action) 조합)
    "infra-github-audit-hook-deleted": ("P1 긴급", {("meta", "deleted")}),
    "infra-github-audit-repo-public": ("P1 긴급", {("repository", "publicized"), ("public", None)}),
    "infra-github-audit-repo-org-deleted": ("P1 긴급", {("repository", "deleted"), ("organization", "deleted")}),
    "infra-github-audit-protection-removed": ("P2 경고", {("branch_protection_rule", "deleted")}),
    "infra-github-audit-ruleset-deleted": ("P2 경고", {("repository_ruleset", "deleted")}),
    "infra-github-audit-deploy-key-created": ("P2 경고", {("deploy_key", "created")}),
    "infra-github-audit-membership-change": ("P3 주의", {
        ("member", "added"), ("member", "edited"), ("member", "removed"), ("membership", "added"), ("membership", "removed"),
        ("organization", "member_added"), ("organization", "member_invited"), ("organization", "member_removed"),
        ("team", "created"), ("team", "deleted"), ("team", "added_to_repository"), ("team", "removed_from_repository")}),
}


def _gha_rec(event, action, **extra):
    # 저장소는 레코드마다 달라 서로 묶이지 않는다. 열은 항상 있다(스트림 스키마에는 다른 이벤트가 만든 열이 이미 있다)
    rec = dict(service_name="github-audit", github_event=event, github_action=action, github_org="example-org", github_repo="o/%s-%s" % (event, action),
               github_actor="alice", github_actor_ghost=False, github_target="bob", github_target_type="user", github_team="platform",
               github_delivery_id="d-%s-%s" % (event, action), github_hook_id="1", _timestamp=1_792_767_302_000_000)
    rec.update(extra)
    return rec


def test_github_audit_alerts_keep_the_prefix_severity_runbook_link_and_timing(desired, rendered):
    for name, (sev, _) in GHA_ALERTS.items():
        assert name.startswith("infra-") and not name.startswith("infra-github-webhook-"), name   # 전달 점검 알림(Ticket-6)과 이름이 겹치지 않는다
        alert = desired.store["alert"][name]
        assert alert["context_attributes"]["severity"] == sev, name
        assert alert["context_attributes"]["runbook"].endswith("#" + name.removeprefix("infra-")), name
        assert alert["stream_name"] == "security_logs", name
        tc = alert["trigger_condition"]
        assert (tc["period"], tc["frequency"], tc["silence"]) == (7, 1, 5), name   # 이벤트 알림: 7분 구간, 발화 뒤 5분 무음
        # 무음이 끝난 뒤 첫 평가는 발화 시각 + 무음 + 평가 간격(+ 지연) 뒤다. 조회 구간이 이보다 짧으면 발화 직후의 이벤트가 영영 구간 밖에 남는다
        # (2026-11-04 서버 적용: 구간 5 = 무음 5라서 team.deleted·membership.removed가 알림에서 빠졌다). 누락보다 한 건 중복이 낫다.
        assert tc["period"] >= tc["silence"] + tc["frequency"] + 1, name
    names = [o["name"] for o in rendered if o["kind"] == "alert"]
    assert len(names) == len(set(names)) and set(GHA_ALERTS) <= set(names)


def test_github_audit_runbook_sections_exist_and_mark_the_severity_as_confirmed():
    text = (ROOT_DIR / "docs" / "runbooks" / "alerts.md").read_text(encoding="utf-8")
    for name in GHA_ALERTS:
        assert '<a id="%s"></a>' % name.removeprefix("infra-") in text and "`%s`" % name in text, name
    assert "사용자 확정 대기" not in text and "2026-11-03 사용자가 확정" in text


@pytest.mark.parametrize("name", sorted(GHA_ALERTS))
def test_github_audit_alert_fires_only_for_its_own_event_action_pairs(desired, name):
    own = GHA_ALERTS[name][1]
    every = set().union(*(v[1] for v in GHA_ALERTS.values())) | {("meta", "created"), ("repository", "created"), ("deploy_key", "deleted"),
                                                                  ("branch_protection_rule", "created"), ("repository_ruleset", "edited"),
                                                                  ("member", "invited"), ("org_block", "blocked"), ("ping", None)}
    recs = [_gha_rec(e, a) for e, a in sorted(every, key=str)]
    recs.append(_gha_rec("meta", "deleted", service_name="other-service", github_delivery_id="d-other"))   # 다른 서비스는 보지 않는다
    rows = _run_alert_on_sqlite(_sql(desired, name), recs, stream="security_logs")
    assert {r["github_delivery_id"] for r in rows} == {"d-%s-%s" % (e, a) for e, a in own}, name


@pytest.mark.parametrize("name", sorted(GHA_ALERTS))
def test_github_audit_rows_name_actor_target_and_repository(desired, name):
    event, action = sorted(GHA_ALERTS[name][1], key=str)[0]
    rows = _run_alert_on_sqlite(_sql(desired, name), [_gha_rec(event, action, github_target="the-target", github_team="the-team")], stream="security_logs")
    assert len(rows) == 1, name
    line = re.sub(r"\{(\w+)\}", lambda m: str(rows[0][m.group(1)]), desired.store["alert"][name]["row_template"])
    for token in ("alice", "the-target", "o/%s-%s" % (event, action)):
        assert token in line, (name, token, line)
    if "{kind}" in desired.store["alert"][name]["row_template"]:   # 같은 알림이 여러 이벤트를 잡으면 행의 이벤트.액션으로 구분한다
        assert "%s.%s" % (event, action) in line


def test_github_audit_row_marks_a_ghost_actor_and_keeps_rows_without_target_or_repository(desired):
    sql = _sql(desired, "infra-github-audit-hook-deleted")
    ghost = _run_alert_on_sqlite(sql, [_gha_rec("meta", "deleted", github_actor="ghost", github_actor_ghost=True)], stream="security_logs")
    assert "ghost" in ghost[0]["actor"] and "불명" in ghost[0]["actor"]
    nosender = _run_alert_on_sqlite(sql, [_gha_rec("meta", "deleted", github_actor=None, github_actor_ghost=True)], stream="security_logs")
    assert "불명" in nosender[0]["actor"]
    real = _run_alert_on_sqlite(sql, [_gha_rec("meta", "deleted", github_actor_ghost="false")], stream="security_logs")
    assert real[0]["actor"] == "alice"
    bare = _gha_rec("organization", "deleted", github_target=None, github_repo=None)
    row = _run_alert_on_sqlite(_sql(desired, "infra-github-audit-repo-org-deleted"), [bare], stream="security_logs")[0]
    assert row["target"] and row["repo"]   # 대상·저장소가 없어도 행에 자리표시가 나온다


@pytest.mark.parametrize("name", sorted(GHA_ALERTS))
def test_github_audit_alert_handles_a_sparse_record_whose_missing_values_are_empty_strings(desired, name):
    """The VRL always sets all 11 fields (empty string when the payload has no value), so a stream made of one sparse record has every column."""
    event, action = sorted(GHA_ALERTS[name][1], key=str)[0]
    sparse = {"service_name": "github-audit", "github_event": event, "github_action": action or "", "github_delivery_id": "d-sparse", "github_hook_id": "",
              "github_actor": "", "github_actor_ghost": True, "github_org": "", "github_repo": "", "github_target": "", "github_target_type": "", "github_team": "",
              "_timestamp": 1_792_767_302_000_000}
    rows = _run_alert_on_sqlite(_sql(desired, name), [sparse], stream="security_logs")
    assert len(rows) == 1, name
    row = rows[0]
    assert "불명" in row["actor"] and row["repo"] == "-" and row["target"] == "(대상 불명)", row   # 빈 문자열도 자리표시로 바뀐다
    if "team" in row:
        assert row["team"] == "-"


def test_github_audit_membership_row_shows_the_team_for_team_membership(desired):
    row = _run_alert_on_sqlite(_sql(desired, "infra-github-audit-membership-change"),
                               [_gha_rec("membership", "added", github_team="platform")], stream="security_logs")[0]
    assert "platform" in row["team"]


def test_github_audit_publicized_and_public_for_one_change_make_one_row(desired):
    recs = [_gha_rec("repository", "publicized", github_delivery_id="d-1", github_repo="example-org/same"),
            _gha_rec("public", None, github_delivery_id="d-2", github_repo="example-org/same")]
    rows = _run_alert_on_sqlite(_sql(desired, "infra-github-audit-repo-public"), recs, stream="security_logs")
    assert len(rows) == 1 and int(rows[0]["events"]) == 2   # 같은 저장소·행위자의 두 전달은 한 행


def test_github_audit_messages_fit_the_limit_in_the_worst_case_and_carry_the_required_sections(desired):
    values = {"actor": "u" * 39, "target": "t" * 30, "repo": "r" * 40, "kind": "team.removed_from_repository", "team": "t" * 20,   # SQL이 자르는 상한
              "events": "9999", "event_time": LONGEST_ROW_VALUES["event_time"], "github_delivery_id": "d" * 36}
    realistic = dict(LONGEST_TEXT, events="999", event_time=LONGEST_ROW_VALUES["event_time"])
    for name in GHA_ALERTS:
        assert len(_rendered_message(desired, name, values)) <= BODY_LIMIT, name        # SQL 상한 값으로 30행이어도 플랫폼 한도(50,000자) 안
        assert len(_rendered_message(desired, name, realistic)) <= 5000, name           # 현실적인 최대 값으로는 실측한 5,000자 안(기존 알림과 같은 기준)
        ctx = desired.store["alert"][name]["context_attributes"]
        for key in ("what", "why", "action_1", "runbook"):
            assert ctx[key], (name, key)


def test_github_audit_alerts_do_not_touch_the_existing_alert_sets(desired):
    assert not (set(GHA_ALERTS) & set(GWW_ALERTS))
    for name in GWW_ALERTS:
        assert name in desired.store["alert"]


# --- 인증 실패 알림 보강: 느린 대입·스프레이·Invalid user·su 거부 (Spec #433 / Ticket-1, #427) ---
SLOW, SPRAY, ESCALATION, PER_SOURCE = ("infra-ssh-login-failures-slow", "infra-ssh-password-spray",
                                       "infra-sudo-escalation-failure", "infra-ssh-login-failures-per-source")
MINUTE_US = 60 * 1_000_000


def _ssh(ts, user="admin", source="203.0.113.10", kind="failed", port=None, host="ns0272"):
    """sshd 한 줄이 수집 함수를 거친 모양. failed=존재하는 계정의 Failed password, invalid_failed=없는 계정의 Failed password,
    probe=`Invalid user` 줄(event_outcome 없음). 옛 OpenSSH의 probe 줄은 포트가 없다."""
    reason, outcome = {"failed": ("failed password", "failure"), "invalid_failed": ("invalid user", "failure"),
                       "probe": ("invalid user", None), "success": (None, "success")}[kind]
    return {"event_action": "ssh_login", "event_outcome": outcome, "event_reason": reason, "user_name": user, "source_address": source,
            "source_port": port, "host_name": host, "_timestamp": _kst_us(ts) if isinstance(ts, str) else ts}


def _window(desired, name, records, end):
    """알림이 `end` 시각에 평가될 때 읽는 구간(period분)의 레코드."""
    period = desired.store["alert"][name]["trigger_condition"]["period"]
    end_us = end if isinstance(end, int) else _kst_us(end)
    return [r for r in records if end_us - period * MINUTE_US < r["_timestamp"] <= end_us]


def _in_window(desired, name, records, end, stream="security_logs"):
    """알림이 `end` 시각에 평가될 때 읽는 구간의 레코드만으로 SQL을 돌려 통지 행을 돌려준다."""
    window = _window(desired, name, records, end)
    return _row_lines(desired, name, window, stream) if window else []


def test_a_slow_brute_force_of_six_failures_every_five_minutes_fires_the_hour_alert_but_never_the_five_minute_one(desired):
    start = _kst_us("2026-10-23 08:00:00")
    recs = [_ssh(start + burst * 5 * MINUTE_US + i * 10_000_000) for burst in range(12) for i in range(6)]   # 5분마다 1분 안에 6회, 1시간
    assert [at for at in range(0, 66) if _in_window(desired, PER_SOURCE, recs, start + at * MINUTE_US)] == []   # 어느 시각에도 5분 알림은 울리지 않는다
    assert _in_window(desired, SLOW, recs, "2026-10-23 08:58:00") == ["• 203.0.113.10 → ns0272: 실패 72회 · 10-23 08:00:00~08:55:50"]
    assert _in_window(desired, SLOW, recs, "2026-10-23 08:12:00")        # 한 시간이 다 차기 전에도 10회를 넘기는 순간 울린다


@pytest.mark.parametrize("failures, fires", [(9, False), (10, True)])
def test_the_hour_alert_fires_from_ten_failures_of_one_source_on_one_host(desired, failures, fires):
    recs = [_ssh(f"2026-10-23 08:{n:02d}:00") for n in range(failures)]
    assert bool(_in_window(desired, SLOW, recs, "2026-10-23 08:59:00")) is fires


def test_the_hour_alert_keeps_hosts_and_sources_apart(desired):
    recs = ([_ssh(f"2026-10-23 08:{n:02d}:00", host="ns0272") for n in range(6)] + [_ssh(f"2026-10-23 08:{n:02d}:30", host="ns0273") for n in range(6)]
            + [_ssh(f"2026-10-23 08:{n:02d}:40", source="203.0.113.11") for n in range(6)])
    assert _in_window(desired, SLOW, recs, "2026-10-23 08:59:00") == []


def test_one_invalid_user_attempt_written_as_two_lines_counts_once_with_or_without_a_port_on_the_probe_line(desired):
    pairs = [(_ssh(f"2026-10-23 08:{n:02d}:00", user=f"u{n}", kind="probe", port=40000 + n if n % 2 else None),
              _ssh(f"2026-10-23 08:{n:02d}:07", user=f"u{n}", kind="invalid_failed", port=40000 + n)) for n in range(5)]   # 7초 뒤의 Failed password(실로그에서 본 간격)
    recs = [r for pair in pairs for r in pair]
    assert _in_window(desired, SLOW, recs, "2026-10-23 08:59:00") == []                       # 한 쌍 5번 = 5회, 줄 수 10이 아니다
    recs += [_ssh(f"2026-10-23 08:{n:02d}:30", user="alice") for n in range(5)]
    assert _in_window(desired, SLOW, recs, "2026-10-23 08:59:00") == ["• 203.0.113.10 → ns0272: 실패 10회 · 10-23 08:00:00~08:04:30"]


def test_an_invalid_user_that_hangs_up_before_a_password_is_a_failure_and_so_is_a_password_line_without_its_probe(desired):
    probes = [_ssh(f"2026-10-23 08:{n:02d}:00", user=f"u{n}", kind="probe") for n in range(10)]
    assert len(_in_window(desired, SLOW, probes, "2026-10-23 08:59:00")) == 1
    only_failed = [_ssh(f"2026-10-23 08:{n:02d}:00", user=f"u{n}", kind="invalid_failed", port=40000 + n) for n in range(10)]
    assert len(_in_window(desired, SLOW, only_failed, "2026-10-23 08:59:00")) == 1


def test_a_login_success_is_not_a_failure_in_either_new_alert(desired):
    recs = [_ssh(f"2026-10-23 08:{n:02d}:00", user=f"u{n}", kind="success") for n in range(40)]
    assert _in_window(desired, SLOW, recs, "2026-10-23 08:59:00") == [] and _in_window(desired, SPRAY, recs, "2026-10-23 08:59:00") == []


@pytest.mark.parametrize("accounts, failures_each, fires", [(11, 3, True), (3, 14, False), (10, 3, False), (11, 2, False)])
def test_the_spray_alert_needs_more_than_ten_accounts_and_at_least_thirty_failures(desired, accounts, failures_each, fires):
    recs = [_ssh(f"2026-10-23 08:5{5 + n % 4}:{(n * 5) % 60:02d}", user=f"user{n}") for n in range(accounts) for _ in range(failures_each)]
    assert bool(_in_window(desired, SPRAY, recs, "2026-10-23 08:59:00")) is fires, (accounts, failures_each)


def test_the_spray_alert_counts_every_account_once_even_when_it_is_probed_and_fails(desired):
    recs = [r for n in range(11) for r in (_ssh(f"2026-10-23 08:55:{n:02d}", user=f"user{n}", kind="probe"),
                                           _ssh(f"2026-10-23 08:55:{n:02d}", user=f"user{n}", kind="invalid_failed", port=50000 + n))]
    recs += [_ssh("2026-10-23 08:56:00", user="user0") for _ in range(8)]
    assert _in_window(desired, SPRAY, recs, "2026-10-23 08:59:00") == []                       # 시도 11 + 8 = 19회
    recs += [_ssh("2026-10-23 08:56:30", user="user1") for _ in range(11)]
    assert _in_window(desired, SPRAY, recs, "2026-10-23 08:59:00") == ["• 203.0.113.10 → ns0272: 계정 11개 · 실패 30회 · 10-23 08:55:00~08:56:30"]


def test_the_spray_window_is_five_minutes(desired):
    recs = [_ssh(f"2026-10-23 08:{n * 2:02d}:00", user=f"user{n}") for n in range(12) for _ in range(3)]   # 24분에 걸친 36회
    assert _in_window(desired, SPRAY, recs, "2026-10-23 09:00:00") == []


def test_the_new_alerts_are_p2_event_alerts_with_variable_windows_thresholds_and_renotify(desired):
    for name, period, silence in ((SLOW, 60, 60), (SPRAY, 5, 15)):
        alert = desired.store["alert"][name]
        assert alert["context_attributes"]["severity"] == "P2 경고" and alert["stream_name"] == "security_logs", name
        assert (alert["trigger_condition"]["period"], alert["trigger_condition"]["frequency"], alert["trigger_condition"]["silence"]) == (period, 1, silence), name
        assert alert["context_attributes"]["raw_log_line"].startswith("▶ 로그 보기: http"), name   # WHERE만으로 원문 조회를 만든다
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert {k: defaults[k] for k in ("o2c_ssh_slow_window_minutes", "o2c_ssh_slow_min_failures", "o2c_ssh_slow_renotify_minutes",
                                     "o2c_ssh_spray_window_minutes", "o2c_ssh_spray_min_failures", "o2c_ssh_spray_accounts_over",
                                     "o2c_ssh_spray_renotify_minutes")} == {
        "o2c_ssh_slow_window_minutes": 60, "o2c_ssh_slow_min_failures": 10, "o2c_ssh_slow_renotify_minutes": 60,
        "o2c_ssh_spray_window_minutes": 5, "o2c_ssh_spray_min_failures": 30, "o2c_ssh_spray_accounts_over": 10, "o2c_ssh_spray_renotify_minutes": 15}


def test_the_new_ssh_alert_variables_reach_the_rendered_definitions(tmp_path):
    rendered = render_desired(tmp_path / "desired.json", extra={
        "o2c_ssh_slow_window_minutes": 120, "o2c_ssh_slow_min_failures": 7, "o2c_ssh_slow_renotify_minutes": 90,
        "o2c_ssh_spray_window_minutes": 10, "o2c_ssh_spray_min_failures": 44, "o2c_ssh_spray_accounts_over": 12, "o2c_ssh_spray_renotify_minutes": 25})
    alerts = {o["name"]: o["body"] for o in rendered if o.get("kind") == "alert"}
    slow, spray = alerts[SLOW], alerts[SPRAY]
    assert (slow["trigger_condition"]["period"], slow["trigger_condition"]["silence"]) == (120, 90) and ">= 7" in slow["query_condition"]["sql"]
    assert (spray["trigger_condition"]["period"], spray["trigger_condition"]["silence"]) == (10, 25)
    assert ">= 44" in spray["query_condition"]["sql"] and "> 12" in spray["query_condition"]["sql"]


def test_the_five_minute_ssh_alerts_are_unchanged(desired):
    per_source = desired.store["alert"][PER_SOURCE]
    assert (per_source["trigger_condition"]["period"], per_source["trigger_condition"]["silence"]) == (5, 15)
    assert _sql(desired, PER_SOURCE).count("event_outcome = 'failure'") == 1 and "invalid user" not in _sql(desired, PER_SOURCE)
    assert "invalid user" not in _sql(desired, "infra-ssh-login-failures-per-host")
    probes = [_ssh(f"2026-10-23 08:5{n}:00", user=f"u{n}", kind="probe") for n in range(10)]
    assert _row_lines(desired, PER_SOURCE, probes, "security_logs") == []   # 5분 알림은 probe 줄을 세지 않는다(계수 방식 그대로)


def _su_audit(ts, host="ns0272", uid=1000, target="root", result="failed", exe="/usr/bin/su", auid=None):
    auid = uid if auid is None else auid
    body = ("type=USER_AUTH msg=audit(1793697289.294:6510864): pid=3814 uid=%d auid=%d ses=96232 msg='op=PAM:authentication grantors=? "
            'acct="%s" exe="%s" hostname=? addr=? terminal=pts/0 res=%s\'') % (uid, auid, target, exe, result)
    return {"service_name": "audit", "body": body, "host_name": host, "_timestamp": _kst_us(ts),
            "event_action": None, "event_outcome": None, "event_reason": None, "user_name": None, "user_effective_name": None}


def _su_secure(ts, host="ns0272", user="alice", target="root", uid=1000):
    body = ("su: pam_unix(su:auth): authentication failure; logname=%s uid=%d euid=0 tty=/dev/pts/0 ruser=%s rhost=  user=%s" % (user, uid, user, target))
    return {"event_action": "su", "event_outcome": "failure", "event_reason": "authentication failure", "user_name": user,
            "user_effective_name": target, "host_name": host, "_timestamp": _kst_us(ts), "service_name": "auth", "body": body}


def test_a_su_refused_by_pam_wheel_leaves_only_an_audit_record_and_the_escalation_alert_fires(desired):
    rows = _row_lines(desired, ESCALATION, [_su_audit("2026-10-23 08:59:14")], "security_logs")
    assert rows == ["• ns0272 / 사용자 uid 1000: 실패 1회 · 10-23 08:59:14"]


def test_the_same_su_failure_in_secure_and_audit_is_notified_once(desired):
    rows = _row_lines(desired, ESCALATION, [_su_secure("2026-10-23 08:59:14"), _su_audit("2026-10-23 08:59:14")], "security_logs")
    assert rows == ["• ns0272 / 사용자 alice: 실패 1회 · 10-23 08:59:14"]
    three = [r for s in ("08:59:03", "08:59:10", "08:59:16") for r in (_su_secure("2026-10-23 " + s), _su_audit("2026-10-23 " + s))]
    assert _row_lines(desired, ESCALATION, three, "security_logs") == ["• ns0272 / 사용자 alice: 실패 3회 · 10-23 08:59:03~08:59:16"]


def test_a_su_audit_success_or_another_programs_audit_failure_does_not_fire_the_escalation_alert(desired):
    sudo_body = "type=USER_AUTH msg=audit(1.1:2): msg='op=PAM:authentication acct=\"root\" exe=\"/usr/bin/sudo\" res=failed'"
    quiet = [_su_audit("2026-10-23 08:59:14", result="success"), _su_audit("2026-10-23 08:59:15", exe="/usr/sbin/sshd"),
             dict(_su_audit("2026-10-23 08:59:16"), body=sudo_body)]
    assert _row_lines(desired, ESCALATION, quiet, "security_logs") == []


def test_su_audit_records_from_the_older_su_path_count_and_sudo_failures_still_count_with_them(desired):
    recs = [_su_audit("2026-10-23 08:59:14", exe="/bin/su"),
            {"event_action": "sudo", "event_outcome": "failure", "user_name": "bob", "host_name": "ns0272", "body": None, "_timestamp": _kst_us("2026-10-23 08:59:20")}]
    rows = _row_lines(desired, ESCALATION, recs, "security_logs")
    assert sorted(rows) == ["• ns0272 / 사용자 bob: 실패 1회 · 10-23 08:59:20", "• ns0272 / 사용자 uid 1000: 실패 1회 · 10-23 08:59:14"]


@pytest.mark.parametrize("name", (SLOW, SPRAY, ESCALATION))
def test_auth_failure_alert_fixtures_fire_as_expected_when_the_rendered_sql_runs(desired, name):
    """서버 검증 단계(O2C-034)가 쓰는 합성 케이스를 로컬에서도 같은 SQL로 돌려, 발화해야 할 가짜 호스트만 나오는지 본다."""
    alert = desired.store["alert"][name]
    spec = FIXTURES[name]
    cases = [(c, _case_records(name, c)) for c in spec["cases"]]
    assert {c["fires"] for c, _ in cases} == {True, False}, name
    rows = _run_alert_on_sqlite(alert["query_condition"]["sql"], [r for _, recs in cases for r in recs], alert["stream_name"])
    assert {row["host_name"] for row in rows} == {c["host"] for c, _ in cases if c["fires"]}, name
    assert len(rows) == len({row["host_name"] for row in rows}), name   # 한 호스트에 한 행(같은 su가 두 기록에 있어도 중복 통지 없음)


def test_the_auth_failure_alerts_are_registered_in_the_spec_table_the_runbook_and_the_expected_list():
    runbook = RUNBOOK.read_text(encoding="utf-8")
    spec = (ROOT_DIR / "docs" / "openobserve_config.md").read_text(encoding="utf-8")
    for name in (SLOW, SPRAY):
        assert name in EXPECTED_ALERTS, name
        assert f'<a id="{name.removeprefix("infra-")}"></a>' in runbook and f"(`{name}`)" in runbook, name
        assert f"| `{name}` |" in spec, name
    assert "고유 키" in spec and "(user_name, source_port)" in spec and "포트 없는" in spec     # 고유 키를 바꾼 근거(실로그 7일)가 명세에 있다
    assert "audit" in spec.split("| `infra-sudo-escalation-failure` |", 1)[1].split("\n", 1)[0] and "pam_wheel" in runbook


def test_a_su_audit_record_of_an_enriched_audit_log_shows_the_name_not_the_uid(desired):
    named = dict(_su_audit("2026-10-23 08:59:14"), body=_su_audit("2026-10-23 08:59:14")["body"] + '\x1dUID="carol" AUID="carol"')
    assert _row_lines(desired, ESCALATION, [named], "security_logs") == ["• ns0272 / 사용자 carol: 실패 1회 · 10-23 08:59:14"]


def test_each_user_keeps_his_own_escalation_row_and_one_users_secure_su_does_not_cancel_anothers_audit_only_su(desired):
    """secure 행은 사용자별이다. 한 사용자의 secure su 실패 3건이 다른 사용자의 audit 전용 su 실패 3건을 상쇄하지 않아 합이 6이다."""
    recs = ([_su_secure("2026-10-23 08:59:%02d" % n, user="alice", uid=1000) for n in (1, 2, 3)]
            + [_su_audit("2026-10-23 08:59:%02d" % n, uid=1001) for n in (4, 5, 6)])
    rows = _row_lines(desired, ESCALATION, recs, "security_logs")
    assert sorted(rows) == ["• ns0272 / 사용자 alice: 실패 3회 · 10-23 08:59:01~08:59:03", "• ns0272 / 사용자 uid 1001: 실패 3회 · 10-23 08:59:04~08:59:06"]
    both = recs + [_su_audit("2026-10-23 08:59:%02d" % n, uid=1000) for n in (1, 2, 3)]   # alice의 secure 3건과 같은 시도의 audit 3건: 더하지 않는다
    assert len(_row_lines(desired, ESCALATION, both, "security_logs")) == 2
    assert sorted(r.split(": 실패 ")[1][:2] for r in _row_lines(desired, ESCALATION, both, "security_logs")) == ["3회", "3회"]


def test_escalation_rows_are_per_user_as_before_without_a_folded_more_users_suffix(desired):
    recs = [_su_secure("2026-10-23 08:59:14", user="alice", uid=1000), _su_secure("2026-10-23 08:59:30", user="bob", uid=1001),
            _su_secure("2026-10-23 08:59:40", user="carol", uid=1002)]
    rows = _row_lines(desired, ESCALATION, recs, "security_logs")
    assert len(rows) == 3 and not any("외 " in r for r in rows)
    assert "more_users" not in _sql(desired, ESCALATION)


# --- 보안 서비스 중지 State Alert와 기존 목록 보정 (Spec #433 / Ticket-3, #429) ---------------------------------------------------
STOPPED = "infra-security-service-stopped"
UNIT_BODY = ("type=%s msg=audit(1792627441.382:46621): pid=1 uid=0 auid=4294967295 ses=4294967295 subj=kernel "
             "msg='unit=%s comm=\"systemd\" exe=\"/usr/lib/systemd/systemd\" hostname=? addr=? terminal=? res=%s'")


def _unit_event(kind, unit, at, host="ns0272", res="success"):
    """감사 로그의 SERVICE_STOP·SERVICE_START 한 줄(실로그 형식). `at`은 기준 시각(2026-10-23 09:00:00 KST)에서의 초."""
    return {"service_name": "audit", "host_name": host, "_timestamp": _kst_us("2026-10-23 09:00:00") + at * 1_000_000,
            "body": UNIT_BODY % (kind, unit, res)}


def _stopped_rows(desired, *events, now=1500):
    """알림 SQL을 합성 행에 돌린다. `now`는 기준 시각(0초)에서 평가 시각까지의 초(기본 25분 — 0초의 중지는 유예를 넘긴 상태)."""
    return _run_alert_on_sqlite(_sql(desired, STOPPED), list(events), stream="security_logs",
                                now_us=_kst_us("2026-10-23 09:00:00") + now * 1_000_000)


@pytest.mark.parametrize("unit", ["fail2ban", "firewalld", "rsyslog"])
def test_a_stop_with_no_start_after_it_alerts_for_each_security_service(desired, unit):
    rows = _stopped_rows(desired, _unit_event("SERVICE_STOP", unit, 0))
    assert [(r["host_name"], r["unit"]) for r in rows] == [("ns0272", unit)]


def test_a_stop_followed_by_a_start_does_not_alert_and_the_restart_ordering_is_judged_per_unit(desired):
    restart = [_unit_event("SERVICE_STOP", "fail2ban", 0), _unit_event("SERVICE_START", "fail2ban", 2)]
    assert _stopped_rows(desired, *restart) == []
    reboot = [_unit_event("SERVICE_STOP", "rsyslog", 0), _unit_event("SERVICE_START", "rsyslog", 840)]   # 실로그의 재부팅: 약 14분 뒤 시작
    assert _stopped_rows(desired, *reboot) == []
    # 다른 unit의 시작은 이 unit의 중지를 풀지 않는다
    rows = _stopped_rows(desired, _unit_event("SERVICE_STOP", "fail2ban", 0), _unit_event("SERVICE_START", "firewalld", 5))
    assert [r["unit"] for r in rows] == ["fail2ban"]
    # 다른 호스트의 시작도 풀지 않는다
    rows = _stopped_rows(desired, _unit_event("SERVICE_STOP", "fail2ban", 0), _unit_event("SERVICE_START", "fail2ban", 5, host="ns0273"))
    assert [(r["host_name"], r["unit"]) for r in rows] == [("ns0272", "fail2ban")]
    # 시작이 먼저이고 중지가 나중이면(다시 멈춤) 울린다
    rows = _stopped_rows(desired, _unit_event("SERVICE_START", "fail2ban", 0), _unit_event("SERVICE_STOP", "fail2ban", 30))
    assert [r["unit"] for r in rows] == ["fail2ban"]


def test_a_stop_alerts_only_once_it_is_older_than_the_grace(desired):
    """유예(20분)는 행마다 SQL이 판정한다: 중지가 유예보다 오래돼야 행이 나온다."""
    stop = _unit_event("SERVICE_STOP", "fail2ban", 0)
    assert _stopped_rows(desired, stop, now=60) == [] and _stopped_rows(desired, stop, now=1199) == []
    assert [r["unit"] for r in _stopped_rows(desired, stop, now=1200)] == ["fail2ban"]


def test_hosts_rebooted_one_after_another_do_not_alert_for_the_one_that_just_stopped(desired):
    """A는 14분 만에 시작됐고 B는 방금(5분 전) 멈췄다 — 쿼리 전체가 아니라 행마다 유예를 판정하므로 B는 아직 울리지 않는다."""
    a = [_unit_event("SERVICE_STOP", "rsyslog", 0, host="ns0001"), _unit_event("SERVICE_START", "rsyslog", 840, host="ns0001")]
    b = [_unit_event("SERVICE_STOP", "rsyslog", 1200, host="ns0002")]     # 평가(1500초) 5분 전에 멈춤
    assert _stopped_rows(desired, *a, *b, now=1500) == []
    rows = _stopped_rows(desired, *a, *b, now=1200 + 1260)               # B가 21분째 멈춰 있음
    assert [(r["host_name"], r["unit"]) for r in rows] == [("ns0002", "rsyslog")]


def test_simultaneous_stops_alert_together_and_a_late_one_is_judged_by_its_own_grace(desired):
    both = [_unit_event("SERVICE_STOP", "fail2ban", 0, host="ns0001"), _unit_event("SERVICE_STOP", "firewalld", 0, host="ns0002")]
    assert _stopped_rows(desired, *both, now=600) == []
    assert sorted((r["host_name"], r["unit"]) for r in _stopped_rows(desired, *both, now=1500)) == [("ns0001", "fail2ban"), ("ns0002", "firewalld")]
    # 먼저 멈춘 A가 이미 울린 뒤에 멈춘 B도 자기 유예가 차면 같은 쿼리에서 행으로 나온다(재통지 간격 동안 막히는 시간은 짧게 둔다)
    late = [_unit_event("SERVICE_STOP", "fail2ban", 0, host="ns0001"), _unit_event("SERVICE_STOP", "fail2ban", 600, host="ns0002")]
    assert [r["host_name"] for r in _stopped_rows(desired, *late, now=1500)] == ["ns0001"]
    assert sorted(r["host_name"] for r in _stopped_rows(desired, *late, now=1800)) == ["ns0001", "ns0002"]


def test_the_row_shows_the_last_stop_time_not_the_range_of_earlier_stop_start_pairs(desired):
    events = [_unit_event("SERVICE_STOP", "fail2ban", 0), _unit_event("SERVICE_START", "fail2ban", 2),
              _unit_event("SERVICE_STOP", "fail2ban", 1800)]                       # 09:30:00에 다시 멈춤
    alert = desired.store["alert"][STOPPED]
    rows = _stopped_rows(desired, *events, now=3600)
    lines = [re.sub(r"\{(\w+)\}", lambda m: str(row[m.group(1)]), alert["row_template"]) for row in rows]
    assert lines == ["• ns0272: fail2ban 중지 · 10-23 09:30:00"]


def test_other_units_auditd_and_failed_records_do_not_alert(desired):
    for unit in ("sshd", "auditd", "backup-audit-daily", "fail2ban-extra", "systemd-journald"):
        assert _stopped_rows(desired, _unit_event("SERVICE_STOP", unit, 0)) == [], unit
    assert _stopped_rows(desired, _unit_event("SERVICE_STOP", "rsyslog", 0, res="failed")) == []   # 멈추지 못한 기록은 중지가 아니다
    # 시작에 실패한 기록은 시작이 아니다: 중지 뒤 시작 실패면 여전히 멈춰 있다
    rows = _stopped_rows(desired, _unit_event("SERVICE_STOP", "rsyslog", 0), _unit_event("SERVICE_START", "rsyslog", 1, res="failed"))
    assert [r["unit"] for r in rows] == ["rsyslog"]


def test_the_target_services_are_a_role_default_and_never_include_auditd(desired):
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert defaults["o2c_security_stop_services"] == ["fail2ban", "firewalld", "rsyslog"]
    assert "auditd" not in defaults["o2c_security_stop_services"] and "auditd" not in _sql(desired, STOPPED)


def test_the_grace_covers_the_longest_logged_reboot_gap_and_is_judged_per_row_not_by_pending(desired):
    """N은 실로그 재부팅 중지→시작 최장 약 14분보다 길다. 유예는 SQL이 행마다 판정하므로 알림 pending은 0이고, 조회 구간은 유예보다 길다."""
    a = desired.store["alert"][STOPPED]
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    grace = defaults["o2c_security_stop_grace_minutes"]
    assert grace > 14 and a["pending_period_sec"] == 0 and a["trigger_condition"]["period"] > grace
    assert a["trigger_condition"]["silence"] == defaults["o2c_security_stop_renotify_minutes"] < grace
    assert a["context_attributes"]["severity"] == "P1 긴급"


def test_the_grace_variable_reaches_the_sql(tmp_path):
    rendered = render_desired(tmp_path / "desired.json", extra={"o2c_security_stop_grace_minutes": 30, "o2c_security_stop_window_minutes": 90})
    sql = next(o["body"]["query_condition"]["sql"] for o in rendered if o["kind"] == "alert" and o["name"] == STOPPED)
    stop = _unit_event("SERVICE_STOP", "fail2ban", 0)
    now = lambda seconds: _kst_us("2026-10-23 09:00:00") + seconds * 1_000_000
    assert _run_alert_on_sqlite(sql, [stop], "security_logs", now_us=now(1799)) == []
    assert len(_run_alert_on_sqlite(sql, [stop], "security_logs", now_us=now(1800))) == 1


def _role_defaults():
    return yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))


def test_the_window_keeps_a_long_outage_alerting_for_a_day_so_silence_is_not_mistaken_for_recovery(desired):
    """조회 구간이 1시간이던 때는 40분 뒤 알림이 조용해져 복구 신호와 구별되지 않았다(사용자 이야기 13). 기본 구간은 24시간이다."""
    defaults = _role_defaults()
    window = defaults["o2c_security_stop_window_minutes"]
    assert window == 1440 and desired.store["alert"][STOPPED]["trigger_condition"]["period"] == window
    stop = _unit_event("SERVICE_STOP", "fail2ban", 0)
    for hours in (2, 12, 23):   # 중지 기록이 구간 안에 있는 한 SQL은 계속 행을 낸다
        assert [r["unit"] for r in _stopped_rows(desired, stop, now=hours * 3600)] == ["fail2ban"], hours


def test_a_longer_window_adds_no_false_positive_for_stops_that_were_followed_by_a_start(desired):
    """HAVING이 마지막 중지 > 마지막 시작으로 판정하므로 구간이 길어져도 시작이 따라온 중지는 행이 되지 않는다."""
    pairs = []
    for unit in ("fail2ban", "firewalld", "rsyslog"):
        for at in (0, 7200, 36000):   # 하루 동안 흩어진 재시작·재부팅 쌍(0초·14분 간격)
            pairs += [_unit_event("SERVICE_STOP", unit, at), _unit_event("SERVICE_START", unit, at + (2 if at != 7200 else 840))]
    assert _stopped_rows(desired, *pairs, now=23 * 3600) == []
    # 오래전 중지가 있어도 나중 시작이 있으면 조용하다. 시작이 오래됐어도 그 뒤 중지가 없으면 마찬가지다
    assert _stopped_rows(desired, _unit_event("SERVICE_STOP", "rsyslog", 0), _unit_event("SERVICE_START", "rsyslog", 60), now=23 * 3600) == []


def test_the_evaluation_frequency_is_a_role_default_not_every_minute_because_the_window_is_a_day(desired):
    """24시간 구간의 평가 한 번은 audit·인증 로그 수천만 건을 훑는다(스캔 비용은 명세). 5분마다 돌리고 재통지 간격 이하로만 둘 수 있다."""
    defaults = _role_defaults()
    assert defaults["o2c_security_stop_frequency_minutes"] == 5
    trigger = desired.store["alert"][STOPPED]["trigger_condition"]
    assert trigger["frequency"] == 5 and trigger["frequency"] <= trigger["silence"]


def test_the_persistence_policy_scan_cost_and_the_quiet_after_a_day_are_written_down(desired):
    text = (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
    comment = text.split("o2c_security_stop_services:")[0].rsplit("\n\n", 1)[-1]
    spec = (ROOT_DIR / "docs" / "openobserve_config.md").read_text(encoding="utf-8")
    runbook = RUNBOOK.read_text(encoding="utf-8")
    for where, doc in (("comment", comment), ("spec", spec), ("runbook", runbook)):
        for token in ("지속 정책", "24시간", "142"):   # 142 = (1440 - 20) / 10: 한 번의 중지가 낼 수 있는 통지 상한
            assert token in doc, (where, token)
    for token in ("스캔 비용", "3.4초", "복구가 아니다"):
        assert token in spec, token
    assert "복구가 아니다" in runbook and "systemctl status" in runbook


def test_the_new_user_alert_documents_that_long_gap_accounts_alert_every_time_and_the_verify_wait_fits_its_window():
    spec = (ROOT_DIR / "docs" / "openobserve_config.md").read_text(encoding="utf-8")
    runbook = RUNBOOK.read_text(encoding="utf-8")
    for where, doc in (("spec", spec), ("runbook", runbook)):
        for token in ("5일 넘게 쉬었다", "월간·주간"):
            assert token in doc, (where, token)
    assert "o2c_verify_retries" in spec and "o2c_verify_delay" in spec
    defaults = _role_defaults()
    # 합성 로그인의 나이(검증이 기다리는 최대 시간)는 알림의 평가 구간 안에 있다
    assert defaults["o2c_verify_retries"] * defaults["o2c_verify_delay"] < defaults["o2c_ssh_new_user_window_minutes"] * 60


def test_the_grace_rationale_scope_and_everyday_false_positives_are_written_down(desired):
    text = (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
    comment = text.split("o2c_security_stop_services:")[0].rsplit("\n\n", 1)[-1]
    spec = (ROOT_DIR / "docs" / "openobserve_config.md").read_text(encoding="utf-8")
    runbook = RUNBOOK.read_text(encoding="utf-8")
    for token in ("14분", "rsyslog", "재부팅"):
        assert token in comment and token in spec, token
    # 대상 범위가 sudo 보호 목록보다 좁은 의도(systemd-journald·otelcol-contrib)를 명세·런북에 적는다
    for token in ("systemd-journald", "otelcol-contrib"):
        assert token in spec and token in runbook, token
    # sudo 위험 명령의 일상 오탐 가능성: 변수 주석(위험 명령 목록 위)과 런북
    risky_comment = text.split("o2c_sudo_risky_commands:")[0].rsplit("\n\n", 1)[-1]
    for token in ("chattr +a", "journalctl --vacuum", "journalctl --rotate"):
        assert token in risky_comment and token in runbook, token
    # 실로그에서 확인한 unit 필드 형식(.service 접미 없음, 이름 뒤 공백)을 주석에 남긴다
    assert ".service" in comment and "공백" in comment


def test_sudo_that_clears_logs_flips_immutable_bits_or_stops_fail2ban_alerts_but_history_clear_no_longer_does(desired):
    sql = _sql(desired, "infra-sudo-risky-command")

    def fires(cmd):
        rec = dict(event_action="sudo", event_outcome="success", user_name="alice", process_command_line=cmd, host_name="ns0272")
        return bool(_run_alert_on_sqlite(sql, [rec], stream="security_logs"))

    for cmd in ("/usr/bin/journalctl --vacuum-time=1d", "/usr/bin/journalctl --rotate", "/usr/bin/chattr -i /var/log/secure",
                "/usr/bin/chattr +a /var/log/secure", "/bin/systemctl stop fail2ban", "/bin/systemctl disable --now fail2ban"):
        assert fires(cmd), cmd
    for cmd in ("history -c", "/bin/systemctl restart fail2ban", "/usr/bin/journalctl -u fail2ban --since today", "/usr/bin/lsattr /var/log"):
        assert not fires(cmd), cmd


@pytest.mark.parametrize("group", ["disk", "shadow", "wheel"])
def test_adding_a_user_to_disk_or_shadow_is_shown_as_a_privileged_group_change(desired, group):
    body = ("type=USER_MGMT msg=audit(1792628133.696:49104): pid=2510319 uid=0 auid=1002 ses=313 subj=kernel msg='op=add-user-to-group "
            f"grp=\"{group}\" acct=\"opsverify\" exe=\"/usr/sbin/usermod\" hostname=? addr=? terminal=? res=success' UID=\"root\" AUID=\"opsverify\"")
    rows = _run_alert_on_sqlite(_sql(desired, "infra-account-change"), [dict(service_name="audit", host_name="ns0272", body=body)], stream="security_logs")
    assert [r["change_kind"] for r in rows] == ["특권 그룹 변경"]


def test_a_group_that_is_not_privileged_stays_a_plain_attribute_change(desired):
    body = ("type=USER_MGMT msg=audit(1792628133.696:49104): pid=2510319 uid=0 auid=1002 ses=313 subj=kernel msg='op=add-user-to-group "
            "grp=\"video\" acct=\"opsverify\" exe=\"/usr/sbin/usermod\" hostname=? addr=? terminal=? res=success' UID=\"root\" AUID=\"opsverify\"")
    rows = _run_alert_on_sqlite(_sql(desired, "infra-account-change"), [dict(service_name="audit", host_name="ns0272", body=body)], stream="security_logs")
    assert [r["change_kind"] for r in rows] == ["계정·그룹 속성 변경"]


def test_the_defaults_list_the_new_privileged_groups_and_protected_service_and_drop_history_clear():
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert {"disk", "shadow"} <= set(defaults["o2c_privileged_groups"]) and "fail2ban" in defaults["o2c_sudo_protected_services"]
    patterns = [p for c in defaults["o2c_sudo_risky_commands"] for p in c["patterns"]]
    assert "history -c" not in patterns and {"journalctl --vacuum", "journalctl --rotate", "chattr"} <= set(patterns)


def _su_audit_named(ts, uid, auid, name):
    rec = _su_audit(ts, uid=uid, auid=auid)
    return dict(rec, body=rec["body"] + '\x1dUID="root" AUID="%s"' % name)


def test_when_the_su_runner_uid_is_zero_people_are_told_apart_by_logname_and_auid_not_lumped_into_uid_0(desired):
    """`sudo su -` 뒤의 su는 secure·audit 모두 uid가 0이다. 그때는 secure의 logname, audit의 auid(또는 AUID 이름)로 사람을 가른다."""
    recs = ([_su_secure("2026-10-23 08:59:%02d" % n, user="alice", uid=0) for n in (1, 2, 3)]
            + [_su_audit("2026-10-23 08:59:%02d" % n, uid=0, auid=1001) for n in (4, 5, 6)])
    rows = _row_lines(desired, ESCALATION, recs, "security_logs")
    assert sorted(rows) == ["• ns0272 / 사용자 alice: 실패 3회 · 10-23 08:59:01~08:59:03", "• ns0272 / 사용자 auid 1001: 실패 3회 · 10-23 08:59:04~08:59:06"]


def test_uid_zero_secure_and_enriched_audit_of_the_same_person_count_once_and_two_people_stay_two_rows(desired):
    same = ([_su_secure("2026-10-23 08:59:%02d" % n, user="alice", uid=0) for n in (1, 2, 3)]
            + [_su_audit_named("2026-10-23 08:59:%02d" % n, 0, 1000, "alice") for n in (1, 2, 3)])
    assert _row_lines(desired, ESCALATION, same, "security_logs") == ["• ns0272 / 사용자 alice: 실패 3회 · 10-23 08:59:01~08:59:03"]
    two = [_su_secure("2026-10-23 08:59:01", user="alice", uid=0), _su_secure("2026-10-23 08:59:02", user="alice", uid=0), _su_secure("2026-10-23 08:59:03", user="bob", uid=0)]
    assert sorted(r.split(" · ")[0] for r in _row_lines(desired, ESCALATION, two, "security_logs")) == ["• ns0272 / 사용자 alice: 실패 2회", "• ns0272 / 사용자 bob: 실패 1회"]


def test_a_su_line_whose_uid_cannot_be_read_falls_back_to_the_user_name_or_unknown_never_to_the_log_text(desired):
    odd_secure = dict(_su_secure("2026-10-23 08:59:01", user="alice"), body="su: pam_unix(su:auth): authentication failure; uid= euid=0 ruser=alice")
    odd_audit = dict(_su_audit("2026-10-23 08:59:02"), body='type=USER_AUTH msg=audit(1.1:2): msg=\'op=PAM:authentication acct="root" exe="/usr/bin/su" res=failed\'')
    rows = _row_lines(desired, ESCALATION, [odd_secure, odd_audit], "security_logs")
    assert sorted(r.split(" · ")[0] for r in rows) == ["• ns0272 / 사용자 alice: 실패 1회", "• ns0272 / 사용자 unknown: 실패 1회"]
    assert not any("type=USER_AUTH" in r or "pam_unix" in r for r in rows)
