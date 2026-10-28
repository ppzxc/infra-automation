"""알림 정의 렌더링·SQL 검사에서 `test_openobserve_config`와 `test_openobserve_render`가 함께 쓰는 상수·헬퍼(#348).

렌더 테스트 모듈이 config 테스트 모듈을 import하지 않도록 여기로 옮겼다. ansible-playbook을 실행하는 helper는 두지 않는다.
"""
import base64
import hashlib
import importlib.util
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import yaml

from o2c_render import ROOT_DIR

sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))   # `from openobserve_config import ...`를 쓰는 테스트가 이 모듈만 import해도 되게 한다
ROLE = ROOT_DIR / "roles" / "openobserve_config"

EXPECTED_ALERTS = {
    "infra-ssh-login-failures-per-source", "infra-ssh-login-failures-per-host", "infra-root-login-success",
    "infra-root-login-known", "infra-sudo-escalation-failure", "infra-oom-kill", "infra-disk-fs-errors",
    "infra-log-parse-errors-security-logs", "infra-log-parse-errors-system-logs",
    "infra-disk-usage-p2", "infra-disk-usage-p1", "infra-inode-usage-p2", "infra-inode-usage-p1",
    "infra-memory-usage-p2", "infra-memory-usage-p1",
    "infra-silent-host-p2", "infra-silent-host-p1", "infra-unreachable-host",
    "infra-auth-silent-p2", "infra-auth-silent-p1",   # 인증 로그 수집 중단(#390)
    "infra-backup-failure", "infra-integrity-check-failure", "infra-backup-missing", "infra-maintenance-missing",
    "infra-app-log-errors", "infra-app-telemetry-silent", "infra-keepalived-script-disabled",
    "infra-switch-config-change", "infra-switch-login-failures", "infra-switch-severity-critical",
    "infra-switch-mac-flap", "infra-switch-syslog-silent",   # 스위치 syslog(Spec #277)
    "infra-fortigate-admin-login-failures", "infra-fortigate-change-unapproved", "infra-fortigate-change-approved",
    "infra-fortigate-ha-failover", "infra-fortigate-critical-detection", "infra-fortigate-syslog-silent",   # 방화벽(Spec #282 / Ticket-3)
    "infra-ssh-bruteforce-success", "infra-account-change", "infra-sudo-risky-command", "infra-auditd-stopped",
    "infra-account-lockout",   # 보안 로그 알림(#318)
    "infra-raid-write-cache-disabled", "infra-raid-controller-fault", "infra-raid-logical-drive-degraded",
    "infra-raid-physical-drive-fault", "infra-raid-cache-battery-fault", "infra-raid-collection-error",
    "infra-host-status-silent",   # RAID 상태(#335)
    "infra-time-offset-exceeded", "infra-time-unsynced", "infra-time-sync-unavailable",   # 시각 동기(#336)
    "infra-audit-watch-change", "infra-ssh-login-unregistered-source", "infra-root-crontab-change",
    "infra-fortigate-admin-login-new-source",   # 남은 보안 로그 알림(#330)
}

PROMQL_ALERTS = {
    "infra-cpu-usage-p1": ("P2 경고", 5, 5, 60, ">=", 90, "system_cpu_utilization", 15),
    "infra-cpu-usage-p2": ("P3 주의", 5, 5, 1440, ">=", 0, "system_cpu_utilization", 15),
    "infra-caddy-5xx-error-rate": ("P1 긴급", 10, 5, 60, ">=", 5, "caddy_http_request_duration_seconds_count", 0),
    "infra-caddy-4xx-error-rate": ("P3 주의", 10, 5, 1440, ">=", 5, "caddy_http_request_duration_seconds_count", 0),
    "infra-disk-fill-24h": ("P2 경고", 30, 30, 1440, ">=", 0, "system_filesystem_usage", 60),
    "infra-disk-fill-4h": ("P1 긴급", 10, 10, 60, ">=", 0, "system_filesystem_usage", 60),
    "infra-network-errors": ("P2 경고", 5, 5, 60, ">=", 0, "system_network_errors", 60),
    "infra-cpu-load-saturation": ("P2 경고", 5, 5, 60, ">=", 0, "system_cpu_load_average_1m", 15),
    "infra-cpu-iowait": ("P3 주의", 5, 5, 1440, ">", 10, "system_cpu_utilization", 15),
    "infra-cpu-steal": ("P3 주의", 5, 5, 1440, ">", 10, "system_cpu_utilization", 30),
    "infra-disk-io-saturation": ("P2 경고", 5, 5, 60, ">", 10, "system_disk_weighted_io_time", 30),
    "infra-disk-read-latency": ("P2 경고", 5, 5, 60, ">", 100, "system_disk_operation_time", 30),
    "infra-disk-write-latency": ("P2 경고", 5, 5, 60, ">", 100, "system_disk_operation_time", 30),
    "infra-inode-fill-24h": ("P2 경고", 30, 30, 1440, ">=", 0, "system_filesystem_inodes_usage", 60),
    "infra-conntrack-limit": ("P2 경고", 5, 5, 60, ">", 80, "system_network_conntrack_count", 0),
    "infra-swap-usage": ("P3 주의", 10, 5, 1440, ">", 80, "system_paging_utilization", 0),
    "infra-memory-pressure": ("P2 경고", 5, 5, 60, ">", 1000, "system_paging_faults", 15),
}

RESOURCE_ALERTS = {  # name -> (severity, silence minutes, period minutes, stream)
    "infra-disk-usage-p2": ("P2 경고", 1440, 15, "system_filesystem_usage"),
    "infra-disk-usage-p1": ("P1 긴급", 60, 15, "system_filesystem_usage"),
    "infra-inode-usage-p2": ("P2 경고", 1440, 15, "system_filesystem_inodes_usage"),
    "infra-inode-usage-p1": ("P1 긴급", 60, 15, "system_filesystem_inodes_usage"),
    "infra-memory-usage-p2": ("P2 경고", 1440, 10, "system_linux_memory_available"),
    "infra-memory-usage-p1": ("P1 긴급", 60, 10, "system_linux_memory_available"),
}

SELFTEST = "infra-alert-selftest"   # 통지 경로 자가 시험 알림(Spec #184 / Ticket-2) — 검증 전용 스트림에 건다

RUNBOOK = ROOT_DIR / "docs" / "runbooks" / "alerts.md"

PROMQL_ROW_FIELDS = {"value", "host_name", "device", "mountpoint", "direction"}   # PromQL 행 템플릿이 쓸 수 있는 값(숫자 value와 안전한 레이블)

FIXTURES = yaml.safe_load((ROLE / "files" / "alert_fixtures.yml").read_text(encoding="utf-8"))

def _sql(o2, name):
    return o2.store["alert"][name]["query_condition"]["sql"]

MEM_ALERTS = ("infra-memory-usage-p2", "infra-memory-usage-p1")

def _run_memory_alert_on_sqlite(sql, case):
    """Execute the rendered alert SQL on the case's synthetic records (portable SQL subset) and return the firing hosts."""
    db = sqlite3.connect(":memory:")
    for stream in ("system_linux_memory_available", "system_memory_limit"):
        db.execute(f'CREATE TABLE "{stream}" (host_name TEXT, _timestamp INTEGER, value INTEGER)')   # 합성 레코드는 정수로 적재된다(나눗셈이 잘리면 안 된다)
    for rec in case["records"]:
        stream = rec.get("stream", "system_linux_memory_available")
        for t in (rec["ts"] if isinstance(rec["ts"], list) else [rec["ts"]]):
            db.execute(f'INSERT INTO "{stream}" VALUES (?, ?, ?)', (case["host"], t, rec["value"]))
    return {r[0] for r in db.execute(sql)}

SWITCH_ALERTS = {   # name -> (severity, period minutes, silence minutes)
    "infra-switch-config-change": ("P2 경고", 5, 5),
    "infra-switch-login-failures": ("P2 경고", 5, 5),
    "infra-switch-severity-critical": ("P1 긴급", 5, 5),
    "infra-switch-mac-flap": ("P2 경고", 10, 60),
    "infra-switch-syslog-silent": ("P2 경고", 1440, 1440),
}

SWITCH_FN = "switch_syslog_semantics"

FORTIGATE_FN = "fortigate_semantics"

def _branch_devices(sql):
    return set(re.findall(r"SELECT '([^']+)' AS device_id", sql))

def _date_format(value, fmt, offset):
    """sqlite stand-in for OpenObserve's ``date_format(<µs or s>, <strftime format>, '+HH:MM')`` (same contract, independent of the SQL under test)."""
    if value is None:
        return None
    seconds = value / 1_000_000 if abs(value) >= 10**11 else value   # 10^11 s is year 5138, so a larger number is microseconds
    sign = -1 if offset[0] == "-" else 1
    hours, minutes = offset[1:].split(":")
    tz = timezone(sign * timedelta(hours=int(hours), minutes=int(minutes)))
    return datetime.fromtimestamp(seconds, tz).strftime(fmt)

def _run_alert_on_sqlite(sql, records, stream="system_logs_alert_verify"):
    """Run a verification search on the injected synthetic records (portable SQL subset + regexp_replace) and return the rows."""
    db = sqlite3.connect(":memory:")
    db.create_function("regexp_replace", 3, lambda text, pattern, repl: re.sub(pattern, repl, text) if text is not None else None)
    db.create_function("date_format", 3, _date_format)
    records = [dict({"_timestamp": 1_792_767_302_000_000}, **r) for r in records]   # OpenObserve stamps every record on ingest
    columns = sorted({k for r in records for k in r})
    db.execute('CREATE TABLE "%s" (%s)' % (stream, ", ".join(f'"{c}"' for c in columns)))
    for r in records:
        db.execute('INSERT INTO "%s" VALUES (%s)' % (stream, ", ".join("?" * len(columns))), [r.get(c) for c in columns])
    cur = db.execute(sql)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, row)) for row in cur.fetchall()]

FORTIGATE_ALERTS = {   # name -> (severity, period minutes, silence minutes)
    "infra-fortigate-admin-login-failures": ("P2 경고", 5, 30),
    "infra-fortigate-change-unapproved": ("P1 긴급", 5, 5),
    "infra-fortigate-change-approved": ("P3 주의", 1440, 1440),
    "infra-fortigate-ha-failover": ("P2 경고", 5, 30),
    "infra-fortigate-critical-detection": ("P1 긴급", 5, 60),
    "infra-fortigate-syslog-silent": ("P2 경고", 30, 1440),
    "infra-fortigate-admin-login-new-source": ("P2 경고", 5, 60),   # #330
}

DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))

PROMQL_DEFS = [a for a in DEFAULTS["o2c_alerts"] if a.get("promql")]

def _filters():
    import importlib.util
    spec = importlib.util.spec_from_file_location("o2c_filters", ROOT_DIR / "filter_plugins" / "openobserve_config.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def _decode_raw_url(url):
    from urllib.parse import parse_qs, urlsplit
    parts = urlsplit(url)
    qs = parse_qs(parts.query)
    return parts.path, {k: v[0] for k, v in qs.items()}, base64.b64decode(qs["query"][0]).decode("utf-8")

def _raw_line(alert):
    return alert["context_attributes"]["raw_log_line"]

def _raw_url(alert):
    """통지 본문에 실린 원문 로그 링크(단축 URL)."""
    line = _raw_line(alert)
    assert line.startswith("▶ 로그 보기: "), line
    return line.split(": ", 1)[1]

def _raw_original(o2, alert):
    """단축 URL이 가리키는 원본(`/web/logs?...`). Config가 서버에 등록했어야 찾을 수 있다."""
    m = re.fullmatch(r"(.+)/web/short/([0-9a-f]{16})\?org_identifier=default", _raw_url(alert))
    assert m and m.group(2) in o2.shorts, _raw_url(alert)
    original = o2.shorts[m.group(2)]
    assert hashlib.md5(original.encode()).hexdigest()[8:24] == m.group(2)
    return original

SECURITY_ALERTS = {   # name -> (severity, period, silence, pending minutes, marker only its search carries)
    "infra-ssh-bruteforce-success": ("P1 긴급", 15, 15, 0, "event_outcome IN ('failure', 'success')"),
    "infra-account-change": ("P2 경고", 5, 5, 0, "type=ADD_USER"),
    "infra-sudo-risky-command": ("P1 긴급", 5, 5, 0, "process_command_line"),
    "infra-auditd-stopped": ("P1 긴급", 10, 10, 2, "type=DAEMON_START"),
    "infra-account-lockout": ("P2 경고", 5, 5, 0, "account temporarily locked"),
    "infra-audit-watch-change": ("P2 경고", 5, 5, 0, 'key="identity"'),                              # 남은 보안 로그 알림(#330)
    "infra-ssh-login-unregistered-source": ("P2 경고", 5, 60, 0, "user_name <> 'root'"),
}

RAID_ALERTS = {   # alert -> a fragment only its search carries
    "infra-raid-write-cache-disabled": "kind = 'controller'\nAND (cache_status",
    "infra-raid-controller-fault": "kind = 'controller' AND hw_state <> 'ok'",
    "infra-raid-logical-drive-degraded": "kind = 'logical_drive'",
    "infra-raid-physical-drive-fault": "kind = 'physical_drive'",
    "infra-raid-cache-battery-fault": "kind = 'cache_battery'",
    "infra-raid-collection-error": "status IN ('timeout', 'error')",
    "infra-host-status-silent": "UNION ALL",
}

TIME_ALERTS = {   # alert -> (period, frequency, a fragment only its search carries)
    "infra-time-offset-exceeded": (15, 5, "abs(offset_ms) > 1000"),
    "infra-time-unsynced": (35, 5, "sync_status = 'unsynced'"),
    "infra-time-sync-unavailable": (15, 5, "sync_status IN ('no_tool', 'error')"),
}

def _kst_us(text):
    """'2026-10-23 08:55:02' (KST) -> µs since the epoch."""
    return int(datetime.fromisoformat(text).replace(tzinfo=timezone(timedelta(hours=9))).timestamp()) * 1_000_000

def _row_lines(o2, name, records, stream):
    """What an operator reads: the alert's row template filled with every row its SQL returns on the records."""
    alert = o2.store["alert"][name]
    rows = _run_alert_on_sqlite(alert["query_condition"]["sql"], records, stream)
    return [re.sub(r"\{(\w+)\}", lambda m: str(row[m.group(1)]), alert["row_template"]) for row in rows]

def _fail(ts, source="203.0.113.10", host="ns0272"):
    return {"event_action": "ssh_login", "event_outcome": "failure", "user_name": "admin", "source_address": source,
            "host_name": host, "_timestamp": _kst_us(ts)}

def _rendered_message(o2, name, row_values):
    """The notification text with 30 rows filled the way OpenObserve does (every variable replaced)."""
    alert = o2.store["alert"][name]
    ctx = alert["context_attributes"]
    text = o2.store["template"]["infra-automation-plain"]["body"]
    rows = "\n".join(re.sub(r"\{(\w+)\}", lambda m: row_values[m.group(1)], alert["row_template"]) for _ in range(30))
    values = dict(ctx, rows=rows, alert_count="30", alert_url="https://o2.example.test/web/short/0123456789abcdef?org_identifier=default",
                  alert_trigger_time_str="2026-10-23T09:00:56", alert_name=name)
    text = text.replace("{rows:30}", "{rows}")
    return re.sub(r"\{(\w+)\}", lambda m: values.get(m.group(1), m.group(0)), text)

LONGEST_ROW_VALUES = {"source_address": "198.51.100.255", "host_name": "ns0272", "host_label": "ns0272 (198.51.100.255)",
                      "failures": "9999", "event_time": "10-23 23:58:00~10-24 00:02:30", "sources": "999"}

COUNT_FIELDS = ("logins", "successes", "changes", "runs", "stops", "locks", "total", "parse_errors", "kills", "matches", "errors",
                "readings", "events", "detections", "downs", "flaps", "severity_code", "offset_ms")

LONGEST_TEXT = {"user_name": "u" * 32, "actor": "u" * 32, "command_kind": "가" * 14, "change_kind": "가" * 9,   # 계정 이름 32자(리눅스 한계), 알림이 정한 짧은 라벨
                "container_name": "c" * 32, "cache_status": "permanently_disabled", "cache_reason": "r" * 30, "raw_state": "Predictive Failure",
                "status": "timeout", "tool": "timedatectl", "sync_status": "unsynced", "tcpcheck_endpoint": "198.51.100.255:65535", "killed_process": "p" * 15, "cfgpath": "firewall.policy.sub", "admin": "a" * 32, "attack": "a" * 40, "event": "e" * 35, "hw_name": "h" * 24, "device": "ns0380+ns0381", "port": "GigabitEthernet1/0/48"}

TEXT_VALUE = "x" * 40   # 그 밖의 자유 문장 필드(명령·경로·이벤트 이름 등)의 현실적으로 긴 값

def _ev(ts, **fields):
    return dict({"host_name": "ns0272", "_timestamp": _kst_us(ts)}, **fields)

SECURITY_TIME_CASES = {   # alert -> (record fields, expected row without the time)
    "infra-ssh-login-failures-per-host": (
        [dict(event_action="ssh_login", event_outcome="failure", source_address=f"203.0.113.{n}") for n in (1, 2, 3)] * 17,
        "• ns0272: 실패 51회 (출발지 3곳)"),
    "infra-root-login-success": (
        [dict(event_action="ssh_login", event_outcome="success", user_name="root", source_address="198.51.100.7")],
        "• ns0272 ← 198.51.100.7 (1회)"),
    "infra-sudo-escalation-failure": (
        [dict(event_action="sudo", event_outcome="failure", user_name="alice")], "• ns0272 / 사용자 alice: 실패 1회"),
    "infra-account-lockout": (
        [dict(body="pam_faillock(sshd:auth): Account temporarily locked")], "• ns0272: 잠금 기록 1건"),
}

SYSTEM_TIME_CASES = {   # alert -> (stream, record fields, expected row without the time; "{n}" is the record count)
    "infra-oom-kill": ("system_logs", [dict(process_executable_name="kernel", body="Out of memory: Killed process 123 (java) total-vm:1kB")],
                       "• ns0272: 종료된 프로세스 java ({n}건)"),
    "infra-disk-fs-errors": ("system_logs", [dict(body="blk_update_request: I/O error, dev sda")], "• ns0272: 오류 패턴 {n}건"),
    "infra-app-log-errors": ("app_logs", [dict(severity="error", container_name="api")], "• ns0272 / api: ERROR 이상 {n}건"),
    "infra-backup-failure": ("backup_logs", [dict(job="backup", success=False, host="ns0272")], "• ns0272: 실패 {n}건"),
    "infra-raid-collection-error": ("host_status_logs", [dict(kind="tool_status", status="error", message="m")] * 3,
                                    "• ns0272: error {n}회 (m)"),
    "infra-time-offset-exceeded": ("host_status_logs", [dict(kind="time_sync", tool="chronyc", sync_status="synced", offset_ms=-2350.0)] * 2,
                                   "• ns0272: 시계 오차 최대 2350ms (chronyc, {n}회 판독)"),
    "infra-time-unsynced": ("host_status_logs", [dict(kind="time_sync", tool="ntpq", sync_status="unsynced", message="ntpq not answering")] * 6,
                            "• ns0272: 동기 안 됨 {n}회 연속 (ntpq not answering)"),
    "infra-time-sync-unavailable": ("host_status_logs", [dict(kind="time_sync", tool="none", sync_status="no_tool", message="")] * 2,
                                    "• ns0272: no_tool {n}회 (none)"),
    "infra-unreachable-host": ("tcpcheck_status", [dict(tcpcheck_endpoint="198.51.100.5:22", value=0)],
                               "• 198.51.100.5:22 (검사: ns0272)"),
}

def _fixture_records(name, host_value="ns0272"):
    """The records of the first firing fixture case with the fake host replaced by one device name (repeat expanded)."""
    case = next(c for c in FIXTURES[name]["cases"] if c["fires"] and not c.get("watch_port"))
    field = FIXTURES[name].get("host_field", "host_name")
    out = []
    for rec in case["records"]:
        rec = dict(rec)
        omit = rec.pop("omit_host_field", False)
        rec.pop("ts", None)
        if isinstance(rec.get("body"), str):
            rec["body"] = rec["body"].replace("{host}", host_value)
        if not omit:
            rec[field] = host_value
        out += [dict(rec) for _ in range(rec.pop("repeat", 1))] if "repeat" in rec else [rec]
    return out

DEVICE_TIME_ALERTS = {
    "infra-switch-config-change": "system_logs", "infra-switch-login-failures": "system_logs",
    "infra-switch-severity-critical": "system_logs", "infra-switch-mac-flap": "system_logs",
    "infra-fortigate-admin-login-failures": "security_logs", "infra-fortigate-change-unapproved": "security_logs",
    "infra-fortigate-change-approved": "security_logs", "infra-fortigate-ha-failover": "security_logs",
    "infra-fortigate-critical-detection": "security_logs",
}

