"""Envelope Parsing (ADR-0008, Spec #93 / Ticket-1).

The rendered ``otelcol-contrib.yaml.j2`` is run through a real otelcol-contrib binary
(0.119.0 = legacy_el6, 0.161.0 = current) against golden log lines of each source, and the
``file`` exporter output is asserted: event time, attributes, severity, ``log.parse_error``,
the original body byte for byte, and that no line is dropped.

Set ``OTELCOL_BIN_0_119_0`` / ``OTELCOL_BIN_0_161_0`` to the binaries; each version's tests skip
without it. (Fetch them from the opentelemetry-collector-releases ``otelcol-contrib_<v>_linux_amd64.tar.gz``.)
"""

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_host_agents as base  # noqa: E402

VERSIONS = {"0.119.0": ("OTELCOL_BIN_0_119_0", "legacy_el6"), "0.161.0": ("OTELCOL_BIN_0_161_0", "modern")}

# severity numbers of the OTel log data model
INFO, INFO2, WARN, ERROR, FATAL, DEBUG, TRACE = 9, 10, 13, 17, 21, 5, 1

SYSLOG_OK = "Mar  5 10:11:12 host1 sshd[1234]: Accepted publickey for root from 10.0.0.1 port 22 ssh2"
SYSLOG_NOPID = "Jan  2 00:00:01 host1 kernel: [    0.000000] Linux version 5.14"
SYSLOG_BAD = ["garbage line without any format", "Foo 99 99:99:99 host1 sshd[1]: not a month", ""]
# (path inside the fake /var/log, [(line, expected), ...]); expected = attributes subset, severity, local time
CASES = {
    "messages": [
        (SYSLOG_OK, dict(attrs={"process.executable.name": "sshd", "process.pid": "1234",
                                "message": "Accepted publickey for root from 10.0.0.1 port 22 ssh2"},
                         local=(3, 5, 10, 11, 12), sev=0)),
        (SYSLOG_NOPID, dict(attrs={"process.executable.name": "kernel", "message": "[    0.000000] Linux version 5.14"},
                            absent=["process.pid"], local=(1, 2, 0, 0, 1), sev=0)),
        (SYSLOG_BAD[0], dict(attrs={"log.parse_error": True}, sev=0, observed=True)),
        (SYSLOG_BAD[1], dict(attrs={"log.parse_error": True}, sev=0, observed=True)),
    ],
    "audit/audit.log": [
        ('type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 success=yes exit=0 comm="ls" exe="/usr/bin/ls" key=(null)',
         dict(attrs={"audit.type": "SYSCALL", "audit.serial": "456",
                     "audit.fields": {"syscall": "59", "success": "yes", "comm": "ls", "exe": "/usr/bin/ls"}},
              epoch_ns=1700000000123000000, sev=0)),
        ("type=USER_AUTH msg=audit(1700000001.500:457): pid=1 uid=0 auid=1000",
         dict(attrs={"audit.type": "USER_AUTH", "audit.serial": "457", "audit.fields": {"uid": "0"}},
              epoch_ns=1700000001500000000, sev=0)),
        ("node=h type=SYSCALL not-the-audit-format", dict(attrs={"log.parse_error": True}, sev=0, observed=True)),
    ],
    "fail2ban.log": [
        ("2024-03-05 10:11:12,345 fail2ban.actions        [1234]: NOTICE  [sshd] Ban 1.2.3.4",
         dict(attrs={"component": "fail2ban.actions", "process.pid": "1234", "message": "[sshd] Ban 1.2.3.4"},
              local=(2024, 3, 5, 10, 11, 12), sev=INFO2)),
        ("2024-03-05 10:11:13,001 fail2ban.filter         [1234]: WARNING [sshd] Found 1.2.3.4",
         dict(attrs={"component": "fail2ban.filter"}, local=(2024, 3, 5, 10, 11, 13), sev=WARN)),
        ("2024-03-05 10:11:14,001 fail2ban.server         [1]: ERROR   boom", dict(attrs={}, sev=ERROR)),
        ("2024-03-05 10:11:15,001 fail2ban.server         [1]: CRITICAL boom", dict(attrs={}, sev=FATAL)),
        ("not a fail2ban line", dict(attrs={"log.parse_error": True}, sev=0, observed=True)),
    ],
    "dnf.log": [
        ("2024-03-05T10:11:12Z DEBUG DNF version: 4.14", dict(attrs={"message": "DNF version: 4.14"}, epoch_ns=1709633472000000000, sev=DEBUG)),
        ("2024-03-05T10:11:13+0900 INFO Installed: foo", dict(attrs={"message": "Installed: foo"}, epoch_ns=1709601073000000000, sev=INFO)),
        ("2024-03-05T10:11:14+0900 SUBDEBUG detail", dict(attrs={}, epoch_ns=1709601074000000000, sev=DEBUG)),
        ("continuation of a multi-line entry", dict(attrs={"log.parse_error": True}, sev=0, observed=True)),
    ],
    "yum.log": [
        ("Mar 05 10:11:12 Installed: foo-1.0-1.x86_64", dict(attrs={"message": "Installed: foo-1.0-1.x86_64"},
                                                           local=(3, 5, 10, 11, 12), sev=0)),
        ("junk", dict(attrs={"log.parse_error": True}, sev=0, observed=True)),
    ],
    "dpkg.log": [
        ("2024-03-05 10:11:12 status installed foo:amd64 1.0",
         dict(attrs={"dpkg.action": "status", "message": "installed foo:amd64 1.0"}, local=(2024, 3, 5, 10, 11, 12), sev=0)),
        ("junk", dict(attrs={"log.parse_error": True}, sev=0, observed=True)),
    ],
}
APP_LINES = ["Mar  5 10:11:12 host1 sshd[1234]: looks like syslog but is app output", "plain app line"]


def _binary(version):
    env = VERSIONS[version][0]
    path = os.environ.get(env)
    if not path or not Path(path).exists():
        pytest.skip(f"set {env} to an otelcol-contrib {version} binary")
    out = subprocess.run([path, "--version"], capture_output=True, text=True).stdout
    assert version in out, out
    return path


def _render(tmp_path, os_path, **over):
    over.setdefault("host_agents_os_path", os_path)
    over.setdefault("host_agents_inputs", {"otel_docker_metrics": False, "otel_logs": [
        {"path": "/var/log/secure", "stream": "security_logs", "service": "auth"},
        {"path": "/var/log/audit/audit.log", "stream": "security_logs", "service": "audit"},
        {"path": "/var/log/fail2ban.log", "stream": "security_logs", "service": "fail2ban"},
        {"path": "/var/log/messages", "stream": "system_logs", "service": "syslog"},
        {"path": "/var/log/dnf.log", "stream": "system_logs", "service": "package-manager"},
        {"path": "/var/log/yum.log", "stream": "system_logs", "service": "package-manager"},
        {"path": "/var/log/dpkg.log", "stream": "system_logs", "service": "package-manager"},
        {"path": "/var/log/app/*.log", "stream": "app_logs", "service": "app"}]})
    return base._render_config(tmp_path, **over)


def _harness(tmp_path, cfg, files):
    """Rewrite the rendered receivers to read fake files under tmp_path and export to a file."""
    root = tmp_path / "fake"
    for rel, lines in files.items():
        f = root / "var" / "log" / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    text = yaml.safe_dump({"receivers": {k: v for k, v in cfg["receivers"].items() if k.startswith("filelog/")}})
    text = text.replace("/var/log", str(root / "var" / "log"))
    receivers = yaml.safe_load(text)["receivers"]
    for name, rcv in receivers.items():
        rcv["start_at"] = "beginning"
        rcv.pop("storage", None)
        rcv.pop("retry_on_failure", None)
        if name == "filelog/backup_logs":
            rcv["include"] = []
    receivers.pop("filelog/backup_logs", None)
    out = tmp_path / "out.json"
    harness = {"receivers": receivers, "exporters": {"file": {"path": str(out)}},
               "service": {"pipelines": {"logs": {"receivers": list(receivers), "exporters": ["file"]}}}}
    cfg_path = tmp_path / "harness.yaml"
    cfg_path.write_text(yaml.safe_dump(harness))
    return cfg_path, out


def _anyval(v):
    key, val = next(iter(v.items()))
    if key == "kvlistValue":
        return {e["key"]: _anyval(e["value"]) for e in val["values"]}
    return val


def _run(binary, cfg_path, out, expected):
    proc = subprocess.Popen([binary, f"--config={cfg_path}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    records = []
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            time.sleep(0.5)
            records = _read(out)
            if len(records) >= expected:
                time.sleep(1.5)                      # catch any surplus record (a duplicate would fail the count)
                records = _read(out)
                break
    finally:
        proc.terminate()
        proc.wait(timeout=20)
    return records


def _read(out):
    if not out.exists():
        return []
    recs = []
    for line in out.read_text().splitlines():
        if not line.strip():
            continue
        try:
            doc = json.loads(line)
        except ValueError:                                  # the exporter is mid-write
            continue
        for rl in doc["resourceLogs"]:
            res = {a["key"]: _anyval(a["value"]) for a in rl["resource"].get("attributes", [])}
            for sl in rl["scopeLogs"]:
                for lr in sl["logRecords"]:
                    lr["_attrs"] = {a["key"]: _anyval(a["value"]) for a in lr.get("attributes", [])}
                    lr["_res"] = res
                    lr["_body"] = _anyval(lr["body"])
                    recs.append(lr)
    return recs


def _check(rec, line, exp, tz):
    attrs = rec["_attrs"]
    assert rec["_body"] == line, "body must be the untouched original line"
    for key, want in exp["attrs"].items():
        got = attrs.get(key)
        if isinstance(want, dict):
            assert isinstance(got, dict) and {k: got.get(k) for k in want} == want, (key, attrs)
        else:
            assert got == want, (key, attrs)
    for key in exp.get("absent", []):
        assert key not in attrs, (key, attrs)
    if "log.parse_error" not in exp["attrs"]:
        assert "log.parse_error" not in attrs, attrs
    for gone in ("ts", "hostname", "level", "epoch", "rest", "process_name", "process_pid", "audit_type", "audit_serial"):
        assert gone not in attrs, (gone, attrs)
    assert int(rec.get("severityNumber", 0)) == exp["sev"], rec
    ts = int(rec.get("timeUnixNano", 0))
    if exp.get("observed"):
        assert ts == 0, "no event time: the collector falls back to the observed time"
        assert int(rec["observedTimeUnixNano"]) > 0
    elif "epoch_ns" in exp:
        assert ts == exp["epoch_ns"]
    elif "local" not in exp:
        assert ts > 0
    else:
        local = datetime.fromtimestamp(ts / 1e9, ZoneInfo(tz))
        want = exp["local"][-5:]
        assert (local.month, local.day, local.hour, local.minute, local.second) == tuple(want)
        if len(exp["local"]) == 6:
            assert local.year == exp["local"][0]
        else:                                            # no year in the line: estimated, never in the future
            assert local <= datetime.now(ZoneInfo(tz))


@pytest.mark.parametrize("tz", ["Asia/Seoul", "America/New_York"])
@pytest.mark.parametrize("version", list(VERSIONS))
def test_real_collector_envelope_parses_every_source_and_keeps_every_line_and_body(tmp_path, version, tz):
    binary = _binary(version)
    cfg, _ = _render(tmp_path, VERSIONS[version][1], host_agents_timezone=tz)
    files = {rel: [ln for ln, _ in cases] for rel, cases in CASES.items()}
    files["secure"] = ["Mar  5 10:11:12 host1 sshd[1234]: Accepted publickey for root from 10.0.0.1 port 22 ssh2"]
    files["app/a.log"] = APP_LINES
    cfg_path, out = _harness(tmp_path, cfg, files)
    total = sum(len(v) for v in files.values())
    records = _run(binary, cfg_path, out, total)
    assert len(records) == total, "no line may be dropped or duplicated"

    by_file = {}
    for r in records:
        by_file.setdefault(r["_attrs"]["log.file.path"], []).append(r)
    root = tmp_path / "fake" / "var" / "log"
    for rel, cases in CASES.items():
        recs = by_file[str(root / rel)]
        assert [r["_body"] for r in recs] == [ln for ln, _ in cases]          # order and bytes
        for rec, (line, exp) in zip(recs, cases):
            _check(rec, line, exp, tz)
    secure = by_file[str(root / "secure")][0]
    assert secure["_attrs"]["process.executable.name"] == "sshd"
    # the file group still gets its service.name, and app_logs is left alone
    assert secure["_res"]["service.name"] == "auth"
    for rec, line in zip(by_file[str(root / "app" / "a.log")], APP_LINES):
        assert rec["_body"] == line
        assert {"process.executable.name", "log.parse_error", "message"}.isdisjoint(rec["_attrs"])
        assert int(rec.get("timeUnixNano", 0)) == 0 and int(rec.get("severityNumber", 0)) == 0


@pytest.mark.parametrize("version", list(VERSIONS))
def test_real_collector_validates_the_envelope_config(tmp_path, version):
    binary = _binary(version)
    cfg, _ = _render(tmp_path, VERSIONS[version][1])
    (tmp_path / "var" / "otelcol").mkdir(parents=True)
    rendered = tmp_path / "config.yaml"
    text = rendered.read_text().replace(base_storage_dir(), str(tmp_path / "var" / "otelcol"))
    doc = yaml.safe_load(text)
    # memory_limiter percentages need cgroup/mount info that some dev hosts (WSL) cannot provide
    doc["processors"]["memory_limiter"] = {"check_interval": "1s", "limit_mib": 400, "spike_limit_mib": 100}
    rendered.write_text(yaml.safe_dump(doc))
    res = subprocess.run([binary, "validate", f"--config={rendered}"], capture_output=True, text=True,
                         env=dict(os.environ, O2_BASIC_AUTH="dGVzdA=="))
    assert res.returncode == 0, res.stdout + res.stderr


def base_storage_dir():
    return yaml.safe_load((base.ROLE / "defaults" / "main.yml").read_text())["otelcol_storage_dir"]


@pytest.mark.skipif(not os.environ.get("OTELCOL_BIN_0_161_0"), reason="set OTELCOL_BIN_0_161_0")
def test_real_collector_journald_priority_becomes_severity_and_body_is_kept(tmp_path):
    """journald is modern-only (CentOS 6 has none); a fake journalctl feeds PRIORITY values."""
    binary = _binary("0.161.0")
    cfg, _ = _render(tmp_path, "modern", host_agents_journald=True)
    jrn = cfg["receivers"]["journald"]
    ops = [op for op in jrn["operators"] if op["type"] == "severity_parser"]
    assert len(ops) == 1
    fake = tmp_path / "bin"
    fake.mkdir()
    rows = [("0", FATAL), ("2", FATAL), ("3", ERROR), ("4", WARN), ("5", INFO2), ("6", INFO), ("7", DEBUG), (None, 0)]
    lines = []
    for i, (prio, _) in enumerate(rows):
        entry = {"MESSAGE": f"m{i}", "__CURSOR": f"c{i}", "__REALTIME_TIMESTAMP": str(1709601072000000 + i * 1000)}
        if prio is not None:
            entry["PRIORITY"] = prio
        lines.append(json.dumps(entry))
    script = fake / "journalctl"
    script.write_text("#!/bin/sh\ncat <<'EOF'\n" + "\n".join(lines) + "\nEOF\nsleep 60\n")
    script.chmod(0o755)
    harness = {"receivers": {"journald": {"start_at": "beginning", "operators": jrn["operators"]}},
               "exporters": {"file": {"path": str(tmp_path / "out.json")}},
               "service": {"pipelines": {"logs": {"receivers": ["journald"], "exporters": ["file"]}}}}
    (tmp_path / "h.yaml").write_text(yaml.safe_dump(harness))
    old = os.environ["PATH"]
    os.environ["PATH"] = f"{fake}:{old}"
    try:
        recs = _run(binary, tmp_path / "h.yaml", tmp_path / "out.json", len(rows))
    finally:
        os.environ["PATH"] = old
    got = {r["_body"]["MESSAGE"]: int(r.get("severityNumber", 0)) for r in recs}
    assert got == {f"m{i}": sev for i, (_, sev) in enumerate(rows)}
    for r in recs:
        assert re.match(r"^m\d$", r["_body"]["MESSAGE"]) and "__CURSOR" in r["_body"]


def test_envelope_operators_are_conditional_per_file_and_never_rewrite_the_body(tmp_path):
    cfg, _ = _render(tmp_path, "modern")
    for name in ("filelog/security_logs", "filelog/system_logs"):
        ops = cfg["receivers"][name]["operators"]
        parsers = [o for o in ops if o["type"] in ("regex_parser", "key_value_parser")]
        assert parsers, name
        assert all(o["if"].startswith("(") or "log.file.path" in o["if"] for o in parsers)
        assert all(o.get("on_error") == "send_quiet" for o in parsers)
        assert not any(o["type"] == "regex_parser" and "preserve_to" in o for o in ops)
        assert all(o.get("parse_from", "body") in ("body", "attributes.rest") for o in parsers)
    assert not [o for o in cfg["receivers"]["filelog/app_logs"]["operators"] if o["type"] != "add"]


def test_receiver_ids_stay_one_per_stream_for_the_checkpoint_key(tmp_path):
    cfg, _ = _render(tmp_path, "modern")
    assert {k for k in cfg["receivers"] if k.startswith("filelog/")} == {
        "filelog/security_logs", "filelog/system_logs", "filelog/app_logs", "filelog/backup_logs"}


def test_syslog_timestamp_location_follows_the_probed_host_timezone(tmp_path):
    cfg, _ = _render(tmp_path, "modern", host_agents_timezone="Europe/Paris")
    ops = cfg["receivers"]["filelog/system_logs"]["operators"]
    assert {o["timestamp"]["location"] for o in ops if "location" in o.get("timestamp", {})} == {"Europe/Paris"}


def test_timezone_defaults_to_asia_seoul_when_no_fact_is_set(tmp_path):
    cfg, _ = _render(tmp_path, "modern")
    ops = cfg["receivers"]["filelog/system_logs"]["operators"]
    assert {o["timestamp"]["location"] for o in ops if "location" in o.get("timestamp", {})} == {"Asia/Seoul"}


def test_probe_sets_timezone_fact_with_variable_fallback_and_warns_only_when_unread():
    probe = yaml.safe_load((base.ROLE / "tasks" / "probe.yml").read_text(encoding="utf-8"))
    facts = next(t for t in probe if t["name"].startswith("[MON-022]"))["ansible.builtin.set_fact"]
    assert "_probe.timezone" in facts["host_agents_timezone"] and "timezone | default('Asia/Seoul'" in facts["host_agents_timezone"]
    warn = next(t for t in probe if t["name"].startswith("[MON-025]"))
    assert "host_agents_warn" in warn["ansible.builtin.debug"]["msg"]
    assert warn["when"] == "not (host_agents_timezone_probed | bool)"
    # one probe feeds every path (modern, legacy_el7, legacy_el6): the imported file has no os-path gate
    assert "when" not in next(t for t in probe if t["name"].startswith("[MON-021]"))
