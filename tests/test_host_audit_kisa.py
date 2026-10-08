"""Host Audit Configuration Vulnerability (ADR-0009, #121): KISA-2026 checks and verdicts.

Observable behaviour only: the check scripts are run with a local ``sh`` against
a fake filesystem root (``KISA_ROOT``) and their output is fed to the same
filters the playbook uses; the report section is asserted through the model and
the rendered template.
"""
import datetime
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit import host_audit_report_model  # noqa: E402
from host_audit_kisa import (  # noqa: E402
    EXCEPTION, GOOD, ITEMS, MANUAL, NOT_APPLICABLE, VULNERABLE,
    host_audit_kisa_result, run_date,
)

ROLE_DIR = ROOT_DIR / "roles" / "host_audit"
KISA_DIR = ROLE_DIR / "files" / "kisa"
TODAY = "2026-10-09"


def kisa_stdout(lines):
    return "banner\n__HOST_AUDIT_KISA_BEGIN__\n" + "\n".join(lines) + "\n__HOST_AUDIT_KISA_END__\n"


def ok_probe(lines):
    return {"rc": 0, "stdout": kisa_stdout(lines), "stderr": ""}


def verdicts(result):
    return {it["code"]: it["verdict"] for it in result["results"]}


def exception(code="KISA-2026:U-02", **overrides):
    entry = {"code": code, "reason": "사유", "risk": "위험", "mitigation": "보완",
             "approver": "정보보호 책임자", "approved_on": "2026-09-01", "expires_on": "2026-12-31"}
    entry.update(overrides)
    return entry


ALL_GOOD = ["U-%02d|GOOD|ok" % i for i in range(1, 14)]


# ------------------------------------------------------------ parser: five verdicts


def test_parser_produces_all_five_verdicts():
    lines = ["U-01|GOOD|PermitRootLogin=no", "U-02|VULN|PASS_MAX_DAYS=99999", "U-06|NA|su not installed",
             "U-07|MANUAL|login-capable accounts: root", "U-03|VULN|deny=0"]
    result = host_audit_kisa_result(ok_probe(lines), [exception("KISA-2026:U-03")], "ns0332", ["servers"], TODAY)

    v = verdicts(result)
    assert result["status"] == "ok" and result["edition"] == "KISA-2026"
    assert v["KISA-2026:U-01"] == GOOD
    assert v["KISA-2026:U-02"] == VULNERABLE
    assert v["KISA-2026:U-03"] == EXCEPTION
    assert v["KISA-2026:U-06"] == NOT_APPLICABLE
    assert v["KISA-2026:U-07"] == MANUAL
    # an implemented item the scripts did not report is never silently 양호
    assert v["KISA-2026:U-13"] == MANUAL
    u13 = next(it for it in result["results"] if it["code"] == "KISA-2026:U-13")
    assert u13["result"] == "NONE" and "결과를 내지 않음" in u13["evidence"]
    assert set(v) == {"KISA-2026:" + c for c in ITEMS}
    assert {EXCEPTION, GOOD, MANUAL, NOT_APPLICABLE, VULNERABLE} == set(v.values())


def test_parser_ignores_noise_and_unknown_lines():
    lines = ALL_GOOD + ["U-99|VULN|not an implemented item", "garbage", "U-02|WHAT|bad status"]
    result = host_audit_kisa_result(ok_probe(lines), [], "h", [], TODAY)
    assert set(verdicts(result).values()) == {GOOD}


def test_run_without_markers_or_unreachable_is_a_failed_check():
    failed = host_audit_kisa_result({"rc": 1, "stdout": "", "stderr": "sudo: a password is required\n"},
                                    [], "h", [], TODAY)
    assert failed["status"] == "failed" and failed["results"] == []
    assert failed["reason"] == "sudo: a password is required"

    unreachable = host_audit_kisa_result({"unreachable": True, "msg": "timed out"}, [], "h", [], TODAY)
    assert unreachable["status"] == "failed" and "timed out" in unreachable["reason"]


# ------------------------------------------------------------ exception register


@pytest.mark.parametrize("raw", ["VULN", "MANUAL"])
def test_active_exception_marks_finding_approved(raw):
    lines = ["U-02|%s|x" % raw]
    result = host_audit_kisa_result(ok_probe(lines), [exception()], "ns0332", ["servers"], TODAY)
    item = next(it for it in result["results"] if it["code"] == "KISA-2026:U-02")
    assert item["verdict"] == EXCEPTION
    assert item["exception"]["state"] == "유효"
    assert item["exception"]["approver"] == "정보보호 책임자"


@pytest.mark.parametrize("raw", ["VULN", "MANUAL"])
def test_expired_exception_reverts_to_vulnerable(raw):
    expired = exception(expires_on="2026-10-08")
    result = host_audit_kisa_result(ok_probe(["U-02|%s|x" % raw]), [expired], "ns0332", [], TODAY)
    item = next(it for it in result["results"] if it["code"] == "KISA-2026:U-02")
    assert item["verdict"] == VULNERABLE
    assert item["exception"]["state"] == "만료"


def test_exception_is_valid_through_its_expiry_date_and_accepts_yaml_dates():
    entry = exception(approved_on=datetime.date(2026, 9, 1), expires_on=datetime.date(2026, 10, 9))
    result = host_audit_kisa_result(ok_probe(["U-02|VULN|x"]), [entry], "h", [], TODAY)
    assert verdicts(result)["KISA-2026:U-02"] == EXCEPTION


def test_pending_or_malformed_exception_changes_nothing():
    pending = exception(approver="", approved_on="")
    result = host_audit_kisa_result(ok_probe(["U-02|VULN|x"]), [pending], "h", [], TODAY)
    item = next(it for it in result["results"] if it["code"] == "KISA-2026:U-02")
    assert item["verdict"] == VULNERABLE and item["exception"]["state"] == "승인 대기"

    no_risk = exception(risk="")
    result = host_audit_kisa_result(ok_probe(["U-02|VULN|x"]), [no_risk], "h", [], TODAY)
    item = next(it for it in result["results"] if it["code"] == "KISA-2026:U-02")
    assert item["verdict"] == VULNERABLE and item["exception"] is None


def test_exception_scope_and_good_items():
    by_host = exception(hosts=["ns0001"])
    by_group = exception(groups=["loadbalancers"])
    lines = ["U-02|VULN|x", "U-01|GOOD|x"]
    assert verdicts(host_audit_kisa_result(ok_probe(lines), [by_host], "ns0332", ["servers"], TODAY))[
        "KISA-2026:U-02"] == VULNERABLE
    assert verdicts(host_audit_kisa_result(ok_probe(lines), [by_group], "lb01", ["loadbalancers"], TODAY))[
        "KISA-2026:U-02"] == EXCEPTION
    # an exception never downgrades a 양호 result
    good = host_audit_kisa_result(ok_probe(lines), [exception("KISA-2026:U-01")], "h", [], TODAY)
    assert verdicts(good)["KISA-2026:U-01"] == GOOD


def test_run_date_is_the_kst_calendar_date():
    assert run_date("2026-10-08T22:00:05Z", "Asia/Seoul") == "2026-10-09"
    assert run_date("2026-10-08T10:00:05Z", "Asia/Seoul") == "2026-10-08"


def test_register_first_entry_is_the_docker_segment_u28_exception():
    defaults = yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8"))
    register = defaults["host_audit_kisa_exceptions"]
    first = register[0]
    assert first["code"] == "KISA-2026:U-28"
    assert "Docker" in first["reason"]
    for key in ("reason", "risk", "mitigation", "approver", "approved_on", "expires_on"):
        assert key in first


# ------------------------------------------------------------ report section


def _record(host, items_lines, register=(), status="ok"):
    rec = {"inventory_hostname": host, "status": status, "reason": "", "declared": {"groups": ["servers"]},
           "identity": {"account": "root"}, "os": {"name": "Rocky Linux 9.6"}}
    if status == "ok" and items_lines is not None:
        rec["config_vulnerability"] = host_audit_kisa_result(ok_probe(items_lines), list(register), host,
                                                             ["servers"], TODAY)
    return rec


def _model(records, register=()):
    # started_at is 2026-10-09 in KST, the same run date as TODAY
    meta = {"run_id": "ha-1", "started_at": "2026-10-08T22:00:05Z", "generated_at": "2026-10-08T22:01:00Z",
            "targets": [r["inventory_hostname"] for r in records], "kisa_exceptions": list(register)}
    return host_audit_report_model(records, meta)


def test_section_shows_findings_other_than_good_and_appendix_has_everything():
    lines_a = ["U-%02d|GOOD|ok" % i for i in range(1, 14) if i not in (2, 6)] + ["U-02|VULN|max", "U-06|NA|no su"]
    lines_b = ["U-%02d|GOOD|ok" % i for i in range(1, 14) if i != 2] + ["U-02|VULN|max"]
    records = [_record("ns0001", lines_a), _record("ns0002", lines_b)]
    cv = _model(records)["config_vulnerability"]

    assert cv["hosts_checked"] == 2
    assert [(f["code"], f["verdict"], f["host_count"]) for f in cv["findings"]] == [
        ("KISA-2026:U-02", VULNERABLE, 2)]
    assert [h["host"] for h in cv["findings"][0]["hosts"]] == ["ns0001", "ns0002"]
    # appendix: every item per host, 양호 included
    assert sorted(cv["appendix"]) == ["ns0001", "ns0002"]
    assert len(cv["appendix"]["ns0001"]) == len(ITEMS)
    assert {it["verdict"] for it in cv["appendix"]["ns0001"]} == {GOOD, VULNERABLE, NOT_APPLICABLE}
    u02 = next(s for s in cv["summary"] if s["code"] == "KISA-2026:U-02")
    assert u02["counts"][cv["verdicts"].index(VULNERABLE)] == 2
    assert sum(cv["totals"]) == 2 * len(ITEMS)


def test_section_orders_findings_by_verdict_then_severity():
    lines = ["U-12|VULN|x", "U-01|VULN|x", "U-07|MANUAL|x", "U-03|VULN|x"]
    cv = _model([_record("h", lines, [exception("KISA-2026:U-03")])], [exception("KISA-2026:U-03")])[
        "config_vulnerability"]
    order = [(f["verdict"], f["code"]) for f in cv["findings"]]
    assert order[0] == (VULNERABLE, "KISA-2026:U-01")  # 상
    assert order[1] == (VULNERABLE, "KISA-2026:U-12")  # 하
    assert order.index((EXCEPTION, "KISA-2026:U-03")) > order.index((MANUAL, "KISA-2026:U-07"))
    reg = cv["register"][0]
    assert reg["state"] == "유효" and reg["applied"] == 1


def test_host_whose_checks_failed_is_listed_as_not_inspected():
    failed = {"inventory_hostname": "ns0009", "status": "ok", "declared": {}, "identity": {}, "os": {},
              "config_vulnerability": {"edition": "KISA-2026", "status": "failed", "reason": "sudo 실패",
                                       "results": []}}
    model = _model([failed, _record("ns0010", None, status="unreachable")])
    rows = [(u["host"], u["item"]) for u in model["unavailable"]]
    assert ("ns0009", "Configuration Vulnerability") in rows
    assert ("ns0010", "전체 점검") in rows  # core model; not duplicated by the section
    assert [r for r in rows if r[0] == "ns0010"] == [("ns0010", "전체 점검")]
    assert model["config_vulnerability"]["hosts_checked"] == 0
    assert len([c for c in model["cover"]["contents"] if "KISA-2026" in c]) == 1


def test_template_renders_section_appendix_and_register():
    jinja2 = pytest.importorskip("jinja2")
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROLE_DIR / "templates")))
    register = [exception("KISA-2026:U-02"),
                exception("KISA-2026:U-28", approver="", approved_on="", expires_on="")]
    lines = ["U-%02d|GOOD|ok-evidence-%02d" % (i, i) for i in range(1, 14) if i != 2] + ["U-02|VULN|max"]
    model = _model([_record("ns0332", lines, register)], register)
    html = env.get_template("report.html.j2").render(host_audit_model=model)

    assert "4. Configuration Vulnerability" in html
    assert "KISA-2026:U-02" in html and EXCEPTION in html
    assert "ok-evidence-13" in html  # 양호 evidence lives in the appendix
    assert "부록 1. ns0332" in html and "<h3 class=\"small\">Configuration Vulnerability" in html
    assert "KISA-2026:U-28" in html and "승인 대기" in html
    assert "http://" not in html and "https://" not in html


# ------------------------------------------------------------ the check scripts themselves


def _script():
    parts = [KISA_DIR / "_lib.sh"] + sorted(KISA_DIR.glob("U-*.sh")) + [KISA_DIR / "_end.sh"]
    return "\n".join(p.read_text(encoding="utf-8").rstrip("\n") for p in parts) + "\n"


def _write(root, rel, text, mode=0o644):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)


def _run(root):
    env = {"KISA_ROOT": str(root), "PATH": "/usr/bin:/bin"}
    out = subprocess.run(["sh", "-s"], input=_script(), capture_output=True, text=True, env=env, timeout=60)
    assert out.returncode == 0, out.stderr
    return out.stdout


HARDENED = {
    "etc/passwd": "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n"
                  "daemon:x:2:2:daemon:/sbin:/sbin/nologin\nppzxc:x:1000:1000::/home/ppzxc:/bin/bash\n",
    "etc/group": "root:x:0:\nbin:x:1:\ndaemon:x:2:\nwheel:x:10:ppzxc\nppzxc:x:1000:\n",
    "etc/shadow": "root:$6$saltsalt$HASHVALUEROOT:19000:0:99999:7:::\nbin:*:19000:0:99999:7:::\n"
                  "daemon:*:19000:0:99999:7:::\nppzxc:!$y$j9T$salt$HASHVALUEUSER:19000:1:90:7:::\n",
    "etc/login.defs": "PASS_MAX_DAYS   90\nPASS_MIN_DAYS   1\nENCRYPT_METHOD SHA512\n",
    "etc/security/pwquality.conf": "# comment\nminlen = 8\nminclass = 3\n",
    "etc/security/faillock.conf": "deny = 5\n",
    "etc/pam.d/system-auth": "auth required pam_faillock.so preauth\n"
                             "password requisite pam_pwquality.so local_users_only\n"
                             "password sufficient pam_unix.so sha512 shadow use_authtok\n",
    "etc/pam.d/su": "auth sufficient pam_rootok.so\nauth required pam_wheel.so use_uid\n",
    "etc/ssh/sshd_config": "Port 22\nPermitRootLogin no\n",
    "etc/profile.d/tmout.sh": "readonly TMOUT=600\nexport TMOUT\n",
}

WEAK = {
    "etc/passwd": "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\n"
                  "games:x:12:100:games:/usr/games:/bin/bash\nold:abcdefghijklm:1001:777::/home/old:/bin/sh\n"
                  "dup:x:1001:1001::/home/dup:/bin/sh\n",
    "etc/group": "root:x:0:dup\nusers:x:100:\ndup:x:1001:\n",
    "etc/shadow": "root:$1$salt$MD5HASHVALUE:19000:0:99999:7:::\ntoor:$6$s$HASH:19000::::::\n",
    "etc/login.defs": "PASS_MAX_DAYS   99999\nPASS_MIN_DAYS   0\nENCRYPT_METHOD MD5\n",
    "etc/pam.d/system-auth": "auth required pam_faillock.so preauth deny=0\n"
                             "password sufficient pam_unix.so md5 shadow\n",
    "etc/pam.d/su": "#auth required pam_wheel.so use_uid\n",
    "etc/ssh/sshd_config": "PermitRootLogin prohibit-password\n",
    "etc/profile": "TMOUT=3600\n",
}


def _status(stdout):
    rows = {}
    for line in stdout.splitlines():
        parts = line.split("|", 2)
        if len(parts) == 3:
            rows[parts[0]] = (parts[1], parts[2])
    return rows


def test_check_scripts_on_hardened_root(tmp_path):
    for rel, text in HARDENED.items():
        _write(tmp_path, rel, text)
    stdout = _run(tmp_path)
    rows = _status(stdout)

    assert set(rows) == set(ITEMS)
    expected = {"U-01": "GOOD", "U-02": "GOOD", "U-03": "GOOD", "U-04": "GOOD", "U-05": "GOOD",
                "U-06": "GOOD", "U-07": "MANUAL", "U-08": "MANUAL", "U-09": "GOOD", "U-10": "GOOD",
                "U-11": "GOOD", "U-12": "GOOD", "U-13": "GOOD"}
    assert {code: st for code, (st, _) in rows.items()} == expected, stdout
    assert "deny=5" in rows["U-03"][1]
    assert "root,ppzxc" in rows["U-07"][1]
    assert "wheel=ppzxc" in rows["U-08"][1]
    assert "sha512=1" in rows["U-13"][1] and "yescrypt=1" in rows["U-13"][1]
    assert "HASHVALUE" not in stdout and "$6$" not in stdout  # never leak password hashes

    # the result feeds the same filter the playbook uses
    result = host_audit_kisa_result({"rc": 0, "stdout": stdout}, [], "h", [], TODAY)
    assert result["status"] == "ok"


def test_check_scripts_on_weak_root(tmp_path):
    for rel, text in WEAK.items():
        _write(tmp_path, rel, text)
    stdout = _run(tmp_path)
    rows = _status(stdout)

    for code in ("U-01", "U-02", "U-03", "U-04", "U-05", "U-09", "U-10", "U-11", "U-12", "U-13"):
        assert rows[code][0] == "VULN", (code, stdout)
    assert "prohibit-password" in rows["U-01"][1]
    assert "deny=0" in rows["U-03"][1]
    assert "old" in rows["U-04"][1]
    assert "toor" in rows["U-05"][1]
    assert "old(777)" in rows["U-09"][1]
    assert "1001=old+dup" in rows["U-10"][1]
    assert "games:/bin/bash" in rows["U-11"][1]
    assert "/etc/profile=3600" in rows["U-12"][1]
    assert "md5=1" in rows["U-13"][1] and "root" in rows["U-13"][1]
    assert "MD5HASHVALUE" not in stdout
    # no su binary and no pam_wheel -> 해당없음
    assert rows["U-06"][0] == "NA"


def test_u13_flags_weak_configured_algorithm_even_with_strong_hashes(tmp_path):
    tree = dict(HARDENED)
    tree["etc/pam.d/system-auth"] = "password sufficient pam_unix.so shadow md5\n"
    for rel, text in tree.items():
        _write(tmp_path, rel, text)
    status, evidence = _status(_run(tmp_path))["U-13"]
    assert status == "VULN" and "weak algorithm configured" in evidence


def test_check_scripts_without_privilege_report_manual(tmp_path):
    for rel, text in HARDENED.items():
        _write(tmp_path, rel, text)
    os.chmod(tmp_path / "etc" / "shadow", 0o000)
    if os.access(tmp_path / "etc" / "shadow", os.R_OK):
        pytest.skip("running as root: unreadable shadow cannot be simulated")
    rows = _status(_run(tmp_path))
    assert rows["U-13"][0] == "MANUAL"


def test_kisa_tasks_run_read_only_via_stdin_and_record_results():
    tasks = yaml.safe_load((ROLE_DIR / "tasks" / "kisa.yml").read_text(encoding="utf-8"))
    run, record = tasks
    assert run["name"].startswith("[AUD-200]") and "read-only" in run["name"]
    assert "sh -s" in run["ansible.builtin.raw"]
    assert run["check_mode"] is False and run["changed_when"] is False
    assert run["become"] is True and run["ignore_unreachable"] is True
    assert "host_audit_kisa_result" in record["ansible.builtin.set_fact"]["host_audit_record"]
    main = yaml.safe_load((ROLE_DIR / "tasks" / "main.yml").read_text(encoding="utf-8"))
    names = [t.get("name", "") for t in main]
    kisa_at = next(i for i, t in enumerate(main) if t.get("ansible.builtin.include_tasks") == "kisa.yml")
    assert kisa_at < next(i for i, n in enumerate(names) if n.startswith("[AUD-012]"))
