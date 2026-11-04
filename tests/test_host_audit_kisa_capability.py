"""Host Audit: file capability list next to the KISA-2026 U-23 SUID/SGID check (#432, Spec #433).

Observable behaviour only: the real check scripts run under a local ``sh`` against a
fake filesystem root, with ``getcap`` replaced by a stub that answers per file the way
libcap does. The U-23 verdict (GOOD / MANUAL) keeps meaning "SUID/SGID files", so
capabilities only ever add evidence text.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_host_audit_kisa import ROLE_DIR, _script, _status, _stub_bin, _write  # noqa: E402

DEFAULTS = yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8"))
DISTRO_PING = "usr/bin/ping"


def _getcap_stub(caps):
    """A getcap that, like the real one, prints a line only for the files it is given that have caps."""
    cases = "".join("    */%s) printf '%%s %s\\n' \"$f\" ;;\n" % (rel, spec) for rel, spec in caps.items())
    return {"getcap": 'for f in "$@"; do\n  case "$f" in\n%s  esac\ndone\nexit 0' % cases}


def _host(tmp_path, caps=None, suid=(), getcap="stub"):
    """A fake root with the capability files in place; returns (root, commands for the stub dir)."""
    root = tmp_path / "root"
    for rel in list((caps or {}).keys()) + ["usr/bin/true"]:
        _write(root, rel, "bin", 0o755)
    for rel in suid:
        _write(root, rel, "bin", 0o4755)
    commands = _getcap_stub(caps or {}) if getcap == "stub" else {}
    if getcap == "broken":  # present on PATH but cannot be executed (missing library, wrong binary)
        commands = {"getcap": "exit 127"}
    return root, commands


def _u23(root, commands, defaults=None, hide_getcap=False):
    bindir = _stub_bin(root, commands=commands)
    path = str(bindir) + ":/usr/bin:/bin"
    if hide_getcap:
        # a PATH that carries every ordinary tool but no getcap, whatever the machine ships
        tools = root.parent / "tools"
        tools.mkdir(exist_ok=True)
        for d in ("/usr/bin", "/bin"):
            for name in os.listdir(d):
                if name != "getcap" and not name.endswith(".exe") and not os.path.lexists(tools / name):
                    os.symlink(Path(d) / name, tools / name)
        path = str(bindir) + ":" + str(tools)
        (bindir / "getcap").unlink(missing_ok=True)
    env = {"KISA_ROOT": str(root), "PATH": path}
    if defaults is not None:
        env["KISA_CAP_DEFAULTS"] = "\n".join(defaults)
    out = subprocess.run(["sh", "-s"], input=_script(), capture_output=True, text=True, env=env, timeout=120)
    assert out.returncode == 0, out.stderr
    return _status(out.stdout)["U-23"]


def role_defaults():
    return DEFAULTS["host_audit_kisa_capability_defaults"]


# ---------------------------------------------------------------- the three cases of the ticket


def test_only_distro_default_capabilities_are_listed_but_not_flagged_for_review(tmp_path):
    root, commands = _host(tmp_path, {DISTRO_PING: "cap_net_raw=ep"})
    verdict, evidence = _u23(root, commands, role_defaults())

    assert verdict == "GOOD"  # no SUID/SGID: the KISA meaning is untouched
    assert "file capability" in evidence and "default only" in evidence
    assert "review" not in evidence


def test_capability_outside_the_distro_defaults_is_marked_for_review(tmp_path):
    root, commands = _host(tmp_path, {DISTRO_PING: "cap_net_raw=ep", "opt/app/tool": "cap_dac_override=ep"})
    verdict, evidence = _u23(root, commands, role_defaults())

    assert verdict == "GOOD"
    assert "file capability review (1)" in evidence
    assert "/opt/app/tool cap_dac_override" in evidence
    assert "/usr/bin/ping" not in evidence  # defaults are not the review list


def test_missing_getcap_is_named_as_unavailable(tmp_path):
    root, commands = _host(tmp_path, getcap="none")
    verdict, evidence = _u23(root, commands, role_defaults(), hide_getcap=True)

    assert verdict == "GOOD"
    assert "file capability" in evidence and "점검불가" in evidence and "getcap" in evidence


def test_getcap_that_cannot_run_is_named_as_unavailable(tmp_path):
    root, commands = _host(tmp_path, getcap="broken")
    _, evidence = _u23(root, commands, role_defaults())

    assert "file capability" in evidence and "점검불가" in evidence


# ---------------------------------------------------------------- KISA verdict is unchanged


@pytest.mark.parametrize("getcap", ["stub", "none"])
def test_suid_files_still_make_u23_manual_whatever_getcap_says(tmp_path, getcap):
    root, commands = _host(tmp_path, {"opt/app/tool": "cap_dac_override=ep"} if getcap == "stub" else {},
                           suid=["usr/bin/su"], getcap=getcap)
    verdict, evidence = _u23(root, commands, role_defaults(), hide_getcap=getcap == "none")

    assert verdict == "MANUAL"
    assert "SUID/SGID files (1): /usr/bin/su" in evidence
    assert "file capability" in evidence


def test_no_capability_at_all_is_reported_as_none(tmp_path):
    root, commands = _host(tmp_path, {})
    verdict, evidence = _u23(root, commands, role_defaults())

    assert verdict == "GOOD" and "file capability: none" in evidence


# ---------------------------------------------------------------- output format, length, defaults


@pytest.mark.parametrize("line", ["/usr/bin/ping = cap_net_raw+ep", "/usr/bin/ping cap_net_raw=ep"])
def test_old_and_new_libcap_output_formats_match_the_same_default(tmp_path, line):
    """CentOS 6/7 print `path = cap+ep`, current libcap prints `path cap=ep`."""
    root, _ = _host(tmp_path, {DISTRO_PING: "x"})
    old_or_new = {"getcap": "for f in \"$@\"; do case \"$f\" in */%s) printf '%%s%s\\n' \"$f\" ;; esac; done"
                           % (DISTRO_PING, line[len("/usr/bin/ping"):])}
    _, evidence = _u23(root, old_or_new, role_defaults())

    assert "default only" in evidence and "review" not in evidence


def test_review_list_is_capped_like_the_suid_list(tmp_path):
    caps = {"opt/app/tool%02d" % i: "cap_chown=ep" for i in range(45)}
    root, commands = _host(tmp_path, caps)
    _, evidence = _u23(root, commands, role_defaults())

    assert "file capability review (45)" in evidence
    assert "...(+5)" in evidence  # kisa_cap 40, the same cut as SUID/SGID
    assert "/opt/app/tool00 cap_chown" in evidence


def test_default_list_is_a_role_variable_the_host_does_not_hardcode(tmp_path):
    root, commands = _host(tmp_path, {"opt/app/tool": "cap_chown=ep"})
    _, evidence = _u23(root, commands, ["/opt/app/tool cap_chown"])

    assert "default only" in evidence and "review" not in evidence


def test_role_defaults_cover_the_well_known_distro_capabilities():
    entries = role_defaults()
    assert isinstance(entries, list) and entries
    assert "/usr/bin/ping cap_net_raw" in entries
    assert all(len(e.split()) == 2 for e in entries)  # "<path> <capability names>"


def test_kisa_task_injects_the_role_variable_into_the_script():
    tasks = yaml.safe_load((ROLE_DIR / "tasks" / "kisa.yml").read_text(encoding="utf-8"))
    script = tasks[0]["vars"]["_host_audit_kisa_script"]
    assert "KISA_CAP_DEFAULTS=" in script and "host_audit_kisa_capability_defaults" in script
    assert "quote" in script  # defaults travel through the raw command line as one quoted word


def test_capability_check_is_read_only_and_bounded():
    text = (ROLE_DIR / "files" / "kisa" / "U-23.sh").read_text(encoding="utf-8")
    assert "-exec getcap" in text and text.count("kisa_find") >= 2  # same 120 s limit and -xdev as SUID/SGID
    assert "getcap -" not in text.replace("-exec getcap {}", "")  # no write/set flags, never setcap
    assert "setcap" not in text
