"""#391: journald 재시작 뒤 rsyslog·fail2ban이 journal 읽기를 놓치지 않게 하는 핸들러 순서."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
HANDLERS = yaml.safe_load((ROOT / "roles/security/handlers/main.yml").read_text(encoding="utf-8"))
TASKS = yaml.safe_load((ROOT / "roles/security/tasks/main.yml").read_text(encoding="utf-8"))

CHAIN = [
    "Restart systemd-journald",
    "Restart rsyslog after journald",
    "Restart fail2ban after journald",
    "Verify rsyslog still writes the auth log after journald restart",
]


def _sec054():
    return next(t for t in _walk(TASKS) if str(t.get("name", "")).startswith("[SEC-054]"))


def _walk(tasks):
    for t in tasks:
        yield t
        for key in ("block", "rescue", "always"):
            if key in t:
                yield from _walk(t[key])


def test_journald_dropin_notifies_the_restart_chain_in_order():
    assert _sec054()["notify"] == CHAIN


def test_handlers_are_defined_in_chain_order_because_ansible_runs_them_in_definition_order():
    names = [h["name"] for h in HANDLERS]
    positions = [names.index(n) for n in CHAIN]
    assert positions == sorted(positions)


def test_followers_restart_only_running_services_and_tolerate_missing_units():
    for name, unit in (("Restart rsyslog after journald", "rsyslog"), ("Restart fail2ban after journald", "fail2ban")):
        h = next(h for h in HANDLERS if h["name"] == name)
        assert h["ansible.builtin.command"] == f"systemctl try-restart {unit}.service"
        assert "rc not in [0, 5]" in h["failed_when"]
        assert h["changed_when"] is True


def test_verify_handler_writes_a_probe_line_and_never_deletes_the_imjournal_state():
    h = next(h for h in HANDLERS if h["name"] == CHAIN[-1])
    script = h["ansible.builtin.shell"]
    assert "logger -p authpriv.info" in script and "/var/log/secure" in script
    assert "imjournal.state" not in script
    assert not any("imjournal.state" in str(x) for x in HANDLERS)
