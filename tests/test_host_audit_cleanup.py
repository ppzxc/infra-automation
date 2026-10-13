"""Host Audit runner directory cleanup (#157, spec #148).

The policy table is exercised on the runner with real ansible-playbook: the tail of
report.yml (keep verdict AUD-516, mail verdict AUD-610, cleanup) runs against a real
output directory, so a run that ends in an AUD-516/AUD-610 failure is covered too.
"""
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
TASKS = ROOT_DIR / "roles" / "host_audit" / "tasks"
RUN_ID = "ha-20261013T000000Z"

pytestmark = pytest.mark.skipif(not shutil.which("ansible-playbook"), reason="ansible-playbook not installed")


def _load(name):
    return yaml.safe_load((TASKS / name).read_text(encoding="utf-8"))


def _tail_block():
    """The real post-report block of report.yml, with includes replaced by the task files."""
    block = next(t for t in _load("report.yml") if "always" in t)

    def inline(tasks):
        out = []
        for t in tasks:
            inc = t.get("ansible.builtin.include_tasks")
            if inc in ("storage_upload.yml", "mail.yml"):
                continue  # network and mail tasks: their results are given as variables
            out.append({"block": _load(inc)} if inc else t)
        return out

    return {"block": inline(block["block"]), "always": inline(block["always"])}


def _run_dir(tmp_path):
    root = tmp_path / "host_audit"
    out = root / RUN_ID
    (out / "hosts").mkdir(parents=True)
    (out / "report.html").write_text("<html/>")
    (out / "hosts" / "h1.json").write_text("{}")
    return root, out


def _vars(root, out, *, storage=True, uploads=(200,), problem="", mail_sent=None, baseline="ok",
          run_kind="on_demand", pointer=200, run_id=RUN_ID, output_dir=None):
    send = mail_sent is not None
    return {
        "host_audit_output_root": str(root),
        "host_audit_run": {"run_id": run_id, "run_kind": run_kind, "output_dir": output_dir or str(out)},
        "host_audit_storage_enabled": storage,
        "_host_audit_storage_active": storage,
        "_host_audit_storage_problem": problem,
        "_host_audit_storage_prefix": "2026-10/" + RUN_ID + "/",
        "_host_audit_storage_target": {"bucket": "host-audit"},
        "_host_audit_uploads": {"results": [{"status": s, "item": {"stat": {"path": "x/f%d" % i}}}
                                            for i, s in enumerate(uploads)]},
        "_host_audit_pointer_put": {"status": pointer},
        "host_audit_baseline_history": {"state": baseline, "reason": "x"},
        "_host_audit_mail_plan": {"send": send, "reason": "" if send else "off"},
        "host_audit_mail_outcome": {"sent": bool(mail_sent), "error": "smtp down", "skipped_reason": "off"},
        "host_audit_mail_doc": {"run_id": RUN_ID, "report": {"archive": "b/k"}},
    }


def _run(tmp_path, variables, check=False):
    pb = tmp_path / "pb.yml"
    pb.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
        "vars": variables, "tasks": [_tail_block()],
    }], allow_unicode=True))
    cmd = ["ansible-playbook", "-i", "localhost,", str(pb)] + (["--check"] if check else [])
    return subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                          cwd=ROOT_DIR, timeout=300, env=dict(os.environ, ANSIBLE_NOCOLOR="1"))


# ---- this run's directory: the policy table ---------------------------------

def test_kept_in_bucket_removes_this_run_even_when_the_run_fails_at_aud_610(tmp_path):
    root, out = _run_dir(tmp_path)
    res = _run(tmp_path, _vars(root, out, mail_sent=False))
    assert res.returncode != 0 and "메일 발송 실패" in res.stdout
    assert not out.exists()
    assert root.is_dir()


def test_kept_in_bucket_removes_this_run(tmp_path):
    root, out = _run_dir(tmp_path)
    res = _run(tmp_path, _vars(root, out, mail_sent=True))
    assert res.returncode == 0, res.stdout[-1500:]
    assert not out.exists() and root.is_dir()


def test_storage_off_and_mail_sent_removes_this_run(tmp_path):
    root, out = _run_dir(tmp_path)
    res = _run(tmp_path, _vars(root, out, storage=False, uploads=(), mail_sent=True))
    assert res.returncode == 0, res.stdout[-1500:]
    assert not out.exists()


@pytest.mark.parametrize("mail", [False, None])
def test_storage_off_and_mail_failed_or_not_sent_keeps_this_run_and_says_why(tmp_path, mail):
    root, out = _run_dir(tmp_path)
    res = _run(tmp_path, _vars(root, out, storage=False, uploads=(), mail_sent=mail))
    assert (out / "report.html").exists()
    assert str(out) in res.stdout and "남김" in res.stdout


def test_upload_failure_keeps_this_run_and_the_run_still_fails_at_aud_516(tmp_path):
    root, out = _run_dir(tmp_path)
    res = _run(tmp_path, _vars(root, out, uploads=(200, 500), mail_sent=False))
    assert res.returncode != 0 and "원본 보관 실패" in res.stdout
    assert (out / "report.html").exists()
    assert str(out) in res.stdout and "남김" in res.stdout


def test_missing_storage_input_keeps_this_run(tmp_path):
    root, out = _run_dir(tmp_path)
    res = _run(tmp_path, _vars(root, out, uploads=(), problem="agents/rustfs 누락", mail_sent=False))
    assert res.returncode != 0
    assert (out / "report.html").exists()


def test_baseline_lookup_failure_keeps_this_run(tmp_path):
    root, out = _run_dir(tmp_path)
    res = _run(tmp_path, _vars(root, out, baseline="failed", mail_sent=True))
    assert res.returncode != 0
    assert (out / "report.html").exists()


def test_failed_pointer_upload_keeps_this_run(tmp_path):
    root, out = _run_dir(tmp_path)
    res = _run(tmp_path, _vars(root, out, run_kind="scheduled", pointer=500, mail_sent=True))
    assert res.returncode != 0
    assert (out / "report.html").exists()


def test_check_mode_never_removes(tmp_path):
    root, out = _run_dir(tmp_path)
    _run(tmp_path, _vars(root, out, mail_sent=True), check=True)
    assert (out / "report.html").exists()


# ---- path validation: only this run's output_dir -----------------------------

@pytest.mark.parametrize("bad", ["root", "outside", "nested", "resend"])
def test_only_a_direct_child_of_the_output_root_named_by_the_run_id_is_removed(tmp_path, bad):
    root, out = _run_dir(tmp_path)
    victim = {"root": root, "outside": tmp_path / "other", "nested": out / "hosts",
              "resend": root / "resend-20261013T000000"}[bad]
    victim.mkdir(parents=True, exist_ok=True)
    (victim / "keep.txt").write_text("x")
    variables = _vars(root, out, mail_sent=True, output_dir=str(victim),
                      run_id="resend-20261013T000000" if bad == "resend" else RUN_ID)
    _run(tmp_path, variables)
    assert (victim / "keep.txt").exists()
    assert (out / "report.html").exists()


# ---- old run directories (prepare.yml) ---------------------------------------

def _prepare(tmp_path, root, out, check=False):
    tasks = [t for t in _load("prepare.yml") if any(f"[AUD-00{i}]" in t["name"] for i in (5, 6, 7))]
    assert len(tasks) == 3
    defaults = yaml.safe_load((ROOT_DIR / "roles/host_audit/defaults/main.yml").read_text())
    variables = {"host_audit_output_root": str(root),
                 "host_audit_run": {"run_id": out.name, "output_dir": str(out)},
                 "host_audit_output_retention_days": defaults["host_audit_output_retention_days"]}
    pb = tmp_path / "prep.yml"
    pb.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local", "gather_facts": False, "become": False, "become": False,
                                   "vars": variables, "tasks": tasks}]))
    cmd = ["ansible-playbook", "-i", "localhost,", str(pb)] + (["--check"] if check else [])
    return subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=ROOT_DIR,
                          timeout=300, env=dict(os.environ, ANSIBLE_NOCOLOR="1"))


def _age(path, days):
    t = time.time() - days * 86400
    os.utime(path, (t, t))


def test_only_run_directories_older_than_the_retention_days_are_removed(tmp_path):
    root = tmp_path / "host_audit"
    out = root / "ha-new"
    for name in ("ha-old", "ha-recent", "resend-old", "ha-new"):
        (root / name).mkdir(parents=True)
        (root / name / "f").write_text("x")
    (root / "stray.txt").write_text("x")
    _age(root / "ha-old", 30)
    _age(root / "resend-old", 30)
    _age(root / "ha-new", 30)        # the current run is never touched, however old its mtime
    _age(root / "ha-recent", 2)
    _age(root / "stray.txt", 30)
    res = _prepare(tmp_path, root, out)
    assert res.returncode == 0, res.stdout[-1500:]
    assert not (root / "ha-old").exists()
    assert (root / "ha-recent").exists()
    assert (root / "ha-new").exists()
    assert (root / "resend-old").exists()   # resend directories are never touched
    assert (root / "stray.txt").exists()    # only directories


def test_a_directory_whose_name_is_not_a_run_id_survives_however_old_it_is(tmp_path):
    root = tmp_path / "host_audit"
    out = root / "ha-new"
    names = ("ha-old", ".hidden", "-dash", "_under", "my backups", "ha old", "resend-x")
    for name in names + ("ha-new",):
        (root / name).mkdir(parents=True)
        (root / name / "f").write_text("x")
        _age(root / name, 30)
    res = _prepare(tmp_path, root, out)
    assert res.returncode == 0, res.stdout[-1500:]
    assert not (root / "ha-old").exists()
    for name in names[1:] + ("ha-new",):
        assert (root / name).exists(), name


def test_the_old_directory_name_rule_is_the_run_id_rule_of_aud_630():
    """AUD-006 deletes only names that AUD-630 would accept as a run_id (one pattern, written in both places)."""
    prepare = next(t for t in _load("prepare.yml") if "[AUD-006]" in t["name"])
    pattern = prepare["ansible.builtin.find"]["patterns"][0]
    cleanup = next(t for t in _load("cleanup.yml") if "[AUD-630]" in t["name"])
    assert "_run_id is match('%s')" % pattern in cleanup["vars"]["_path_ok"]
    assert prepare["ansible.builtin.find"]["use_regex"] is True


def test_retention_days_default_is_documented_and_positive():
    defaults = yaml.safe_load((ROOT_DIR / "roles/host_audit/defaults/main.yml").read_text())
    days = defaults["host_audit_output_retention_days"]
    assert isinstance(days, int) and days >= 1
    assert f"`host_audit_output_retention_days` | `{days}`" in (ROOT_DIR / "docs/host_audit.md").read_text()


def test_check_mode_removes_no_old_directory(tmp_path):
    root = tmp_path / "host_audit"
    (root / "ha-old").mkdir(parents=True)
    _age(root / "ha-old", 30)
    _prepare(tmp_path, root, root / "ha-new", check=True)
    assert (root / "ha-old").exists()
