"""Host Audit report stage: the Remediation Plan xlsx of every host is written (AUD-025) and kept (AUD-512~514).

Few integration tests (ADR-0013): the real AUD-025 task of report.yml and the keep tasks of storage_upload.yml run
with ansible-playbook on a synthetic report model.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
TASKS = ROOT_DIR / "roles" / "host_audit" / "tasks"
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit import host_audit_report_model  # noqa: E402
from host_audit_kisa import host_audit_kisa_result  # noqa: E402

pytestmark = pytest.mark.skipif(not shutil.which("ansible-playbook"), reason="ansible-playbook not installed")
if os.environ.get("CI"):
    import openpyxl
else:
    openpyxl = pytest.importorskip("openpyxl")


def _tasks(name):
    return yaml.safe_load((TASKS / name).read_text(encoding="utf-8"))


def _flat(tasks):
    for task in tasks:
        yield task
        yield from _flat(task.get("block", []))


def _task(file, spec_id):
    return next(t for t in _flat(_tasks(file)) if "[%s]" % spec_id in t.get("name", ""))


def _named(name):
    return next(t for t in _flat(_tasks("report.yml")) if t.get("name") == name)


def _plan_task():
    return next(t for t in _flat(_tasks("report.yml")) if t.get("name") == "Build the Remediation Plan of every host")


def _record(host, vulnerable):
    lines = ["U-%02d|%s|ev" % (i, "VULN" if i in vulnerable else "GOOD") for i in range(1, 68)]
    probe = {"rc": 0, "stdout": "__HOST_AUDIT_KISA_BEGIN__\n" + "\n".join(lines) + "\n__HOST_AUDIT_KISA_END__\n",
             "stderr": ""}
    return {"inventory_hostname": host, "status": "ok", "reason": "", "declared": {"groups": ["servers"]},
            "identity": {"account": "root"}, "os": {"id": "rocky", "name": "Rocky"},
            "config_vulnerability": host_audit_kisa_result(probe, [], host, ["servers"], "2026-10-09")}


def _run(tmp_path, out, model, run_kind="scheduled"):
    ids = ("AUD-512", "AUD-513")
    keep = [t for t in _tasks("storage_upload.yml") if any("[%s]" % i in t["name"] for i in ids)]
    pb = tmp_path / "pb.yml"
    model_file = tmp_path / "model.json"
    model_file.write_text(json.dumps(model, ensure_ascii=False))
    # like report.yml: the model is data read from a file, never a trusted playbook variable
    load = {"ansible.builtin.set_fact": {"host_audit_model": "{{ lookup('ansible.builtin.file', '%s') | from_json }}"
                                         % model_file}}
    pb.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
        "vars": {"host_audit_run": {"run_id": "ha-1", "run_kind": run_kind, "output_dir": str(out)},
                 "_host_audit_storage_active": True, "_host_audit_storage_problem": ""},
        "tasks": [load, _plan_task(), _named("Name the hosts whose Remediation Plan could not be built"),
                  _task("report.yml", "AUD-025")] + keep + [{"ansible.builtin.debug": {
            "msg": "{{ _host_audit_keep_stats.results | map(attribute='stat', default={}) | list }}"}}],
    }], allow_unicode=True))
    env = dict(os.environ, ANSIBLE_STDOUT_CALLBACK="ansible.posix.json",
               ANSIBLE_LIBRARY=str(ROOT_DIR / "roles" / "host_audit" / "library"),
               ANSIBLE_MODULE_UTILS=str(ROOT_DIR / "roles" / "host_audit" / "module_utils"),
               ANSIBLE_FILTER_PLUGINS=str(ROOT_DIR / "filter_plugins"))
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300, env=env)
    assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-2000:]
    plays = json.JSONDecoder().raw_decode(res.stdout[res.stdout.index("{"):])[0]["plays"][0]["tasks"]
    return {s["path"][len(str(out)) + 1:]: s["checksum"] for s in plays[-1]["hosts"]["localhost"]["msg"]}


def _model():
    records = [_record("h1", {1, 2}), _record("h2", set())]
    meta = {"run_id": "ha-1", "started_at": "2026-10-08T22:00:05Z", "generated_at": "2026-10-08T22:01:00Z",
            "targets": ["h1", "h2"], "kisa_exceptions": []}
    return host_audit_report_model(records, meta)


def test_one_xlsx_per_host_is_written_and_is_in_the_keep_list(tmp_path):
    out = tmp_path / "run"
    out.mkdir()
    (out / "xlsx").mkdir()
    (out / "xlsx" / ".leftover.tmp").write_bytes(b"partial")
    stats = _run(tmp_path, out, _model())
    assert not [rel for rel in stats if rel.endswith(".tmp")]  # a killed writer's (hidden) temp file is never listed
    names = {"xlsx/host-audit-ha-1-h1.xlsx", "xlsx/host-audit-ha-1-h2.xlsx", "xlsx/host-audit-ha-1-total.xlsx"}
    assert names <= set(stats)
    for rel in names:
        assert stats[rel] == hashlib.sha256((out / rel).read_bytes()).hexdigest()
    h1 = openpyxl.load_workbook(out / "xlsx/host-audit-ha-1-h1.xlsx").active
    assert [c.value for c in h1[1]][:2] == ["그룹", "자산명"]
    assert h1.max_row > 3 and h1["B2"].value == "h1"
    h2 = openpyxl.load_workbook(out / "xlsx/host-audit-ha-1-h2.xlsx").active
    assert h2["D2"].value == "양호 외 항목 없음"
    total = openpyxl.load_workbook(out / "xlsx/host-audit-ha-1-total.xlsx").active
    assert [c.value for c in total[1]] == [c.value for c in h1[1]]  # the same 15 columns
    def body(ws):  # the rows under the header, up to the blank row before the footer
        rows = [[c.value for c in row] for row in ws.iter_rows(min_row=2)]
        return rows[:rows.index(next(r for r in rows if not any(r)))], rows[-2:]

    h1_rows, h1_footer = body(h1)
    total_rows, total_footer = body(total)
    assert sorted(total_rows, key=repr) == sorted(h1_rows, key=repr) and total_footer == h1_footer  # h2 is clean


def test_template_text_in_host_evidence_stays_text_through_the_module_arguments(tmp_path):
    out = tmp_path / "run"
    out.mkdir()
    model = _model()
    evidence = "{{ lookup('pipe', 'echo pwned') }} {% if x %}"
    model["config_vulnerability"]["findings"][0]["hosts"][0]["evidence"] = evidence
    _run(tmp_path, out, model)
    for name in ("h1", "total"):  # the total carries the same cell, and it is text there too
        ws = openpyxl.load_workbook(out / ("xlsx/host-audit-ha-1-%s.xlsx" % name)).active
        texts = [c.value for row in ws.iter_rows() for c in row if isinstance(c.value, str)]
        assert any(evidence in t for t in texts), name


def test_a_host_whose_plan_cannot_be_built_gets_a_one_line_file_and_the_run_goes_on(tmp_path):
    out = tmp_path / "run"
    out.mkdir()
    model = _model()
    model["config_vulnerability"]["findings"][0]["hosts"][0].pop("evidence")  # h1's entry is broken
    stats = _run(tmp_path, out, model)
    assert {"xlsx/host-audit-ha-1-h1.xlsx", "xlsx/host-audit-ha-1-h2.xlsx"} <= set(stats)
    ws = openpyxl.load_workbook(out / "xlsx/host-audit-ha-1-h1.xlsx").active
    assert ws["D2"].value.startswith("이행계획서 생성 실패 (KeyError")


def test_the_run_stops_when_every_plan_failed_but_not_when_one_did(tmp_path):
    assert_task = _named("Stop when the Remediation Plan could not be built for any host")
    for failing, ok in ((2, False), (1, True)):
        facts = {"f%d" % i: ({"error": "KeyError: x", "label": "h%d" % i, "kind": "items"}
                  if i < failing else {"rows": [], "kind": "items"})
                 for i in range(2)}
        facts["total"] = {"rows": [], "label": "합계 xlsx", "kind": "total"}  # the total has no error: it must not hide that every host failed
        pb = tmp_path / ("a%d.yml" % failing)
        pb.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local", "gather_facts": False,
                                       "vars": {"_host_audit_remediation_by_file": facts,
                                                "host_audit_model": {"hosts": ["h0", "h1"]}}, "tasks": [assert_task]}],
                                     allow_unicode=True))
        res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True,
                             stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=120)
        assert (res.returncode == 0) is ok, res.stdout[-1500:]


def _problem(hosts):
    return {"failed": bool(hosts), "targets": hosts}


def test_a_failed_write_does_not_stop_the_run_until_the_final_judgement(tmp_path):
    write = _task("report.yml", "AUD-025")
    assert write["ignore_errors"] is True and write["register"] == "_host_audit_xlsx_write"
    judge = _named("Fail the run when a Remediation Plan xlsx could not be written")
    block = next(t for t in _tasks("report.yml") if "always" in t)["block"]
    names = [t.get("name", "") for t in block]
    assert names.index(judge["name"]) > names.index("Judge the report mail")  # after keeping and mailing
    for failed, ok in (([{"failed": True, "item": "h2"}, {"item": "h1"}], False), ([{"item": "h1"}], True)):
        pb = tmp_path / ("j%d.yml" % len(failed))
        pb.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local", "gather_facts": False,
                                       "vars": {"_host_audit_xlsx_problem": _problem([r["item"] for r in failed if r.get("failed")])}, "tasks": [judge]}],
                                     allow_unicode=True))
        res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True,
                             stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=120)
        assert (res.returncode == 0) is ok, res.stdout[-1500:]
        if not ok:
            assert "h2" in res.stdout


def test_the_failed_hosts_of_a_real_failing_write_loop_are_collected(tmp_path):
    """Runs the real loop: the run directory does not exist, so the writer cannot create xlsx/ (one level only)."""
    model_file = tmp_path / "model.json"
    model_file.write_text(json.dumps(_model(), ensure_ascii=False))
    load = {"ansible.builtin.set_fact": {"host_audit_model": "{{ lookup('ansible.builtin.file', '%s') | from_json }}"
                                         % model_file}}
    pb = tmp_path / "f.yml"
    pb.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "vars": {"host_audit_run": {"run_id": "ha-1", "run_kind": "scheduled", "output_dir": str(tmp_path / "missing")}},
        "tasks": [load, _plan_task(), _task("report.yml", "AUD-025"),
                  _named("Collect the hosts whose Remediation Plan xlsx could not be written"),
                  {"ansible.builtin.debug": {"var": "_host_audit_xlsx_failed_hosts"}}],
    }], allow_unicode=True))
    env = dict(os.environ, ANSIBLE_LIBRARY=str(ROOT_DIR / "roles" / "host_audit" / "library"),
               ANSIBLE_MODULE_UTILS=str(ROOT_DIR / "roles" / "host_audit" / "module_utils"),
               ANSIBLE_FILTER_PLUGINS=str(ROOT_DIR / "filter_plugins"), ANSIBLE_STDOUT_CALLBACK="ansible.posix.json")
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300, env=env)
    assert res.returncode == 0, res.stdout[-2000:]
    tasks = json.JSONDecoder().raw_decode(res.stdout[res.stdout.index("{"):])[0]["plays"][0]["tasks"]
    assert tasks[-1]["hosts"]["localhost"]["_host_audit_xlsx_failed_hosts"] == ["h1", "h2", "합계 xlsx"]  # the total is a file of its own


def test_the_xlsx_is_written_for_an_on_demand_run_too(tmp_path):
    out = tmp_path / "run"
    out.mkdir()
    assert "xlsx/host-audit-ha-1-h1.xlsx" in _run(tmp_path, out, _model(), run_kind="on_demand")


def test_upload_maps_the_xlsx_content_type():
    upload = _task("storage_upload.yml", "AUD-514")
    assert "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" in upload["vars"]["_content_type"]
    assert ".xlsx" in upload["vars"]["_content_type"]
    assert "'.zip': 'application/zip'" in upload["vars"]["_content_type"]  # the xlsx zip of the mail attachment (AUD-026)


def test_the_writer_is_inside_the_cleanup_block_before_the_upload():
    """A failing AUD-025 must still reach the always: cleanup (it says why the directory is kept)."""
    block = next(t for t in _tasks("report.yml") if "always" in t)
    names = [t.get("name", "") for t in block["block"]]
    write = next(i for i, n in enumerate(names) if "[AUD-025]" in n)
    assert write < names.index("Keep the originals in the Host Audit bucket")
    assert "[AUD-025]" not in " ".join(t.get("name", "") for t in _tasks("report.yml") if "block" not in t)


def test_a_failing_item_does_not_echo_the_rows(tmp_path):
    """The loop only carries host names, so a failing item prints no rows; the plan is built once in a set_fact
    (deliberately not no_log, so a filter error stays readable)."""
    write = _task("report.yml", "AUD-025")
    assert write["loop"] == "{{ _host_audit_remediation_by_file | list }}"  # ASCII file names, not plans
    assert "no_log" not in _plan_task()  # a filter error must stay readable
