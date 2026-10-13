"""Audit Baseline from files, not from facts (#156, Spec #148).

The previous scheduled run's findings.json (hundreds of thousands of Package ids) goes to the runner disk; the custom
module ``host_audit_baseline_load`` splits the Package ids into per-host files and the comparison reads them one host
at a time. The statuses stay what tests/test_host_audit_baseline.py defines; here the expected values come from the
same comparison run on the old in-memory shape, and the input is an old-format findings.json (schema_version 1).
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
ROLE = ROOT_DIR / "roles" / "host_audit"
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit_baseline import FIRST, NEW, PERSIST, host_audit_baseline_section  # noqa: E402

import ansible.module_utils  # noqa: E402

ansible.module_utils.__path__.append(str(ROLE / "module_utils"))  # what ANSIBLE_MODULE_UTILS does for a run


def _load_module(name):
    spec = importlib.util.spec_from_file_location(name, ROLE / "library" / ("%s.py" % name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


writer = _load_module("host_audit_findings_write")
_spec = importlib.util.spec_from_file_location("host_audit_baseline_load", ROLE / "library" / "host_audit_baseline_load.py")
loader = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(loader)

PKG = "package_vulnerability"
# findings.json as the code before #156 stored it (and as every kept run in the bucket is).
OLD_FORMAT = {
    "schema_version": 1, "run_id": "ha-prev", "run_kind": "scheduled", "started_at": "2026-10-01T00:00:00Z",
    "baseline_run_id": "", "resolved": [],
    "sections": {
        "config_vulnerability": {"hosts": ["a"], "ids": {"a": ["KISA-2026:U-01", "KISA-2026:U-02"]}},
        "asset_inventory": {"hosts": ["a"], "ids": {"a": ["account:alice"]}},
        PKG: {"hosts": ["a", "b", "gone"], "ids": {
            "a": ["CVE-1|openssl", "CVE-OLD|zlib"], "b": ["CVE-B|bash"], "gone": ["CVE-X|bash"]}},
    },
}
RUN_META = {"run_id": "ha-new", "run_kind": "scheduled", "started_at": "2026-11-01T00:00:00Z", "timezone": "Asia/Seoul"}


def _current_findings(tmp_path):
    """This run's Package findings as host_audit_package_scan leaves them on disk."""
    out = tmp_path / "package_findings"
    out.mkdir()
    for host, ids in {"a": ["CVE-1|openssl", "CVE-NEW|curl"], "b": ["CVE-B|bash"]}.items():
        findings = [{"id": i, "cve": i.split("|")[0], "package": i.split("|")[1]} for i in ids]
        (out / ("%s.json" % host)).write_text(json.dumps({"host": host, "status": "ok", "findings": findings}))
    return out


def _model():
    return {"cover": {"baseline": ""},
            PKG: {"status": "ok", "hosts": [{"host": "a", "inspected": True}, {"host": "b", "inspected": True}],
                  "details": [{"host": "a", "id": "CVE-1|openssl", "cve": "CVE-1", "package": "openssl"},
                              {"host": "a", "id": "CVE-NEW|curl", "cve": "CVE-NEW", "package": "curl"}]},
            "config_vulnerability": {"appendix": {"a": [{"code": "KISA-2026:U-01", "title": "root", "verdict": "취약"}]},
                                     "findings": []}}


def test_old_format_findings_json_is_split_so_the_package_ids_stay_on_disk(tmp_path):
    src = tmp_path / "previous_findings.json"
    src.write_text(json.dumps(OLD_FORMAT))
    document, hosts, ids = loader.load(str(src), str(tmp_path / "previous"))

    assert (hosts, ids) == (3, 4)
    assert document["run_id"] == "ha-prev" and document["started_at"] == "2026-10-01T00:00:00Z"
    assert document["sections"]["config_vulnerability"] == OLD_FORMAT["sections"]["config_vulnerability"]
    assert document["sections"]["asset_inventory"] == OLD_FORMAT["sections"]["asset_inventory"]
    package = document["sections"][PKG]
    assert "ids" not in package and package["hosts"] == ["a", "b", "gone"] and package["ids_hosts"] == ["a", "b", "gone"]
    assert json.loads((tmp_path / "previous" / "a.json").read_text()) == ["CVE-1|openssl", "CVE-OLD|zlib"]
    assert oct((tmp_path / "previous" / "a.json").stat().st_mode & 0o777) == "0o600"


@pytest.mark.parametrize("content", [None, "", "{not json", "[1, 2]"])
def test_missing_or_damaged_findings_json_is_not_a_baseline(tmp_path, content):
    src = tmp_path / "previous_findings.json"
    if content is not None:
        src.write_text(content)
    assert loader.load(str(src), str(tmp_path / "previous"))[0] is None


def test_a_second_load_leaves_no_host_files_of_the_first(tmp_path):
    src = tmp_path / "previous_findings.json"
    src.write_text(json.dumps(OLD_FORMAT))
    loader.load(str(src), str(tmp_path / "previous"))
    smaller = json.loads(json.dumps(OLD_FORMAT))
    smaller["sections"][PKG] = {"hosts": ["a"], "ids": {"a": ["CVE-1|openssl"]}}
    src.write_text(json.dumps(smaller))
    loader.load(str(src), str(tmp_path / "previous"))
    assert sorted(p.name for p in (tmp_path / "previous").glob("*.json")) == ["a.json"]


def test_statuses_from_the_split_baseline_equal_those_from_the_whole_document(tmp_path):
    """New (신규), persisting (지속), recurring (재발), resolved (해소) come out the same as with the old shape."""
    findings = _current_findings(tmp_path)
    src = tmp_path / "previous_findings.json"
    src.write_text(json.dumps(OLD_FORMAT))
    split, _, _ = loader.load(str(src), str(tmp_path / "previous"))
    meta = dict(RUN_META, package_findings_dir=str(findings))
    pointers = [{"run_id": "ha-mar", "run_kind": "scheduled", "started_at": "2026-03-01T00:00:00Z",
                 "resolved": ["package_vulnerability|a|CVE-NEW|curl"]}]

    whole = host_audit_baseline_section(_model(), {"state": "ok", "baseline": OLD_FORMAT, "pointers": pointers}, meta)
    files = host_audit_baseline_section(_model(), {"state": "ok", "baseline": split, "pointers": pointers}, meta)

    assert files == whole
    rows = {d["id"]: d["baseline"]["status"] for d in files[PKG]["details"]}
    assert rows == {"CVE-1|openssl": PERSIST, "CVE-NEW|curl": "재발"}
    assert ("a", "CVE-OLD zlib") in [(r["host"], r["item"]) for r in files["baseline"]["resolved"]]
    assert [(r["host"], r["item"]) for r in files["baseline"]["unknown"]] == [("gone", "CVE-X bash")]


def test_the_first_run_and_a_new_package_finding_keep_their_status(tmp_path):
    findings = _current_findings(tmp_path)
    meta = dict(RUN_META, package_findings_dir=str(findings))
    first = host_audit_baseline_section(_model(), {"state": "ok", "baseline": None, "pointers": []}, meta)
    assert {d["baseline"]["status"] for d in first[PKG]["details"]} == {FIRST}
    src = tmp_path / "previous_findings.json"
    src.write_text(json.dumps(OLD_FORMAT))
    split, _, _ = loader.load(str(src), str(tmp_path / "previous"))
    later = host_audit_baseline_section(_model(), {"state": "ok", "baseline": split, "pointers": []}, meta)
    assert {d["id"]: d["baseline"]["status"] for d in later[PKG]["details"]}["CVE-NEW|curl"] == NEW


# ------------------------------------------------------------------------------
# The tasks: the previous findings go to disk, the facts keep only the small part
# ------------------------------------------------------------------------------
def _tasks(name):
    return yaml.safe_load((ROLE / "tasks" / name).read_text(encoding="utf-8"))


def _task(filename, spec_id):
    return next(t for t in _tasks(filename) if "[%s]" % spec_id in t.get("name", ""))


def test_previous_findings_are_downloaded_to_a_runner_only_file_and_not_into_a_variable():
    get = _task("storage_lookup.yml", "AUD-505")
    uri = get["ansible.builtin.uri"]
    assert not uri.get("return_content")
    assert uri["dest"].endswith("/package_findings/previous_findings.json"), "package_findings/ is never archived (#155)"
    assert uri["mode"] == "0600" and get["no_log"] is True
    load = _task("storage_lookup.yml", "AUD-508")
    assert load["host_audit_baseline_load"]["src"] == uri["dest"]
    assert load["host_audit_baseline_load"]["ids_dir"].endswith("/package_findings/previous")
    names = [t["name"] for t in _tasks("storage_lookup.yml")]
    order = [next(i for i, n in enumerate(names) if "[%s]" % s in n) for s in ("AUD-507", "AUD-505", "AUD-508", "AUD-506")]
    assert order == sorted(order), "directory, download, split, then the decision"


def test_the_decision_reads_the_split_result_and_never_the_downloaded_content():
    text = json.dumps(_task("storage_lookup.yml", "AUD-506"))
    assert "_host_audit_baseline_get.content" not in text
    assert "_host_audit_baseline_loaded" in text


def _decide(tmp_path, previous_text, status=200):
    """Run AUD-507, AUD-508 and AUD-506 as storage_lookup.yml has them; the download itself is a file written here."""
    out = tmp_path / "run"
    (out / "package_findings").mkdir(parents=True)
    if previous_text is not None:
        (out / "package_findings" / "previous_findings.json").write_text(previous_text)
    tasks = [_task("storage_lookup.yml", s) for s in ("AUD-507", "AUD-508", "AUD-506")]
    pb = tmp_path / "pb.yml"
    pb.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
        "vars_files": [str(ROLE / "defaults" / "main.yml")],
        "vars": {"host_audit_run": {"output_dir": str(out)}, "_host_audit_storage_active": True,
                 "_host_audit_storage_problem": "", "_host_audit_pointer_list": {"status": 200},
                 "_host_audit_pointer_docs": {"results": []}, "_host_audit_baseline_get": {"status": status},
                 "_pick": {"findings_key": "x"}},
        "tasks": tasks + [{"ansible.builtin.debug": {"var": "host_audit_baseline_history"}, "name": "show"}],
    }], allow_unicode=True))
    env = dict(os.environ, ANSIBLE_LIBRARY=str(ROLE / "library"), ANSIBLE_MODULE_UTILS=str(ROLE / "module_utils"),
               ANSIBLE_STDOUT_CALLBACK="ansible.posix.json")
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300, env=env)
    assert res.returncode == 0, res.stdout[-3000:] + res.stderr[-2000:]
    play = json.JSONDecoder().raw_decode(res.stdout[res.stdout.index("{"):])[0]["plays"][0]["tasks"]
    return next(t for t in play if t["task"]["name"] == "show")["hosts"]["localhost"]["host_audit_baseline_history"], out


def test_old_format_baseline_goes_through_the_tasks_without_its_ids_entering_the_facts(tmp_path):
    if not shutil.which("ansible-playbook"):
        pytest.skip("ansible-playbook not installed")
    history, out = _decide(tmp_path, json.dumps(OLD_FORMAT))
    assert history["state"] == "ok"
    assert history["baseline"]["run_id"] == "ha-prev"
    assert "CVE-OLD" not in json.dumps(history)
    assert json.loads((out / "package_findings" / "previous" / "a.json").read_text()) == ["CVE-1|openssl", "CVE-OLD|zlib"]


def test_a_damaged_baseline_or_failed_download_still_fails_the_lookup_but_not_the_report(tmp_path):
    if not shutil.which("ansible-playbook"):
        pytest.skip("ansible-playbook not installed")
    history, _ = _decide(tmp_path / "damaged", "{not json")
    assert history["state"] == "failed" and "findings.json" in history["reason"]
    history, _ = _decide(tmp_path / "missing", None, status=404)
    assert history["state"] == "failed" and "404" in history["reason"]


# ---- one file-name rule for every writer and reader (#148) ------------------

ODD_HOST = "web/01 ../ü"


def test_an_unusual_host_name_is_written_and_read_under_the_same_file_name_everywhere(tmp_path):
    from host_audit_files import host_audit_host_file

    # previous findings.json -> per-host ids (baseline_load)
    old = json.loads(json.dumps(OLD_FORMAT))
    old["sections"][PKG] = {"hosts": [ODD_HOST], "ids": {ODD_HOST: ["CVE-1|openssl"]}}
    src = tmp_path / "previous_findings.json"
    src.write_text(json.dumps(old))
    previous = tmp_path / "previous"
    split, _, _ = loader.load(str(src), str(previous))
    assert [p.name for p in previous.iterdir()] == [Path(host_audit_host_file(str(previous), ODD_HOST)).name]

    # this run's per-host findings, named by the same rule (as host_audit_package_scan does)
    current = tmp_path / "package_findings"
    current.mkdir()
    findings = [{"id": "CVE-1|openssl", "cve": "CVE-1", "package": "openssl"}]
    Path(host_audit_host_file(str(current), ODD_HOST)).write_text(
        json.dumps({"host": ODD_HOST, "status": "ok", "findings": findings}))
    assert sorted(p.name for p in tmp_path.iterdir()) == ["package_findings", "previous", "previous_findings.json"]

    # the findings writer reads it ...
    assert writer._host_ids(str(current), ODD_HOST) == ["CVE-1|openssl"]
    # ... and so does the comparison, which also finds the previous id: persisting, not new
    model = {"cover": {"baseline": ""},
             PKG: {"status": "ok", "hosts": [{"host": ODD_HOST, "inspected": True}],
                   "details": [{"host": ODD_HOST, "id": "CVE-1|openssl", "cve": "CVE-1", "package": "openssl"}]}}
    out = host_audit_baseline_section(model, {"state": "ok", "baseline": split, "pointers": []},
                                      dict(RUN_META, package_findings_dir=str(current)))
    assert [d["baseline"]["status"] for d in out[PKG]["details"]] == [PERSIST]
