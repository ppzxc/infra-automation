"""Host Audit — Package Vulnerability (ADR-0009, #123).

Only observable behaviour is asserted:
- the raw package probe output (real output of package_probe.sh on 6 OS images) becomes a package record;
- the record becomes a CycloneDX SBOM that Trivy judges exactly like ``trivy image``;
- the DB freshness rule, the CentOS 6/7 / will-not-fix classification and the section model;
- the report model and template carry the section.

SBOM equivalence chain (Vuls PoC #112 method): tests/fixtures/host_audit_packages was produced by running
package_probe.sh in each image, converting with host_audit_sbom, and checking that ``trivy sbom`` and
``trivy image`` give the same (CVE, package, installed, status, fixed) set — 0 differences on all 6 OSes.
``sbom_equivalence.json`` pins the digest of each SBOM that passed. If the converter's output changes, the
digest test fails: re-run the comparison with Trivy (see docs/host_audit.md §Package Vulnerability) and
update the fixtures only when it still shows 0 differences. pytest itself needs no network and no Trivy.
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
sys.path.insert(0, str(ROOT_DIR / "filter_plugins"))

from host_audit import host_audit_report_model  # noqa: E402
from host_audit_packages import (  # noqa: E402
    host_audit_package_findings,
    host_audit_package_record,
    host_audit_package_section,
    host_audit_sbom,
    host_audit_trivy_db_state,
    host_audit_trivy_provenance,
    parse_vault_final,
    rpm_vr_compare,
)

FIXTURES = ROOT_DIR / "tests" / "fixtures" / "host_audit_packages"
ROLE = ROOT_DIR / "roles" / "host_audit"
PROBE_SCRIPT = ROLE / "files" / "package_probe.sh"
EQUIVALENCE = json.loads((FIXTURES / "sbom_equivalence.json").read_text(encoding="utf-8"))
COLLECTED_AT = EQUIVALENCE["collected_at"]
NOW = "2026-10-08T22:00:00Z"


def _record(name):
    stdout = (FIXTURES / ("%s.probe.txt" % name)).read_text(encoding="utf-8")
    return host_audit_package_record({"stdout": stdout, "rc": 0}, name, COLLECTED_AT)


def _vault(major):
    return parse_vault_final((ROLE / "files" / "centos_vault_final" / ("centos-%s.tsv" % major)).read_text(encoding="utf-8"))


def _fresh_db():
    return host_audit_trivy_db_state(True, {"UpdatedAt": "2026-10-07T07:38:55.515026687Z",
                                            "DownloadedAt": "2026-10-08T12:58:07.64804309Z"}, NOW)


# ------------------------------------------------------------------------------
# package record
# ------------------------------------------------------------------------------
@pytest.mark.parametrize("name, family, version, fmt, count", [
    ("rocky9", "rocky", "9.8", "rpm", 146),
    ("rocky8", "rocky", "8.10", "rpm", 148),
    ("centos7", "centos", "7.9.2009", "rpm", 148),
    ("centos6", "centos", "6.10", "rpm", 129),
    ("ubuntu2204", "ubuntu", "22.04", "deb", 101),
    ("debian13", "debian", "13.7", "deb", 78),
])
def test_probe_output_becomes_package_record(name, family, version, fmt, count):
    rec = _record(name)
    assert rec["status"] == "ok"
    assert rec["os"]["family"] == family and rec["os"]["version"] == version
    assert rec["format"] == fmt
    assert len(rec["packages"]) == count
    assert all(p["name"] != "gpg-pubkey" for p in rec["packages"])


def test_centos6_without_os_release_is_identified_from_redhat_release():
    rec = _record("centos6")
    assert rec["os"]["family"] == "centos" and rec["os"]["major"] == "6"
    assert rec["os"]["name"] == "CentOS release 6.10 (Final)"


def test_deb_source_version_keeps_epoch_apart_from_binary_epoch():
    pkgs = {p["name"]: p for p in _record("ubuntu2204")["packages"]}
    # bsdutils 1:2.37.2-4ubuntu3.6 is built from util-linux 2.37.2-4ubuntu3.6 (no source epoch)
    assert (pkgs["bsdutils"]["epoch"], pkgs["bsdutils"]["src_name"], pkgs["bsdutils"]["src_epoch"]) == ("1", "util-linux", "")
    assert (pkgs["diffutils"]["src_epoch"], pkgs["diffutils"]["src_version"], pkgs["diffutils"]["src_release"]) == ("1", "3.8", "0ubuntu2.1")


def test_unreachable_and_markerless_probes_are_not_ok():
    assert host_audit_package_record({"unreachable": True, "msg": "timed out"}, "h", NOW)["status"] == "unreachable"
    failed = host_audit_package_record({"stdout": "", "stderr": "sh: rpm: Permission denied", "rc": 1}, "h", NOW)
    assert failed["status"] == "probe_failed" and "Permission denied" in failed["reason"]
    none = host_audit_package_record({"stdout": "===RELEASE===\nID=alpine\nVERSION_ID=3.22\n===PKGS_NONE===\n===END===\n"}, "h", NOW)
    assert none["status"] == "unsupported"


def test_probe_script_runs_here_and_parses():
    if not shutil.which("sh") or not (shutil.which("rpm") or shutil.which("dpkg-query")):
        pytest.skip("no sh or package manager on this machine")
    out = subprocess.run(["sh", "-s"], input=PROBE_SCRIPT.read_text(encoding="utf-8"),
                         capture_output=True, text=True, timeout=60)
    rec = host_audit_package_record({"stdout": out.stdout, "stderr": out.stderr, "rc": out.returncode}, "local", NOW)
    assert rec["format"] in ("rpm", "deb")
    assert len(rec["packages"]) > 0


def test_probe_script_is_posix_sh_and_reads_only():
    text = "\n".join(l for l in PROBE_SCRIPT.read_text(encoding="utf-8").splitlines() if not l.lstrip().startswith("#"))
    assert "python" not in text.lower()
    for writer in (" > /", ">>", "rm ", "mv ", "install", "yum ", "dnf ", "apt-get", "touch "):
        assert writer not in text, writer


# ------------------------------------------------------------------------------
# SBOM
# ------------------------------------------------------------------------------
@pytest.mark.parametrize("name", sorted(EQUIVALENCE["hosts"]))
def test_sbom_is_the_one_trivy_judged_like_trivy_image(name):
    pinned = EQUIVALENCE["hosts"][name]
    text = json.dumps(host_audit_sbom(_record(name)), sort_keys=True, ensure_ascii=False)
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == pinned["sbom_sha256"], (
        "SBOM output changed: re-run the trivy sbom vs trivy image comparison before updating the fixture")
    pairs = [l for l in (FIXTURES / ("%s.trivy-image.pairs.tsv" % name)).read_text(encoding="utf-8").splitlines()
             if l and not l.startswith("#")]
    assert len(pairs) == pinned["pairs"] > 0


def test_sbom_root_is_application_with_a_single_os_component():
    sbom = host_audit_sbom(_record("rocky9"))
    assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"
    assert sbom["metadata"]["component"]["type"] == "application"
    oses = [c for c in sbom["components"] if c["type"] == "operating-system"]
    assert [(o["name"], o["version"]) for o in oses] == [("rocky", "9.8")]
    libs = [c["bom-ref"] for c in sbom["components"] if c["type"] == "library"]
    deps = {d["ref"]: d["dependsOn"] for d in sbom["dependencies"]}
    assert sorted(deps[oses[0]["bom-ref"]]) == sorted(libs)


def test_sbom_purls_carry_epoch_and_distro():
    comps = {c["name"]: c for c in host_audit_sbom(_record("rocky9"))["components"]}
    assert comps["openssl-libs"]["purl"].startswith("pkg:rpm/rocky/openssl-libs@3.5.5-2.el9_8?arch=x86_64&distro=rocky-9.8&epoch=1")
    props = {p["name"]: p["value"] for p in comps["openssl-libs"]["properties"]}
    assert props["aquasecurity:trivy:SrcName"] == "openssl" and props["aquasecurity:trivy:SrcEpoch"] == "1"
    deb = {c["name"]: c for c in host_audit_sbom(_record("debian13"))["components"]}
    assert "%2B" in deb["base-files"]["purl"]  # '+' in versions is percent-encoded


def test_sbom_is_deterministic():
    assert host_audit_sbom(_record("centos7")) == host_audit_sbom(_record("centos7"))


# ------------------------------------------------------------------------------
# Trivy DB freshness
# ------------------------------------------------------------------------------
def test_db_refreshed_this_run_is_fresh_and_dated():
    db = _fresh_db()
    assert db["status"] == "fresh" and db["usable"]
    assert db["updated_at"] == "2026-10-07T07:38:55Z" and db["downloaded_at"] == "2026-10-08T12:58:07Z"


def test_failed_refresh_uses_cache_up_to_seven_days():
    cached = host_audit_trivy_db_state(False, {"UpdatedAt": "2026-10-02T00:00:00Z"}, NOW, refresh_error="dial tcp: timeout")
    assert cached["status"] == "cached" and cached["usable"] and cached["age_days"] == 6.9
    assert cached["refresh_error"] == "dial tcp: timeout"


def test_failed_refresh_with_cache_older_than_seven_days_makes_section_unavailable():
    stale = host_audit_trivy_db_state(False, {"UpdatedAt": "2026-09-30T21:00:00Z"}, NOW)
    assert stale["status"] == "unavailable" and not stale["usable"]
    section = host_audit_package_section([], stale, "0.75.0")
    assert section["status"] == "unavailable"
    assert section["unavailable"] == [{"host": "전체", "item": "Package Vulnerability", "label": "점검불가",
                                       "reason": stale["reason"]}]


def test_numbers_from_extra_vars_are_accepted_as_strings():
    stale = host_audit_trivy_db_state(False, {"UpdatedAt": "2026-10-07T07:38:55Z"}, NOW, "1", "\t* dial tcp: timeout")
    assert stale["status"] == "unavailable" and stale["refresh_error"] == "dial tcp: timeout"
    assert host_audit_package_section([], _fresh_db(), "0.75.0", "5")["status"] == "ok"


def test_no_db_at_all_is_unavailable_even_if_refresh_claims_success():
    assert host_audit_trivy_db_state(True, {}, NOW)["status"] == "unavailable"
    assert host_audit_trivy_db_state(False, None, NOW)["status"] == "unavailable"


# ------------------------------------------------------------------------------
# findings and classification
# ------------------------------------------------------------------------------
def _centos7_findings():
    trivy = json.loads((FIXTURES / "centos7.trivy-sbom.min.json").read_text(encoding="utf-8"))
    return host_audit_package_findings(trivy, _record("centos7"), _vault("7"))


def test_centos7_findings_split_update_from_no_centos_fix_and_will_not_fix():
    hr = _centos7_findings()
    assert hr["status"] == "ok" and hr["eosl"] is True
    cls = {(f["cve"], f["package"]): f["class"] for f in hr["findings"]}
    assert cls[("CVE-2024-33599", "glibc")] == "update"              # fixed 2.17-326.el7_9.3 = vault final
    assert cls[("CVE-2025-49794", "libxml2")] == "no_centos_fix"     # fixed el7_9.10 > vault final el7_9.6 (RHEL 7 ELS only)
    assert cls[("CVE-2020-8625", "bind-license")] == "update"        # epoch 32 ignored against vault file names
    assert cls[("CVE-2015-5186", "audit-libs")] == "will_not_fix"
    assert cls[("CVE-2026-54369", "acl")] == "unfixed"
    assert cls[("CVE-2021-25219", "bind-license")] == "unfixed"      # end_of_life
    assert all(f["id"] == "%s|%s" % (f["cve"], f["package"]) for f in hr["findings"])


def test_non_centos_fixed_findings_are_update_without_vault():
    trivy = {"Metadata": {"OS": {"Family": "rocky", "Name": "9.8"}},
             "Results": [{"Vulnerabilities": [
                 {"VulnerabilityID": "CVE-1", "PkgName": "openssl-libs", "InstalledVersion": "1:3.5.5-2.el9_8",
                  "FixedVersion": "1:3.5.5-3.el9_8", "Status": "fixed", "Severity": "HIGH"}]}]}
    hr = host_audit_package_findings(trivy, _record("rocky9"))
    assert [f["class"] for f in hr["findings"]] == ["update"] and hr["eosl"] is False


def test_trivy_that_did_not_recognise_the_os_fails_the_host_instead_of_reporting_zero():
    trivy = {"Metadata": {"OS": {}}, "Results": []}
    hr = host_audit_package_findings(trivy, _record("rocky9"))
    assert hr["status"] == "scan_failed" and "OS 인식 불일치" in hr["reason"]
    assert host_audit_package_findings(None, _record("rocky9"))["status"] == "scan_failed"


def test_failed_collection_is_carried_into_the_host_result():
    rec = host_audit_package_record({"stdout": "", "rc": 1}, "ns0001", NOW)
    hr = host_audit_package_findings(None, rec)
    assert hr["status"] == "probe_failed" and "패키지 수집 실패" in hr["reason"]


def test_rpm_vr_compare_ignores_epoch_and_orders_releases():
    assert rpm_vr_compare("2.9.1-6.el7_9.10", "2.9.1-6.el7_9.6") == 1
    assert rpm_vr_compare("32:9.11.4-26.P2.el7_9.4", "9.11.4-26.P2.el7_9.16") == -1
    assert rpm_vr_compare("2.17-326.el7_9.3", "2.17-326.el7_9.3") == 0


# ------------------------------------------------------------------------------
# section model, report model, template
# ------------------------------------------------------------------------------
def _section(detail_limit=300):
    good = _centos7_findings()
    bad = host_audit_package_findings(None, _record("rocky9"))
    return host_audit_package_section([good, bad], _fresh_db(), "0.75.0", detail_limit)


def test_section_counts_by_severity_and_class_and_lists_actionable_high_findings():
    s = _section()
    assert s["status"] == "ok" and s["total"] == 7
    assert s["totals"] == {"CRITICAL": 0, "HIGH": 4, "MEDIUM": 3, "LOW": 0, "UNKNOWN": 0}
    assert s["classes"] == {"update": 2, "no_centos_fix": 1, "will_not_fix": 1, "unfixed": 3}
    assert [b["bar"] for b in s["bars"]][:2] == [0.0, 130.0]
    assert {d["severity"] for d in s["details"]} <= {"CRITICAL", "HIGH"}
    assert all(d["class"] != "will_not_fix" for d in s["details"])
    assert len(s["details"]) == 4
    assert "Trivy DB 2026-10-07T07:38:55Z 생성 · 이번 실행에서 갱신" == s["db_label"]


def test_section_marks_failed_hosts_and_caps_details():
    s = _section(detail_limit=1)
    assert [h["inspected"] for h in s["hosts"]] == [True, False]
    assert s["unavailable"] == [{"host": "rocky9", "item": "Package Vulnerability", "label": "점검불가",
                                 "reason": "Trivy 판정 결과 없음 (판정 실패, 러너 로그 참고)"}]
    assert len(s["details"]) == 1 and s["details_truncated"] == 3


def test_report_model_carries_package_section_db_time_and_unavailable_hosts():
    s = _section()
    model = host_audit_report_model([], {"run_id": "ha-1", "targets": [], "package_vulnerability": s})
    assert model["package_vulnerability"] is s
    assert model["cover"]["vuln_db"] == s["db_label"]
    assert any("Package Vulnerability" in c for c in model["cover"]["contents"])
    assert {"host": "rocky9", "item": "Package Vulnerability", "label": "점검불가",
            "reason": "Trivy 판정 결과 없음 (판정 실패, 러너 로그 참고)"} in model["unavailable"]
    plain = host_audit_report_model([], {"run_id": "ha-1", "targets": [], "package_vulnerability": {}})
    assert plain["package_vulnerability"] is None and plain["cover"]["vuln_db"] == ""


def test_template_draws_bars_host_counts_and_details():
    jinja2 = pytest.importorskip("jinja2")
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROLE / "templates")))
    model = host_audit_report_model([], {"run_id": "ha-1", "targets": [], "package_vulnerability": _section()})
    html = env.get_template("report.html.j2").render(host_audit_model=model)
    assert "Package Vulnerability" in html and "<svg" in html and 'class="sev-HIGH"' in html
    assert "CVE-2025-49794" in html and "CentOS용 수정본 없음" in html
    assert "CVE-2015-5186" not in html  # will-not-fix is counted, not detailed
    assert "취약점 DB" in html and "http" not in html.split("<body>")[1].replace("http://www.w3.org", "")
    stale = host_audit_package_section([], host_audit_trivy_db_state(False, {}, NOW), "0.75.0")
    html = env.get_template("report.html.j2").render(
        host_audit_model=host_audit_report_model([], {"targets": [], "package_vulnerability": stale}))
    assert "점검불가" in html and "<svg" not in html


# ------------------------------------------------------------------------------
# pinned Trivy and task wiring
# ------------------------------------------------------------------------------
def _tasks(name):
    return yaml.safe_load((ROLE / "tasks" / name).read_text(encoding="utf-8"))


def test_trivy_is_pinned_by_sha256_for_every_runner_arch():
    pins = yaml.safe_load((ROLE / "vars" / "trivy.yml").read_text(encoding="utf-8"))
    version = pins["host_audit_trivy_version"]
    assert version != "0.69.4"  # GHSA-69fq-xp46-6x23
    sums = pins["host_audit_trivy_checksums"][version]
    assert set(pins["host_audit_trivy_arch"].values()) == set(sums)
    assert all(len(v) == 64 and int(v, 16) >= 0 for v in sums.values())


def test_trivy_runs_only_after_the_checksum_verified_download():
    tasks = _tasks("packages_scan.yml")
    names = [t["name"] for t in tasks]
    download = next(i for i, t in enumerate(tasks) if "ansible.builtin.get_url" in t)
    assert "checksum" in tasks[download]["ansible.builtin.get_url"]
    assert "sha256:" in tasks[download]["ansible.builtin.get_url"]["checksum"]
    extract = next(i for i, t in enumerate(tasks) if "ansible.builtin.unarchive" in t)
    assert extract == download + 1
    for i, t in enumerate(tasks):
        if "ansible.builtin.command" in t and "_host_audit_trivy" in str(t["ansible.builtin.command"]):
            assert i > extract, names[i]
    db = next(t for t in tasks if "download-db-only" in str(t))
    assert db["failed_when"] is False  # a failed refresh falls back to the cache rule, never stops the run


def test_host_side_package_probe_is_raw_read_only_and_skips_uninspected_hosts():
    tasks = _tasks("packages.yml")
    probe = next(t for t in tasks if "ansible.builtin.raw" in t)
    assert "read-only" in probe["name"]
    assert probe["changed_when"] is False and probe["become"] is False and probe["ignore_unreachable"] is True
    assert "package_probe.sh" in probe["ansible.builtin.raw"]
    assert probe["when"] == "host_audit_record.status == 'ok'"


def test_vault_tables_cover_known_centos_final_versions():
    v7, v6 = _vault("7"), _vault("6")
    assert v7["glibc"] == "2.17-326.el7_9.3" and v7["libxml2"] == "2.9.1-6.el7_9.6"
    assert len(v7) > 7000 and len(v6) > 5000


def test_appendix_piece_draws_per_host_counts_or_unavailable():
    jinja2 = pytest.importorskip("jinja2")
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(ROLE / "templates")))
    piece = env.get_template("sections/appendix_package_vulnerability.html.j2")
    s = _section()
    html = piece.render(m={"package_vulnerability": s}, host="centos7")
    assert "높음 4" in html and "CentOS용 수정본 없음 1" in html and "EOS" in html
    assert "점검불가" in piece.render(m={"package_vulnerability": s}, host="rocky9")
    assert piece.render(m={"package_vulnerability": s}, host="not-collected").strip() == ""


def _scan_env(**extra):
    """ansible-playbook environment that finds the role's own module (library/) and its module_utils the way a
    role-run task does. The role-less test playbooks need it spelled out."""
    return dict(os.environ, ANSIBLE_LIBRARY=str(ROLE / "library"), ANSIBLE_MODULE_UTILS=str(ROLE / "module_utils"),
                ANSIBLE_STDOUT_CALLBACK="ansible.posix.json", **extra)


def _trivy_doc(vulns, family="ubuntu", name="22.04"):
    return {"Metadata": {"OS": {"Family": family, "Name": name}}, "Results": [{"Vulnerabilities": vulns}]}


def _vuln(cve, severity="HIGH", pkg="openssl", status="fixed", fixed="3.0.3", installed="3.0.2"):
    return {"VulnerabilityID": cve, "PkgName": pkg, "InstalledVersion": installed, "FixedVersion": fixed,
            "Status": status, "Severity": severity, "Title": "t %s" % cve}


def _write_run(out, cases, os_info=None, os_by_host=None):
    """cases: host -> (trivy output text or None for no file, AUD-321 rc). Returns the fake AUD-321 register items
    (the shape ``command`` gives per loop item: ``item`` = record path, ``rc``)."""
    os_info = os_info or {"family": "ubuntu", "major": "22", "version": "22.04", "name": "Ubuntu 22.04"}
    for sub in ("packages", "trivy", "package_findings"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    scans = []
    for h, (text, rc) in cases.items():
        record = {"inventory_hostname": h, "status": "ok", "packages": [{"name": "openssl"}],
                  "os": (os_by_host or {}).get(h, os_info)}
        path = out / "packages" / ("%s.json" % h)
        path.write_text(json.dumps(record))
        if text is not None:
            (out / "trivy" / ("%s.json" % h)).write_text(text)
        scans.append({"item": str(path), "rc": rc, "changed": False, "failed": False})
    return scans


def _run_scan_tasks(tmp_path, out, scans, detail_limit=300, extra_vars=None):
    """Run the real AUD-322/323 tasks; return the localhost task results of the whole play keyed by task name."""
    tasks = _tasks("packages_scan.yml")
    classify = next(t for t in tasks if "[AUD-322]" in t["name"])
    section = next(t for t in tasks if "[AUD-323]" in t["name"])
    pb = tmp_path / "pb.yml"
    pb.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
        "vars": dict({"host_audit_run": {"output_dir": str(out)}, "host_audit_trivy_db": {"usable": True},
                      "host_audit_trivy_version": "0.0.0", "host_audit_package_detail_limit": detail_limit,
                      "role_path": str(ROLE), "_host_audit_trivy_scans": {"results": scans}}, **(extra_vars or {})),
        "tasks": [{"ansible.builtin.find": {"paths": str(out / "packages"), "patterns": "*.json"},
                   "register": "_host_audit_package_files", "name": "find"}, classify, section,
                  {"ansible.builtin.debug": {"var": "host_audit_package_section"}, "name": "show"}],
    }], allow_unicode=True))
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300, env=_scan_env())
    assert res.returncode == 0, res.stdout[-2000:] + res.stderr[-2000:]
    plays = json.JSONDecoder().raw_decode(res.stdout[res.stdout.index("{"):])[0]["plays"][0]["tasks"]
    return dict((t["task"]["name"], t["hosts"]["localhost"]) for t in plays)


def test_classify_returns_summaries_and_file_paths_never_the_findings(tmp_path):
    """#155: AUD-322 must not carry a host's findings in the loop result or in facts. The module writes them to
    <run>/package_findings/<host>.json and returns the counts, the top details and the path. (Older shapes: set_fact
    accumulation was O(N^2) and killed the 1024M worker in task 265; the in-process filter kept every finding in
    ansible-playbook's memory in task 287.)"""
    if not shutil.which("ansible-playbook"):
        pytest.skip("ansible-playbook not installed")
    out = tmp_path / "run"
    hosts = ["h1", "h2", "h3"]
    cases = {h: (json.dumps(_trivy_doc([_vuln("CVE-2024-%s-%d" % (h, n), "HIGH") for n in range(5)]
                                       + [_vuln("CVE-LOW-%s-%d" % (h, n), "LOW") for n in range(7)])), 0)
             for h in hosts}
    ran = _run_scan_tasks(tmp_path, out, _write_run(out, cases), detail_limit=2)
    items = ran["[AUD-322] Classify the Trivy findings of each host"]["results"]
    assert [i["item"].rsplit("/", 1)[-1] for i in items] == ["h1.json", "h2.json", "h3.json"]
    for item in items:
        host = item["item"].rsplit("/", 1)[-1][:-len(".json")]
        assert "ansible_facts" not in item, "the per-host result must not become a fact"
        carried = json.dumps(item)
        assert "CVE-LOW" not in carried, "findings below the detail threshold must stay in the file"
        assert [h for h in hosts if h != host and "CVE-2024-%s" % h in carried] == [], host
        assert len(item["package_host"]["details"]) == 2, "at most detail_limit detail rows come back"
        file = out / "package_findings" / ("%s.json" % host)
        assert len(json.loads(file.read_text())["findings"]) == 12, "the file holds every finding of the host"
        assert oct(file.stat().st_mode & 0o777) == "0o600"
    section = ran["show"]["host_audit_package_section"]
    assert [h["host"] for h in section["hosts"]] == hosts and section["total"] == 36
    assert len(section["details"]) == 2 and section["details_truncated"] == 13
    assert '"findings"' not in json.dumps(ran["[AUD-323] Build the Package Vulnerability section model"])


def _run_classify(tmp_path, cases):
    """Run the real AUD-322/323 tasks with failing/odd Trivy outputs; return the section model."""
    out = tmp_path / "run"
    ran = _run_scan_tasks(tmp_path, out, _write_run(out, cases))
    return ran["show"]["host_audit_package_section"]


def _good_trivy(cve):
    return json.dumps({"Metadata": {"OS": {"Family": "ubuntu", "Name": "22.04"}},
                       "Results": [{"Vulnerabilities": [{"VulnerabilityID": cve, "PkgName": "openssl",
                                                         "InstalledVersion": "3.0.2", "FixedVersion": "3.0.3",
                                                         "Status": "fixed", "Severity": "HIGH"}]}]})


def test_failed_trivy_marks_only_that_host_unavailable_with_the_cause_and_the_run_continues(tmp_path):
    """#154: task 287 — Trivy OOM-killed on 3 hosts must not look healthy. Four failure shapes, plus healthy hosts."""
    if not shutil.which("ansible-playbook"):
        pytest.skip("ansible-playbook not installed")
    good = _good_trivy("CVE-2024-1")
    section = _run_classify(tmp_path, {
        "a-ok": (good, 0),
        "b-rc137": (good, 137),                              # rc != 0 although the JSON looks valid
        "c-empty": ("", 0),                                  # 0-byte output
        "d-truncated": (good[:len(good) // 2], 0),           # killed mid-write
        "e-nofile": (None, 2),                               # no result file
        "g-nofile-rc0": (None, 0),                           # file missing although rc=0: the lookup(errors=ignore) path
        "f-ok": (good, 0),
    })
    assert {h["host"]: h["inspected"] for h in section["hosts"]} == {
        "a-ok": True, "b-rc137": False, "c-empty": False, "d-truncated": False, "e-nofile": False,
        "g-nofile-rc0": False, "f-ok": True}
    reasons = {u["host"]: u["reason"] for u in section["unavailable"]}
    assert set(reasons) == {"b-rc137", "c-empty", "d-truncated", "e-nofile", "g-nofile-rc0"}
    assert all(u["item"] == "Package Vulnerability" and u["label"] == "점검불가" for u in section["unavailable"])
    assert "rc=137" in reasons["b-rc137"] and "OOM-kill" in reasons["b-rc137"]
    assert "비어" in reasons["c-empty"]
    assert "JSON" in reasons["d-truncated"]
    assert "rc=2" in reasons["e-nofile"]
    assert "결과 없음" in reasons["g-nofile-rc0"] and "rc=0" in reasons["g-nofile-rc0"]
    assert section["total"] == 2  # the two healthy hosts are still judged


def test_trivy_rc_decides_before_the_output_and_describes_signal_kills():
    ok = json.loads(_good_trivy("CVE-1"))
    rec = _record("ubuntu2204")
    ok["Metadata"]["OS"] = {"Family": "ubuntu", "Name": rec["os"]["version"]}
    assert host_audit_package_findings(ok, rec, None, 0)["status"] == "ok"
    killed = host_audit_package_findings(ok, rec, None, 137)
    assert killed["status"] == "scan_failed" and "rc=137" in killed["reason"] and "OOM-kill" in killed["reason"]
    assert "OOM-kill" in host_audit_package_findings(None, rec, None, -9)["reason"]  # Ansible reports signal kills as -9
    assert "OOM-kill" not in host_audit_package_findings(ok, rec, None, 1)["reason"]


# ------------------------------------------------------------------------------
# #155: same report as before, findings on disk instead of in ansible-playbook
# ------------------------------------------------------------------------------
CENTOS7 = {"family": "centos", "major": "7", "version": "7", "name": "CentOS Linux 7"}


def _mixed_cases():
    """Every classification, severities, a duplicate, a failed Trivy and a clean host."""
    ubuntu = [_vuln("CVE-2024-%04d" % n, ["CRITICAL", "HIGH", "MEDIUM", "LOW"][n % 4], pkg="pkg%d" % (n % 5))
              for n in range(40)]
    ubuntu += [ubuntu[0], _vuln("CVE-W", "HIGH", status="will_not_fix", fixed=""),
               _vuln("CVE-U", "CRITICAL", status="affected", fixed="")]
    centos = [_vuln("CVE-C-1", "HIGH", pkg="glibc", fixed="2.17-326.el7_9.3"),     # in the vault: updatable
              _vuln("CVE-C-2", "CRITICAL", pkg="glibc", fixed="2.17-999.el7"),     # newer than the vault: no CentOS fix
              _vuln("CVE-C-3", "HIGH", pkg="not-in-vault", fixed="9.9")]
    return {
        "a-ubuntu": (json.dumps(_trivy_doc(ubuntu)), 0),
        "b-centos7": (json.dumps(_trivy_doc(centos, "centos", "7")), 0),
        "c-clean": (json.dumps(_trivy_doc([])), 0),
        "d-killed": (json.dumps(_trivy_doc(ubuntu)), 137),
        "e-empty": ("", 0),
    }, {"b-centos7": CENTOS7}


def _legacy_results(cases, os_by_host):
    """What the in-process filters built before #155 (kept as the reference for the same synthetic input)."""
    out = []
    for h, (text, rc) in cases.items():
        os_info = os_by_host.get(h, {"family": "ubuntu", "major": "22", "version": "22.04", "name": "Ubuntu 22.04"})
        record = {"inventory_hostname": h, "status": "ok", "packages": [{"name": "openssl"}], "os": os_info}
        vault = _vault(os_info["major"]) if os_info["family"] == "centos" else {}
        out.append(host_audit_package_findings(text, record, vault, rc))
    return out


def test_section_model_is_the_same_as_the_in_process_filters_gave(tmp_path):
    if not shutil.which("ansible-playbook"):
        pytest.skip("ansible-playbook not installed")
    cases, os_by_host = _mixed_cases()
    out = tmp_path / "run"
    ran = _run_scan_tasks(tmp_path, out, _write_run(out, cases, os_by_host=os_by_host), detail_limit=6)
    new = ran["show"]["host_audit_package_section"]
    old = host_audit_package_section(_legacy_results(cases, os_by_host), {"usable": True}, "0.0.0", 6)
    assert new == old
    assert new["total"] > 40 and new["details_truncated"] > 0 and len(new["unavailable"]) == 2


def test_report_model_baseline_and_findings_json_are_the_same_as_before(tmp_path):
    """The Audit Baseline section (counts, badges, rows) and the stored findings.json built from the files on disk
    equal what the old path built from the in-memory results of the same input."""
    if not shutil.which("ansible-playbook"):
        pytest.skip("ansible-playbook not installed")
    from host_audit_baseline import host_audit_baseline_section
    cases, os_by_host = _mixed_cases()
    out = tmp_path / "run"
    ran = _run_scan_tasks(tmp_path, out, _write_run(out, cases, os_by_host=os_by_host), detail_limit=6)
    section = ran["show"]["host_audit_package_section"]
    legacy = _legacy_results(cases, os_by_host)
    ids = lambda hr: sorted(set(f["id"] for f in hr["findings"]))  # noqa: E731
    base = {"schema_version": 1, "run_id": "ha-prev", "started_at": "2026-10-01T00:00:00Z", "sections": {
        "package_vulnerability": {"hosts": ["a-ubuntu", "b-centos7", "gone"], "ids": {
            "a-ubuntu": ids(legacy[0])[:20] + ["CVE-OLD|zlib"], "b-centos7": ["CVE-C-1|glibc"], "gone": ["CVE-X|bash"]}}}}
    history = {"state": "ok", "baseline": base, "pointers": [
        {"run_id": "ha-old", "run_kind": "scheduled", "started_at": "2026-09-01T00:00:00Z",
         "resolved": ["package_vulnerability|a-ubuntu|CVE-OLD|zlib", "package_vulnerability|a-ubuntu|CVE-2024-0030|pkg0"]}]}
    meta = {"run_id": "ha-new", "run_kind": "scheduled", "started_at": "2026-11-01T00:00:00Z", "timezone": "Asia/Seoul"}
    model = {"cover": {"baseline": ""}, "package_vulnerability": section}
    old = host_audit_baseline_section(dict(model), history, dict(meta, package_results=legacy))
    new = host_audit_baseline_section(dict(model), history, dict(meta, package_findings_dir=str(out / "package_findings")))

    old_doc, new_doc = old["baseline"].pop("document"), new["baseline"].pop("document")
    new_index = new["baseline"].pop("package_index")
    for key in old["baseline"]:
        assert new["baseline"][key] == old["baseline"][key], key
    assert new == old
    assert new_index["hosts"] == sorted(h["host"] for h in legacy if h["status"] == "ok")
    assert "package_vulnerability" not in new_doc["sections"], "the ids stay on disk, not in the model"
    assert new_doc == dict(old_doc, sections={k: v for k, v in old_doc["sections"].items()
                                              if k != "package_vulnerability"})

    # AUD-510 merges the ids from the files into findings.json: identical to the document the old path stored
    save = next(t for t in _tasks("storage_upload.yml") if "[AUD-510]" in t["name"])
    dest = tmp_path / "findings.json"
    pb = tmp_path / "pb510.yml"
    pb.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
        "vars": {"host_audit_run": {"output_dir": str(out)}, "host_audit_model": {"baseline": {
            "document": new_doc, "package_index": new_index}}},
        "tasks": [dict(save)],
    }], allow_unicode=True))
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300, env=_scan_env())
    assert res.returncode == 0, res.stdout[-2000:] + res.stderr[-2000:]
    written = json.loads((out / "findings.json").read_text())
    assert written == old_doc
    assert oct((out / "findings.json").stat().st_mode & 0o777) == "0o600"
    assert all(ids(hr) == written["sections"]["package_vulnerability"]["ids"].get(hr["host"], [])
               for hr in legacy if hr["status"] == "ok")


def test_audit_report_model_gets_a_findings_directory_not_the_package_results():
    """AUD-021 must not pass ``package_results`` (every finding of every host) into the report model."""
    build = next(t for t in _tasks("report.yml") if "[AUD-021]" in t.get("name", ""))
    meta = build["vars"]["_meta"]
    assert "package_results" not in meta
    assert "package_findings" in meta["package_findings_dir"]
    assert "_host_audit_package_results" not in (ROLE / "tasks" / "packages_scan.yml").read_text(encoding="utf-8")


# ------------------------------------------------------------------------------
# #155: the output recorded from the code before this change (b1665bb) is the independent expected value
# ------------------------------------------------------------------------------
GOLDEN = FIXTURES / "golden_before_155.json"


def _golden_scenario():
    """The synthetic input the golden file was recorded with, on the filters of b1665bb (findings held in memory)."""
    ubuntu = [_vuln("CVE-2024-%04d" % n, ["CRITICAL", "HIGH", "MEDIUM", "LOW"][n % 4], pkg="pkg%d" % (n % 5))
              for n in range(400)]
    ubuntu += [ubuntu[0], _vuln("CVE-W", "HIGH", status="will_not_fix", fixed=""),
               _vuln("CVE-U", "CRITICAL", status="affected", fixed="")]
    centos = [_vuln("CVE-C-1", "HIGH", pkg="glibc", fixed="2.17-326.el7_9.3"),
              _vuln("CVE-C-2", "CRITICAL", pkg="glibc", fixed="2.17-999.el7"),
              _vuln("CVE-C-3", "HIGH", pkg="not-in-vault", fixed="9.9")]
    return {"a-ubuntu": (json.dumps(_trivy_doc(ubuntu)), 0),
            "b-centos7": (json.dumps(_trivy_doc(centos, "centos", "7")), 0),
            "c-clean": (json.dumps(_trivy_doc([])), 0),
            "d-killed": (json.dumps(_trivy_doc(ubuntu)), 137),
            "e-empty": ("", 0)}, {"b-centos7": CENTOS7}


def test_report_model_and_findings_json_equal_the_output_recorded_before_155(tmp_path):
    from host_audit_baseline import host_audit_baseline_section
    from host_audit_packages import host_audit_package_summary
    cases, os_by_host = _golden_scenario()
    legacy = _legacy_results(cases, os_by_host)
    out = tmp_path / "package_findings"
    out.mkdir()
    for hr in legacy:  # what host_audit_package_scan writes
        (out / ("%s.json" % hr["host"])).write_text(json.dumps(hr))
    ids = lambda hr: sorted(set(f["id"] for f in hr["findings"]))  # noqa: E731
    base = {"schema_version": 1, "run_id": "ha-prev", "started_at": "2026-10-01T00:00:00Z", "sections": {
        "package_vulnerability": {"hosts": ["a-ubuntu", "b-centos7", "gone"], "ids": {
            "a-ubuntu": ids(legacy[0])[:200] + ["CVE-OLD|zlib"], "b-centos7": ["CVE-C-1|glibc"], "gone": ["CVE-X|bash"]}}}}
    history = {"state": "ok", "baseline": base, "pointers": [
        {"run_id": "ha-old", "run_kind": "scheduled", "started_at": "2026-09-01T00:00:00Z",
         "resolved": ["package_vulnerability|a-ubuntu|CVE-OLD|zlib",
                      "package_vulnerability|a-ubuntu|CVE-2024-0300|pkg0"]}]}
    meta = {"run_id": "ha-new", "run_kind": "scheduled", "started_at": "2026-11-01T00:00:00Z", "timezone": "Asia/Seoul"}
    section = host_audit_package_section([host_audit_package_summary(hr, 25) for hr in legacy],
                                         {"usable": True}, "0.0.0", 25)
    model = host_audit_baseline_section({"cover": {"baseline": ""}, "package_vulnerability": section}, history,
                                        dict(meta, package_findings_dir=str(out)))
    index = model["baseline"].pop("package_index")
    # AUD-510 puts the ids from the files into findings.json
    stored = {"hosts": sorted(index["hosts"]), "ids": {}}
    for h in index["hosts"]:
        got = ids(json.loads((out / ("%s.json" % h)).read_text()))
        if got:
            stored["ids"][h] = got
    model["baseline"]["document"]["sections"]["package_vulnerability"] = stored
    recorded = json.loads(GOLDEN.read_text(encoding="utf-8"))
    assert json.loads(json.dumps(section)) == recorded["section"]
    assert json.loads(json.dumps(model)) == recorded["model"]


# ------------------------------------------------------------------------------
# Trivy version + DB record of a run (#159): what judged this run, kept with the archived SBOMs
# ------------------------------------------------------------------------------
TRIVY_VERSION_JSON = json.dumps({
    "Version": "0.75.0",
    "VulnerabilityDB": {"Version": 2, "NextUpdate": "2026-10-08T12:38:55Z",
                        "UpdatedAt": "2026-10-07T07:38:55Z", "DownloadedAt": "2026-10-08T12:58:07Z"},
})


def test_trivy_provenance_takes_version_and_db_from_trivy_version_output():
    rec = host_audit_trivy_provenance(0, TRIVY_VERSION_JSON, "0.75.0", _fresh_db())
    assert rec["trivy_version"] == "0.75.0"
    assert rec["db_version"] == 2
    assert rec["db_updated_at"] == "2026-10-07T07:38:55Z"
    assert rec["db_downloaded_at"] == "2026-10-08T12:58:07Z"
    assert rec["db_next_update"] == "2026-10-08T12:38:55Z"
    assert rec["db_status"] == "fresh" and rec["db_refreshed"] is True
    assert rec["source"] == "trivy version"


@pytest.mark.parametrize("rc, out", [(1, ""), (0, ""), (0, "not json"), (124, TRIVY_VERSION_JSON)])
def test_trivy_provenance_falls_back_to_the_pinned_version_and_db_state_when_trivy_version_fails(rc, out):
    rec = host_audit_trivy_provenance(rc, out, "0.75.0", _fresh_db())
    assert rec["trivy_version"] == "0.75.0"
    assert rec["db_updated_at"] == "2026-10-07T07:38:55Z" and rec["db_downloaded_at"] == "2026-10-08T12:58:07Z"
    assert rec["db_version"] is None and rec["db_next_update"] is None
    assert rec["source"] == "pinned version, DB metadata file"


def test_trivy_provenance_records_an_unavailable_db():
    rec = host_audit_trivy_provenance(1, "", "0.75.0", host_audit_trivy_db_state(False, {}, NOW))
    assert rec["db_status"] == "unavailable" and rec["db_updated_at"] is None and rec["trivy_version"] == "0.75.0"


def test_trivy_version_tasks_write_trivy_version_json_with_a_fake_trivy(tmp_path):
    """AUD-325/326 as written in packages_scan.yml, with a fake `trivy` that answers `version --format json`."""
    if not shutil.which("ansible-playbook"):
        pytest.skip("ansible-playbook not installed")
    tasks = yaml.safe_load((ROOT_DIR / "roles" / "host_audit" / "tasks" / "packages_scan.yml").read_text(encoding="utf-8"))
    picked = [t for t in tasks if "[AUD-325]" in t["name"] or "[AUD-326]" in t["name"]]
    assert len(picked) == 2
    fake = tmp_path / "trivy"
    fake.write_text("#!/bin/sh\necho '%s'\n" % TRIVY_VERSION_JSON)
    fake.chmod(0o755)
    out = tmp_path / "run"
    out.mkdir()
    pb = tmp_path / "pb.yml"
    pb.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
        "vars": {"host_audit_run": {"output_dir": str(out)}, "_host_audit_trivy": [str(fake)],
                 "host_audit_trivy_version": "0.75.0", "host_audit_trivy_db": _fresh_db()},
        "tasks": picked,
    }], allow_unicode=True))
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300)
    assert res.returncode == 0, res.stdout[-2000:] + res.stderr[-2000:]
    rec = json.loads((out / "trivy_version.json").read_text(encoding="utf-8"))
    assert rec["trivy_version"] == "0.75.0" and rec["db_version"] == 2 and rec["source"] == "trivy version"
    assert (out / "trivy_version.json").stat().st_mode & 0o777 == 0o600
