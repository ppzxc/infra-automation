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
