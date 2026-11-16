"""Host Audit KISA item catalog (Spec #488 / Ticket-1, #489): U-01~U-67 live in one Korean YAML file.

The YAML is the only source of the item list; the filter module reads it at import time.
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
FILTER_DIR = ROOT_DIR / "filter_plugins"
CATALOG = FILTER_DIR / "host_audit_kisa_items.yml"
sys.path.insert(0, str(FILTER_DIR))

import host_audit_kisa as kisa  # noqa: E402
from host_audit_kisa import CATEGORIES, ITEMS  # noqa: E402

CODES = ["U-%02d" % i for i in range(1, 68)]
REQUIRED = ("title", "severity", "category", "criteria")


def _catalog():
    return yaml.safe_load(CATALOG.read_text(encoding="utf-8"))


def test_catalog_yaml_holds_all_67_items_with_required_fields():
    data = _catalog()
    assert sorted(data) == CODES
    for code, meta in data.items():
        for field in REQUIRED:
            assert meta.get(field), (code, field)
        assert meta["severity"] in ("상", "중", "하"), code
        assert meta["category"] in CATEGORIES, code
        assert set(meta) == set(REQUIRED) | {"cis"}, code
        assert all(isinstance(meta[k], str) for k in meta), code
        assert meta["criteria"] == meta["criteria"].strip(), code


def test_migrated_catalog_keeps_the_pre_migration_shape():
    """Literals taken from the hard-coded dict this YAML replaced: severity of every item, category ranges, CIS count."""
    assert "".join({"상": "H", "중": "M", "하": "L"}[ITEMS[c]["severity"]] for c in CODES) == (
        "HHHHHHLMLMLLMHHHHHHHHHHHHHHHLMMMLHHHHHHHHHHHHHHMHHMMLMMLMMHMHLMHMMM")
    ranges = [(1, 13, CATEGORIES[0]), (14, 33, CATEGORIES[1]), (34, 63, CATEGORIES[2]), (64, 64, CATEGORIES[3]),
              (65, 67, CATEGORIES[4])]
    for lo, hi, category in ranges:
        assert {ITEMS["U-%02d" % i]["category"] for i in range(lo, hi + 1)} == {category}, category
    assert sum(1 for c in CODES if ITEMS[c]["cis"]) == 26


def test_loader_rejects_blank_title_or_criteria(tmp_path):
    with pytest.raises(RuntimeError, match=r"U-01.*title"):
        kisa._load_items(_write(tmp_path, ONE_ITEM.replace("title: t", "title: ' '")))
    with pytest.raises(RuntimeError, match=r"U-01.*criteria"):
        kisa._load_items(_write(tmp_path, ONE_ITEM.replace("criteria: c", "criteria: ''")))


def test_default_catalog_must_hold_every_item(tmp_path):
    with pytest.raises(RuntimeError, match="U-02"):
        kisa._require_all_items(kisa._load_items(_write(tmp_path, ONE_ITEM.replace("U-01", "U-03"))))
    assert kisa._require_all_items(kisa.ITEMS) is kisa.ITEMS


def test_loader_accepts_a_field_overridden_over_a_yaml_merge(tmp_path):
    text = ONE_ITEM.replace("U-01:\n  title: t\n", "U-01:\n  <<: {title: base}\n  title: t\n")
    assert kisa._load_items(_write(tmp_path, text))["U-01"]["title"] == "t"


def test_migrated_items_keep_their_known_values():
    """Known-good literals from the pre-migration filter pin the content independently of the loader."""
    assert ITEMS["U-01"] == {
        "title": "root 계정 원격 접속 제한", "severity": "상", "category": "계정 관리",
        "criteria": "원격터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우 양호", "cis": "5.1.20"}
    assert (ITEMS["U-23"]["severity"], ITEMS["U-23"]["category"], ITEMS["U-23"]["cis"]) == ("상", "파일 및 디렉토리 관리", "7.1.13")
    assert (ITEMS["U-64"]["severity"], ITEMS["U-64"]["category"]) == ("상", "패치 관리")
    assert (ITEMS["U-67"]["title"], ITEMS["U-67"]["cis"]) == ("로그 디렉터리 소유자 및 권한 설정", "6.2.4.1")
    assert ITEMS["U-07"]["cis"] == ""


def _write(tmp_path, text):
    path = tmp_path / "items.yml"
    path.write_text(text, encoding="utf-8")
    return str(path)


ONE_ITEM = "U-01:\n  title: t\n  severity: 상\n  category: 계정 관리\n  criteria: c\n  cis: ''\n"


def test_loader_reads_the_given_catalog_file(tmp_path):
    assert list(kisa._load_items(_write(tmp_path, ONE_ITEM))) == ["U-01"]


def test_loader_rejects_duplicate_item_codes(tmp_path):
    with pytest.raises(RuntimeError, match="U-01"):
        kisa._load_items(_write(tmp_path, ONE_ITEM + ONE_ITEM))


def test_loader_rejects_duplicate_field_keys(tmp_path):
    with pytest.raises(RuntimeError, match="severity"):
        kisa._load_items(_write(tmp_path, ONE_ITEM + "  severity: 하\n"))


def test_loader_parses_each_catalog_only_once(tmp_path, monkeypatch):
    path = _write(tmp_path, ONE_ITEM)
    calls = []
    real = yaml.load
    monkeypatch.setattr(yaml, "load", lambda *a, **k: calls.append(1) or real(*a, **k))
    kisa._load_items(path)
    kisa._load_items(path)
    assert len(calls) == 1


def test_default_path_and_explicit_catalog_path_share_one_parse():
    assert kisa._load_items() is kisa._load_items(kisa.CATALOG_PATH) is kisa.ITEMS


def test_loader_wraps_undecodable_and_unhashable_catalogs(tmp_path):
    bad_bytes = tmp_path / "bytes.yml"
    bad_bytes.write_bytes(b"U-01: \xff\xfe\n")
    with pytest.raises(RuntimeError, match="bytes.yml"):
        kisa._load_items(str(bad_bytes))
    with pytest.raises(RuntimeError, match="cannot be loaded"):
        kisa._load_items(_write(tmp_path, "? [a]\n: 1\n"))


def test_loader_names_the_offending_item_and_field(tmp_path):
    with pytest.raises(RuntimeError, match=r"U-01.*cis"):
        kisa._load_items(_write(tmp_path, ONE_ITEM.replace("cis: ''", "cis: 7.2")))
    with pytest.raises(RuntimeError, match=r"U-01.*severity"):
        kisa._load_items(_write(tmp_path, ONE_ITEM.replace("상", "높음")))
    with pytest.raises(RuntimeError, match=r"U-01.*category"):
        kisa._load_items(_write(tmp_path, ONE_ITEM.replace("계정 관리", "기타")))


def test_loader_rejects_malformed_codes_and_unknown_fields(tmp_path):
    with pytest.raises(RuntimeError, match="u-01"):
        kisa._load_items(_write(tmp_path, ONE_ITEM.replace("U-01", "u-01")))
    with pytest.raises(RuntimeError, match=r"U-01.*serverity"):
        kisa._load_items(_write(tmp_path, ONE_ITEM + "  serverity: 상\n"))


def test_catalog_is_read_only():
    with pytest.raises(TypeError):
        ITEMS["U-01"]["severity"] = "하"
    with pytest.raises(TypeError):
        ITEMS["U-99"] = {}


def test_catalog_is_found_through_a_symlinked_filter_copy(tmp_path):
    """A filter symlinked into another directory still resolves the catalog next to the real file."""
    link = tmp_path / "host_audit_kisa.py"
    link.symlink_to(FILTER_DIR / "host_audit_kisa.py")
    res = subprocess.run(
        [sys.executable, "-I", "-c",
         "import importlib.util as u, sys; sys.path.insert(0, %r);"
         "s = u.spec_from_file_location('linked_kisa', %r); m = u.module_from_spec(s); s.loader.exec_module(m);"
         "print(len(m.ITEMS))" % (str(FILTER_DIR), str(link))],
        capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == "67"


@pytest.mark.skipif(shutil.which("ansible-playbook") is None, reason="ansible-playbook not installed")
def test_runner_finds_catalog_next_to_filter(tmp_path):
    """ansible-playbook configured with only the filter dir still resolves every item."""
    probe = {"rc": 0, "stdout": "__HOST_AUDIT_KISA_BEGIN__\n__HOST_AUDIT_KISA_END__\n", "stderr": ""}
    play = tmp_path / "play.yml"
    play.write_text(yaml.safe_dump([{
        "hosts": "localhost", "gather_facts": False,
        "tasks": [{"ansible.builtin.debug": {
            "msg": "ITEMS={{ (probe | host_audit_kisa_result([], 'h', [], '2026-10-09'))['results'] | length }}"}}],
        "vars": {"probe": probe},
    }]))
    res = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-c", "local", str(play)],
        capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120, cwd=tmp_path,
        env={**os.environ, "ANSIBLE_NOCOLOR": "1", "ANSIBLE_FILTER_PLUGINS": str(FILTER_DIR),
             "ANSIBLE_LOCALHOST_WARNING": "False"})
    assert res.returncode == 0, res.stdout + res.stderr
    assert "ITEMS=67" in res.stdout, res.stdout
