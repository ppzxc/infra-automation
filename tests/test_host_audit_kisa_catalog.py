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
        assert isinstance(meta.get("cis"), str), code
        assert meta["criteria"] == meta["criteria"].strip(), code


def test_filter_items_are_exactly_the_yaml_catalog():
    assert ITEMS == _catalog()


def test_filter_module_keeps_no_item_literals():
    src = (FILTER_DIR / "host_audit_kisa.py").read_text(encoding="utf-8")
    assert not re.search(r"['\"]U-\d\d['\"]", src)


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
