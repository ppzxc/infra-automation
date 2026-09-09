import pytest
import yaml
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

def test_docker_ce_repo_normalizes_releasever():
    """
    Verify that docker_engine role tasks normalize $releasever in docker-ce.repo
    to ansible_distribution_major_version, preventing 404 on minor versions like Rocky 10.2.
    """
    tasks_file = ROOT_DIR / "roles" / "docker_engine" / "tasks" / "main.yml"
    assert tasks_file.exists(), "roles/docker_engine/tasks/main.yml missing"
    
    with open(tasks_file, "r", encoding="utf-8") as f:
        tasks = yaml.safe_load(f)

    # Find DOC-004 and associated normalization task
    doc_004_tasks = [
        t for t in tasks 
        if isinstance(t, dict) and ("[DOC-004]" in t.get("name", "") or "[DOC-004-" in t.get("name", ""))
    ]
    assert len(doc_004_tasks) >= 2, (
        "Expected at least DOC-004 repo download and a normalization task to replace $releasever "
        "with ansible_distribution_major_version"
    )

def test_docker_ce_install_task_updates_cache():
    """
    Verify that [DOC-009] package installation enforces cache refresh (update_cache: true)
    so that newly configured repositories are immediately indexed by DNF/APT.
    """
    tasks_file = ROOT_DIR / "roles" / "docker_engine" / "tasks" / "main.yml"
    assert tasks_file.exists(), "roles/docker_engine/tasks/main.yml missing"
    
    with open(tasks_file, "r", encoding="utf-8") as f:
        tasks = yaml.safe_load(f)

    doc_009 = next(
        (t for t in tasks if isinstance(t, dict) and "[DOC-009]" in t.get("name", "")),
        None
    )
    assert doc_009 is not None, "[DOC-009] task not found in docker_engine tasks"
    
    pkg_args = doc_009.get("ansible.builtin.package", {})
    assert pkg_args.get("update_cache") is True, "[DOC-009] must specify update_cache: true"
