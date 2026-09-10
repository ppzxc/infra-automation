import pytest
import yaml
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent

def test_docker_ce_repo_normalizes_releasever():
    """
    Verify that docker_engine role tasks configure Docker CE repo via yum_repository
    with ansible_distribution_major_version, preventing 404 on minor versions like Rocky 10.2.
    """
    tasks_file = ROOT_DIR / "roles" / "docker_engine" / "tasks" / "main.yml"
    assert tasks_file.exists(), "roles/docker_engine/tasks/main.yml missing"
    
    with open(tasks_file, "r", encoding="utf-8") as f:
        tasks = yaml.safe_load(f)

    # Find DOC-004 task
    doc_004 = next(
        (t for t in tasks if isinstance(t, dict) and "[DOC-004]" in t.get("name", "")),
        None
    )
    assert doc_004 is not None, "[DOC-004] task missing from docker_engine tasks"
    repo_args = doc_004.get("ansible.builtin.yum_repository", {})
    assert "ansible_distribution_major_version" in repo_args.get("baseurl", ""), (
        "DOC-004 baseurl must reference ansible_distribution_major_version"
    )
    assert repo_args.get("file") == "docker-ce"

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

def test_docker_ce_repo_imports_gpg_key_and_refreshes_cache():
    """
    Verify that RedHat/Rocky targets explicitly import the Docker GPG key via rpm_key
    and force a DNF/YUM cache refresh before package installation.
    """
    tasks_file = ROOT_DIR / "roles" / "docker_engine" / "tasks" / "main.yml"
    with open(tasks_file, "r", encoding="utf-8") as f:
        tasks = yaml.safe_load(f)

    # Check DOC-003-GPG
    doc_gpg = next(
        (t for t in tasks if isinstance(t, dict) and "[DOC-003-GPG]" in t.get("name", "")),
        None
    )
    assert doc_gpg is not None, "[DOC-003-GPG] task missing from docker_engine tasks"
    rpm_key = doc_gpg.get("ansible.builtin.rpm_key", {})
    assert "download.docker.com" in rpm_key.get("key", ""), "DOC-003-GPG must specify Docker GPG key"
    assert rpm_key.get("state") == "present"

    # Check DOC-004-CACHE
    doc_cache = next(
        (t for t in tasks if isinstance(t, dict) and "[DOC-004-CACHE]" in t.get("name", "")),
        None
    )
    assert doc_cache is not None, "[DOC-004-CACHE] task missing from docker_engine tasks"
    cmd_args = doc_cache.get("ansible.builtin.command", {})
    cmd_str = cmd_args.get("cmd", "")
    assert "makecache" in cmd_str, "DOC-004-CACHE must execute makecache"
    assert doc_cache.get("changed_when") is False, "DOC-004-CACHE must set changed_when: false"

