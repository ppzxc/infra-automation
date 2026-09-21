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
    cmd_val = doc_cache.get("ansible.builtin.command")
    cmd_str = cmd_val if isinstance(cmd_val, str) else cmd_val.get("cmd", "")
    assert "makecache" in cmd_str, "DOC-004-CACHE must execute makecache"
    assert doc_cache.get("changed_when") is False, "DOC-004-CACHE must set changed_when: false"

def test_service_tasks_are_check_mode_safe():
    """
    ansible.builtin.service/systemd queries real host state (LoadState via systemd) even
    under --check, so if a prior task in the same role only *simulated* its change (e.g.
    package install, directory/symlink creation skipped in check mode), a later
    state-inspecting task can hard-fail dry runs on a host that hasn't actually been
    provisioned yet (see DOC-012).

    The same "prior task simulated, later task inspects real state" pattern also bit
    [DOC-020] (ansible.builtin.file, state=link, force=false — inspects whether `src`
    really exists on disk) and the "Restart docker" handler notified by [DOC-011]. Every
    task/handler in docker_engine that inspects real host state this way must be guarded
    so it cleanly skips under --check instead of hard-failing, via either:
      - a `when` list containing a clause that references ansible_check_mode, or
      - `ignore_errors: "{{ ansible_check_mode }}"`.

    This check is deliberately generalized over *any* module name that can trigger this
    class of failure (service/systemd variants, and file with state=link), rather than
    hardcoding the three sites found during triage, so it also catches e.g. a rewrite
    from `service` to `systemd` losing its guard along the way.
    """
    service_like_modules = {
        "ansible.builtin.service",
        "service",
        "ansible.builtin.systemd",
        "systemd",
        "ansible.builtin.systemd_service",
        "systemd_service",
    }
    file_like_modules = {"ansible.builtin.file", "file"}

    def inspects_real_host_state(entry):
        if service_like_modules & entry.keys():
            return True
        for key in file_like_modules:
            args = entry.get(key)
            if isinstance(args, dict) and args.get("state") == "link":
                return True
        return False

    def is_guarded(entry):
        when_val = entry.get("when")
        if isinstance(when_val, list):
            if any("ansible_check_mode" in str(cond) for cond in when_val):
                return True
        elif isinstance(when_val, str) and "ansible_check_mode" in when_val:
            return True
        ignore_errors_val = entry.get("ignore_errors")
        if isinstance(ignore_errors_val, str) and "ansible_check_mode" in ignore_errors_val:
            return True
        return False

    files_to_check = [
        ROOT_DIR / "roles" / "docker_engine" / "tasks" / "main.yml",
        ROOT_DIR / "roles" / "docker_engine" / "handlers" / "main.yml",
    ]

    unguarded = []
    for tasks_file in files_to_check:
        assert tasks_file.exists(), f"{tasks_file} missing"
        with open(tasks_file, "r", encoding="utf-8") as f:
            entries = yaml.safe_load(f)
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if inspects_real_host_state(entry) and not is_guarded(entry):
                unguarded.append(f"{tasks_file.name}: {entry.get('name', '<unnamed>')}")

    assert not unguarded, (
        "The following tasks/handlers inspect real host state and must be guarded so "
        "they skip cleanly under --check instead of hard-failing when a prior task in "
        f"the role was only simulated: {unguarded}"
    )

def test_docker_ce_repo_architecture_and_cache_refresh_invariants():
    """
    Ensure [DOC-004] explicitly uses ansible_architecture in baseurl to prevent $basearch expansion issues,
    and [DOC-004-CACHE] sets check_mode: false and structured list-based conditionals to prevent unexpected task skips.
    """
    tasks_file = ROOT_DIR / "roles" / "docker_engine" / "tasks" / "main.yml"
    with open(tasks_file, "r", encoding="utf-8") as f:
        tasks = yaml.safe_load(f)

    doc_004 = next(
        (t for t in tasks if isinstance(t, dict) and "[DOC-004]" in t.get("name", "")),
        None
    )
    assert doc_004 is not None, "[DOC-004] task missing from docker_engine tasks"
    repo_args = doc_004.get("ansible.builtin.yum_repository", {})
    baseurl = repo_args.get("baseurl", "")
    assert "ansible_architecture" in baseurl, (
        f"DOC-004 baseurl must explicitly use ansible_architecture instead of $basearch: {baseurl}"
    )

    doc_cache = next(
        (t for t in tasks if isinstance(t, dict) and "[DOC-004-CACHE]" in t.get("name", "")),
        None
    )
    assert doc_cache is not None, "[DOC-004-CACHE] task missing from docker_engine tasks"
    assert doc_cache.get("check_mode") is False, (
        "DOC-004-CACHE must explicitly set check_mode: false to ensure cache refresh runs even under dry-run/check modes"
    )
    when_val = doc_cache.get("when")
    assert isinstance(when_val, list), (
        "DOC-004-CACHE when condition must be a structured list matching COMMON-004 standard"
    )


