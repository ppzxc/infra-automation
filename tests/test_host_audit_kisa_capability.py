"""Host Audit: file capability list next to the KISA-2026 U-23 SUID/SGID check (#432, Spec #433).

Observable behaviour only: the real check scripts run under a local ``sh`` against a
fake filesystem root, with ``getcap`` replaced by a stub that answers per file the way
libcap does. The U-23 verdict (GOOD / MANUAL) keeps meaning "SUID/SGID files", so
capabilities only ever add evidence text.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_host_audit_kisa import KISA_DIR, ROLE_DIR, _script, _status, _stub_bin, _write  # noqa: E402

DEFAULTS = yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8"))
DISTRO_PING = "usr/bin/ping"


def _getcap_stub(caps, sep=" "):
    """A getcap that, like the real one, prints a line only for the files it is given that have caps.

    ``sep`` is what sits between path and capabilities: " " for current libcap, " = " for CentOS 6/7.
    """
    cases = "".join("    *\"/%s\") printf '%%s%s%s\\n' \"$f\" ;;\n" % (rel, sep, spec) for rel, spec in caps.items())
    return {"getcap": 'for f in "$@"; do\n  case "$f" in\n%s  esac\ndone\nexit 0' % cases}


def _host(tmp_path, caps=None, suid=(), getcap="stub", sep=" "):
    """A fake root with the capability files in place; returns (root, commands for the stub dir)."""
    root = tmp_path / "root"
    for rel in list((caps or {}).keys()) + ["usr/bin/true"]:
        _write(root, rel, "bin", 0o755)
    for rel in suid:
        _write(root, rel, "bin", 0o4755)
    commands = _getcap_stub(caps or {}, sep) if getcap == "stub" else {}
    if getcap == "broken":  # present on PATH but cannot be executed (missing library, wrong binary)
        commands = {"getcap": "exit 127"}
    return root, commands


def _u23(root, commands, defaults=None, hide_getcap=False, exclude=None):
    bindir = _stub_bin(root, commands=commands)
    path = str(bindir) + ":/usr/bin:/bin"
    if hide_getcap:
        # a PATH that carries every ordinary tool but no getcap, whatever the machine ships
        tools = root.parent / "tools"
        tools.mkdir(exist_ok=True)
        for d in ("/usr/bin", "/bin"):
            for name in os.listdir(d):
                if name != "getcap" and not name.endswith(".exe") and not os.path.lexists(tools / name):
                    os.symlink(Path(d) / name, tools / name)
        path = str(bindir) + ":" + str(tools)
        (bindir / "getcap").unlink(missing_ok=True)
    env = {"KISA_ROOT": str(root), "PATH": path}
    if defaults is not None:
        env["KISA_CAP_DEFAULTS"] = "\n".join(defaults)
    if exclude is not None:
        env["KISA_CAP_EXCLUDE"] = "\n".join(exclude)
    out = subprocess.run(["sh", "-s"], input=_script(), capture_output=True, text=True, env=env, timeout=120)
    assert out.returncode == 0, out.stderr
    return _status(out.stdout)["U-23"]


def role_defaults():
    return DEFAULTS["host_audit_kisa_capability_defaults"]


def role_exclude():
    return DEFAULTS["host_audit_kisa_capability_exclude_paths"]


# ---------------------------------------------------------------- the three cases of the ticket


def test_only_distro_default_capabilities_are_listed_but_not_flagged_for_review(tmp_path):
    root, commands = _host(tmp_path, {DISTRO_PING: "cap_net_raw=ep"})
    verdict, evidence = _u23(root, commands, role_defaults())

    assert verdict == "GOOD"  # no SUID/SGID: the KISA meaning is untouched
    assert "file capability" in evidence and "default only" in evidence
    assert "review" not in evidence


def test_capability_outside_the_distro_defaults_is_marked_for_review(tmp_path):
    root, commands = _host(tmp_path, {DISTRO_PING: "cap_net_raw=ep", "opt/app/tool": "cap_dac_override=ep"})
    verdict, evidence = _u23(root, commands, role_defaults())

    assert verdict == "GOOD"
    assert "file capability review (1)" in evidence
    assert "/opt/app/tool cap_dac_override" in evidence
    assert "/usr/bin/ping" not in evidence  # defaults are not the review list


def test_missing_getcap_is_named_as_unavailable(tmp_path):
    root, commands = _host(tmp_path, getcap="none")
    verdict, evidence = _u23(root, commands, role_defaults(), hide_getcap=True)

    assert verdict == "GOOD"
    assert "file capability" in evidence and "점검불가" in evidence and "getcap" in evidence


def test_getcap_that_cannot_run_is_named_as_unavailable(tmp_path):
    root, commands = _host(tmp_path, getcap="broken")
    _, evidence = _u23(root, commands, role_defaults())

    assert "file capability" in evidence and "점검불가" in evidence


# ---------------------------------------------------------------- KISA verdict is unchanged


@pytest.mark.parametrize("getcap", ["stub", "none"])
def test_suid_files_still_make_u23_manual_whatever_getcap_says(tmp_path, getcap):
    root, commands = _host(tmp_path, {"opt/app/tool": "cap_dac_override=ep"} if getcap == "stub" else {},
                           suid=["usr/bin/su"], getcap=getcap)
    verdict, evidence = _u23(root, commands, role_defaults(), hide_getcap=getcap == "none")

    assert verdict == "MANUAL"
    assert "SUID/SGID files (1): /usr/bin/su" in evidence
    assert "file capability" in evidence


def test_no_capability_at_all_is_reported_as_none(tmp_path):
    root, commands = _host(tmp_path, {})
    verdict, evidence = _u23(root, commands, role_defaults())

    assert verdict == "GOOD" and "file capability: none" in evidence


# ---------------------------------------------------------------- output format, length, defaults


@pytest.mark.parametrize("line", ["/usr/bin/ping = cap_net_raw+ep", "/usr/bin/ping cap_net_raw=ep"])
def test_old_and_new_libcap_output_formats_match_the_same_default(tmp_path, line):
    """CentOS 6/7 print `path = cap+ep`, current libcap prints `path cap=ep`."""
    root, _ = _host(tmp_path, {DISTRO_PING: "x"})
    old_or_new = {"getcap": "for f in \"$@\"; do case \"$f\" in */%s) printf '%%s%s\\n' \"$f\" ;; esac; done"
                           % (DISTRO_PING, line[len("/usr/bin/ping"):])}
    _, evidence = _u23(root, old_or_new, role_defaults())

    assert "default only" in evidence and "review" not in evidence


def test_review_list_is_capped_like_the_suid_list(tmp_path):
    caps = {"opt/app/tool%02d" % i: "cap_chown=ep" for i in range(45)}
    root, commands = _host(tmp_path, caps)
    _, evidence = _u23(root, commands, role_defaults())

    assert "file capability review (45)" in evidence
    assert "...(+5)" in evidence  # kisa_cap 40, the same cut as SUID/SGID
    assert "/opt/app/tool00 cap_chown" in evidence


def test_default_list_is_a_role_variable_the_host_does_not_hardcode(tmp_path):
    root, commands = _host(tmp_path, {"opt/app/tool": "cap_chown=ep"})
    _, evidence = _u23(root, commands, ["/opt/app/tool cap_chown"])

    assert "default only" in evidence and "review" not in evidence


def test_role_defaults_cover_the_well_known_distro_capabilities():
    entries = role_defaults()
    assert isinstance(entries, list) and entries
    assert "/usr/bin/ping cap_net_raw" in entries
    assert all(_splits_into_path_and_names(e) for e in entries), entries


def _splits_into_path_and_names(entry):
    """The check's own rule: the path runs up to the one " cap_", names are a comma-joined set (no spaces)."""
    path, sep, names = entry.partition(" cap_")
    return bool(sep) and path.startswith("/") and " cap_" not in names and " " not in names.strip()


def test_default_entry_format_rule_accepts_paths_with_spaces_and_rejects_malformed_entries():
    assert _splits_into_path_and_names("/opt/my app/tool cap_chown,cap_kill")
    assert not _splits_into_path_and_names("/usr/bin/ping")  # no capability names
    assert not _splits_into_path_and_names("/usr/bin/ping cap_net_raw cap_net_admin")  # names must be comma-joined
    assert not _splits_into_path_and_names("/a cap_x /b cap_y")  # two entries on one line


def test_kisa_task_injects_the_role_variable_into_the_script():
    tasks = yaml.safe_load((ROLE_DIR / "tasks" / "kisa.yml").read_text(encoding="utf-8"))
    script = tasks[0]["vars"]["_host_audit_kisa_script"]
    assert "KISA_CAP_DEFAULTS=" in script and "host_audit_kisa_capability_defaults" in script
    assert "quote" in script  # defaults travel through the raw command line as one quoted word


def test_capability_check_is_read_only_and_bounded():
    u23 = (ROLE_DIR / "files" / "kisa" / "U-23.sh").read_text(encoding="utf-8")
    lib = (ROLE_DIR / "files" / "kisa" / "_lib.sh").read_text(encoding="utf-8")
    func = lib.split("kisa_getcap_find() {", 1)[1].split("\n}\n", 1)[0]   # the walk lives in one helper, called from U-23
    assert "kisa_getcap_find" in u23
    text = u23 + func
    assert "-exec getcap" in func and func.count("kisa_find") >= 2 and "-xdev" in func  # same 120 s limit and -xdev as SUID/SGID
    assert "getcap -" not in text.replace("-exec getcap {}", "")  # no write/set flags, never setcap
    assert "setcap" not in text


# ---------------------------------------------------------------- set comparison, several allowed sets


@pytest.mark.parametrize("printed", ["cap_net_admin,cap_net_raw", "cap_net_raw,cap_net_admin"])
def test_capability_names_are_compared_as_a_set_whatever_their_order(tmp_path, printed):
    root, commands = _host(tmp_path, {"usr/bin/tool": printed + "=ep"})
    _, evidence = _u23(root, commands, ["/usr/bin/tool cap_net_admin,cap_net_raw"])

    assert "default only" in evidence and "review" not in evidence


def test_default_list_may_name_several_allowed_sets_for_one_path(tmp_path):
    """RHEL 8+ ping may carry cap_net_admin,cap_net_raw while other releases carry cap_net_raw alone."""
    allowed = ["/usr/bin/tool cap_net_raw", "/usr/bin/tool cap_net_admin,cap_net_raw"]
    for printed in ("cap_net_raw=p", "cap_net_raw,cap_net_admin=p"):
        root, commands = _host(tmp_path / printed.split("=")[0].replace(",", "_"), {"usr/bin/tool": printed})
        _, evidence = _u23(root, commands, allowed)
        assert "default only" in evidence, evidence


def test_a_different_capability_set_on_a_default_path_is_still_reviewed(tmp_path):
    root, commands = _host(tmp_path, {"usr/bin/tool": "cap_net_raw,cap_sys_admin=ep"})
    _, evidence = _u23(root, commands, ["/usr/bin/tool cap_net_raw", "/usr/bin/tool cap_net_admin,cap_net_raw"])

    assert "file capability review (1)" in evidence and "cap_sys_admin" in evidence


def test_role_defaults_allow_both_ping_capability_sets_of_the_distro_releases():
    entries = role_defaults()
    assert "/usr/bin/ping cap_net_raw" in entries
    assert "/usr/bin/ping cap_net_admin,cap_net_raw" in entries


# ---------------------------------------------------------------- paths with spaces


@pytest.mark.parametrize("sep,spec", [(" ", "cap_chown=ep"), (" = ", "cap_chown+ep")])
def test_path_with_spaces_is_kept_whole_in_both_libcap_formats(tmp_path, sep, spec):
    root, commands = _host(tmp_path, {"opt/my app/tool": spec}, sep=sep)
    _, evidence = _u23(root, commands, role_defaults())

    assert "file capability review (1): /opt/my app/tool cap_chown" in evidence

    _, evidence = _u23(root, commands, ["/opt/my app/tool cap_chown"])
    assert "default only" in evidence


# ---------------------------------------------------------------- container storage is not walked (Spec #433 final review)

CONTAINER_LAYER_CAPS = {
    "var/lib/docker/overlay2/0a1b/diff/usr/bin/ping": "cap_net_raw=ep",
    "var/lib/docker/overlay2/0a1b/diff/usr/bin/app": "cap_dac_override=ep",
    "var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs/bin/x": "cap_chown=ep",
    "var/lib/containers/storage/overlay/ab/diff/usr/bin/y": "cap_chown=ep",
    "home/alice/.local/share/containers/storage/overlay/cd/diff/usr/bin/z": "cap_chown=ep",
}


def test_container_image_layers_are_not_walked_so_their_capabilities_are_noise_no_more(tmp_path):
    """overlay2 등 컨테이너 레이어는 호스트 파일이 아니라 이미지 내용이다. 걸으면 같은 이미지가 늘 검토 항목으로 쏟아진다."""
    root, commands = _host(tmp_path, dict(CONTAINER_LAYER_CAPS, **{"opt/app/tool": "cap_dac_override=ep"}))
    verdict, evidence = _u23(root, commands, role_defaults(), exclude=role_exclude())

    assert verdict == "GOOD"
    assert "file capability review (1)" in evidence and "/opt/app/tool cap_dac_override" in evidence
    assert "overlay" not in evidence and "snapshots" not in evidence and "default: 0" in evidence


def test_a_host_with_capabilities_only_inside_container_layers_reports_none(tmp_path):
    root, commands = _host(tmp_path, CONTAINER_LAYER_CAPS)
    _, evidence = _u23(root, commands, role_defaults(), exclude=role_exclude())

    assert "file capability: none" in evidence


def test_without_the_exclusion_list_the_layers_would_be_reported(tmp_path):
    """제외가 빈 목록이면 이전 동작(전부 탐색)이다 — 목록이 변수로 조정된다는 뜻이다."""
    root, commands = _host(tmp_path, CONTAINER_LAYER_CAPS)
    _, evidence = _u23(root, commands, role_defaults(), exclude=[])

    assert "file capability review (5)" in evidence


def test_the_exclusion_only_touches_the_capability_list_not_the_suid_verdict(tmp_path):
    root, commands = _host(tmp_path, {}, suid=["var/lib/docker/overlay2/0a1b/diff/usr/bin/su"])
    verdict, evidence = _u23(root, commands, role_defaults(), exclude=role_exclude())

    assert verdict == "MANUAL" and "SUID/SGID files (1)" in evidence


def test_a_similar_looking_path_outside_the_container_storage_is_still_checked(tmp_path):
    root, commands = _host(tmp_path, {"opt/var/lib/docker-tools/x": "cap_chown=ep", "var/lib/dockerfiles/y": "cap_chown=ep"})
    _, evidence = _u23(root, commands, role_defaults(), exclude=role_exclude())

    assert "file capability review (2)" in evidence


def test_the_exclusion_defaults_name_docker_containerd_podman_and_the_kisa_task_passes_them_in():
    entries = role_exclude()
    for path in ("/var/lib/docker", "/var/lib/containerd", "/var/lib/containers"):
        assert path in entries
    assert any(e.endswith("/.local/share/containers") for e in entries)   # rootless podman
    assert all(e.startswith("/") and "\n" not in e for e in entries)
    tasks = yaml.safe_load((ROLE_DIR / "tasks" / "kisa.yml").read_text(encoding="utf-8"))
    script = tasks[0]["vars"]["_host_audit_kisa_script"]
    assert "KISA_CAP_EXCLUDE=" in script and "host_audit_kisa_capability_exclude_paths" in script


# ---------------------------------------------------------------- a walk that starts inside an excluded path (re-review)


def _u23_with_mounts(tmp_path, mounts, exclude, caps):
    """U-23 alone on the real filesystem (no KISA_ROOT) with kisa_local_mounts stubbed to hand back ``mounts`` as the walk's start points.

    A host whose container storage is a mount of its own (e.g. /var/lib/docker/overlay2) makes that mount a top-level start point,
    which sits *inside* the excluded path, so `-path <excluded>` alone never matches it.
    """
    lib = (KISA_DIR / "_lib.sh").read_text(encoding="utf-8").rstrip("\n")
    stub = "kisa_local_mounts() {\n" + "".join("  printf '%%s\\n' '%s'\n" % m for m in mounts) + "}\n"
    script = "\n".join([lib, stub, (KISA_DIR / "U-23.sh").read_text(encoding="utf-8"), (KISA_DIR / "_end.sh").read_text(encoding="utf-8")])
    bindir = _stub_bin(tmp_path / "fake", commands=_getcap_stub(caps))
    env = {"PATH": str(bindir) + ":/usr/bin:/bin", "KISA_CAP_EXCLUDE": "\n".join(exclude), "KISA_CAP_DEFAULTS": ""}
    out = subprocess.run(["sh", "-s"], input=script, capture_output=True, text=True, env=env, timeout=120)
    assert out.returncode == 0, out.stderr
    return _status(out.stdout)["U-23"]


def test_a_mount_inside_an_excluded_path_is_not_walked_when_it_is_the_walk_start(tmp_path):
    docker = tmp_path / "var" / "lib" / "docker"
    layer = docker / "overlay2"
    other = tmp_path / "opt"
    _write(layer / "0a1b" / "diff", "app", "bin", 0o755)
    _write(other / "app", "tool", "bin", 0o755)
    caps = {str(layer / "0a1b" / "diff" / "app").lstrip("/"): "cap_dac_override=ep",
            str(other / "app" / "tool").lstrip("/"): "cap_chown=ep"}
    _, evidence = _u23_with_mounts(tmp_path, [str(other), str(layer)], [str(docker)], caps)

    assert "file capability review (1)" in evidence and "/app/tool cap_chown" in evidence
    assert "overlay2" not in evidence


def test_the_excluded_path_itself_as_a_start_point_is_skipped_too(tmp_path):
    docker = tmp_path / "var" / "lib" / "docker"
    _write(docker / "x", "app", "bin", 0o755)
    _, evidence = _u23_with_mounts(tmp_path, [str(docker)], [str(docker)], {str(docker / "x" / "app").lstrip("/"): "cap_chown=ep"})

    assert "file capability: none" in evidence


# ---------------------------------------------------------------- the task's own rendering (실호스트에서 목록이 한 줄로 뭉친 버그)


def test_the_kisa_task_hands_each_list_entry_to_the_shell_on_its_own_line():
    """Ansible leaves ``join('\\n')`` as the two characters backslash+n, so the lists reached the host as one
    garbage line: nothing was excluded and no default matched. Render the real task expression with Ansible's
    templating, run the assignments in sh, and count the lines."""
    from ansible.parsing.dataloader import DataLoader
    from ansible.template import Templar, trust_as_template

    tasks = yaml.safe_load((ROLE_DIR / "tasks" / "kisa.yml").read_text(encoding="utf-8"))
    task_vars = tasks[0]["vars"]
    variables = {
        "host_audit_kisa_capability_defaults": DEFAULTS["host_audit_kisa_capability_defaults"],
        "host_audit_kisa_capability_exclude_paths": DEFAULTS["host_audit_kisa_capability_exclude_paths"],
        "_host_audit_kisa_files": [],
    }
    templar = Templar(loader=DataLoader(), variables={**variables, **{k: v for k, v in task_vars.items() if k != "_host_audit_kisa_script"}})
    rendered = templar.template(trust_as_template(task_vars["_host_audit_kisa_script"].split("{% for")[0]))
    probe = rendered + '\nprintf "%s" "$KISA_CAP_EXCLUDE" | wc -l; printf "%s" "$KISA_CAP_DEFAULTS" | wc -l\n'
    out = subprocess.run(["sh", "-c", probe], capture_output=True, text=True, check=True).stdout.split()
    assert int(out[0]) == len(variables["host_audit_kisa_capability_exclude_paths"]) - 1
    assert int(out[1]) == len(variables["host_audit_kisa_capability_defaults"]) - 1
