"""Run a Host Audit custom module the way Ansible does, for the tests that exercise a module file directly."""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
MODULE_UTILS = ROOT_DIR / "roles" / "host_audit" / "module_utils"
# What ANSIBLE_MODULE_UTILS does for a run: the role's module_utils/ joins ansible.module_utils.
_LAUNCH = ("import runpy, sys, ansible.module_utils as m; m.__path__.append(sys.argv[1]); "
           "sys.argv = [sys.argv[2], sys.argv[3]]; runpy.run_path(sys.argv[0], run_name='__main__')")


def run_module_file(module, module_args, args_file):
    """Write ``module_args`` as the JSON args file Ansible hands a module, run the module, return its JSON result."""
    Path(args_file).write_text(json.dumps({"ANSIBLE_MODULE_ARGS": dict(module_args)}))
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    res = subprocess.run([sys.executable, "-c", _LAUNCH, str(MODULE_UTILS), str(module), str(args_file)],
                         capture_output=True, text=True, env=env)
    try:
        return json.loads(res.stdout)
    except ValueError:
        raise AssertionError("module printed no JSON (rc=%s)\nstdout: %s\nstderr: %s" % (res.returncode, res.stdout, res.stderr))
