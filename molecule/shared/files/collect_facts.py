#!/usr/bin/env python3
"""Collect every fact the molecule verify playbooks assert on, in ONE remote
execution. Each verify task used to be its own `docker exec` round trip
(stat/slurp/getent/command); the assertions themselves run on the controller
and cost nothing, so collecting once removes nearly all of verify's runtime.

usage: collect_facts.py '<json spec>'
spec keys: stat[], read[], group[], passwd[], cmd{name: [argv...]}
Missing things are reported (exists=false / null), never raised, so a missing
file fails the *assertion* that owns it rather than the whole collection.
"""
import grp
import json
import os
import pwd
import subprocess
import sys

spec = json.loads(sys.argv[1])
out = {"stat": {}, "read": {}, "group": {}, "passwd": {}, "cmd": {}}

for path in spec.get("stat", []):
    try:
        st = os.stat(path)
        out["stat"][path] = {"exists": True, "mode": "%04o" % (st.st_mode & 0o7777)}
    except OSError:
        out["stat"][path] = {"exists": False, "mode": None}

for path in spec.get("read", []):
    try:
        with open(path) as fh:
            out["read"][path] = fh.read()
    except OSError:
        out["read"][path] = None

for name in spec.get("group", []):
    try:
        grp.getgrnam(name)
        out["group"][name] = True
    except KeyError:
        out["group"][name] = False

for name in spec.get("passwd", []):
    try:
        pwd.getpwnam(name)
        out["passwd"][name] = True
    except KeyError:
        out["passwd"][name] = False

for name, argv in spec.get("cmd", {}).items():
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True)
        out["cmd"][name] = {"rc": p.returncode, "stdout": p.stdout}
    except OSError as exc:
        out["cmd"][name] = {"rc": 127, "stdout": str(exc)}

print(json.dumps(out))
