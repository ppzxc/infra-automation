"""molecule 공유 group_vars 픽스처가 역할 기본값·verify 단언과 맞는지 본다(최종 리뷰 5차 1·2번)."""
import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SHARED = ROOT / "molecule" / "shared" / "group_vars" / "all.yml"


def test_the_molecule_environment_resolves_through_the_role_defaults_to_test():
    """monitoring·host_audit 기본값이 deployment_environment를 참조하므로 molecule이 이 값을 줘야 MON-036이 돈다(verify는 "test"를 단언)."""
    play = [{"hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
             "vars_files": [str(SHARED), str(ROOT / "roles" / "monitoring" / "defaults" / "main.yml"),
                            str(ROOT / "roles" / "host_audit" / "defaults" / "main.yml")],
             "tasks": [{"ansible.builtin.assert": {"that": ["host_agents_environment == 'test'", "host_audit_environment == 'test'"],
                                                   "quiet": True}}]}]
    pb = ROOT / "molecule" / "shared" / ".env_check_tmp.yml"
    pb.write_text(yaml.safe_dump(play))
    try:
        res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True,
                             stdin=subprocess.DEVNULL, cwd=ROOT, timeout=120)
    finally:
        pb.unlink(missing_ok=True)
    assert res.returncode == 0, res.stdout + res.stderr


def test_slow_verify_secret_guards_use_values_that_exist_in_the_fixture():
    """검사 문자열(설정에 없어야 하는 비밀)이 현재 픽스처 값이어야 가드가 의미 있다."""
    fixture = SHARED.read_text(encoding="utf-8")
    verify = (ROOT / "molecule" / "slow" / "verify.yml").read_text(encoding="utf-8")
    guard = re.search(r"'([^']+)' in f\.read\['/etc/otelcol/config\.yaml'\]\n\n", verify).group(1)
    assert f"'{guard}'" in fixture                       # 가드가 찾는 값이 실제 픽스처 값이다(옛 값이 아니다)
    assert "molecule-fixture-o2-ingest" not in verify + fixture
