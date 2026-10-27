"""호스트 백업 키 정책 (Spec #364 / Ticket-6, #373).

저장소의 정책 JSON(roles/backup/files/host-key-policy.json)이 문서·가드 태스크(BAK-220)와 일치하고,
호스트 키가 "쓰기 + 잠금 해제용 삭제"만 갖는지(삭제는 locks/* 하나뿐) 정의만 읽어 확인한다(ADR-0013, ansible 불필요).
가드 태스크가 넓어진 정책을 실제로 거부하는지는 통합 테스트 하나가 본다(ansible-playbook 사용 -> 자동 slow).
"""
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
POLICY = ROOT_DIR / "roles" / "backup" / "files" / "host-key-policy.json"
ROLE = ROOT_DIR / "roles" / "backup"
RUNBOOK = ROOT_DIR / "docs" / "runbooks" / "backup-host-key-scope.md"
BACKUP_DOC = ROOT_DIR / "docs" / "backup.md"
ADR = ROOT_DIR / "docs" / "adr" / "0006-host-agents-otelcol-resticprofile.md"
INDEX = ROOT_DIR / "docs" / "INDEX.md"
BUCKET = "arn:aws:s3:::${BUCKET}"
LOCKS = BUCKET + "/locks/*"


def _policy():
    return json.loads(POLICY.read_text(encoding="utf-8"))


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _statements(policy):
    return policy["Statement"]


def _delete_grants(policy):
    """(액션, 리소스) 중 삭제 성격인 것 전부."""
    grants = []
    for st in _statements(policy):
        for action in _as_list(st["Action"]):
            if "delete" in action.lower():
                grants.extend((action, res) for res in _as_list(st["Resource"]))
    return grants


def _violations(policy):
    """가드 태스크(BAK-220)와 같은 기준을 파이썬으로 다시 쓴 것. 문제 목록을 돌려준다."""
    problems = []
    for st in _statements(policy):
        if st["Effect"] != "Allow":
            problems.append("effect:" + st["Effect"])
        if "NotAction" in st or "NotResource" in st:
            problems.append("not-form")
        for action in _as_list(st["Action"]):
            if "*" in action:
                problems.append("wildcard-action:" + action)
        for res in _as_list(st["Resource"]):
            if not res.startswith(BUCKET):
                problems.append("foreign-resource:" + res)
    for action, res in _delete_grants(policy):
        if action != "s3:DeleteObject" or res != LOCKS:
            problems.append(f"delete:{action}:{res}")
    return problems


def test_the_policy_file_is_valid_json_with_the_expected_shape():
    policy = _policy()
    assert policy["Version"] == "2012-10-17"
    assert len({st["Sid"] for st in _statements(policy)}) == len(_statements(policy))


def test_the_host_key_can_delete_only_lock_objects():
    policy = _policy()
    assert _delete_grants(policy) == [("s3:DeleteObject", LOCKS)]
    assert _violations(policy) == []


def test_the_host_key_can_still_write_and_list_what_a_restic_backup_needs():
    allowed = {a for st in _statements(_policy()) for a in _as_list(st["Action"])}
    assert {"s3:ListBucket", "s3:GetObject", "s3:PutObject"} <= allowed


def test_the_host_key_has_no_bucket_policy_lifecycle_or_retention_authority():
    allowed = {a for st in _statements(_policy()) for a in _as_list(st["Action"])}
    for forbidden in ("s3:DeleteBucket", "s3:PutBucketPolicy", "s3:PutLifecycleConfiguration",
                      "s3:PutBucketObjectLockConfiguration", "s3:PutObjectRetention", "s3:BypassGovernanceRetention",
                      "s3:DeleteObjectVersion", "s3:ListAllMyBuckets", "s3:CreateBucket"):
        assert forbidden not in allowed, forbidden


def test_the_policy_never_reaches_beyond_its_own_bucket():
    resources = {r for st in _statements(_policy()) for r in _as_list(st["Resource"])}
    assert resources == {BUCKET, BUCKET + "/*", LOCKS}


@pytest.mark.parametrize("mutation", [
    lambda p: _statements(p)[1]["Action"].append("s3:DeleteObject"),                  # 데이터 prefix에 삭제 추가
    lambda p: _statements(p)[2]["Resource"].append(BUCKET + "/*"),                     # 삭제 범위를 버킷 전체로
    lambda p: _statements(p)[1]["Action"].__setitem__(0, "s3:*"),                      # 와일드카드
    lambda p: _statements(p)[2]["Action"].append("s3:DeleteObjectVersion"),            # 다른 삭제 동작
    lambda p: _statements(p)[0]["Resource"].append("arn:aws:s3:::other-bucket"),       # 다른 버킷
])
def test_the_checker_catches_every_way_of_widening_the_delete_scope(mutation):
    policy = _policy()
    mutation(policy)
    assert _violations(policy)


# --- 문서·정책·검증 일치 -------------------------------------------------------------------

def test_the_docs_point_at_the_policy_file_and_describe_the_same_delete_scope():
    for doc in (BACKUP_DOC, ADR, RUNBOOK):
        text = doc.read_text(encoding="utf-8")
        assert "roles/backup/files/host-key-policy.json" in text, doc.name
        assert "locks/*" in text, doc.name
    assert "BAK-220" in BACKUP_DOC.read_text(encoding="utf-8")


def test_the_adr_no_longer_describes_the_old_host_prefix_layout_for_the_host_key():
    text = ADR.read_text(encoding="utf-8")
    assert "Delete는 `<host>/locks/*`만" not in text


def test_the_spec_row_the_guard_task_and_the_molecule_check_agree():
    row = re.search(r"\| `BAK-220` \| `([^`]+)`", BACKUP_DOC.read_text(encoding="utf-8"))
    assert row, "docs/backup.md에 BAK-220 행이 없다"
    tasks = yaml.safe_load((ROLE / "tasks" / "host_key_policy.yml").read_text(encoding="utf-8"))
    assert [t["name"] for t in tasks] == [f"[BAK-220] {row.group(1)}"]
    verify = (ROOT_DIR / "molecule" / "slow" / "verify.yml").read_text(encoding="utf-8")
    assert "[VERIFY-BAK-220]" in verify and "tasks_from: host_key_policy" in verify


def test_the_default_policy_path_and_unlock_sid_match_the_file():
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert defaults["backup_host_key_policy_file"].endswith("/files/host-key-policy.json")
    unlock = [st for st in _statements(_policy()) if st["Sid"] == defaults["backup_host_key_unlock_sid"]]
    assert len(unlock) == 1 and _as_list(unlock[0]["Action"]) == ["s3:DeleteObject"]


# --- 런북 -----------------------------------------------------------------------------------

def _runbook():
    return RUNBOOK.read_text(encoding="utf-8")


def _section(title):
    match = re.search(rf"^## [0-9]+\. {re.escape(title)}.*?(?=^## |\Z)", _runbook(), re.S | re.M)
    assert match, f"'{title}' 절이 없다"
    return match.group(0)


def test_the_runbook_covers_canary_rollout_isolation_rollback_and_central_maintenance():
    for title in ("카나리 적용", "카나리 검증", "전체 확대", "호스트별 격리 확인 절차", "롤백", "중앙 유지보수 경로 확인"):
        assert _section(title).strip(), title


def test_the_canary_checks_name_the_negative_test_and_the_central_maintenance_run():
    checks = _section("카나리 검증")
    assert "거부" in checks and "임시 객체" in checks
    assert "backup_maintenance_read_subset=always" in checks and "target_hosts" in checks
    assert "unlock" in checks


def test_the_rollout_waits_for_the_first_backup_cycle_and_the_rollback_comes_before_applying():
    assert "첫 백업 주기" in _section("전체 확대")
    text = _runbook()
    assert text.index("## 2. 적용 전 준비") < text.index("## 3. 카나리 적용")
    assert "롤백 기준" in _section("적용 전 준비")
    assert "수집기" in _section("롤백") or "스냅샷" in _section("롤백")


def test_the_runbook_is_linked_from_the_index_and_carries_no_infrastructure_details():
    assert "runbooks/backup-host-key-scope.md" in INDEX.read_text(encoding="utf-8")
    text = _runbook()
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text), "IP 주소"
    assert not re.search(r"\bns0\d{3}\b", text), "관리번호(장비 식별)"
    assert not re.search(r"(?i)\bport\s*[:=]?\s*\d{2,5}\b|포트\s*\d{2,5}|\b[A-Za-z][A-Za-z0-9.-]*:\d{2,5}\b", text), "포트"
    assert not re.search(r"(?i)(password|passwd|token|secret)\s*[:=]\s*\S+", text), "시크릿 값"
    assert not re.search(r"\bAKIA[0-9A-Z]{8,}", text), "접근키"


# --- 통합: 가드 태스크 BAK-220이 실제로 거부한다 (ansible-playbook 사용 -> 자동 slow) --------------

def _guard(tmp_path, policy_file):
    (tmp_path / "pb.yml").write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "vars": {"backup_host_key_policy_file": str(policy_file)},
        "tasks": [{"ansible.builtin.include_role": {"name": "backup", "tasks_from": "host_key_policy"}}],
    }]))
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    env = dict(os.environ, ANSIBLE_ROLES_PATH=str(ROOT_DIR / "roles"))
    assert "backup_host_key_unlock_sid" in defaults
    return subprocess.run(["ansible-playbook", "-i", "localhost,", str(tmp_path / "pb.yml")], capture_output=True,
                          text=True, stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300, env=env)


def test_the_guard_task_passes_the_shipped_policy_and_rejects_a_widened_one(tmp_path):
    ok = _guard(tmp_path, POLICY)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    wide = _policy()
    _statements(wide)[1]["Action"].append("s3:DeleteObject")
    bad_file = tmp_path / "wide.json"
    bad_file.write_text(json.dumps(wide))
    bad = _guard(tmp_path, bad_file)
    assert bad.returncode != 0
    assert "locks/*" in bad.stdout + bad.stderr
