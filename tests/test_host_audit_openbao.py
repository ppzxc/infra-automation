"""Host Audit의 OpenBao 입력은 새 구조뿐이다 (Spec #511 / Ticket-17, #528).

- 선언: `host_audit_openbao_required`(역할 vars/main.yml)가 읽는 문서 패턴과 필수 키의 유일한 원본이다. 입력 검증과 스키마 대조,
  요청 기록 단언이 같은 선언을 쓴다.
- 보관 대상(`secrets/services/rustfs/audit_reports` + `inventory/services/rustfs`)과 메일 수신자·발신자·표시 이름
  (`inventory/config/host_audit`)은 공용 읽기 지점(`lookup openbao_doc`)에서만 읽는다. Extra variables로 덮어쓰는 길은 없다.
- 읽기 실패는 실행을 멈추지 않고 '보관 문제'·'메일 문제'로 남긴다(뒤의 판정 AUD-516·610이 실패로 끝낸다).

통합 테스트는 소수다(ADR-0013): 실제 태스크를 가짜 OpenBao(`tests/openbao_fake.py`)로 돌린다. 나머지는 정적 검사다.
"""
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
ROLE_DIR = ROOT_DIR / "roles" / "host_audit"
sys.path.insert(0, str(ROOT_DIR / "scripts"))
sys.path.insert(0, str(ROOT_DIR / "tests"))

needs_ansible = pytest.mark.skipif(not shutil.which("ansible-playbook"), reason="ansible-playbook not installed")

STORAGE_DOCS = {"inventory/services/rustfs", "secrets/services/rustfs/audit_reports"}


def _vars():
    return yaml.safe_load((ROLE_DIR / "vars" / "main.yml").read_text(encoding="utf-8"))


def _defaults():
    return yaml.safe_load((ROLE_DIR / "defaults" / "main.yml").read_text(encoding="utf-8"))


def _role_text(skip=()):
    return "".join(p.read_text(encoding="utf-8") for p in sorted(ROLE_DIR.rglob("*.yml")) if p.name not in skip)


def _flat(tasks):
    for task in tasks:
        yield task
        for key in ("block", "rescue", "always"):
            yield from _flat(task.get(key, []))


def _task(file, prefix):
    tasks = yaml.safe_load((ROLE_DIR / "tasks" / file).read_text(encoding="utf-8"))
    return next(t for t in _flat(tasks) if t.get("name", "").startswith(prefix))


# ------------------------------------------------------------------ 선언

def test_openbao_required_is_declared_and_matches_index_and_schemas():
    ob = importlib.import_module("openbao_validation")
    declared = _vars()["host_audit_openbao_required"]
    assert set(declared) == STORAGE_DOCS | {"secrets/services/alert/notify", "inventory/config/host_audit"}
    for pattern, keys in declared.items():
        rel = ob.resolve_schema(pattern)
        assert rel is not None, pattern
        schema = json.loads((ob.DEFAULT_SCHEMA_DIR / rel).read_text(encoding="utf-8"))
        assert set(keys) <= set(schema["properties"]), pattern
        assert set(schema.get("required", [])) <= set(keys), pattern


def test_the_role_reads_only_through_the_shared_read_point():
    # drift_subrun.yml은 하위 프로세스에 주소와 인증을 환경 변수로 넘길 뿐 OpenBao를 읽지 않는다(아래 테스트가 그 환경을 고정한다).
    text = _role_text(skip=("drift_subrun.yml",))
    for banned in ("VAULT_", "OPENBAO_", "vault_namespace", "vault_mount", "vault_addr", "X-Vault", "approle", "infra/prod/host",
                   "agents/host_audit", "agents/rustfs", "agents/openobserve", "_host_kv_dict", "_effective_host_resp",
                   "host_agents_environment", "host_agents_vault"):
        assert banned not in text, banned
    assert "lookup('openbao_doc'" in text or 'lookup("openbao_doc"' in text or "query('openbao_doc'" in text
    for task in _flat(yaml.safe_load((ROLE_DIR / "tasks" / "storage_credentials.yml").read_text(encoding="utf-8"))):
        assert "ansible.builtin.uri" not in task or "approle" not in json.dumps(task)


def test_no_extra_variable_replaces_the_stored_values():
    defaults = _defaults()
    for gone in ("host_audit_storage", "host_audit_alert_webhook", "host_audit_mail_to", "host_audit_mail_from",
                 "host_audit_mail_from_name"):
        assert gone not in defaults, gone
        assert not re.search(r"\b%s\b" % gone, _role_text()), gone
    assert defaults["host_audit_storage_bucket"] == "host-audit"   # 버킷 이름은 공개해도 되는 역할 기본값이다


def test_the_environment_is_a_role_default_not_an_inventory_lookup():
    assert _defaults()["host_audit_environment"] == "production"
    assert "host_agents_environment" not in _role_text()
    assert "host_audit_environment" in _task("main.yml", "[AUD-011]")["vars"]["_declared"]["environment"]


def test_the_drift_subrun_forwards_only_the_one_off_account_input_and_the_runner_credentials():
    assert _defaults()["host_audit_drift_forward_vars"] == ["target_removed_users"]
    run = _task("drift_subrun.yml", "[AUD-403]")
    assert set(run["environment"]) >= {"VAULT_ADDR", "VAULT_ROLE_ID", "VAULT_SECRET_ID", "VAULT_TOKEN"}
    assert not {"VAULT_NAMESPACE", "VAULT_MOUNT"} & set(run["environment"])
    assert run["no_log"] is True


def test_the_drift_subruns_render_the_provisioning_and_host_agents_config_playbooks_in_check_mode():
    subruns = _task("drift.yml", "[AUD-401]")["ansible.builtin.set_fact"]["_host_audit_drift_subruns"]
    assert [(s["playbook"], s["args"]) for s in subruns] == [("site.yml", []), ("host_agents.yml", ["--tags", "agents_config"])]
    assert "--check" in _task("drift_subrun.yml", "[AUD-403]")["ansible.builtin.shell"]
    for playbook in ("site.yml", "host_agents.yml"):
        text = (ROOT_DIR / "playbooks" / playbook).read_text(encoding="utf-8")
        assert "common/resolve_connection.yml" in text


def test_the_read_lists_come_from_the_declaration_and_both_logins_share_one_task():
    v = _vars()
    parts = set(v["host_audit_openbao_storage_docs"]) | {v["host_audit_openbao_alert_doc"], v["host_audit_openbao_mail_doc"]}
    assert parts == set(v["host_audit_openbao_required"])
    for name in ("storage_credentials.yml", "mail.yml"):
        text = (ROLE_DIR / "tasks" / name).read_text(encoding="utf-8")
        assert "vault_token.yml" in text and "'@token'" not in text
    assert "[AUD-500]" in (ROLE_DIR / "tasks" / "vault_token.yml").read_text(encoding="utf-8")
    assert "inventory/services/rustfs'" not in (ROLE_DIR / "tasks" / "storage_credentials.yml").read_text(encoding="utf-8").split("[AUD-501]")[1].split("[AUD-502]")[0]


# ------------------------------------------------------------------ 가짜 OpenBao로 실제 태스크를 돌린다

def _run(tmp_path, fake, tasks, play_vars=None, extra_files=None):
    """localhost play 하나로 role 태스크를 돌리고 결과 팩트를 JSON으로 받는다. 인증은 AppRole(환경 변수)뿐이다."""
    out = tmp_path / "out.json"
    play = [{"hosts": "localhost", "connection": "local", "gather_facts": False, "become": False,
             "vars": play_vars or {}, "tasks": tasks + [
                 {"ansible.builtin.copy": {"dest": str(out), "mode": "0600", "content": "{{ _result | to_json }}"}}]}]
    pb = tmp_path / "pb.yml"
    pb.write_text(yaml.safe_dump(play, allow_unicode=True), encoding="utf-8")
    env = dict(os.environ, ANSIBLE_NOCOLOR="1", ANSIBLE_ROLES_PATH=str(ROOT_DIR / "roles"),
               VAULT_ADDR=fake.url, VAULT_ROLE_ID="fake-role", VAULT_SECRET_ID="fake-secret")
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300, env=env)
    return res, (json.loads(out.read_text(encoding="utf-8")) if out.exists() else None)


def _storage(tmp_path, fake, **play_vars):
    tasks = [{"ansible.builtin.include_role": {"name": "host_audit", "tasks_from": "storage_credentials"}},
             {"ansible.builtin.set_fact": {"_result": {"problem": "{{ _host_audit_storage_problem }}",
                                                       "target": "{{ _host_audit_storage_target }}",
                                                       "alert": "{{ _host_audit_alert_target }}"}}}]
    return _run(tmp_path, fake, tasks, dict({"host_audit_run": {"run_id": "r"}}, **play_vars))


def _pattern_regex(pattern):
    return re.compile("^" + re.escape(pattern).replace(r"\+", "[^/]+") + "$")


def _assert_reads_inside(fake, patterns):
    regexes = [_pattern_regex(p) for p in patterns]
    for r in fake.reads():
        assert any(rx.match(f"{r.mount}/{r.doc}") for rx in regexes), (r.mount, r.doc)
    assert {r.namespace for r in fake.reads()} == {"infra"}


@needs_ansible
def test_the_storage_target_comes_from_the_service_documents_and_only_the_declared_ones_are_read(tmp_path, fake_openbao):
    fake_openbao.set("inventory", "services/rustfs", {"url": "https://s3.example.test", "region": "fake-region-1"})
    fake_openbao.set("secrets", "services/rustfs/audit_reports", {"access_key": "fake-ak-1", "secret_key": "fake-sk-1"})
    res, out = _storage(tmp_path, fake_openbao)
    assert res.returncode == 0, res.stdout + res.stderr
    assert out["problem"] == ""
    assert out["target"] == {"endpoint": "https://s3.example.test", "bucket": "host-audit", "access_key": "fake-ak-1",
                             "secret_key": "fake-sk-1", "region": "fake-region-1"}
    assert out["alert"] == {"url": "https://hooks.example.test/fake-notify-0019"}
    _assert_reads_inside(fake_openbao, _vars()["host_audit_openbao_required"])
    assert {f"{r.mount}/{r.doc}" for r in fake_openbao.reads()} == STORAGE_DOCS | {"secrets/services/alert/notify"}
    assert fake_openbao.writes() == [] and len(fake_openbao.logins()) >= 1
    assert "fake-sk-1" not in res.stdout + res.stderr


@needs_ansible
def test_the_region_defaults_when_the_service_document_has_none(tmp_path, fake_openbao):
    fake_openbao.set("inventory", "services/rustfs", {"url": "https://s3.example.test"})
    res, out = _storage(tmp_path, fake_openbao)
    assert res.returncode == 0, res.stdout + res.stderr
    assert out["target"]["region"] == "us-east-1" and out["problem"] == ""


@needs_ansible
@pytest.mark.parametrize("deny", [("secrets", "services/rustfs/audit_reports"), ("inventory", "services/rustfs")])
def test_a_storage_document_that_cannot_be_read_is_a_storage_problem_naming_documents_only(tmp_path, fake_openbao, deny):
    fake_openbao.deny(*deny)
    res, out = _storage(tmp_path, fake_openbao)
    assert res.returncode == 0, res.stdout + res.stderr          # 실행을 여기서 멈추지 않는다(AUD-516이 판정한다)
    failing = f"{deny[0]}/{deny[1]}"
    assert "OpenBao" in out["problem"] and failing in out["problem"]
    assert all(d not in out["problem"] for d in STORAGE_DOCS - {failing})   # 못 읽은 문서만 이름이 나온다
    assert "fake-secret-0018" not in res.stdout + res.stderr + out["problem"]


@needs_ansible
def test_a_missing_required_key_is_named_by_document_and_key_only(tmp_path, fake_openbao):
    fake_openbao.set("secrets", "services/rustfs/audit_reports", {"access_key": "fake-ak-1", "secret_key": "x"})
    fake_openbao._docs[("secrets", "services/rustfs/audit_reports")][1]["data"]["data"].pop("secret_key")
    res, out = _storage(tmp_path, fake_openbao)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "secrets/services/rustfs/audit_reports.secret_key" in out["problem"]
    assert "fake-ak-1" not in json.dumps(out["problem"])


@needs_ansible
def test_not_being_allowed_to_read_the_alert_document_costs_only_the_notification(tmp_path, fake_openbao):
    fake_openbao.deny("secrets", "services/alert/notify")
    res, out = _storage(tmp_path, fake_openbao)
    assert res.returncode == 0, res.stdout + res.stderr
    assert out["problem"] == "" and out["alert"]["url"] == ""


@needs_ansible
def test_no_credentials_at_all_is_a_storage_problem_not_a_default(tmp_path, fake_openbao):
    tasks = [{"ansible.builtin.include_role": {"name": "host_audit", "tasks_from": "storage_credentials"}},
             {"ansible.builtin.set_fact": {"_result": {"problem": "{{ _host_audit_storage_problem }}"}}}]
    out_file = tmp_path / "out.json"
    pb = tmp_path / "pb.yml"
    pb.write_text(yaml.safe_dump([{"hosts": "localhost", "connection": "local", "gather_facts": False, "become": False, "vars": {},
                                   "tasks": tasks + [{"ansible.builtin.copy": {"dest": str(out_file),
                                                                               "content": "{{ _result | to_json }}"}}]}]))
    env = {k: v for k, v in os.environ.items() if not k.startswith("VAULT_")}
    env.update(ANSIBLE_ROLES_PATH=str(ROOT_DIR / "roles"), VAULT_ADDR=fake_openbao.url)
    res = subprocess.run(["ansible-playbook", "-i", "localhost,", str(pb)], capture_output=True, text=True,
                         stdin=subprocess.DEVNULL, cwd=ROOT_DIR, timeout=300, env=env)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "OpenBao" in json.loads(out_file.read_text())["problem"] and fake_openbao.reads() == []


def _mail(tmp_path, fake, send=True):
    """mail.yml의 AUD-600~603(보낼지 정하기, 로그인, 설정 문서 읽기, 수신자·발신자 해석)만 돌린다. 요약에 zip이 없으므로
    첨부 조건은 보고서 파일뿐이다."""
    report = tmp_path / "report.html"
    report.write_text("<html></html>")
    mail_tasks = yaml.safe_load((ROLE_DIR / "tasks" / "mail.yml").read_text(encoding="utf-8"))
    # AUD-600, 로그인(vault_token.yml을 포함하는 태스크), AUD-602·603
    tasks = [t for t in mail_tasks if re.match(r"\[AUD-60[023]\]", t.get("name", ""))
             or "vault_token.yml" in json.dumps(t)]
    assert len(tasks) == 4
    tasks = [dict(t, **{"ansible.builtin.include_tasks": str(ROLE_DIR / "tasks" / "vault_token.yml")})
             if "ansible.builtin.include_tasks" in t else t for t in tasks]
    play_vars = {"host_audit_mail_doc": {"subject": "s", "run_id": "r"}, "_host_audit_archive_ok": send,
                 "_host_audit_mail_report_path": str(report), "host_audit_mail_enabled": True,
                 "host_audit_openbao_mail_doc": _vars()["host_audit_openbao_mail_doc"]}
    tasks.append({"ansible.builtin.set_fact": {"_result": {
        "problem": "{{ _host_audit_mail_problem | default('') }}",
        "sender": "{{ _host_audit_mail_rcpt.from_header | default('') }}",
        "to_count": "{{ _host_audit_mail_rcpt.to | default([]) | length }}"}}})
    return _run(tmp_path, fake, tasks, play_vars)


@needs_ansible
def test_recipients_sender_and_display_name_come_from_the_host_audit_config_document(tmp_path, fake_openbao):
    fake_openbao.set("inventory", "config/host_audit", {"mail_recipients": ["a@example.test", "b@example.test"],
                                                         "mail_sender": "noreply@example.test",
                                                         "mail_sender_display_name": "Fake Audit"})
    res, out = _mail(tmp_path, fake_openbao)
    assert res.returncode == 0, res.stdout + res.stderr
    assert out["problem"] == "" and int(out["to_count"]) == 2
    assert "noreply@example.test" in out["sender"] and "Fake Audit" in out["sender"]
    assert {f"{r.mount}/{r.doc}" for r in fake_openbao.reads()} == {"inventory/config/host_audit"}
    _assert_reads_inside(fake_openbao, _vars()["host_audit_openbao_required"])
    assert "a@example.test" not in res.stdout + res.stderr       # 주소는 개인정보라 어디에도 남지 않는다


@needs_ansible
def test_a_missing_config_document_is_a_mail_problem_about_the_recipients_not_a_crash(tmp_path, fake_openbao):
    fake_openbao.remove("inventory", "config/host_audit")
    res, out = _mail(tmp_path, fake_openbao)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "수신자 없음" in out["problem"] and "inventory/config/host_audit" in out["problem"]


@needs_ansible
def test_an_unreadable_config_document_is_a_mail_problem_naming_the_document(tmp_path, fake_openbao):
    fake_openbao.deny("inventory", "config/host_audit")
    res, out = _mail(tmp_path, fake_openbao)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "OpenBao" in out["problem"] and "inventory/config/host_audit" in out["problem"]


@needs_ansible
def test_the_mail_settings_are_not_read_when_nothing_is_sent(tmp_path, fake_openbao):
    res, out = _mail(tmp_path, fake_openbao, send=False)
    assert res.returncode == 0, res.stdout + res.stderr
    assert fake_openbao.reads() == [] and fake_openbao.logins() == []
