"""시크릿 파일 권한 런북과 수집기 (Spec #364 / Ticket-8, #375).

런북은 인수 기준을 기계로 확인한다: 소비자 목록 양식, 분류 규칙, 종료 코드 판정, up 금지,
이력은 줄 수·위치만, 잔재는 항목별 승인, #374 보관 전제, 이미지 목록 양식, 공개 저장소 위생.
수집기는 실제로 임시 디렉터리에서 돌려 값을 읽지 않는지 본다.
"""
import os
import re
import stat
import subprocess
from pathlib import Path
from runbook_helpers import runbook_section

ROOT_DIR = Path(__file__).resolve().parent.parent
RUNBOOK = ROOT_DIR / "docs" / "runbooks" / "secret-file-permissions.md"
SCRIPT = ROOT_DIR / "scripts" / "collect-secret-perms.sh"
INDEX = ROOT_DIR / "docs" / "INDEX.md"


def _text():
    return RUNBOOK.read_text(encoding="utf-8")


def _section(title):
    return runbook_section(RUNBOOK, title)


def test_the_consumer_list_template_and_the_three_classes_are_defined():
    s = _section("1. 소비자 목록 만들기")
    for col in ("소비자", "읽는 경로", "목표 mode"):
        assert col in s, col
    assert "env_file" in s and "0640 root:dockermgmt" in s
    assert "bind mount" in s and "컨테이너 내부 UID" in s
    assert "0600" in s and "root 전용" in s


def test_the_verdict_is_the_exit_code_of_compose_config_quiet_and_never_up():
    s = _section("3. 권한 변경과 판정")
    assert "docker compose config --quiet" in s and "exit" in s
    assert "개인 운영자 계정" in s
    assert re.search(r"docker compose up.*확인 수단으로 쓰지 않", s, re.S)
    assert "재생성" in s and "운영자" in s
    assert "버전이 지원" in _section("2. 적용 전 준비")


def test_plaintext_cleanup_requires_the_374_archive_first():
    assert "#374" in _section("전제") and "#374" in _section("4. 평문 인증 정보 정리")
    assert "사본" in _section("4. 평문 인증 정보 정리")


def test_history_reports_only_counts_and_locations_and_leftovers_need_per_item_approval():
    h = _section("5. 셸 이력 후보")
    assert "줄 수" in h and "위치" in h and "운영자가 직접" in h
    left = _section("6. 잔재 정리(오래된 도구·이미지·옛 이름)")
    assert "항목별" in left and "승인" in left


def test_the_image_version_list_template_exists():
    s = _section("7. 컨테이너 이미지 고정 버전 목록")
    for col in ("이미지:태그", "이미지 ID", "갱신 계획"):
        assert col in s, col


def test_rollback_is_written_before_applying_and_snapshots_are_diffed():
    assert "롤백 절차를 적용 전에 적는다" in _section("2. 적용 전 준비")
    after = _section("8. 적용 후 검증과 기록")
    assert "diff" in after and "통과 여부만" in after


def test_the_runbook_is_indexed_and_carries_no_infrastructure_details():
    assert "runbooks/secret-file-permissions.md" in INDEX.read_text(encoding="utf-8")
    text = _text()
    assert not re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text), "IP 주소"
    assert not re.search(r"\bns0\d{3}\b", text), "관리번호"
    assert not re.search(r"(?i)(password|passwd|token|secret)\s*[:=]\s*\S+", text), "시크릿 값"


def test_collector_is_syntax_ok_executable_and_has_no_mutating_or_content_reading_commands():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
    assert SCRIPT.stat().st_mode & stat.S_IXUSR
    code = "\n".join(l for l in SCRIPT.read_text().splitlines() if l.strip() and not l.lstrip().startswith("#"))
    for pat in (r"\brm\b", r"\bmv\b", r"\bcp\b", r"\btee\b", r"\bchmod\b", r"\bchown\b", r"\bsed\s+-i",
                r"(?<![-\w])cat(?![-\w])", r"\bhead\b", r"\btail\b", r"docker\s+compose\s+up", r"\bdocker\s+exec\b"):
        assert not re.search(pat, code), pat


def test_collector_lists_metadata_and_history_counts_without_printing_contents(tmp_path):
    secret_value = "SUPERSECRETVALUE123"
    leaky = tmp_path / "app" / "a.env"
    leaky.parent.mkdir()
    leaky.write_text(f"DB_PASSWORD={secret_value}\n")
    leaky.chmod(0o644)
    ok = tmp_path / "app" / "b.env"
    ok.write_text(f"API_TOKEN={secret_value}\n")
    ok.chmod(0o640)
    home = tmp_path / "home"
    home.mkdir()
    (home / ".bash_history").write_text(f"export PASSWORD={secret_value}\nls\nls\n")

    env = dict(os.environ, SECRET_PERMS_ROOTS=str(tmp_path / "app"))
    out = subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True, check=True).stdout

    assert secret_value not in out
    assert f"644 " in out and str(leaky) in out and str(ok) in out
    too_open = out.split("## too-open-candidates")[1].split("## shell-history-candidates")[0]
    assert str(leaky) in too_open and str(ok) not in too_open
