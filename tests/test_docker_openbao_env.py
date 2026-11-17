"""컨테이너 실행 래퍼가 읽기 지점이 받는 OpenBao 환경 변수만 넘긴다(최종 리뷰 5차 6번). 평문 토큰 경로는 없다."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
READER_VARS = ("VAULT_ADDR", "VAULT_ROLE_ID", "VAULT_SECRET_ID", "VAULT_CACERT", "VAULT_SKIP_VERIFY")


def test_docker_run_passes_only_the_reader_variables():
    text = (ROOT / "docker-run.sh").read_text(encoding="utf-8")
    for var in READER_VARS:
        assert var in text, var
    for old in ("BAO_TOKEN", "BAO_ADDR", "VAULT_TOKEN"):
        assert old not in text, old


def test_compose_passes_only_the_reader_variables():
    env = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))["services"]["ansible"]["environment"]
    names = {e.split("=", 1)[0] for e in env}
    assert set(READER_VARS) <= names and not ({"BAO_TOKEN", "BAO_ADDR", "VAULT_TOKEN"} & names)


def test_no_entry_point_document_or_makefile_still_names_the_old_token_variables():
    for name in ("README.md", "Makefile", "Dockerfile", "docker-run.sh", "docker-compose.yml"):
        text = (ROOT / name).read_text(encoding="utf-8")
        for old in ("BAO_TOKEN", "BAO_ADDR"):
            assert old not in text, (name, old)
