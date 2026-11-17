#!/usr/bin/env python3
"""OpenBao 문서 등록·검증 도구 (#515, Spec #511).

하위 명령:
  validate ROOT   로컬 YAML 트리를 스키마·참조 규칙으로 검증한다(OpenBao에 접속하지 않는다).
                  ROOT 아래 `<마운트>/<문서 경로>.yml`이 문서 하나다(예: ROOT/inventory/assets/ns0001.yml).
                  `secrets/` 문서는 값 자리에 null을 적어도 된다(값은 put이 getpass로 받는다).
  (put, check는 후속 티켓이 같은 검증 모듈 `openbao_validation`으로 추가한다.)

출력은 `문서 경로<TAB>JSON 포인터<TAB>규칙 이름`뿐이다. 값은 어디에도 내지 않는다.
종료 코드: 0 통과, 1 위반 있음, 2 사용법 오류.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import openbao_validation as ov  # noqa: E402


def cmd_validate(args):
    root = Path(args.root)
    if not root.is_dir():
        print("루트 디렉터리가 없다", file=sys.stderr)
        return 2
    store = ov.load_tree(root)
    if not store:
        print("검증할 문서(.yml)가 없다: <마운트>/<경로>.yml 배치를 확인한다", file=sys.stderr)
        return 2
    try:
        violations = ov.validate_store(store, args.schemas)
    except Exception as exc:  # noqa: BLE001 - 어떤 실패든 종료 코드 2와 예외 종류만 낸다(트레이스백에 값이 섞이지 않게)
        # 스키마·index.yml 자체의 문제다(문서 위반이 아니다). 예외 내용에 경로·값이 섞일 수 있어 종류만 낸다.
        print("스키마 또는 index.yml 오류: %s" % type(exc).__name__, file=sys.stderr)
        return 2
    for v in violations:
        print(v.format())
    print("%d개 문서, 위반 %d건" % (len(store), len(violations)), file=sys.stderr)
    return 1 if violations else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("validate", help="로컬 YAML 트리 검증")
    p.add_argument("root")
    p.add_argument("--schemas", default=str(ov.DEFAULT_SCHEMA_DIR), help="스키마 디렉터리(기본: schemas/openbao)")
    p.set_defaults(func=cmd_validate)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
