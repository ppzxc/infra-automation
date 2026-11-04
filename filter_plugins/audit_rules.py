"""감사 규칙 적재 상태 비교 (#424).

`auditctl -l`(커널에 적재된 규칙)과 규칙 파일 본문(`audit.rules.j2`로 렌더링한 선언)을 같은 모양으로 줄여 비교한다.
`security` 역할의 `SEC-083`이 이 필터로 적재 drift를 판정하고, 핸들러가 적재 뒤 같은 필터로 결과를 확인한다.

비교 기준(근사다. 완전한 문자열 일치가 아니다):
  - watch 규칙은 (경로, 권한 문자 집합, 키)로 본다. `-w`/`-p`/`-k` 표기와 `-F path=`/`-F dir=`/`-F perm=`/`-F key=` 표기를
    같게 보고, 디렉터리 끝 `/`는 무시한다(`auditctl -l`이 찍는 방식이 감사 패키지 버전마다 다를 수 있어서다).
  - 그 밖의 규칙(syscall 등)은 키만 본다. 시스템 호출 목록·arch는 `auditctl -l`이 정규화해 찍어 문자열 비교가 오탐을 내기 쉽다.
  - 제어 줄(`-D`, `-b`, `-f`, `-e`, `-r`, `--backlog_wait_time` 등), 주석, 빈 줄, `No rules`는 규칙이 아니다.
  - 같은 규칙의 중복과 줄 순서는 무시한다.

`augenrules --load`는 `/etc/audit/rules.d/*.rules`를 모두 합쳐 적재한다(augenrules(8): "merges all component audit rules files"). 그래서 이 역할이 만든
`overseer.rules` 밖의 `.rules` 파일(하드닝 프로파일, 손으로 둔 파일)의 규칙도 정상 적재 결과에 들어간다. `audit_rules_probe_drift`는 조회 출력의
`MARKER` 뒤에 그 파일들의 내용을 받아 선언에 합친다. 안 그러면 그런 호스트는 매 실행 drift로 보이고 적재·확인 실패가 반복된다.
"""

MARKER = "__OVERSEER_OTHER_RULES__"

_CONTROL = {"-D", "-b", "-f", "-e", "-r", "-i", "-c"}


def _signature(line):
    """규칙 한 줄을 ('watch', 경로, 권한, 키) 또는 ('key', 키)로 줄인다. 규칙이 아니면 None."""
    line = line.strip()
    if not line or line.startswith("#") or line.lower().startswith("no rules"):
        return None
    tokens = line.split()
    if tokens[0] in _CONTROL or tokens[0].startswith("--"):
        return None
    path, perms, key = None, "", ""
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        if tok == "-w":
            path, i = nxt, i + 2
        elif tok == "-p":
            perms, i = nxt, i + 2
        elif tok == "-k":
            key, i = nxt, i + 2
        elif tok == "-F" and "=" in nxt:
            name, _, value = nxt.partition("=")
            if name in ("path", "dir"):
                path = value
            elif name == "perm":
                perms = value
            elif name == "key":
                key = value
            i += 2
        else:
            i += 1
    if path is None:
        return ("key", key)
    perms = perms or "rwxa"  # `-p` 없는 watch는 모든 권한이다(auditctl -l도 -p rwxa로 찍는다)
    canonical = "".join(c for c in "rwxa" if c in perms) + "".join(sorted(set(perms) - set("rwxa")))
    return ("watch", path.rstrip("/") or "/", canonical, key)


def _signatures(text):
    found = {}
    for line in str(text or "").splitlines():
        sig = _signature(line)
        if sig is not None:
            found[sig] = None  # 순서를 지키는 집합
    return list(found)


def _describe(sig):
    if sig[0] == "key":
        return "키 %s" % sig[1] if sig[1] else "키 없는 규칙"
    _, path, perms, key = sig
    text = "watch %s 권한 %s" % (path, perms)
    return text + (" 키 %s" % key if key else "")


def _diff(loaded, declared):
    loaded_sigs, declared_sigs = _signatures(loaded), _signatures(declared)
    return ([s for s in declared_sigs if s not in loaded_sigs], [s for s in loaded_sigs if s not in declared_sigs])


def audit_rules_drift(loaded, declared):
    """적재된 규칙(`auditctl -l` 출력)과 선언한 규칙 파일 본문의 차이. 같으면 빈 목록. 경로가 들어 있으므로 실행 로그에 직접 싣지 않는다."""
    missing, extra = _diff(loaded, declared)
    return (["적재 안 됨: %s" % _describe(s) for s in missing]
            + ["선언에 없는 규칙이 적재됨: %s" % _describe(s) for s in extra])


def _keys(sigs):
    names = sorted({s[1] if s[0] == "key" else s[3] for s in sigs})
    return ", ".join(n or "(키 없음)" for n in names)


def audit_rules_probe_drift(output, declared):
    """`auditctl -l` 출력 + MARKER 줄 + 다른 rules.d 파일 내용(조회 스크립트의 출력)을 선언과 비교한다. MARKER가 없으면 앞의 비교와 같다."""
    loaded, _, other = str(output or "").partition(MARKER)
    return audit_rules_drift(loaded, str(declared or "") + "\n" + other)


def audit_rules_drift_summary(output, declared):
    """`audit_rules_probe_drift`의 차이를 건수와 키 이름으로만 줄인 한 줄(경로 없음, 시크릿 감시 경로가 실행 로그에 남지 않게). 같으면 빈 문자열."""
    loaded, _, other = str(output or "").partition(MARKER)
    missing, extra = _diff(loaded, str(declared or "") + "\n" + other)
    parts = []
    if missing:
        parts.append("적재 안 됨 %d건(키: %s)" % (len(missing), _keys(missing)))
    if extra:
        parts.append("선언에 없는 규칙 %d건(키: %s)" % (len(extra), _keys(extra)))
    return ", ".join(parts)


class FilterModule(object):
    def filters(self):
        return {"audit_rules_drift": audit_rules_drift, "audit_rules_probe_drift": audit_rules_probe_drift,
                "audit_rules_drift_summary": audit_rules_drift_summary}
