"""Log Review 판정 모듈이 함께 쓰는 작은 헬퍼 (Spec #544 / Ticket-16 #573).

``host_audit_log_review*.py`` 모듈마다 따로 있던 ``_int``·``_tz``·``_local``·``_pii_cell``·``_STAMP``를 한곳에 모았다.
항목 정의(``host_audit_log_review_items``)는 데이터만 두므로 코드는 여기에 둔다.
"""
import re
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9 runner
    ZoneInfo = None

REPORT_TIMEZONE = 'Asia/Seoul'
STAMP = re.compile(r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$')
PII_YES, PII_NO, PII_UNSET = '예', '아니오', '미지정'


def to_int(value):
    """정수로 읽는다. 비었거나 숫자가 아니면 0."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def tz(tz_name):
    if ZoneInfo is None:  # pragma: no cover
        return timezone(timedelta(hours=9))
    return ZoneInfo(tz_name or REPORT_TIMEZONE)


def parse_stamp(iso):
    """UTC ISO(``...Z``) 문자열을 시각으로. 형식이 맞지 않으면 ``None``."""
    m = STAMP.match(str(iso or '').strip())
    return datetime(*[int(x) for x in m.groups()], tzinfo=timezone.utc) if m else None


def local_iso(iso, tz_name, fmt='%Y-%m-%d %H:%M'):
    """UTC ISO 문자열을 보고서 시간대 표기로. 형식이 맞지 않으면 받은 문자열 그대로."""
    dt = parse_stamp(iso)
    return dt.astimezone(tz(tz_name)).strftime(fmt) if dt else str(iso or '')


def pii_cell(pii, host):
    """개인정보처리시스템 표시. ``pii``는 호스트 집합이고 ``None``이면 목록이 없는 것('미지정')."""
    if pii is None:
        return PII_UNSET
    return PII_YES if host in pii else PII_NO


def gap_label(gap, noun='호스트'):
    """요약 줄에 쓰는 '로그가 없는 날이 있는 호스트(장비)' 표기. 3대까지는 이름을, 그 이상은 대수만 적는다(전체 목록은 3부 1번)."""
    names = ', '.join(gap) if len(gap) <= 3 else '목록은 3부 1번'
    return '점검 기간 중 로그가 없는 날이 있는 %s %d대(%s)' % (noun, len(gap), names)


NO_DATA = '기록 없음'
GAP_NOTE = '로그가 없는 날이 있어'
FINDING_NOTE = '기준에 걸린 건이 있어'
