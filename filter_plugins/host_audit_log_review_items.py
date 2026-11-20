"""Log Review Report 항목 정의 (Spec #544, ADR-0015 §3). 데이터만 있다.

1부는 회사 로그·보안정책 검토결과 대장(AK-034)의 로그 검토 19개, 2부는 보안시스템 정책 적정성 9개 항목이고 순서·문구는
양식 그대로다(심사원이 양식과 일대일로 대조한다). 3부는 로그 관리 상태다.

항목마다 ``key``가 있고, 판정은 ``host_audit_log_review_<묶음>.py`` 모듈의 ``JUDGES[key]``가 한다(``host_audit_log_review.py``의
``_JUDGE_MODULES``). 판정 함수가 없는 항목은 ``unavailable``이 기본 상태이고 그 사유(``reason``)가 보고서에 찍힌다.
후속 티켓은 이 표의 ``method``·``criterion`` 문구를 채우고 판정 모듈에 함수를 더한다(항목을 빼거나 순서를 바꾸지 않는다).
"""

# 항목 상태(ADR-0015 §4). 판정 모듈은 아래 result()·failed()·unavailable()로 값을 만든다.
AUTO, PARTIAL, MANUAL, UNAVAILABLE, FAILED = 'auto', 'partial', 'manual', 'unavailable', 'failed'
STATUS_LABELS = {
    AUTO: '자동 점검',
    PARTIAL: '일부 자동',
    MANUAL: '사람 대조',
    UNAVAILABLE: '점검 불가',
    FAILED: '조회 실패',
}
STATUS_MEANINGS = {
    AUTO: '서버가 기준대로 끝까지 점검함',
    PARTIAL: '서버가 점검한 부분과 사람이 채울 부분이 섞임',
    MANUAL: '사람이 명단·화면과 직접 대조',
    UNAVAILABLE: '필요한 기록이 없어 점검하지 못함(이상 없음이 아님)',
    FAILED: '조회 중 오류가 남',
}

# 각주(쪽 끝). 본문은 쉬운 말로 쓰고 기술 용어·필드 이름·조건은 여기에 모은다. 번호는 보고서에서 처음 쓰인 순서로 붙는다.
FOOTNOTES = {
    'readonly': '조회 전용: 보고서는 OpenObserve에 POST _search(검색)만 호출한다. 오픈소스 OpenObserve는 서버가 조회 전용 권한을 강제하지 못해, 앞단 프록시가 그 요청만 통과시키는 방식으로 막는다.',
    'logs': '로그 종류: 보안 로그(security_logs: 로그인·sudo 등, 조건 예 event_action=ssh_login·event_outcome=success), 시스템 로그(system_logs), 서버 상태 로그(host_status_logs), 백업 로그(backup_logs). OpenObserve 화면에서 같은 이름으로 재현할 수 있다.',
    'account': '등록된 관리 계정: provisioning(서버 구성 선언)에 적힌 운영자 계정, 초기 접속(bootstrap)용 계정, root. 에이전트만 설치된 호스트는 자산 목록(Asset Inventory)의 계정.',
    'invalid': '서버에 없는 계정으로 시도한 로그인: invalid user. 대부분 인터넷의 무차별 대입(스캔)이라 진짜 이상과 섞이지 않게 따로 센다.',
    'aggregate': '집계 단위: 분 또는 시 단위로 모아 센 값이라 구간 경계에서 1분(시 단위는 1시간) 정도 차이가 날 수 있다.',
    'sudo': 'sudo·su: sudo는 일반 계정이 관리자 권한으로 명령을 실행하는 것, su는 다른 계정(주로 root)으로 전환하는 것.',
    'audit': '계정 생성·변경 기록: 리눅스 감사 로그(auditd)의 ADD_USER·USER_MGMT·USER_CHAUTHTOK 등과 실행 계정(AUID).',
    'ansible': '자동화 도구가 실행한 관리자 명령: Ansible become(BECOME-SUCCESS). 사람이 한 것이 아니라 건수를 따로 센다.',
    'location': '접속 위치: 로그인이 들어온 출발지 IP. 허용 목록은 IP 또는 IP 대역(CIDR)으로 적는다.',
    'switchcode': '스위치 로그인 실패 코드: SEC_LOGIN-4-LOGIN_FAILED. 스위치가 로그인에 실패했을 때 남기는 메시지 코드다.',
    'timesync': '시각 동기: kind=time_sync 판독(5분 주기). 오차 1000ms(1초) 초과나 도구 없음(no_tool)이면 확인 필요, 판독이 없으면 확인 불가. 구형 CentOS 6은 rdate로 주기적으로 시각을 맞춰 도구가 판독하지 못한다.',
    'fingerprint': '파일 지문(SHA-256): 파일이 바뀌지 않았음을 확인하는 값. 서명본 등록 기록은 보관 경로의 signed/registration.json.',
}
# 항목 키 → 각주 키(본문 순서). 항목의 '점검 방법' 끝에 [번호]로 붙는다.
REFS = {
    'part1.unauthorized_account': ['logs', 'account', 'invalid'],
    'part1.login_failures': ['logs', 'invalid', 'aggregate', 'switchcode'],
    'part1.off_hours_login': ['logs', 'aggregate'],
    'part1.off_hours_privilege': ['logs', 'sudo', 'audit', 'ansible', 'aggregate'],
    'part1.absentee_login': ['logs'],
    'part1.relogin_from_managed_host': ['logs', 'location'],
    'part1.unauthorized_source': ['logs', 'location'],
    'part1.multi_source_login': ['logs', 'location'],
    'part1.command_burst': ['logs', 'sudo', 'ansible', 'aggregate'],
    'part3.collection_gap': ['logs'],
    'part3.retention': ['readonly'],
    'part3.time_sync': ['logs', 'timesync'],
    'part3.backup': ['logs'],
    'part3.previous_signed_copy': ['fingerprint'],
}
VERDICT_OK = '이상 없음'
VERDICT_CHECK = '확인 필요'


def split_summary(summary):
    """요약 문자열을 ' · '로 나눈 목록. 보고서는 이 목록을 '-' 줄로 그린다(문자열 ``summary``는 그대로 남는다)."""
    return [p.strip() for p in (summary or '').split(' · ') if p.strip()]


def result(status, verdict='', reason='', summary='', columns=None, rows=None, method='', criterion='', verdict_note=''):
    """판정 함수가 돌려주는 값. ``verdict``(이상 없음/확인 필요)는 auto·partial일 때만 남는다.

    ``method``·``criterion``을 주면 표의 문구 대신 이번 판정에 쓴 방법·기준(임곗값 등)이 보고서에 찍힌다.
    """
    return {'status': status, 'verdict': verdict if status in (AUTO, PARTIAL) else '', 'reason': reason,
            'summary': summary, 'summary_lines': split_summary(summary), 'verdict_note': verdict_note, 'columns': list(columns or []), 'rows': [list(r) for r in (rows or [])],
            'method': method, 'criterion': criterion}


def failed(reason):
    return result(FAILED, reason=reason)


def unavailable(reason):
    return result(UNAVAILABLE, reason=reason)


# 판정 함수가 아직 없는 항목의 사유.
NOT_IMPLEMENTED = '미구현'
# 애플리케이션 접속기록·업무 기록을 수집하지 않아 매달 점검할 수 없는 항목(1부 8~11·14~19, ADR-0015 §3·Consequences).
NOT_COLLECTED = '애플리케이션 접속기록·업무 기록 미수집'
# 2부는 1차 구현에서 사람이 채우는 빈 표다(FortiGate 정책·Hit-Count 자동 조회는 #554).
POLICY_MANUAL = '점검자가 방화벽 정책을 직접 보고 기입(자동 조회 없음)'


def _item(no, key, title, method='', criterion='', reason=NOT_IMPLEMENTED, status='unavailable'):
    return {'no': no, 'key': key, 'title': title, 'method': method, 'criterion': criterion,
            'default_status': status, 'default_reason': reason}


def _not_collected(no, key, title):
    return _item(no, key, title, method='애플리케이션(개인정보처리시스템)의 조회·다운로드·업무 기록이 필요하다',
                 reason=NOT_COLLECTED)


PART1 = (
    _item(1, 'part1.unauthorized_account', '접근권한이 부여되지 않은 계정으로 접속한 행위'),
    _item(2, 'part1.login_failures', '접근권한이 부여된 계정으로 로그인 연속 실패한 경우'),
    _item(3, 'part1.off_hours_login', '출근시간 전, 퇴근시간 후, 새벽시간, 휴무일 등 업무시간 외 접속한 경우'),
    _item(4, 'part1.off_hours_privilege', '출근시간 전, 퇴근시간 후, 새벽시간, 휴무일 등 업무시간 외 권한변경한 경우'),
    _item(5, 'part1.absentee_login', '휴직자 또는 휴가자 등의 접속한 행위'),
    _item(6, 'part1.relogin_from_managed_host', '로그인 후에 다른 시스템으로 재 로그인 시도한 경우',
          method='서버 sshd 로그인 성공 중 접속 위치가 관리 서버 주소(인벤토리 계산 + 작업 설정 문서의 내부 주소 대응)인 것',
          criterion='다른 관리 호스트에서 온 로그인 성공이 있으면 확인 필요'),
    _item(7, 'part1.unauthorized_source', '인가되지 않은 단말기 또는 지역/IP에서 접속한 행위',
          method='서버 sshd 로그인 성공의 접속 위치를 작업 설정 문서의 허용된 접속 위치(IP) 목록과 대조',
          criterion='허용된 접속 위치(IP) 목록 밖(관리 서버 주소 제외)에서 온 로그인 성공이 있으면 확인 필요'),
    _not_collected(8, 'part1.specific_record_lookup', '특정 정보에 대해 조회한 행위'),
    _not_collected(9, 'part1.excessive_lookup', '개인정보를 과다 조회한 행위'),
    _not_collected(10, 'part1.lookup_surge', '개인정보 조회가 급증한 경우'),
    _not_collected(11, 'part1.bulk_operation', '대량의 정보에 대한 조회, 정정, 다운로드, 삭제 등의 행위'),
    _item(12, 'part1.multi_source_login', '짧은 시간(2분 내외)에 하나의 계정으로 여러 지역(IP)에서 접속한 행위',
          method='서버 sshd 로그인 성공을 계정·접속 위치별 시각으로 모아 같은 계정의 다른 접속 위치 간격을 잰다',
          criterion='같은 계정이 2분 안에 접속 위치 2개 이상에서 로그인 성공하면 확인 필요'),
    _item(13, 'part1.command_burst', '짧은 시간(2분 내외)에 정상적인 명령어 집중 진행 등'),
    _not_collected(14, 'part1.download_reason', '기준이상으로 개인정보 다운로드한 건에 대한 사유확인'),
    _not_collected(15, 'part1.self_lookup', '본인 정보를 1일간 2회 이상 조회한 행위'),
    _not_collected(16, 'part1.employee_lookup', '재직자 정보를 조회한 행위'),
    _not_collected(17, 'part1.family_lookup', '임직원 가족 정보를 조회한 행위'),
    _not_collected(18, 'part1.unapproved_work', '수행업무 중 승인내역이 없는 업무(예외사용 적용 등)를 진행한 경우'),
    _not_collected(19, 'part1.unfit_attachment', '수행업무 중 적합하지 않은 파일을 첨부하여 진행한 경우'),
)


def _policy(no, key, title):
    return _item(no, key, title, method='방화벽(FortiGate) 정책 목록과 Hit-Count를 점검자가 확인',
                 reason=POLICY_MANUAL, status='manual')


PART2 = (
    _policy(1, 'part2.unused_policy', '장기간 사용하지 않는 정책(Hit-Count가 0 등) 존재'),
    _policy(2, 'part2.departed_owner_policy', '퇴직 또는 직무변경에 따른 불필요 정책 존재'),
    _policy(3, 'part2.test_policy', '불필요한 테스트 정책 존재'),
    _policy(4, 'part2.over_permissive_policy', '과다 허용(Any 서비스, 전체대역 허용 등) 정책 존재'),
    _policy(5, 'part2.expired_policy', '사용기간을 초과한 정책이 존재'),
    _policy(6, 'part2.duplicate_policy', '중복되는 정책'),
    _policy(7, 'part2.unused_ip_policy', '사용하지 않는 IP 정책 존재'),
    _policy(8, 'part2.unused_range_policy', '미사용하는 IP대역이 포함된 정책 존재'),
    _policy(9, 'part2.unneeded_destination_policy', '불필요한 목적지 정책 존재'),
)

# 3부 로그 관리 상태. 수집 공백은 1부 판정이 공백 호스트를 연결하려고 먼저 계산된다(host_audit_log_review._evaluate).
PART3 = (
    _item(1, 'part3.collection_gap', '로그가 없는 날(전월 로그가 없거나 일부 날짜가 빈 서버·장비)'),
    _item(2, 'part3.retention', '로그 보존 기간'),
    _item(3, 'part3.time_sync', '시각 동기 상태'),
    _item(4, 'part3.backup', '전월 백업 결과'),
    _item(5, 'part3.alert_history', '알림 이력'),
    _item(6, 'part3.previous_signed_copy', '전월 보고서 서명본 등록'),
)


class FilterModule(object):
    """데이터 모듈(필터 없음). filter_plugins의 모든 파일이 FilterModule을 갖는 관례를 따른다."""

    def filters(self):
        return {}
