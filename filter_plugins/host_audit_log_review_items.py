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
    AUTO: '자동 판정',
    PARTIAL: '일부 자동',
    MANUAL: '사람 대조',
    UNAVAILABLE: '점검 불가',
    FAILED: '조회 실패',
}
VERDICT_OK = '이상 없음'
VERDICT_CHECK = '확인 필요'


def result(status, verdict='', reason='', summary='', columns=None, rows=None, method='', criterion=''):
    """판정 함수가 돌려주는 값. ``verdict``(이상 없음/확인 필요)는 auto·partial일 때만 남는다.

    ``method``·``criterion``을 주면 표의 문구 대신 이번 판정에 쓴 방법·기준(임곗값 등)이 보고서에 찍힌다.
    """
    return {'status': status, 'verdict': verdict if status in (AUTO, PARTIAL) else '', 'reason': reason,
            'summary': summary, 'columns': list(columns or []), 'rows': [list(r) for r in (rows or [])],
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
    _item(6, 'part1.relogin_from_managed_host', '로그인 후에 다른 시스템으로 재 로그인 시도한 경우'),
    _item(7, 'part1.unauthorized_source', '인가되지 않은 단말기 또는 지역/IP에서 접속한 행위'),
    _not_collected(8, 'part1.specific_record_lookup', '특정 정보에 대해 조회한 행위'),
    _not_collected(9, 'part1.excessive_lookup', '개인정보를 과다 조회한 행위'),
    _not_collected(10, 'part1.lookup_surge', '개인정보 조회가 급증한 경우'),
    _not_collected(11, 'part1.bulk_operation', '대량의 정보에 대한 조회, 정정, 다운로드, 삭제 등의 행위'),
    _item(12, 'part1.multi_source_login', '짧은 시간(2분 내외)에 하나의 계정으로 여러 지역(IP)에서 접속한 행위'),
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
    _item(1, 'part3.collection_gap', '수집 공백(전월 로그가 없거나 끊긴 호스트·장비)'),
    _item(2, 'part3.retention', '로그 보존 기간'),
    _item(3, 'part3.time_sync', '시각 동기 상태'),
    _item(4, 'part3.backup', '전월 백업 결과'),
    _item(5, 'part3.alert_history', '알림 이력'),
    _item(6, 'part3.github_audit', 'GitHub 감사 로그 수집 상태'),
    _item(7, 'part3.previous_signed_copy', '전월 보고서 서명본 등록'),
)


class FilterModule(object):
    """데이터 모듈(필터 없음). filter_plugins의 모든 파일이 FilterModule을 갖는 관례를 따른다."""

    def filters(self):
        return {}
