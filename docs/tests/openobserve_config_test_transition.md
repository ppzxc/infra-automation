# OpenObserve Config 테스트 전환 기록 (Spec #348 / Ticket-3, #351)

`tests/test_openobserve_config.py`는 알림 정의만 읽는 테스트도 `_apply()`로 전체 play(`ansible-playbook`, 약 8초)를 매번 돌렸다.
알림 정의만 읽는 테스트 44개를 `tests/test_openobserve_render.py`로 옮겼다. 옮긴 테스트는 렌더링 play를 한 번 돌린
결과(`o2c_render_dump`, `O2C-008`·`O2C-009`)를 공유한다. 이름은 옛 테스트와 같다.

## 원칙

- **같은 검사, 다른 입력.** 새 테스트의 단언은 옛 테스트와 같다. 바뀐 것은 입력뿐이다. 옛 테스트는 play가 가짜 서버에 쌓은 알림을 읽었고,
  새 테스트는 렌더링 결과를 `FakeO2.store`와 같은 모양으로 보여 주는 `desired` fixture에서 읽는다.
- **다리 테스트.** 두 입력이 같다는 것은 통합 테스트 `test_apply_sends_exactly_what_the_render_play_shows`가 지킨다. 실제 반영(`O2C-020`)이
  서버에 보낸 알림·템플릿·함수·파이프라인과 원문 로그 단축 링크가 렌더링 결과와 정확히 같고 알림 이름 집합도 같다.
  이 테스트가 깨지면 새 테스트는 운영 동작을 대변하지 못한다.
- **destination은 옮기지 않았다.** 웹훅 주소와 토큰이 있는 destination은 비밀이라 덤프에 없다. destination을 읽는 부분은 통합 테스트에 남겼다.
- **삭제 기준.** 옛 테스트는 새 테스트가 대상 동작을 일부러 깼을 때 실패하는 것을 확인한 뒤에만 지웠다(아래 표). 묶음마다
  role·필터 코드를 임시로 바꿔 `tests/test_openobserve_render.py`를 돌리고 실패한 테스트를 기록한 뒤 원래대로 되돌렸다.

## 대응표

옛 테스트는 `tests/test_openobserve_config.py`에서 삭제했고, 같은 이름의 새 테스트가 `tests/test_openobserve_render.py`에 있다.
마지막 열은 그 테스트를 실패시킨 변경 ID다(아래 확인 기록).

| 묶음 | 테스트 이름(옛 = 새) | 실패 확인 |
|---|---|---|
| A | `test_template_body_is_the_plain_text_message_without_a_json_wrapper` | A3 |
| A | `test_template_uses_the_new_labels_and_not_the_old_ones` | A1 |
| A | `test_rendered_body_puts_one_numbered_item_per_line_and_keeps_newlines_out_of_values` | A4 |
| A | `test_template_places_the_raw_log_line_right_after_the_alert_url` | A2 |
| B | `test_every_alert_is_actionable` | B2 |
| B | `test_severity_mapping_follows_impact` | B1 |
| B | `test_every_alert_action_is_one_numbered_slot_per_item_after_rendering` | B3 |
| B | `test_log_alerts_keep_the_sql_condition_and_the_link_label` | B4 |
| B | `test_selftest_notification_is_clearly_marked_as_a_test` | B3, B5 |
| B | `test_promql_row_templates_use_only_numbers_and_safe_labels` | B6 |
| B | `test_promql_alerts_round_the_value_so_notifications_carry_no_decimals` | B7 |
| B | `test_promql_alerts_are_created_as_promql_metrics_alerts_to_the_current_destination` | B3, B8 |
| C | `test_resource_alerts_are_metric_state_alerts_with_grade_and_renotify_interval` | C1 |
| C | `test_unreachable_host_is_a_p1_state_alert_on_tcpcheck_status_zero_for_5_minutes` | C2 |
| C | `test_existing_log_alerts_stay_logs` | C3 |
| C | `test_resource_sql_groups_by_timestamp_uses_min_and_default_thresholds_and_fstype_exclusions` | C4 |
| C | `test_app_log_error_alert_is_a_p2_event_alert_on_error_or_worse_per_host_and_container` | C5 |
| C | `test_memory_alert_sql_uses_available_and_limit_streams_not_usage_states` | C6 |
| C | `test_memory_alert_fixtures_fire_as_expected_when_the_rendered_sql_runs` | C6, C7 |
| C | `test_raid_alerts_are_p2_with_a_two_reading_window_and_a_runbook_entry` | C8 |
| D | `test_switch_alerts_are_created_on_system_logs_with_the_specified_grades_and_windows` | D1 |
| D | `test_switch_function_and_pipeline_are_added_beside_the_security_ones_and_the_security_pipeline_is_untouched` | D2, D3 |
| D | `test_firewall_function_runs_in_the_security_pipeline_right_after_the_security_function` | D2, D3 |
| D | `test_default_noise_list_holds_the_arp_resolution_failure_and_every_alert_excludes_it` | D4 |
| D | `test_default_silent_roster_is_the_explicit_list_of_confirmed_senders_and_the_default_window_is_24_hours` | D5, D7 |
| D | `test_silent_alert_counts_a_record_that_only_names_the_device_in_its_raw_body` | D5, D6, D7 |
| D | `test_silent_alert_does_not_fire_right_after_the_pipeline_is_applied_when_old_logs_exist` | D6, D7 |
| E | `test_firewall_alerts_are_created_on_security_logs_with_the_specified_grades_windows_and_silences` | E1, E2 |
| E | `test_firewall_alert_sql_needs_no_firewall_column_so_it_is_valid_before_the_first_firewall_line_arrives` | E3 |
| E | `test_firewall_alerts_do_not_break_the_existing_ones` | E4 |
| E | `test_without_a_source_list_every_public_root_login_is_p1_and_private_ones_are_p2` | F1 |
| G | `test_per_source_ssh_row_shows_one_time_for_one_event_and_first_to_last_for_a_range` | G1, G2, G6, G7 |
| G | `test_event_time_range_across_midnight_keeps_both_dates` | G1, G2, G6, G7 |
| G | `test_event_time_does_not_change_which_sources_fire` | G3 |
| G | `test_per_source_rows_come_out_with_the_most_failures_first_so_the_row_cap_keeps_the_worst` | G4 |
| G | `test_raw_log_link_survives_the_event_time_column` | G5 |
| G | `test_every_alert_with_an_event_time_column_fits_the_5000_character_limit_with_30_longest_rows` | G6, G7 |
| G | `test_security_server_alert_rows_show_one_time_for_one_instant_and_first_to_last_for_a_range` | G1, G2, G7 |
| G | `test_parse_error_alerts_keep_the_raw_log_link_and_show_the_time` | G1, G2, G7, G8 |
| G | `test_system_app_backup_raid_and_reachability_rows_show_one_time_or_first_to_last` | G1, G2, G7 |
| G | `test_backup_and_raid_missing_and_usage_alerts_keep_their_rows` | G9 |
| G | `test_device_rows_show_one_time_or_first_to_last_and_keep_the_device_name` | G1, G2, G7 |
| H | `test_log_alerts_with_a_derivable_where_carry_the_raw_log_link_and_the_others_do_not` | H1 |
| H | `test_security_alerts_are_created_with_their_grades_windows_and_raw_log_links` | H2, H3 |

## 실패 확인 기록

### 묶음 A. 통지 템플릿 본문

| ID | 일부러 깬 곳 | 실패한 새 테스트 |
|---|---|---|
| A1 | `roles/openobserve_config/defaults/main.yml` — 템플릿 라벨 '현상'을 '상황'으로 | `test_template_uses_the_new_labels_and_not_the_old_ones` |
| A2 | `roles/openobserve_config/defaults/main.yml` — 원문 링크 줄을 알림 링크 앞으로 | `test_template_places_the_raw_log_line_right_after_the_alert_url` |
| A3 | `roles/openobserve_config/defaults/main.yml` — 평가 시각 줄을 UTC로 | `test_template_body_is_the_plain_text_message_without_a_json_wrapper` |
| A4 | `filter_plugins/openobserve_config.py` — 조치 항목 값 안에 개행 넣기 | `test_rendered_body_puts_one_numbered_item_per_line_and_keeps_newlines_out_of_values` |

### 묶음 B. 알림 공통 필드(심각도·조치·링크 라벨·PromQL 모양)

| ID | 일부러 깬 곳 | 실패한 새 테스트 |
|---|---|---|
| B1 | `roles/openobserve_config/defaults/main.yml` — OOM kill 알림의 심각도를 P2에서 P1로 | `test_severity_mapping_follows_impact` |
| B2 | `roles/openobserve_config/defaults/main.yml` — OOM kill 알림의 런북 앵커를 없는 앵커로 | `test_every_alert_is_actionable` |
| B3 | `filter_plugins/openobserve_config.py` — 조치 항목 번호 표기를 '1.'에서 '1)'로 | `test_every_alert_action_is_one_numbered_slot_per_item_after_rendering`, `test_promql_alerts_are_created_as_promql_metrics_alerts_to_the_current_destination`, `test_rendered_body_puts_one_numbered_item_per_line_and_keeps_newlines_out_of_values`, `test_selftest_notification_is_clearly_marked_as_a_test` |
| B4 | `filter_plugins/openobserve_config.py` — 로그 알림 링크 라벨을 바꿈 | `test_log_alerts_keep_the_sql_condition_and_the_link_label` |
| B5 | `roles/openobserve_config/defaults/main.yml` — 자가 시험 알림의 심각도 TEST를 P3로 | `test_selftest_notification_is_clearly_marked_as_a_test` |
| B6 | `roles/openobserve_config/defaults/main.yml` — PromQL 행 템플릿에 따옴표 레이블 추가 | `test_promql_row_templates_use_only_numbers_and_safe_labels` |
| B7 | `filter_plugins/openobserve_config.py` — PromQL 값 반올림을 floor로 | `test_promql_alerts_round_the_value_so_notifications_carry_no_decimals` |
| B8 | `roles/openobserve_config/defaults/main.yml` — CPU 사용률 P1(PromQL) 알림의 비교 연산자를 >=에서 >로 | `test_promql_alerts_are_created_as_promql_metrics_alerts_to_the_current_destination` |

### 묶음 C. 리소스·앱 로그·RAID 알림

| ID | 일부러 깬 곳 | 실패한 새 테스트 |
|---|---|---|
| C1 | `roles/openobserve_config/defaults/main.yml` — 디스크 P1 알림의 재통지 간격을 60분에서 30분으로 | `test_resource_alerts_are_metric_state_alerts_with_grade_and_renotify_interval` |
| C2 | `roles/openobserve_config/defaults/main.yml` — 도달 불가 알림의 판정을 max(value) = 0에서 = 1로 | `test_unreachable_host_is_a_p1_state_alert_on_tcpcheck_status_zero_for_5_minutes` |
| C3 | `roles/openobserve_config/defaults/main.yml` — OOM kill 로그 알림의 스트림 종류를 metrics로 | `test_existing_log_alerts_stay_logs` |
| C4 | `roles/openobserve_config/defaults/main.yml` — 디스크 제외 파일시스템 목록에서 squashfs 제거 | `test_resource_sql_groups_by_timestamp_uses_min_and_default_thresholds_and_fstype_exclusions` |
| C5 | `roles/openobserve_config/defaults/main.yml` — 앱 로그 ERROR 알림의 SQL에서 dpanic 레벨 제거 | `test_app_log_error_alert_is_a_p2_event_alert_on_error_or_worse_per_host_and_container` |
| C6 | `filter_plugins/openobserve_config.py` — 메모리 알림이 읽는 두 번째 스트림을 limit에서 usage로 | `test_memory_alert_fixtures_fire_as_expected_when_the_rendered_sql_runs`, `test_memory_alert_sql_uses_available_and_limit_streams_not_usage_states` |
| C7 | `filter_plugins/openobserve_config.py` — 메모리 사용률 계산식을 (1.0 - 가용/한도)에서 (0.0 - 가용/한도)로 | `test_memory_alert_fixtures_fire_as_expected_when_the_rendered_sql_runs` |
| C8 | `roles/openobserve_config/defaults/main.yml` — RAID 컨트롤러 알림의 연속 두 번 판정을 한 번으로 | `test_raid_alerts_are_p2_with_a_two_reading_window_and_a_runbook_entry` |

### 묶음 D. 스위치 syslog 알림과 파이프라인

| ID | 일부러 깬 곳 | 실패한 새 테스트 |
|---|---|---|
| D1 | `roles/openobserve_config/defaults/main.yml` — 스위치 syslog 수신 중단 알림의 재통지 간격을 1440분에서 60분으로 | `test_switch_alerts_are_created_on_system_logs_with_the_specified_grades_and_windows` |
| D2 | `filter_plugins/openobserve_config.py` — 파이프라인을 비활성 상태로 만듦 | `test_firewall_function_runs_in_the_security_pipeline_right_after_the_security_function`, `test_switch_function_and_pipeline_are_added_beside_the_security_ones_and_the_security_pipeline_is_untouched` |
| D3 | `filter_plugins/openobserve_config.py` — 파이프라인 함수 노드의 after_flatten을 거짓으로 | `test_firewall_function_runs_in_the_security_pipeline_right_after_the_security_function`, `test_switch_function_and_pipeline_are_added_beside_the_security_ones_and_the_security_pipeline_is_untouched` |
| D4 | `roles/openobserve_config/defaults/main.yml` — 스위치 잡음 코드 목록을 비움 | `test_default_noise_list_holds_the_arp_resolution_failure_and_every_alert_excludes_it` |
| D5 | `roles/openobserve_config/defaults/main.yml` — 수신 중단 감시 기본 목록에서 ns0347 제거 | `test_default_silent_roster_is_the_explicit_list_of_confirmed_senders_and_the_default_window_is_24_hours`, `test_silent_alert_counts_a_record_that_only_names_the_device_in_its_raw_body` |
| D6 | `filter_plugins/openobserve_config.py` — 부재 감지가 원문의 장비 이름을 세지 않게 함 | `test_silent_alert_counts_a_record_that_only_names_the_device_in_its_raw_body`, `test_silent_alert_does_not_fire_right_after_the_pipeline_is_applied_when_old_logs_exist` |
| D7 | `filter_plugins/openobserve_config.py` — 부재 감지 판정을 count(*) < 1에서 < 0으로 | `test_default_silent_roster_is_the_explicit_list_of_confirmed_senders_and_the_default_window_is_24_hours`, `test_silent_alert_counts_a_record_that_only_names_the_device_in_its_raw_body`, `test_silent_alert_does_not_fire_right_after_the_pipeline_is_applied_when_old_logs_exist` |

### 묶음 E. 방화벽·root 로그인 알림

| ID | 일부러 깬 곳 | 실패한 새 테스트 |
|---|---|---|
| E1 | `roles/openobserve_config/defaults/main.yml` — 방화벽 HA 알림의 재통지 간격을 30분에서 45분으로 | `test_firewall_alerts_are_created_on_security_logs_with_the_specified_grades_windows_and_silences` |
| E2 | `roles/openobserve_config/defaults/main.yml` — 방화벽 관리자 로그인 실패 알림의 스트림을 system_logs로 | `test_firewall_alerts_are_created_on_security_logs_with_the_specified_grades_windows_and_silences` |
| E3 | `roles/openobserve_config/defaults/main.yml` — 방화벽 HA 알림 SQL이 device_name 컬럼을 읽게 함 | `test_firewall_alert_sql_needs_no_firewall_column_so_it_is_valid_before_the_first_firewall_line_arrives` |
| E4 | `roles/openobserve_config/defaults/main.yml` — 기존 알림(infra-oom-kill) 이름을 바꿔 정의에서 사라지게 함 | `test_existing_log_alerts_stay_logs`, `test_firewall_alerts_do_not_break_the_existing_ones`, `test_log_alerts_keep_the_sql_condition_and_the_link_label`, `test_render_returns_every_managed_alert`, `test_severity_mapping_follows_impact` |
| F1 | `roles/openobserve_config/defaults/main.yml` — 사설 대역 패턴에서 10.% 제거 | `test_without_a_source_list_every_public_root_login_is_p1_and_private_ones_are_p2` |

### 묶음 G. 발생 시각(KST)·행 길이

| ID | 일부러 깬 곳 | 실패한 새 테스트 |
|---|---|---|
| G1 | `roles/openobserve_config/defaults/main.yml` — 발생 시각 표시 형식을 월-일에서 일-월로 | `test_device_rows_show_one_time_or_first_to_last_and_keep_the_device_name`, `test_event_time_range_across_midnight_keeps_both_dates`, `test_parse_error_alerts_keep_the_raw_log_link_and_show_the_time`, `test_per_source_ssh_row_shows_one_time_for_one_event_and_first_to_last_for_a_range`, `test_security_server_alert_rows_show_one_time_for_one_instant_and_first_to_last_for_a_range`, `test_system_app_backup_raid_and_reachability_rows_show_one_time_or_first_to_last` |
| G2 | `roles/openobserve_config/defaults/main.yml` — 발생 시각 표시 시간대를 +09:00에서 +00:00으로 | `test_device_rows_show_one_time_or_first_to_last_and_keep_the_device_name`, `test_event_time_range_across_midnight_keeps_both_dates`, `test_parse_error_alerts_keep_the_raw_log_link_and_show_the_time`, `test_per_source_ssh_row_shows_one_time_for_one_event_and_first_to_last_for_a_range`, `test_security_server_alert_rows_show_one_time_for_one_instant_and_first_to_last_for_a_range`, `test_system_app_backup_raid_and_reachability_rows_show_one_time_or_first_to_last` |
| G3 | `roles/openobserve_config/defaults/main.yml` — 출발지별 SSH 실패 알림 임계를 10에서 9로 | `test_event_time_does_not_change_which_sources_fire` |
| G4 | `roles/openobserve_config/defaults/main.yml` — 출발지별 SSH 실패 알림의 정렬을 실패 많은 순에서 적은 순으로 | `test_per_source_rows_come_out_with_the_most_failures_first_so_the_row_cap_keeps_the_worst` |
| G5 | `filter_plugins/openobserve_config.py` — 원문 로그 링크의 조회 상한을 200에서 100으로 | `test_raw_log_link_survives_the_event_time_column` |
| G6 | `roles/openobserve_config/defaults/main.yml` — 출발지별 SSH 실패 행 템플릿 뒤에 150자를 붙여 5000자 제한을 넘김 | `test_event_time_range_across_midnight_keeps_both_dates`, `test_every_alert_with_an_event_time_column_fits_the_5000_character_limit_with_30_longest_rows`, `test_per_source_ssh_row_shows_one_time_for_one_event_and_first_to_last_for_a_range` |
| G7 | `roles/openobserve_config/defaults/main.yml` — 모든 행 템플릿에서 발생 시각(event_time) 제거 | `test_device_rows_show_one_time_or_first_to_last_and_keep_the_device_name`, `test_event_time_range_across_midnight_keeps_both_dates`, `test_every_alert_with_an_event_time_column_fits_the_5000_character_limit_with_30_longest_rows`, `test_parse_error_alerts_keep_the_raw_log_link_and_show_the_time`, `test_per_source_ssh_row_shows_one_time_for_one_event_and_first_to_last_for_a_range`, `test_security_server_alert_rows_show_one_time_for_one_instant_and_first_to_last_for_a_range`, `test_system_app_backup_raid_and_reachability_rows_show_one_time_or_first_to_last` |
| G8 | `roles/openobserve_config/defaults/main.yml` — 보안 로그 해석 실패 알림 행 템플릿에서 발생 시각 제거 | `test_parse_error_alerts_keep_the_raw_log_link_and_show_the_time` |
| G9 | `roles/openobserve_config/defaults/main.yml` — 디스크 P1 알림 행 템플릿에 발생 시각 추가 | `test_backup_and_raid_missing_and_usage_alerts_keep_their_rows`, `test_every_alert_is_actionable` |

### 묶음 H. 원문 로그 링크·보안 로그 알림

| ID | 일부러 깬 곳 | 실패한 새 테스트 |
|---|---|---|
| H1 | `filter_plugins/openobserve_config.py` — 원문 로그 조회의 정렬을 최신순에서 오래된 순으로 | `test_log_alerts_with_a_derivable_where_carry_the_raw_log_link_and_the_others_do_not`, `test_raw_log_link_survives_the_event_time_column` |
| H2 | `roles/openobserve_config/defaults/main.yml` — auditd 중지 알림의 대기(pending) 시간을 2분에서 0으로 | `test_security_alerts_are_created_with_their_grades_windows_and_raw_log_links` |
| H3 | `roles/openobserve_config/defaults/main.yml` — 보안 알림(account-lockout)의 재통지 간격을 5분에서 10분으로 | `test_security_alerts_are_created_with_their_grades_windows_and_raw_log_links` |

변경은 모두 실행 직후 `git checkout`과 같은 방식으로 되돌렸다(변경 전 파일 내용을 그대로 다시 씀). 묶음 B의 첫 시도 `B8`은 모든
PromQL 알림이 연산자를 직접 지정해 기본값이 쓰이지 않아 효과가 없었으므로 CPU 사용률 P1 알림의 연산자를 바꾸는 변경으로 바꿨다.
묶음 G의 `G1`~`G4`와 `G5`~`G9`는 두 번에 나눠 돌렸다(`G5`의 첫 변경 대상 문자열이 없어 다시 지정).

## 통합 테스트로 남긴 것

`tests/test_openobserve_config.py`에 남은 테스트는 서버와 주고받는 동작을 본다. 렌더링 결과만으로는 볼 수 없다.

| 영역 | 이유 |
|---|---|
| 멱등성(두 번째 실행은 쓰기 0, `changed=0`) | 서버 상태와 계획의 비교 |
| 계획·반영 순서(템플릿 → destination → 함수 → 파이프라인 → 알림, 삭제 후 생성) | 쓰기 요청 순서 |
| check 모드, `o2c_plan_only` | 쓰기·주입이 없어야 함 |
| `no_log`, 시크릿 비출력 | 출력과 저장소 검사 |
| 실패 경로(입력 검증, 토큰 누락, 폐기 목록 충돌, 단축 URL 충돌) | 요청 전에 멈추는지 |
| destination·웹훅 헤더(`test_function_pipeline_destination_and_alert_payloads_follow_the_definitions`, `test_the_legacy_json_destination_and_template_are_neither_defined_nor_deleted`) | destination은 덤프에 없음 |
| 검증 단계(합성 레코드 주입, 시드, 자가 시험, `test_no_fixture_is_marked_as_a_known_failure_any_more`) | 주입·검색 요청과 출력 |
| 변수를 바꿨을 때 갱신 한 번(`test_changed_definition_...`, 임계·목록 변경) | 서버에 있는 객체와의 비교 |
| 다리 테스트 `test_apply_sends_exactly_what_the_render_play_shows` | 위 원칙 |

`host_agents_legacy_*`와 `test_backup`은 전환 대상이 아니며 그대로 CI에 남는다.

## 알려진 한계

- 새 렌더링 테스트도 `ansible-playbook`을 실행하는 helper(`render_desired`)를 쓰므로 `tests/conftest.py`의 자동 표시로 `slow`가 된다.
  커밋 hook(`-m "not slow"`)에서 빠진다. 옛 통합 테스트도 `slow`였으므로 hook이 잃은 것은 없다.
- CI 샤딩은 nodeid의 crc32로 나누므로 같은 `xdist_group`이 샤드에 흩어지면 샤드마다 한 번씩 렌더링한다.
