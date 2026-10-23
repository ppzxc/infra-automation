"""#349: ansible-playbook을 실행하는 테스트는 marker 없이도 slow로 분류된다."""
import textwrap

from conftest import _slow_functions


def _classify(tmp_path, source):
    path = tmp_path / "test_sample.py"
    path.write_text(textwrap.dedent(source))
    return _slow_functions(str(path))


def test_helper_that_runs_ansible_playbook_and_its_callers_are_slow(tmp_path):
    slow = _classify(tmp_path, '''
        import subprocess

        def _apply(*args):
            return subprocess.run(["ansible-playbook", *args])

        def test_uses_helper():
            assert _apply().returncode == 0

        def test_pure():
            assert 1 + 1 == 2
    ''')
    assert {"_apply", "test_uses_helper"} <= slow
    assert "test_pure" not in slow


def test_tests_using_a_fixture_that_calls_the_runner_are_slow(tmp_path):
    slow = _classify(tmp_path, '''
        import subprocess

        def _run():
            subprocess.run(["ansible-playbook", "x.yml"])

        def rendered():
            return _run()

        def test_reads_fixture(rendered):
            assert rendered is None

        def test_unrelated(tmp_path):
            assert tmp_path
    ''')
    assert "test_reads_fixture" in slow
    assert "test_unrelated" not in slow


def test_direct_subprocess_call_in_the_test_is_slow(tmp_path):
    slow = _classify(tmp_path, '''
        import subprocess

        def test_direct():
            subprocess.run(["ansible-playbook", "-i", "localhost,", "p.yml"])
    ''')
    assert "test_direct" in slow


def test_real_openobserve_config_tests_are_all_detected():
    from pathlib import Path
    slow = _slow_functions(str(Path(__file__).with_name("test_openobserve_config.py")))
    assert "_apply" in slow
    assert "test_first_run_creates_template_destination_function_pipeline_and_every_alert_in_dependency_order" in slow


def test_helper_imported_from_a_sibling_test_module_is_followed(tmp_path):
    (tmp_path / "helper_mod.py").write_text('import subprocess\n\ndef play():\n    subprocess.run(["ansible-playbook", "p.yml"])\n')
    slow = _classify(tmp_path, '''
        import helper_mod as hm
        from helper_mod import play

        def test_via_alias():
            hm.play()

        def test_via_from_import():
            play()

        def test_other():
            hm.unrelated()
    ''')
    assert {"test_via_alias", "test_via_from_import"} <= slow
    assert "test_other" not in slow


def test_module_level_alias_of_a_sibling_helper_is_followed(tmp_path):
    (tmp_path / "helper_mod.py").write_text('import subprocess\n\ndef play():\n    subprocess.run(["ansible-playbook", "p.yml"])\n')
    slow = _classify(tmp_path, '''
        import helper_mod as hm
        _play, _other = hm.play, hm.unrelated

        def test_alias():
            _play()

        def test_other_alias():
            _other()
    ''')
    assert "test_alias" in slow
    assert "test_other_alias" not in slow


def test_this_file_stays_in_the_fast_set():
    from pathlib import Path
    assert not _slow_functions(str(Path(__file__)))
