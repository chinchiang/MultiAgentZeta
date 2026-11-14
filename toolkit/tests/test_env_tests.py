"""toolkit/tools/env_tests.py, the environment test runner behind run-env-tests.sh: reading its log,
counting the planned tests, the lock that lets one run at a time, and spotting other test runs."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from toolkit.tools import env_tests


def header(total, args='["-p", "test_x.py"]'):
    return f'# env-tests name=demo head=abc1234 args={args} total={total} started=2026-11-04T01:00:00Z\n'


END = '# end exit={exit} wall=12.6 ended=2026-11-04T01:00:13Z\n'
RUNNING = header(5) + (
    'test_a (toolkit.tests.test_x.A.test_a) ... ok\n'
    'test_b (toolkit.tests.test_x.A.test_b)\nHas a docstring. ... ok\n'
    'test_c (toolkit.tests.test_x.A.test_c) ... \n'
    '  test_c (toolkit.tests.test_x.A.test_c) (i=1) ... FAIL\n'
    "test_s (toolkit.tests.test_x.A.test_s) ... skipped 'no Docker'\n"
    'test_d (toolkit.tests.test_x.A.test_d) ... ')
FINISHED = RUNNING + (
    'ok\n\n======================================================================\n'
    'FAIL: test_c (toolkit.tests.test_x.A.test_c) (i=1)\n'
    '----------------------------------------------------------------------\nAssertionError: 1 != 0\n\n'
    '----------------------------------------------------------------------\nRan 5 tests in 12.500s\n\n'
    'FAILED (failures=1, skipped=1)\n' + END.format(exit=1))


class ParseLog(unittest.TestCase):
    def test_a_running_log_counts_tests_with_a_result_and_names_failures_so_far(self):
        s = env_tests.parse_log(RUNNING)
        self.assertEqual((s.finished, s.total, s.done, s.skipped, s.exit), (False, 5, 4, 1, None))
        self.assertEqual(s.failures, ['test_c (toolkit.tests.test_x.A.test_c) (i=1)'])
        self.assertEqual((s.head, s.args), ('abc1234', ['-p', 'test_x.py']))

    def test_the_last_test_counts_once_it_has_its_result(self):
        self.assertEqual(env_tests.parse_log(RUNNING + 'ok\n').done, 5)

    def test_a_finished_log_gives_the_count_exit_code_and_time(self):
        s = env_tests.parse_log(FINISHED)
        self.assertEqual((s.finished, s.done, s.ran, s.exit, s.wall, s.not_run), (True, 5, 5, 1, 12.6, 0))
        self.assertEqual(s.failures, ['test_c (toolkit.tests.test_x.A.test_c) (i=1)'])

    def test_a_result_after_output_of_the_test_itself_is_still_read(self):
        s = env_tests.parse_log(header(1) + 'test_m (toolkit.tests.test_x.C.test_m) ... noiseFAIL\n')
        self.assertEqual((s.done, s.failures), (1, ['test_m (toolkit.tests.test_x.C.test_m)']))

    def test_a_setupclass_error_is_a_failure_and_its_tests_are_not_run(self):
        log = header(3) + ('setUpClass (toolkit.tests.test_x.B) ... ERROR\n'
                           'test_a (toolkit.tests.test_x.A.test_a) ... ok\n\n'
                           'ERROR: setUpClass (toolkit.tests.test_x.B)\nRuntimeError: boom\n\n'
                           'Ran 1 test in 0.1s\n\nFAILED (errors=1)\n' + END.format(exit=1))
        s = env_tests.parse_log(log)
        self.assertEqual((s.done, s.ran, s.total, s.not_run), (1, 1, 3, 2))
        self.assertEqual(s.failures, ['setUpClass (toolkit.tests.test_x.B)'])
        self.assertIn('2 planned tests did not run', env_tests.describe(s))

    def test_a_run_that_failed_before_its_tests_says_why(self):
        log = header(0) + '# not started: fetch-supabase-cli.sh failed: curl: (6) Could not resolve host\n' + END.format(exit=2)
        s = env_tests.parse_log(log)
        self.assertEqual((s.finished, s.exit, s.problem), (True, 2, 'fetch-supabase-cli.sh failed: curl: (6) Could not resolve host'))
        self.assertIn('Could not resolve host', env_tests.describe(s))

    def test_status_shows_done_of_total_running_and_finished(self):
        self.assertIn('4/5 tests done', env_tests.describe(env_tests.parse_log(RUNNING)))
        finished = env_tests.describe(env_tests.parse_log(FINISHED))
        self.assertIn('5/5 tests done', finished)
        self.assertIn('1 skipped', finished)

    def test_a_log_without_its_header_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'header'):
            env_tests.parse_log('test_a (toolkit.tests.test_x.A.test_a) ... ok\n')


class CountTests(unittest.TestCase):
    """The total is what discover will run with the same -p and -k, not an estimate."""

    def ran(self, *args):
        out = subprocess.run(['python3', '-I', '-m', 'unittest', *env_tests.DISCOVER, *args],
                             cwd=env_tests.REPO, capture_output=True, text=True).stderr
        return int(next(l for l in out.splitlines() if l.startswith('Ran ')).split()[1])

    def test_counts_follow_pattern_and_name_filters(self):
        self.assertEqual(env_tests.count_tests(['-p', 'test_layout.py']), self.ran('-p', 'test_layout.py'))
        self.assertEqual(env_tests.count_tests(['-p', 'test_layout.py', '-k', 'every']), 1)
        self.assertEqual(env_tests.count_tests(['-p', 'test_layout.py', '-k', 'guard', '-k', 'every']), 3)

    def test_no_matching_test_counts_zero_and_other_arguments_are_refused(self):
        self.assertEqual(env_tests.count_tests(['-p', 'test_no_such_file.py']), 0)
        with self.assertRaisesRegex(ValueError, '-f'):
            env_tests.count_tests(['-f'])


class Lock(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.lock = Path(d.name) / 'env-tests.lock'

    def test_a_live_run_refuses_a_second_start(self):
        env_tests.acquire_lock(self.lock, os.getpid(), 'first')
        with self.assertRaisesRegex(env_tests.Busy, f'{os.getpid()}.*first'):
            env_tests.acquire_lock(self.lock, os.getpid(), 'second')

    def test_a_lock_left_by_a_run_that_is_gone_is_replaced(self):
        gone = subprocess.Popen(['true'])
        gone.wait()
        env_tests.acquire_lock(self.lock, gone.pid, 'old')
        env_tests.acquire_lock(self.lock, os.getpid(), 'new')
        self.assertEqual(env_tests.read_lock(self.lock), (os.getpid(), 'new'))


class OtherTestRuns(unittest.TestCase):
    """Leftover Docker resources are removed only when no test run uses them: none from another clone, a
    manual MAZ_ENV_TESTS=1 run, or a test process a stopped runner left behind."""

    PS = ('  101 /usr/bin/python3 -I -m unittest discover -v -s toolkit/tests -t .\n'
          '  102 python3 -I -m unittest discover -s toolkit/tests -t . -p test_scan.py\n'
          '  103 /bin/bash -c grep unittest discover\n'
          '  104 python3 -m pytest tests\n')

    def test_test_processes_are_found_and_others_are_not(self):
        self.assertEqual(env_tests.other_test_runs(self.PS, exclude={102}), [
            '101 /usr/bin/python3 -I -m unittest discover -v -s toolkit/tests -t .'])
        self.assertEqual(env_tests.other_test_runs('  104 python3 -m pytest tests\n', exclude=set()), [])


@unittest.skipUnless(shutil.which('sh'), 'sh is not installed')
class RunScriptPicksTheInterpreter(unittest.TestCase):
    """run-env-tests.sh in a throwaway copy of the layout, with fake interpreters that only say who they are."""

    SCRIPT = Path(__file__).resolve().parents[1] / 'tools' / 'run-env-tests.sh'

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name).resolve() / 'repo'
        tools = self.root / 'toolkit' / 'tools'
        tools.mkdir(parents=True)
        shutil.copy(self.SCRIPT, tools / 'run-env-tests.sh')
        (tools / 'env_tests.py').write_text('', encoding='utf-8')
        self.path_bin = Path(self.dir.name).resolve() / 'bin'
        self.path_bin.mkdir()
        self.fake(self.path_bin / 'python3', 'path-python3')

    def fake(self, path, name, mode=0o755):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f'#!/bin/sh\necho "{name} $*"\n', encoding='utf-8')
        path.chmod(mode)

    def run_script(self, *args, cwd=None, env=None):
        environ = {'PATH': f'{self.path_bin}:/usr/bin:/bin', **(env or {})}
        run = subprocess.run(['sh', str(self.root / 'toolkit' / 'tools' / 'run-env-tests.sh'), *args],
                             cwd=cwd or self.root, env=environ, capture_output=True, text=True)
        return run.returncode, run.stdout.strip()

    def test_the_repository_venv_is_used_when_it_exists_and_arguments_pass_through(self):
        self.fake(self.root / '.venv' / 'bin' / 'python', 'venv-python')
        code, out = self.run_script('demo', '-p', 'test_x.py', '-k', 'a b')
        self.assertEqual((code, out), (0, f'venv-python -I {self.root}/toolkit/tools/env_tests.py demo -p test_x.py -k a b'))

    def test_without_a_venv_python3_on_the_path_is_used(self):
        code, out = self.run_script('--status', 'demo')
        self.assertEqual((code, out), (0, f'path-python3 -I {self.root}/toolkit/tools/env_tests.py --status demo'))

    def test_a_venv_python_that_cannot_run_falls_back_to_python3(self):
        self.fake(self.root / '.venv' / 'bin' / 'python', 'venv-python', mode=0o644)
        self.assertEqual(self.run_script('demo')[1].split()[0], 'path-python3')
        (self.root / '.venv' / 'bin' / 'python').unlink()
        (self.root / '.venv' / 'bin' / 'python').symlink_to(self.root / 'nowhere')
        self.assertEqual(self.run_script('demo')[1].split()[0], 'path-python3')

    def test_the_repository_venv_wins_over_another_active_environment(self):
        self.fake(self.root / '.venv' / 'bin' / 'python', 'venv-python')
        other = Path(self.dir.name).resolve() / 'other-venv'
        self.fake(other / 'bin' / 'python3', 'other-python3')
        code, out = self.run_script('demo', env={'VIRTUAL_ENV': str(other), 'PATH': f'{other}/bin:{self.path_bin}:/usr/bin:/bin'})
        self.assertEqual(out.split()[0], 'venv-python')

    def test_it_finds_the_venv_from_any_working_directory(self):
        self.fake(self.root / '.venv' / 'bin' / 'python', 'venv-python')
        elsewhere = Path(self.dir.name).resolve() / 'elsewhere'
        elsewhere.mkdir()
        self.assertEqual(self.run_script('demo', cwd=elsewhere)[1].split()[0], 'venv-python')


if __name__ == '__main__':
    unittest.main()
