"""toolkit/tools/env_tests.py, the environment test runner behind run-env-tests.sh: reading its log,
counting the planned tests, the lock that lets one run at a time, and spotting other test runs."""
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
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
    """The lock is held by open descriptors, not by what the file says: a start is refused exactly while a
    process holding it lives."""

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.lock = Path(d.name) / 'env-tests.lock'

    def take(self, name):
        fd = env_tests.acquire_lock(self.lock, name)
        self.addCleanup(self.close, fd)
        return fd

    @staticmethod
    def close(fd):
        try:
            os.close(fd)
        except OSError:
            pass

    def holder(self, fd, seconds):
        """A child process that inherits the lock descriptor, as a run does, and lives for a while."""
        child = subprocess.Popen([sys.executable, '-c', f'import time; time.sleep({seconds})'], pass_fds=(fd,))
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        return child

    def test_a_live_run_refuses_a_second_start_and_says_who_holds_it(self):
        self.take('first')
        self.assertTrue(env_tests.lock_held(self.lock))
        with self.assertRaisesRegex(env_tests.Busy, f'{os.getpid()}.*first'):
            env_tests.acquire_lock(self.lock, 'second')
        self.assertEqual(env_tests.read_lock(self.lock), (os.getpid(), 'first'))  # the refusal changed nothing

    def test_no_lock_file_and_a_released_lock_are_both_free(self):
        self.assertFalse(env_tests.lock_held(self.lock))
        os.close(self.take('first'))
        self.assertFalse(env_tests.lock_held(self.lock))
        self.take('second')
        self.assertEqual(env_tests.read_lock(self.lock), (os.getpid(), 'second'))

    def test_a_lock_file_naming_a_live_process_that_does_not_hold_it_is_free(self):
        # What the file says is not the lock: a process id reused by something else locks nothing.
        self.lock.write_text(f'{os.getpid()} stale\n', encoding='utf-8')
        self.assertFalse(env_tests.lock_held(self.lock))
        self.take('new')

    def test_the_run_keeps_the_lock_after_the_starter_let_go(self):
        # The starter is interrupted, or simply returns, right after starting the run.
        fd = self.take('run')
        child = self.holder(fd, 30)
        os.close(fd)
        self.assertTrue(env_tests.lock_held(self.lock))
        with self.assertRaises(env_tests.Busy):
            env_tests.acquire_lock(self.lock, 'second')
        child.kill()
        child.wait()
        self.assertFalse(env_tests.lock_held(self.lock))

    def test_a_run_that_ends_at_once_leaves_no_lock_behind(self):
        fd = self.take('run')
        child = subprocess.Popen([sys.executable, '-c', 'pass'], pass_fds=(fd,))
        child.wait()  # gone before the starter did anything else
        self.assertTrue(env_tests.lock_held(self.lock))  # the starter still holds its own copy
        os.close(fd)
        self.assertFalse(env_tests.lock_held(self.lock))
        self.take('next')

    def test_asking_whether_it_is_held_does_not_take_it(self):
        self.assertFalse(env_tests.lock_held(self.lock))
        self.lock.write_text('', encoding='utf-8')
        for _ in range(3):
            self.assertFalse(env_tests.lock_held(self.lock))
        self.take('first')


class SupabaseCli(unittest.TestCase):
    """The run uses the CLI MAZ_SUPABASE_BIN names when that file exists, and fetches one only otherwise."""

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.given = Path(d.name) / 'supabase'
        self.fetched = []

    def fetch(self):
        self.fetched.append(True)
        return '/fetched/supabase', None

    def test_a_cli_that_is_already_given_is_kept(self):
        self.given.write_bytes(b'cli')
        self.assertEqual(env_tests.supabase_cli({'MAZ_SUPABASE_BIN': str(self.given)}, self.fetch),
                         (str(self.given), None))
        self.assertEqual(self.fetched, [])

    def test_without_one_or_with_a_path_that_is_no_file_it_is_fetched(self):
        for environ in ({}, {'MAZ_SUPABASE_BIN': ''}, {'MAZ_SUPABASE_BIN': str(self.given)},
                        {'MAZ_SUPABASE_BIN': str(self.given.parent)}):
            with self.subTest(environ=environ):
                self.fetched.clear()
                self.assertEqual(env_tests.supabase_cli(environ, self.fetch), ('/fetched/supabase', None))
                self.assertEqual(self.fetched, [True])

    def test_a_fetch_that_fails_is_passed_on(self):
        self.assertEqual(env_tests.supabase_cli({}, lambda: (None, 'no network')), (None, 'no network'))


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

    def test_a_test_run_is_found_however_it_was_started(self):
        for command in ('python3 -I toolkit/tests/test_e1.py',
                        '/repo/.venv/bin/python -I -m unittest toolkit/tests/test_scan.py',
                        'python3.12 -I -m unittest discover -s ./toolkit/tests -t .',
                        'python3 -m unittest discover -s /home/me/clone/toolkit/tests -t /home/me/clone',
                        'python3 -m unittest toolkit.tests.test_scan.VulnerableRunEnv',
                        'python -I -m unittest -v toolkit/tests/test_e1.py -k Reset',
                        '/other/clone/.venv/bin/python -I /other/clone/toolkit/tools/env_tests.py _run nightly -p test_e1.py'):
            with self.subTest(command=command):
                self.assertEqual(env_tests.other_test_runs(f'  201 {command}\n', exclude=set()), [f'201 {command}'])

    def test_what_only_mentions_the_tests_or_tests_something_else_is_not_a_test_run(self):
        for command in ('vim toolkit/tests/test_e1.py', 'grep -rn needs_env toolkit/tests',
                        '/bin/sh toolkit/tools/run-env-tests.sh --status demo',
                        'python3 -I -m unittest discover -s docs/toolkit/tools',
                        'python3 -I docs/toolkit/tools/build.py --check', 'python3 -I toolkit/tools/env_tests.py --status x'):
            with self.subTest(command=command):
                self.assertEqual(env_tests.other_test_runs(f'  301 {command}\n', exclude=set()), [])

    def test_the_asking_process_is_left_out(self):
        self.assertEqual(env_tests.other_test_runs('  401 python3 -I toolkit/tests/test_e1.py\n', exclude={401}), [])


@unittest.skipUnless(all(shutil.which(t) for t in ('sh', 'tar', 'sha256sum', 'mktemp')), 'needs sh, tar, sha256sum, mktemp')
class FetchSupabaseCli(unittest.TestCase):
    """fetch-supabase-cli.sh in a throwaway copy of the layout, with its own support matrix, a curl that
    serves a local archive and a uname the test sets: nothing is downloaded."""

    SCRIPT = Path(__file__).resolve().parents[1] / 'tools' / 'fetch-supabase-cli.sh'
    BINARY = b'#!/bin/sh\necho pinned supabase\n'

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        root = Path(self.dir.name).resolve()
        self.repo, self.bin, self.dest = root / 'repo', root / 'bin', root / 'dest'
        (self.repo / 'toolkit' / 'tools').mkdir(parents=True)
        self.bin.mkdir()
        shutil.copy(self.SCRIPT, self.repo / 'toolkit' / 'tools' / 'fetch-supabase-cli.sh')
        self.archive = root / 'served.tar.gz'
        self.pack(self.BINARY)
        self.tool('curl', f'out=; while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done; cp "{self.archive}" "$out"')
        self.machine('Linux', 'x86_64')
        self.matrix(binary=self.BINARY)

    def tool(self, name, body):
        (self.bin / name).write_text(f'#!/bin/sh\n{body}\n', encoding='utf-8')
        (self.bin / name).chmod(0o755)

    def machine(self, system, arch):
        self.tool('uname', f'case "$1" in -s) echo {system};; -m) echo {arch};; esac')

    def pack(self, content):
        with tarfile.open(self.archive, 'w:gz') as tar:
            info = tarfile.TarInfo('supabase')
            info.size, info.mode = len(content), 0o755
            tar.addfile(info, io.BytesIO(content))

    def matrix(self, binary, archive=None):
        digest = lambda data: hashlib.sha256(data).hexdigest()
        entry = {'version': '9.9.9', 'archive_sha256': digest(self.archive.read_bytes() if archive is None else archive),
                 'binary_sha256': digest(binary)}
        (self.repo / 'toolkit' / 'support-matrix.json').write_text(json.dumps({'tools': {'supabase-cli': entry}}),
                                                                 encoding='utf-8')

    def fetch(self):
        run = subprocess.run(['sh', str(self.repo / 'toolkit' / 'tools' / 'fetch-supabase-cli.sh'), str(self.dest)],
                             env={'PATH': f'{self.bin}:{os.environ["PATH"]}'}, capture_output=True, text=True)
        return run.returncode, run.stdout.strip(), run.stderr

    def left_in_dest(self):
        return sorted(p.name for p in self.dest.iterdir()) if self.dest.exists() else []

    def test_a_verified_binary_is_put_in_place_and_its_path_printed(self):
        code, out, err = self.fetch()
        self.assertEqual((code, out), (0, str(self.dest / 'supabase')), err)
        self.assertEqual((self.dest / 'supabase').read_bytes(), self.BINARY)
        self.assertEqual(self.left_in_dest(), ['supabase'])  # no archive and no temporary directory left

    def test_a_binary_already_there_with_the_pinned_digest_is_reused_without_fetching(self):
        self.fetch()
        self.tool('curl', 'echo "curl must not run" >&2; exit 9')
        code, out, err = self.fetch()
        self.assertEqual((code, out), (0, str(self.dest / 'supabase')), err)

    def test_an_archive_with_another_digest_leaves_no_binary(self):
        self.matrix(binary=self.BINARY, archive=b'another archive')
        code, out, _ = self.fetch()
        self.assertNotEqual(code, 0)
        self.assertEqual((out, self.left_in_dest()), ('', []))

    def test_a_binary_with_another_digest_leaves_no_binary(self):
        self.matrix(binary=b'what the matrix pins')
        code, out, _ = self.fetch()
        self.assertNotEqual(code, 0)
        self.assertEqual((out, self.left_in_dest()), ('', []))

    def test_a_download_that_fails_removes_a_stale_binary_and_leaves_none(self):
        self.dest.mkdir()
        (self.dest / 'supabase').write_bytes(b'an old or tampered binary')
        self.tool('curl', 'exit 22')
        code, out, _ = self.fetch()
        self.assertNotEqual(code, 0)
        self.assertEqual((out, self.left_in_dest()), ('', []))

    def test_another_system_or_architecture_is_refused_before_anything_is_fetched(self):
        self.tool('curl', 'echo "curl must not run" >&2; exit 9')
        for system, arch in (('Darwin', 'arm64'), ('Linux', 'aarch64'), ('Darwin', 'x86_64')):
            with self.subTest(system=system, arch=arch):
                self.machine(system, arch)
                code, out, err = self.fetch()
                self.assertNotEqual(code, 0)
                self.assertIn(f'{system} {arch}', err)
                self.assertNotIn('curl must not run', err)
                self.assertEqual((out, self.left_in_dest()), ('', []))


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
