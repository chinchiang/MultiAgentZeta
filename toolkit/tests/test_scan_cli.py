"""The command line of one scan run (〈定義：命令列入口〉): scan.main() over a stack that answers from a script
(tests/scripted.py), so no Docker is needed; one environment test runs it against a real stack."""
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from toolkit import report, scan
from toolkit.tests import scripted
from toolkit.tests.test_e1 import SAMPLES, needs_env
from toolkit.tests.test_scan import EXPECTED, judgement_results, shared_manifest
from toolkit.tests.test_scripted_run import one_case, passing_read

REPO = Path(__file__).resolve().parents[2]


class CommandLine(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.work = Path(self.dir.name)
        self.out = self.work / 'report'

    def manifest_file(self, manifest):
        path = self.work / 'manifest.json'
        path.write_text(manifest if isinstance(manifest, str) else json.dumps(manifest), encoding='utf-8')
        return path

    def run_main(self, manifest, world=None, out_dir=None, prepare=None):
        """(exit status, standard output, standard error, the world the stack answered from)."""
        world = world or scripted.World(attempt=(403, []))
        if prepare is None:
            prepare, _ = scripted.prepare_with(world)
        out, err = io.StringIO(), io.StringIO()
        code = scan.main(['--manifest', str(self.manifest_file(manifest)), '--out', str(out_dir or self.out)],
                         out, err, prepare=prepare)
        return code, out.getvalue(), err.getvalue(), world

    def written(self):
        return sorted(p.name for p in self.out.iterdir()) if self.out.exists() else []

    def test_a_run_writes_the_json_report_and_the_markdown_made_from_it(self):
        m, world = passing_read()
        code, out, err, _ = self.run_main(m, world)
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(self.written(), ['report.json', 'report.md', 'seal.json'])
        doc = json.loads((self.out / 'report.json').read_text(encoding='utf-8'))
        self.assertEqual(report.validate(doc), [])
        self.assertEqual((self.out / 'report.md').read_text(encoding='utf-8'), report.render_markdown(doc))  # TK-EVD-003
        self.assertEqual(doc['status'], 'completed')
        self.assertIn(f'run {doc["run_id"]}: completed (完整完成)', out)  # 完整完成, written here by hand
        self.assertIn(str(self.out / 'report.json'), out)

    def test_a_run_blocked_in_preflight_still_writes_its_report_and_says_why(self):
        m, _ = passing_read()
        del m['limits']
        code, out, err, world = self.run_main(m)
        self.assertEqual((code, err), (0, ''))  # a report was written: the status is in it, and on the line
        doc = json.loads((self.out / 'report.json').read_text(encoding='utf-8'))
        self.assertEqual(doc['status'], 'blocked')
        self.assertIn('blocked (受阻)', out)
        self.assertIn('reason: ', out)
        self.assertIn('limits', out)
        self.assertEqual(world.http_calls, [])  # TK-RUN-002: blocked, and nothing was sent

    def test_a_manifest_that_cannot_be_read_as_an_object_starts_nothing_and_writes_nothing(self):
        prepared = []

        def prepare(project):
            prepared.append(project)
            raise AssertionError('the environment must not be prepared')
        cases = {'cannot be read': self.work / 'gone.json', 'not valid JSON': '<html>', 'must be a JSON object': '[1, 2]'}
        for said, manifest in cases.items():
            with self.subTest(said=said):
                out, err = io.StringIO(), io.StringIO()
                path = manifest if isinstance(manifest, Path) else self.manifest_file(manifest)
                code = scan.main(['--manifest', str(path), '--out', str(self.out)], out, err, prepare=prepare)
                self.assertEqual((code, out.getvalue(), prepared, self.written()), (2, '', [], []))
                self.assertIn(said, err.getvalue())
                self.assertNotIn('Traceback', err.getvalue())

    def test_an_output_directory_inside_the_source_under_test_is_refused(self):
        project = self.work / 'sample'
        shutil.copytree(SAMPLES / 'vulnerable', project)
        m, world = passing_read()
        m['target']['project'] = str(project)
        for inside in (project, project / 'reports' / 'today'):
            with self.subTest(out=inside):
                code, out, err, _ = self.run_main(m, world, out_dir=inside)
                self.assertEqual((code, out), (2, ''))
                self.assertIn('inside the sample source', err)
                self.assertEqual(world.http_calls, [])
                self.assertFalse((project / 'reports').exists())
                self.assertFalse((project / 'report.json').exists())

    def test_an_earlier_report_is_not_overwritten(self):
        m, world = passing_read()
        self.assertEqual(self.run_main(m, world)[0], 0)
        first = (self.out / 'report.json').read_bytes()
        code, out, err, again = self.run_main(m)
        self.assertEqual((code, out), (2, ''))
        self.assertIn('not overwritten', err)
        self.assertEqual(again.http_calls, [])  # refused before the run, not after it
        self.assertEqual((self.out / 'report.json').read_bytes(), first)

    def test_an_output_path_that_is_a_file_is_refused(self):
        self.out.write_text('not a directory', encoding='utf-8')
        m, world = passing_read()
        code, out, err, _ = self.run_main(m, world)
        self.assertEqual((code, out, world.http_calls), (2, '', []))
        self.assertIn('cannot be used', err)

    def test_a_failure_of_the_toolkit_itself_is_status_3_and_writes_no_report(self):
        def prepare(project):
            raise RuntimeError('the container tool broke')
        m, _ = passing_read()
        code, out, err, _ = self.run_main(m, prepare=prepare)
        self.assertEqual((code, out, self.written()), (3, '', []))
        self.assertIn('the container tool broke', err)

    def signalling(self, world, sends):
        """A `prepare` that sends this process the signal `sends` times once the stack is ready."""
        import os
        import signal
        prepare, lifecycle = scripted.prepare_with(world)

        def prepared(project_dir):
            ready = prepare(project_dir)
            for _ in range(sends):
                os.kill(os.getpid(), signal.SIGTERM)
            return ready
        return prepared, lifecycle

    def test_a_signal_aborts_the_run_and_the_report_is_still_written(self):
        import signal
        before = signal.getsignal(signal.SIGTERM)
        m, world = passing_read()
        prepare, lifecycle = self.signalling(world, sends=1)
        code, out, err, _ = self.run_main(m, world, prepare=prepare)
        self.assertEqual(code, 0)
        self.assertIn('abort requested (SIGTERM)', err)
        doc = json.loads((self.out / 'report.json').read_text(encoding='utf-8'))
        self.assertEqual(report.validate(doc), [])
        self.assertEqual(doc['status'], 'cancelled')
        self.assertEqual({e['result'] for e in doc['execution_records']}, {'cancelled'})
        self.assertEqual((doc['abort']['source'], doc['abort']['reason']), ('operator', 'stopped by the operator (SIGTERM)'))
        self.assertIn('cancelled (已取消)', out)  # 已取消, written here by hand
        self.assertEqual(lifecycle.calls, ['destroy'])
        self.assertIs(signal.getsignal(signal.SIGTERM), before)  # the earlier handler is back

    def test_a_second_signal_forces_the_stop_without_a_report_and_the_stack_is_destroyed(self):
        m, world = passing_read()
        prepare, lifecycle = scripted.prepare_with(world)

        def prepared(project_dir):
            import os
            import signal
            ready = prepare(project_dir)
            request = ready.env.request

            def then_signal(*args, **kwargs):  # twice, while a case is running
                os.kill(os.getpid(), signal.SIGTERM)
                os.kill(os.getpid(), signal.SIGTERM)
                return request(*args, **kwargs)
            ready.env.request = then_signal
            return ready
        code, out, err, _ = self.run_main(m, world, prepare=prepared)
        self.assertEqual(code, 3)
        self.assertIn('no report was written', err)
        self.assertEqual(self.written(), [])
        self.assertEqual(lifecycle.calls, ['destroy'])

    def test_the_report_is_sealed_and_a_later_change_is_noticed(self):
        # TK-DAT-009 封存: the digests of the report files are recorded, the files are read-only.
        import os
        import stat
        m, world = passing_read()
        code, out, _, _ = self.run_main(m, world)
        self.assertEqual(code, 0)
        self.assertIn(str(self.out / 'seal.json'), out)
        self.assertEqual(scan.seal_problems(self.out), [])
        for name in ('report.json', 'report.md', 'seal.json'):
            self.assertFalse(stat.S_IMODE(os.stat(self.out / name).st_mode) & 0o222, name)
        sealed = json.loads((self.out / 'seal.json').read_text(encoding='utf-8'))
        self.assertEqual(sorted(sealed['files']), ['report.json', 'report.md'])
        os.chmod(self.out / 'report.md', 0o644)
        (self.out / 'report.md').write_text('rewritten', encoding='utf-8')
        self.assertEqual(scan.seal_problems(self.out), ['report.md was changed after it was sealed'])
        os.chmod(self.out / 'report.json', 0o644)
        (self.out / 'report.json').unlink()
        self.assertIn('report.json is missing', scan.seal_problems(self.out))

    def test_a_directory_without_a_seal_is_not_taken_for_sealed(self):
        self.out.mkdir()
        self.assertEqual(scan.seal_problems(self.out), ['seal.json is missing or unreadable'])

    def test_an_earlier_seal_is_not_overwritten_either(self):
        self.out.mkdir()
        (self.out / 'seal.json').write_text('{}', encoding='utf-8')
        m, world = passing_read()
        code, _, err, _ = self.run_main(m, world)
        self.assertEqual(code, 2)
        self.assertIn('seal.json', err)

    def test_a_fault_is_taken_only_with_the_self_validation_flag(self):
        m, world = passing_read()
        m['tests'] = [dict(m['tests'][0], fault='observer-timeout')]
        code, out, _, _ = self.run_main(m, world)
        self.assertEqual(code, 0)
        self.assertIn('blocked', out)
        self.assertIn('self-validation', out)
        prepare, _ = scripted.prepare_with(world)
        stdout, err = io.StringIO(), io.StringIO()
        other = self.work / 'self-validation'
        code = scan.main(['--manifest', str(self.manifest_file(m)), '--out', str(other), '--self-validation'],
                         stdout, err, prepare=prepare)
        self.assertEqual((code, err.getvalue()), (0, ''))
        doc = json.loads((other / 'report.json').read_text(encoding='utf-8'))
        self.assertIs(doc['self_validation'], True)
        self.assertEqual([(e['result'], e['fault']) for e in doc['execution_records']], [('blocked', 'observer-timeout')])

    def test_no_credential_reaches_the_output_or_the_files(self):
        m = one_case('READ-other-tenant')
        code, out, err, world = self.run_main(m, scripted.World(attempt=(200, [{'title': 'MARK-A-ALICE-PRIVATE', 'body': 'b'}])))
        self.assertEqual(code, 0)
        files = ''.join(p.read_text(encoding='utf-8') for p in self.out.iterdir())
        sent = {v for _, _, headers, _ in world.http_calls for v in headers.values()}
        secrets = {scripted.OBSERVER_PASSWORD, 'anon-key', 'sb_publishable_key',
                   *(v.removeprefix('Bearer ') for v in sent if v.startswith('Bearer '))}
        self.assertTrue(any(s.startswith('token-') for s in secrets), secrets)  # the tokens really were sent
        for secret in secrets:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, out + err + files)  # TK-IDN-005

    def test_the_script_runs_under_isolated_python_and_refuses_a_missing_manifest(self):
        done = subprocess.run([sys.executable, '-I', str(REPO / 'toolkit' / 'tools' / 'scan_run.py'),
                               '--manifest', str(self.work / 'gone.json'), '--out', str(self.out)],
                              cwd=self.work, capture_output=True, text=True, timeout=60)
        self.assertEqual((done.returncode, done.stdout), (2, ''), done.stderr)
        self.assertIn('cannot be read', done.stderr)
        self.assertEqual(self.written(), [])


@needs_env
class CommandLineEnv(unittest.TestCase):
    """The same judgement through the command line as through scan.run(), against a real E1 stack."""

    def test_the_vulnerable_sample_is_judged_as_by_scan_run(self):
        with tempfile.TemporaryDirectory() as d:
            manifest = Path(d) / 'manifest.json'
            manifest.write_text(json.dumps(shared_manifest('vulnerable')), encoding='utf-8')
            out, err = io.StringIO(), io.StringIO()
            code = scan.main(['--manifest', str(manifest), '--out', str(Path(d) / 'report')], out, err)
            self.assertEqual((code, err.getvalue()), (0, ''))
            doc = json.loads((Path(d) / 'report' / 'report.json').read_text(encoding='utf-8'))
        self.assertEqual(report.validate(doc), [])
        self.assertEqual(doc['status'], 'completed')
        self.assertEqual(judgement_results(doc), EXPECTED['vulnerable'])


if __name__ == '__main__':
    unittest.main()
