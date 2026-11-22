"""Records in the control zone (〈定義：確認清單〉 保存位置, 〈定義：測試授權紀錄〉), tested through toolkit.control.

Fast tests only.
"""
import fcntl
import multiprocessing
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from toolkit import control


def _append_in_child(path, source, begin, contended):
    if not begin.wait(10):
        raise TimeoutError('parent did not start its update')
    flock = fcntl.flock

    def observe_lock(fd, mode):
        try:
            flock(fd, mode | fcntl.LOCK_NB)
        except BlockingIOError:
            contended.set()
            flock(fd, mode)

    with patch.object(fcntl, 'flock', observe_lock):
        with control.writer(path, source, 'record') as save:
            save(control.current(path, source, 'record') + ['child'])


class ReadWrite(unittest.TestCase):
    """A record lives outside the sample source and is read only with the digest that references it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.source = Path(self.tmp.name) / 'project'
        self.source.mkdir()
        self.path = Path(self.tmp.name) / 'control' / 'record.json'
        self.doc = {'schema_version': '1', 'note': '確認'}

    def test_a_written_record_reads_back_with_its_digest(self):
        digest = control.write(self.path, self.doc, self.source)
        self.assertRegex(digest, r'^sha256:[0-9a-f]{64}$')
        self.assertEqual(digest, control.file_digest(self.path))
        self.assertEqual(control.read(self.path, digest, self.source), self.doc)

    def test_read_uses_the_bytes_that_were_verified(self):
        digest = control.write(self.path, self.doc, self.source)
        original = Path.read_bytes

        def replace_after_read(path):
            data = original(path)
            path.write_bytes(b'{"new": true}')
            return data

        with patch.object(Path, 'read_bytes', replace_after_read):
            self.assertEqual(control.read(self.path, digest, self.source), self.doc)

    def test_writer_returns_the_digest_of_its_own_bytes(self):
        expected = control.write(self.path, self.doc, self.source)
        replace = os.replace

        def update_after_replace(src, dst):
            replace(src, dst)
            Path(dst).write_bytes(b'{"new": true}')

        with patch.object(os, 'replace', update_after_replace):
            self.assertEqual(control.write(self.path, self.doc, self.source), expected)

    def test_child_process_waits_then_updates_the_committed_version(self):
        control.write(self.path, [], self.source)
        ctx = multiprocessing.get_context('fork')
        begin, contended = ctx.Event(), ctx.Event()
        child = ctx.Process(target=_append_in_child, args=(self.path, self.source, begin, contended))
        child.start()
        try:
            with control.writer(self.path, self.source, 'record') as save:
                begin.set()
                self.assertTrue(contended.wait(10), 'child did not encounter the held lock')
                save(['parent'])
            child.join(10)
            self.assertEqual(child.exitcode, 0)
            self.assertEqual(control.current(self.path, self.source, 'record'), ['parent', 'child'])
        finally:
            if child.is_alive():
                child.kill()
                child.join()
            child.close()

    def test_failed_replace_preserves_the_record_and_allows_retry(self):
        original = control.write(self.path, self.doc, self.source)
        revised = {**self.doc, 'note': '核准'}
        with patch.object(os, 'replace', side_effect=OSError('replace failed')):
            with self.assertRaisesRegex(control.RecordUnusable, 'replace failed'):
                control.write(self.path, revised, self.source)
        self.assertEqual(control.read(self.path, original, self.source), self.doc)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])
        updated = control.write(self.path, revised, self.source)
        self.assertEqual(control.read(self.path, updated, self.source), revised)

    def test_a_path_inside_the_sample_source_is_refused(self):
        for path in (self.source / 'record.json', self.source / 'sub' / '..' / 'record.json'):
            with self.subTest(path=str(path)):
                with self.assertRaises(control.RecordUnusable) as cm:
                    control.write(path, self.doc, self.source)
                self.assertIn('inside the sample source', str(cm.exception))
                with self.assertRaises(control.RecordUnusable):
                    control.read(path, 'sha256:' + '0' * 64, self.source)

    def test_a_missing_file_is_not_replaced(self):
        digest = 'sha256:' + 'ab' * 32
        with self.assertRaises(control.RecordUnusable) as cm:
            control.read(self.path, digest, self.source)
        self.assertIn(f'is referenced with digest {digest} but does not exist', str(cm.exception))
        self.assertFalse(self.path.exists())

    def test_a_digest_that_does_not_match_or_an_unreadable_file_is_refused(self):
        control.write(self.path, self.doc, self.source)
        with self.assertRaises(control.RecordUnusable) as cm:
            control.read(self.path, 'sha256:' + '0' * 64, self.source)
        self.assertIn('the ScanManifest says', str(cm.exception))
        self.path.write_text('not json', encoding='utf-8')
        with self.assertRaises(control.RecordUnusable) as cm:
            control.read(self.path, control.file_digest(self.path), self.source)
        self.assertIn('cannot be read', str(cm.exception))


class UtcTime(unittest.TestCase):
    """The times of control-zone records: ISO 8601 UTC, such as 2027-05-01T00:00:00Z."""

    def test_utc_times_are_read_and_anything_else_is_none(self):
        self.assertEqual(control.utc_time('2027-05-01T00:00:00Z'), datetime(2027, 5, 1, tzinfo=timezone.utc))
        self.assertEqual(control.utc_time('2027-05-01T00:00:00.5Z'),
                         datetime(2027, 5, 1, 0, 0, 0, 500000, tzinfo=timezone.utc))
        for value in ('2027-05-01', '2027-05-01T00:00:00+08:00', '2027-02-30T00:00:00Z', 'soon', None, 20270501):
            with self.subTest(value=value):
                self.assertIsNone(control.utc_time(value))


if __name__ == '__main__':
    unittest.main()
