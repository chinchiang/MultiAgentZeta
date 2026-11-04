"""Records in the control zone (〈定義：確認清單〉 保存位置, 〈定義：測試授權紀錄〉), tested through toolkit.control.

Fast tests only.
"""
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from toolkit import control


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
