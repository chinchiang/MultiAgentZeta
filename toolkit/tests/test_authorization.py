"""The test authorization record (〈定義：測試授權紀錄〉, TK-ENV-001, TK-ENV-002), tested through toolkit.authorization.

Fast tests only. Expected values are written from the definition, not derived from the code.
"""
import copy
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from toolkit import authorization, scan

NOW = datetime(2026, 11, 5, 9, 0, tzinfo=timezone.utc)


def record(**changes):
    """A complete authorization record: the vulnerable sample in E1, documents read only, one extra
    approval for DELETE on documents."""
    doc = {'schema_version': '1', 'targets': ['object-authz/vulnerable'], 'environment': 'E1',
           'data_scope': 'synthetic sample data of samples/object-authz only',
           'valid_from': '2026-11-01T00:00:00Z', 'valid_until': '2026-12-01T00:00:00Z',
           'operations': [{'resource': 'documents', 'methods': ['GET']}],
           'roles': {'app_owner': 'app-owner', 'operator': 'tester'},
           'issued_by': 'app-owner', 'issued_at': '2026-11-01T00:00:00Z',
           'extra_approvals': [{'approval_id': 'APR-001', 'operations': [{'resource': 'documents', 'methods': ['DELETE']}],
                                'by': 'security-lead', 'at': '2026-11-02T00:00:00Z', 'reason': 'delete cases on E1',
                                'valid_until': '2026-11-30T00:00:00Z'}]}
    doc.update(changes)
    return doc


class Validate(unittest.TestCase):
    """validate(): the schema, and the conditions it cannot express."""

    def test_a_complete_record_is_valid(self):
        self.assertEqual(authorization.validate(record()), [])
        self.assertEqual(authorization.validate(record(extra_approvals=[])), [])
        no_approvals = record()
        del no_approvals['extra_approvals']
        self.assertEqual(authorization.validate(no_approvals), [])

    def test_each_part_of_the_record_is_required(self):
        for name in ('targets', 'environment', 'data_scope', 'valid_from', 'valid_until', 'operations', 'roles',
                     'issued_by', 'issued_at'):
            with self.subTest(missing=name):
                doc = record()
                del doc[name]
                self.assertTrue(any(name in p for p in authorization.validate(doc)), authorization.validate(doc))

    def test_blank_or_empty_parts_are_invalid(self):
        changes = {'targets': [], 'data_scope': '  ', 'operations': [], 'issued_by': '',
                   'roles': {'app_owner': 'app-owner', 'operator': ' '}}
        for name, value in changes.items():
            with self.subTest(name=name):
                self.assertNotEqual(authorization.validate(record(**{name: value})), [])

    def test_methods_are_http_methods_of_the_scope(self):
        bad = record(operations=[{'resource': 'documents', 'methods': ['TRUNCATE']}])
        self.assertNotEqual(authorization.validate(bad), [])

    def test_times_are_iso_8601_utc_and_the_period_is_in_order(self):
        cases = {'valid_from': '2026-11-01', 'valid_until': 'next month', 'issued_at': '2026-11-01T08:00:00+08:00'}
        for name, value in cases.items():
            with self.subTest(name=name):
                self.assertIn(f'{name} {value!r} is not an ISO 8601 UTC time',
                              '; '.join(authorization.validate(record(**{name: value}))))
        reversed_period = record(valid_from='2026-12-01T00:00:00Z', valid_until='2026-11-01T00:00:00Z')
        self.assertIn('valid_from must be earlier than valid_until', '; '.join(authorization.validate(reversed_period)))

    def test_a_resource_is_listed_once(self):
        twice = record(operations=[{'resource': 'documents', 'methods': ['GET']},
                                   {'resource': 'documents', 'methods': ['POST']}])
        self.assertIn("operations lists resource 'documents' twice", '; '.join(authorization.validate(twice)))

    def test_an_extra_approval_needs_each_part_an_id_of_its_own_and_ends_within_the_record(self):
        for name in ('approval_id', 'operations', 'by', 'at', 'reason', 'valid_until'):
            with self.subTest(missing=name):
                doc = record()
                del doc['extra_approvals'][0][name]
                self.assertNotEqual(authorization.validate(doc), [])
        doc = record()
        doc['extra_approvals'][0]['reason'] = ' '
        self.assertNotEqual(authorization.validate(doc), [])
        doc = record()
        doc['extra_approvals'].append(copy.deepcopy(doc['extra_approvals'][0]))
        self.assertIn("approval_id 'APR-001' is used twice", '; '.join(authorization.validate(doc)))
        doc = record()
        doc['extra_approvals'][0]['valid_until'] = '2026-12-02T00:00:00Z'
        self.assertIn('extra_approvals/0.valid_until must not be later than valid_until',
                      '; '.join(authorization.validate(doc)))
        doc = record()
        doc['extra_approvals'][0]['at'] = 'yesterday'
        self.assertIn("extra_approvals/0.at 'yesterday' is not an ISO 8601 UTC time", '; '.join(authorization.validate(doc)))

    def test_the_methods_agree_with_both_schemas(self):
        from toolkit import report
        schema = authorization.SCHEMA['$defs']['operation']['properties']['methods']['items']['enum']
        self.assertEqual(schema, list(authorization.METHODS))
        shown = report.SCHEMA['$defs']['authorized_operation']['properties']['methods']['items']['enum']
        self.assertEqual(shown, list(authorization.METHODS))
        self.assertEqual(list(authorization.METHODS), ['GET', 'POST', 'PATCH', 'DELETE'])


class Read(unittest.TestCase):
    """read(): from the control zone with its digest (toolkit.control), then validated."""

    def setUp(self):
        from toolkit import control
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.source = Path(self.tmp.name) / 'project'
        self.source.mkdir()
        self.path = Path(self.tmp.name) / 'control' / 'authorization.json'
        self.write = lambda doc: control.write(self.path, doc, self.source)

    def test_a_valid_record_is_read(self):
        self.assertEqual(authorization.read(self.path, self.write(record()), self.source), record())

    def test_an_invalid_record_is_refused_with_its_problems(self):
        digest = self.write(record(environment=''))
        with self.assertRaises(authorization.AuthorizationUnusable) as cm:
            authorization.read(self.path, digest, self.source)
        self.assertIn('not a valid test authorization record', str(cm.exception))

    def test_a_record_inside_the_sample_source_or_with_another_digest_is_refused(self):
        self.write(record())
        for path, digest in ((self.source / 'authorization.json', 'sha256:' + '0' * 64), (self.path, 'sha256:' + '0' * 64)):
            with self.subTest(path=str(path)):
                with self.assertRaises(authorization.AuthorizationUnusable):
                    authorization.read(path, digest, self.source)


class RunProblem(unittest.TestCase):
    """The record covers the run: its period at the run's start, the sample and the environment."""

    def test_the_period_is_judged_at_the_runs_start(self):
        self.assertIsNone(authorization.period_problem(record(), NOW))
        for now in (datetime(2026, 10, 31, tzinfo=timezone.utc), datetime(2026, 12, 1, tzinfo=timezone.utc)):
            with self.subTest(now=now):
                self.assertIn('outside the authorized period 2026-11-01T00:00:00Z to 2026-12-01T00:00:00Z',
                              authorization.period_problem(record(), now))

    def test_the_sample_and_the_environment_must_be_targets(self):
        self.assertIsNone(authorization.target_problem(record(), 'object-authz/vulnerable', 'E1'))
        self.assertIn("sample 'object-authz/patched' is not a target",
                      authorization.target_problem(record(), 'object-authz/patched', 'E1'))
        self.assertIn("environment 'E2' is not the authorized environment 'E1'",
                      authorization.target_problem(record(), 'object-authz/vulnerable', 'E2'))


class OperationProblem(unittest.TestCase):
    """An operation the record does not list needs an extra approval covering it (TK-ENV-001)."""

    def test_an_operation_the_record_lists_needs_no_approval(self):
        self.assertEqual(authorization.operation_problem(record(), 'documents', 'GET', NOW), (None, None))

    def test_an_operation_outside_the_record_runs_only_with_an_extra_approval(self):
        self.assertEqual(authorization.operation_problem(record(), 'documents', 'DELETE', NOW), ('APR-001', None))
        approval, problem = authorization.operation_problem(record(), 'documents', 'PATCH', NOW)
        self.assertIsNone(approval)
        self.assertIn("PATCH on 'documents' is not in the test authorization and no extra approval covers it", problem)
        self.assertIn("'announcements'", authorization.operation_problem(record(), 'announcements', 'GET', NOW)[1])

    def test_an_expired_approval_or_one_the_operator_gave_does_not_count(self):
        expired = datetime(2026, 11, 30, tzinfo=timezone.utc)
        approval, problem = authorization.operation_problem(record(), 'documents', 'DELETE', expired)
        self.assertIsNone(approval)
        self.assertIn('APR-001 expired at 2026-11-30T00:00:00Z', problem)
        for by in ('tester', ' Tester ', 'TESTER'):  # declared names: compared without spaces or case
            with self.subTest(by=by):
                doc = record()
                doc['extra_approvals'][0]['by'] = by
                approval, problem = authorization.operation_problem(doc, 'documents', 'DELETE', NOW)
                self.assertIsNone(approval)
                self.assertIn(f"APR-001 was given by the operator {by!r}", problem)


class TestOperation(unittest.TestCase):
    """The resource and method of a test follow from its template, never from the test itself."""

    def test_every_template_names_its_resource_and_method(self):
        self.assertEqual(scan.test_operation({'template_id': 'cross-user-read-v1'}), ('documents', 'GET'))
        self.assertEqual(scan.test_operation({'template_id': 'cross-user-delete-v1'}), ('documents', 'DELETE'))
        self.assertEqual(scan.test_operation({'template_id': 'public-read-v1'}), ('announcements', 'GET'))
        self.assertEqual(scan.test_operation({'template_id': 'shared-read-v1'}), ('documents', 'GET'))
        for template in (*scan.DENIAL_TEMPLATES, *scan.ALLOWED_TEMPLATES):
            with self.subTest(template=template):
                self.assertIn(scan.test_operation({'template_id': template})[1], authorization.METHODS)


if __name__ == '__main__':
    unittest.main()
