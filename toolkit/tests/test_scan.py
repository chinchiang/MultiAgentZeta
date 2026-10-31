"""A scan run, tested through its interface: scan.run(manifest) -> Run(report, markdown).

Environment tests: they start a real E1 stack and are skipped unless MAZ_ENV_TESTS=1.
Expected results follow the sample design (samples/object-authz): in the vulnerable
version a same-tenant non-owner can read the owner's private document; nobody else
can, in any version.
"""
import copy
import unittest

from toolkit import report, scan
from toolkit.tests.test_e1 import SAMPLES, needs_env

REQUIREMENT = {
    'id': 'REQ-DOCUMENT-OWNER-READ',
    'statement': 'Only the owner may read a document that is not shared.',
    'confirmation': {'by': 'app-owner', 'at': '2026-11-01T09:00:00Z', 'version': '1'},
}
TESTS = [
    {'test_id': 'AUTHZ-001-same-tenant', 'template_id': 'cross-user-read-v1',
     'requirement_id': 'REQ-DOCUMENT-OWNER-READ', 'owner_ref': 'owner',
     'actor_ref': 'same_tenant_non_owner', 'resource_ref': 'MARK-A-ALICE-PRIVATE'},
    {'test_id': 'AUTHZ-001-other-tenant', 'template_id': 'cross-user-read-v1',
     'requirement_id': 'REQ-DOCUMENT-OWNER-READ', 'owner_ref': 'owner',
     'actor_ref': 'other_tenant_user', 'resource_ref': 'MARK-A-ALICE-PRIVATE'},
]


def manifest(version):
    from toolkit import e1
    project = SAMPLES / version
    return {
        'schema_version': '1',
        'id': f'manifest-object-authz-{version}',
        'commit': 'test-commit-0001',
        'target': {'project': str(project), 'source_digest': e1.source_digest(project)},
        'requirements': [copy.deepcopy(REQUIREMENT)],
        'tests': copy.deepcopy(TESTS),
    }


def results(rep):
    return {e['test_id']: e['result'] for e in rep['execution_records']}


_RUNS = {}


def run_once(version):
    """One scan per sample version per test session; the stack is destroyed after each run."""
    if version not in _RUNS:
        _RUNS[version] = scan.run(manifest(version))
    return _RUNS[version]


@needs_env
class VulnerableRunEnv(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.outcome = run_once('vulnerable')
        cls.report = cls.outcome.report

    def test_report_is_valid(self):
        self.assertEqual(report.validate(self.report), [])

    def test_run_is_completed(self):
        self.assertEqual(self.report['status'], 'completed')

    def test_same_tenant_read_fails_and_other_tenant_read_passes(self):
        self.assertEqual(results(self.report),
                         {'AUTHZ-001-same-tenant': 'failed', 'AUTHZ-001-other-tenant': 'passed'})

    def test_one_confirmed_finding_for_the_failed_test(self):
        findings = self.report['findings']
        self.assertEqual(len(findings), 1, findings)
        f = findings[0]
        failed = [e['id'] for e in self.report['execution_records'] if e['test_id'] == 'AUTHZ-001-same-tenant']
        self.assertEqual((f['status'], f['requirement_id'], f['execution_record_ids']),
                         ('confirmed', 'REQ-DOCUMENT-OWNER-READ', failed))
        self.assertEqual(f['fingerprint_version'], 'fp-authz-v1')
        self.assertRegex(f['fingerprint'], r'^sha256:[0-9a-f]{64}$')

    def test_test_result_and_finding_status_are_separate(self):
        # TK-DYN-015: a test result describes one test; a finding status describes one problem.
        for e in self.report['execution_records']:
            self.assertNotIn('status', e)
        for f in self.report['findings']:
            self.assertNotIn('result', f)

    def test_markdown_is_generated_from_the_report(self):
        self.assertEqual(self.outcome.markdown, report.render_markdown(self.report))


@needs_env
class PatchedAndLegitRunsEnv(unittest.TestCase):
    def test_no_finding_and_both_tests_pass(self):
        for version in ('patched', 'legit'):
            with self.subTest(version=version):
                rep = scan.run(manifest(version)).report
                self.assertEqual(report.validate(rep), [])
                self.assertEqual(rep['status'], 'completed')
                self.assertEqual(results(rep), {'AUTHZ-001-same-tenant': 'passed', 'AUTHZ-001-other-tenant': 'passed'})
                self.assertEqual(rep['findings'], [])


@needs_env
class EvidenceChannelsEnv(unittest.TestCase):
    """TK-IDN-008, TK-DYN-009: actor requests go through the data API; the observer reads state."""

    @classmethod
    def setUpClass(cls):
        cls.report = run_once('vulnerable').report

    def evidence(self, test_id):
        return next(e for e in self.report['execution_records'] if e['test_id'] == test_id)['evidence']

    def test_actor_request_goes_through_the_data_api_as_the_actor(self):
        for t in TESTS:
            with self.subTest(test=t['test_id']):
                actor = [ev for ev in self.evidence(t['test_id'])
                         if ev['channel'] == 'actor' and ev['identity_ref'] == t['actor_ref']]
                self.assertTrue(any(ev['request']['path'].startswith('/rest/v1/documents') for ev in actor), actor)

    def test_owner_positive_control_is_recorded(self):
        for t in TESTS:
            with self.subTest(test=t['test_id']):
                owner = [ev for ev in self.evidence(t['test_id'])
                         if ev['channel'] == 'actor' and ev['identity_ref'] == 'owner']
                self.assertEqual([ev['response']['rows'] for ev in owner], [1])

    def test_observer_evidence_uses_the_observer_role(self):
        for t in TESTS:
            with self.subTest(test=t['test_id']):
                obs = [ev for ev in self.evidence(t['test_id']) if ev['channel'] == 'observer']
                self.assertEqual(len(obs), 2, obs)  # before and after the actor request
                self.assertEqual({ev['identity_ref'] for ev in obs}, {'maz_observer'})

    def test_no_evidence_uses_a_privileged_identity(self):
        for e in self.report['execution_records']:
            for ev in e['evidence']:
                self.assertNotIn(ev['identity_ref'], ('service_role', 'postgres', 'supabase_admin', 'provisioning'))


@needs_env
class AuthorizationMatrixEnv(unittest.TestCase):
    """TK-IDN-001, TK-IDN-003: the matrix holds the v0.1 identities; transport comes from the confirmed recipe."""

    def test_matrix_identities_and_their_confirmed_transport(self):
        rep = run_once('vulnerable').report
        matrix = {m['identity']: m for m in rep['authorization_matrix']}
        self.assertEqual({k: v['transport'] for k, v in matrix.items()}, {
            'anonymous': 'none', 'owner': 'bearer-header',
            'same_tenant_non_owner': 'bearer-header', 'other_tenant_user': 'bearer-header'})
        for name, m in matrix.items():
            self.assertEqual(m['transport_source'], 'BuildRecipe auth.token_transport', name)
            self.assertTrue(m['path'], name)


@needs_env
class CommitBindingEnv(unittest.TestCase):
    """TK-DAT-001: every record carries the common fields and is bound to the tested commit."""

    def test_every_record_is_bound_to_the_manifest_commit(self):
        rep = run_once('vulnerable').report
        records = [rep, rep['coverage'], *rep['execution_records'], *rep['findings']]
        self.assertEqual({r['commit'] for r in records}, {'test-commit-0001'})
        self.assertEqual({r['run_id'] for r in records}, {rep['run_id']})
        self.assertEqual(len({r['id'] for r in records}), len(records))  # unique ids


class BlockedRun(unittest.TestCase):
    """A run that cannot start is reported as blocked, with a reason, in a valid report."""

    def assert_blocked(self, rep, reason_part):
        self.assertEqual(report.validate(rep), [])
        self.assertEqual(rep['status'], 'blocked')
        self.assertIn(reason_part, rep['status_reason'])
        self.assertEqual(set(results(rep).values()), {'blocked'})
        self.assertEqual(rep['findings'], [])
        self.assertEqual((rep['coverage']['denominator'], rep['coverage']['blocked']), (2, 2))

    def test_source_digest_mismatch_blocks_the_run(self):
        m = manifest('vulnerable')
        m['target']['source_digest'] = 'sha256:' + '0' * 64
        self.assert_blocked(scan.run(m).report, 'source_digest')

    def test_project_without_a_recipe_blocks_the_run(self):
        import tempfile
        from toolkit import e1
        with tempfile.TemporaryDirectory() as d:
            m = manifest('vulnerable')
            m['target'] = {'project': d, 'source_digest': e1.source_digest(d)}
            self.assert_blocked(scan.run(m).report, 'BuildRecipe')
