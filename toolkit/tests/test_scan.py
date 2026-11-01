"""A scan run, tested through its interface: scan.run(manifest) -> Run(report, markdown).

Environment tests: they start a real E1 stack and are skipped unless MAZ_ENV_TESTS=1.
Expected results follow the sample design (samples/object-authz):
  vulnerable  a same-tenant non-owner can read, change and delete the owner's private document
  patched     only the owner can; legit adds read-only sharing of documents marked shared
Creating a document as someone else is denied in every version (TK-DYN-007).
"""
import copy
import unittest

from toolkit import report, scan
from toolkit.tests.test_e1 import SAMPLES, needs_env

REQUIREMENT = {
    'id': 'REQ-DOCUMENT-OWNER-ONLY',
    'statement': 'Only the owner may read, change or delete a document that is not shared, '
                 'and documents are created only in the name and tenant of their creator.',
    'confirmation': {'by': 'app-owner', 'at': '2026-11-01T09:00:00Z', 'version': '2'},
}
PUBLIC_REQUIREMENT = {
    'id': 'REQ-ANNOUNCEMENTS-PUBLIC-READ',
    'statement': 'Anyone, signed in or not, may read announcements.',
    'confirmation': {'by': 'app-owner', 'at': '2026-11-01T09:00:00Z', 'version': '1'},
}
# Seeded identifiers (samples/object-authz/*/supabase/seed.sql).
ALICE_ID = 'a0000000-0000-4000-8000-00000000a11c'
TENANT_A = '7e000000-0000-4000-8000-00000000000a'
ACTORS = {'same-tenant': 'same_tenant_non_owner', 'other-tenant': 'other_tenant_user'}
OPERATIONS = {
    'READ': {'template_id': 'cross-user-read-v1', 'resource_ref': 'MARK-A-ALICE-PRIVATE'},
    'UPDATE': {'template_id': 'cross-user-update-v1', 'resource_ref': 'MARK-A-ALICE-PRIVATE',
               'control_ref': 'MARK-A-ALICE-SHARED'},
    'DELETE': {'template_id': 'cross-user-delete-v1', 'resource_ref': 'MARK-A-ALICE-PRIVATE',
               'control_ref': 'MARK-A-ALICE-SHARED'},
    'CREATE': {'template_id': 'cross-user-create-v1', 'resource_ref': 'MARK-A-CREATED-AS-ALICE',
               'control_ref': 'MARK-A-OWNER-CONTROL', 'claimed_owner_id': ALICE_ID, 'tenant_id': TENANT_A},
}
TESTS = [{'test_id': f'{op}-{short}', 'requirement_id': REQUIREMENT['id'], 'owner_ref': 'owner',
          'observation_ref': 'document-row-state-v1', 'actor_ref': actor, **params}
         for op, params in OPERATIONS.items() for short, actor in ACTORS.items()]
# TK-DYN-004: anonymous requests with both API key formats (legacy anon JWT, sb_publishable_).
TESTS += [{'test_id': f'READ-anonymous-{fmt}', 'requirement_id': REQUIREMENT['id'], 'owner_ref': 'owner',
           'observation_ref': 'document-row-state-v1', 'actor_ref': 'anonymous', 'api_key': fmt,
           **OPERATIONS['READ']}
          for fmt in ('anon-jwt', 'publishable')]
# TK-DYN-004: USING (true) on public data is a legitimate read policy, not a finding.
PUBLIC_READERS = {'anonymous-anon-jwt': ('anonymous', 'anon-jwt'), 'anonymous-publishable': ('anonymous', 'publishable'),
                  'other-tenant': ('other_tenant_user', 'anon-jwt')}
TESTS += [{'test_id': f'PUBLIC-READ-{short}', 'template_id': 'public-read-v1',
           'requirement_id': PUBLIC_REQUIREMENT['id'], 'actor_ref': actor, 'api_key': fmt,
           'resource_ref': 'MARK-PUBLIC-ANNOUNCEMENT'}
          for short, (actor, fmt) in PUBLIC_READERS.items()]

EXPECTED = {
    'vulnerable': {'READ-same-tenant': 'failed', 'UPDATE-same-tenant': 'failed', 'DELETE-same-tenant': 'failed',
                   'CREATE-same-tenant': 'passed', 'READ-other-tenant': 'passed', 'UPDATE-other-tenant': 'passed',
                   'DELETE-other-tenant': 'passed', 'CREATE-other-tenant': 'passed',
                   'READ-anonymous-anon-jwt': 'passed', 'READ-anonymous-publishable': 'passed',
                   'PUBLIC-READ-anonymous-anon-jwt': 'passed', 'PUBLIC-READ-anonymous-publishable': 'passed',
                   'PUBLIC-READ-other-tenant': 'passed'},
}
ALL_PASSED = {t['test_id']: 'passed' for t in TESTS}
# Denial cases (TK-DYN-001); allowed cases are checked in PublicDataEnv.
DENIAL_TESTS = [t for t in TESTS if t['template_id'] in scan.DENIAL_TEMPLATES]


def manifest(version):
    from toolkit import e1
    project = SAMPLES / version
    return {
        'schema_version': '1',
        'id': f'manifest-object-authz-{version}',
        'commit': 'test-commit-0001',
        'target': {'project': str(project), 'source_digest': e1.source_digest(project)},
        'requirements': [copy.deepcopy(REQUIREMENT), copy.deepcopy(PUBLIC_REQUIREMENT)],
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

    def test_read_create_update_delete_are_judged_separately(self):
        self.assertEqual(results(self.report), EXPECTED['vulnerable'])

    def test_one_confirmed_finding_per_failed_test(self):
        failed = {e['id']: e['test_id'] for e in self.report['execution_records'] if e['result'] == 'failed'}
        findings = self.report['findings']
        self.assertEqual(sorted(failed[f['execution_record_ids'][0]] for f in findings),
                         ['DELETE-same-tenant', 'READ-same-tenant', 'UPDATE-same-tenant'])
        for f in findings:
            self.assertEqual((f['status'], f['requirement_id'], len(f['execution_record_ids'])),
                             ('confirmed', REQUIREMENT['id'], 1))
            self.assertEqual(f['fingerprint_version'], 'fp-authz-v1')
            self.assertRegex(f['fingerprint'], r'^sha256:[0-9a-f]{64}$')
        self.assertEqual(len({f['fingerprint'] for f in findings}), 3)  # one problem per operation

    def test_findings_are_confirmed_in_e1_without_production_exploitation(self):
        # TK-DYN-016: dynamic evidence from the E1 stack is enough; no production system is touched.
        self.assertEqual(self.report['environment']['mode'], 'E1')
        self.assertEqual({f['evidence_type'] for f in self.report['findings']}, {'dynamic'})

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
    def test_no_finding_and_every_test_passes(self):
        for version in ('patched', 'legit'):
            with self.subTest(version=version):
                rep = run_once(version).report
                self.assertEqual(report.validate(rep), [])
                self.assertEqual(rep['status'], 'completed')
                self.assertEqual(results(rep), ALL_PASSED)
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
        for t in DENIAL_TESTS:
            with self.subTest(test=t['test_id']):
                actor = [ev for ev in self.evidence(t['test_id'])
                         if ev['channel'] == 'actor' and ev['identity_ref'] == t['actor_ref']]
                self.assertTrue(any(ev['request']['path'].startswith('/rest/v1/documents') for ev in actor), actor)

    def test_owner_positive_control_is_recorded(self):
        for t in DENIAL_TESTS:
            with self.subTest(test=t['test_id']):
                owner = [ev for ev in self.evidence(t['test_id'])
                         if ev['channel'] == 'actor' and ev['identity_ref'] == 'owner']
                self.assertEqual(len(owner), 1, owner)
                self.assertIn(owner[0]['response']['status'], (200, 201))
                self.assertEqual(owner[0]['response']['rows'], 1)

    def test_observer_evidence_uses_the_observer_role(self):
        for t in DENIAL_TESTS:
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
        self.assertEqual(rep['coverage']['blocked'], len(TESTS))

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


class ObservationTemplatesOnly(unittest.TestCase):
    """TK-IDN-006: a test can only name an allow-listed observation template with a typed identifier."""

    def assert_rejected_before_start(self, change, reason_part):
        m = manifest('vulnerable')
        for t in m['tests']:
            change(t)
        rep = scan.run(m).report
        self.assertEqual(report.validate(rep), [])
        self.assertEqual(rep['status'], 'blocked')
        self.assertNotIn('environment', rep)  # nothing was started
        for e in rep['execution_records']:
            self.assertEqual(e['result'], 'blocked')
            self.assertIn(reason_part, e['error'])

    def test_unknown_observation_template_is_rejected(self):
        self.assert_rejected_before_start(lambda t: t.update(observation_ref='raw-sql-v1'), 'observation_ref')

    def test_query_string_instead_of_a_template_is_rejected(self):
        self.assert_rejected_before_start(
            lambda t: t.update(observation_ref='select * from auth.users'), 'observation_ref')

    def test_resource_identifier_outside_its_type_is_rejected(self):
        self.assert_rejected_before_start(
            lambda t: t.update(resource_ref="MARK-A'; delete from public.documents; --"), 'resource_ref')

    def test_unknown_test_template_is_rejected(self):
        self.assert_rejected_before_start(lambda t: t.update(template_id='free-form-http-v1'), 'template_id')


@needs_env
class LaxUpdatePolicyRunEnv(unittest.TestCase):
    """TK-DYN-002, TK-DYN-004: judge the actual result, not how wide a policy looks.

    The update policy admits the whole tenant, but an UPDATE that reads columns must also
    pass the SELECT policies (PostgreSQL, CREATE POLICY), so the owner's rows stay out of reach.
    """

    @classmethod
    def setUpClass(cls):
        cls.report = run_once('lax-update-policy').report

    def test_no_finding_and_every_test_passes(self):
        self.assertEqual(report.validate(self.report), [])
        self.assertEqual(results(self.report), ALL_PASSED)
        self.assertEqual(self.report['findings'], [])

    def test_the_update_attempt_was_answered_and_changed_nothing(self):
        record = next(e for e in self.report['execution_records'] if e['test_id'] == 'UPDATE-same-tenant')
        attempt = [ev for ev in record['evidence'] if ev['channel'] == 'actor'
                   and ev['identity_ref'] == 'same_tenant_non_owner' and ev['request']['method'] == 'PATCH']
        # return=minimal: 204 with no body whether or not a row changed; only the observer can tell.
        self.assertEqual([(ev['response']['status'], ev['response']['rows'], ev['request']['prefer'])
                          for ev in attempt], [(204, None, 'return=minimal')])
        self.assertTrue(record['checks']['no_disclosure_or_change'])


@needs_env
class DenialChecksEnv(unittest.TestCase):
    """TK-DYN-001, TK-IDN-010: four checks per case; observation before and after; passing cases leave state untouched."""

    @classmethod
    def setUpClass(cls):
        cls.reports = [run_once(v).report for v in ('vulnerable', 'patched')]

    def records(self):
        """Denial cases only; allowed cases (public-read-v1) make no observation and have no denial checks."""
        return [e for rep in self.reports for e in rep['execution_records'] if e.get('case_kind') == 'denial']

    def test_every_executed_case_records_all_four_checks(self):
        for e in self.records():
            with self.subTest(test=e['test_id']):
                self.assertEqual(set(e['checks']), {'resource_and_control', 'identity', 'no_disclosure_or_change',
                                                    'response_and_side_effects'})

    def test_observations_are_made_before_and_after_the_attempt(self):
        for e in self.records():
            with self.subTest(test=e['test_id']):
                points = [ev['point'] for ev in e['evidence'] if ev['channel'] == 'observer']
                self.assertEqual(points, ['before', 'after'])

    def test_passing_cases_leave_the_observed_state_unchanged(self):
        for e in (e for e in self.records() if e['result'] == 'passed'):
            with self.subTest(test=e['test_id']):
                before, after = [ev['observation'] for ev in e['evidence'] if ev['channel'] == 'observer']
                self.assertEqual(before['table_digest'], after['table_digest'])
                self.assertEqual(before.get('state_digest'), after.get('state_digest'))


@needs_env
class AnonymousKeyFormatsEnv(unittest.TestCase):
    """TK-DYN-004: anonymous requests are tested with the legacy anon JWT and the sb_publishable_ key."""

    @classmethod
    def setUpClass(cls):
        cls.report = run_once('vulnerable').report

    def test_each_key_format_is_used_and_denied(self):
        for fmt in ('anon-jwt', 'publishable'):
            with self.subTest(format=fmt):
                record = next(e for e in self.report['execution_records'] if e['test_id'] == f'READ-anonymous-{fmt}')
                self.assertEqual(record['result'], 'passed')
                attempts = [ev for ev in record['evidence']
                            if ev['channel'] == 'actor' and ev['identity_ref'] == 'anonymous']
                self.assertTrue(attempts)
                self.assertEqual({ev['api_key_format'] for ev in attempts}, {fmt})


@needs_env
class PublicDataEnv(unittest.TestCase):
    """TK-DYN-004: a USING (true) read policy on public data is not a vulnerability."""

    @classmethod
    def setUpClass(cls):
        cls.report = run_once('vulnerable').report

    def test_public_announcement_is_readable_and_not_a_finding(self):
        records = [e for e in self.report['execution_records'] if e['template_id'] == 'public-read-v1']
        self.assertEqual(sorted(e['test_id'] for e in records),
                         sorted(f'PUBLIC-READ-{short}' for short in PUBLIC_READERS))
        for e in records:
            with self.subTest(test=e['test_id']):
                self.assertEqual((e['result'], e['case_kind'], e['checks']), ('passed', 'allowed', {'access_granted': True}))
        finding_records = {i for f in self.report['findings'] for i in f['execution_record_ids']}
        self.assertFalse(finding_records & {e['id'] for e in records})

    def test_both_key_formats_actually_reach_the_api(self):
        # Without this positive case a rejected key would look like a denial in READ-anonymous-*.
        for fmt in ('anon-jwt', 'publishable'):
            with self.subTest(format=fmt):
                e = next(e for e in self.report['execution_records'] if e['test_id'] == f'PUBLIC-READ-anonymous-{fmt}')
                attempt = [ev for ev in e['evidence'] if ev['channel'] == 'actor']
                self.assertEqual([(ev['api_key_format'], ev['response']['status'], ev['response']['rows'])
                                  for ev in attempt], [(fmt, 200, 1)])


class UnsupportedScopes(unittest.TestCase):
    """TK-DYN-004 scope not covered yet stays in the report and in the denominator (AG-07)."""

    # The access paths of TK-DYN-004 that no v0.1 template covers yet.
    EXPECTED_SCOPES = {'rls-functions', 'rls-views', 'rls-column-privileges'}

    def test_unsupported_rls_scopes_are_listed_and_counted(self):
        m = manifest('vulnerable')
        m['target']['source_digest'] = 'sha256:' + '0' * 64  # blocked before start: no Docker needed
        rep = scan.run(m).report
        cov = rep['coverage']
        self.assertEqual({u['scope'] for u in cov['unsupported_items']}, self.EXPECTED_SCOPES)
        for u in cov['unsupported_items']:
            self.assertTrue(u['reason'], u)
        self.assertEqual(cov['unsupported'], len(self.EXPECTED_SCOPES))
        self.assertEqual(cov['denominator'], len(TESTS) + len(self.EXPECTED_SCOPES))
        md = scan.run(m).markdown
        for scope in self.EXPECTED_SCOPES:
            self.assertIn(scope, md)


@needs_env
class MixedPlanEnv(unittest.TestCase):
    """An invalid test is blocked before it runs; the valid ones still run (TK-IDN-006)."""

    def test_invalid_test_is_blocked_and_the_rest_runs(self):
        m = manifest('patched')
        valid = next(t for t in m['tests'] if t['test_id'] == 'READ-same-tenant')
        invalid = dict(valid, test_id='READ-raw-sql', observation_ref='select * from public.documents')
        m['tests'] = [valid, invalid]
        rep = scan.run(m).report
        self.assertEqual(report.validate(rep), [])
        self.assertEqual(results(rep), {'READ-same-tenant': 'passed', 'READ-raw-sql': 'blocked'})
        blocked = next(e for e in rep['execution_records'] if e['test_id'] == 'READ-raw-sql')
        self.assertEqual(blocked['evidence'], [])
        self.assertIn('observation_ref', blocked['error'])
        self.assertEqual(rep['status'], 'partial')
