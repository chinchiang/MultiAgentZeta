"""A scan run, tested through its interface: scan.run(manifest) -> Run(report, markdown).

Environment tests: they start a real E1 stack and are skipped unless MAZ_ENV_TESTS=1.
Expected results follow the sample design (samples/object-authz):
  vulnerable  a same-tenant non-owner can read, change and delete the owner's private document
  patched     only the owner can; legit adds read-only sharing of documents marked shared
Creating a document as someone else is denied in every version (TK-DYN-007).
"""
import atexit
import copy
import json
import shutil
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from toolkit import e1, report, scan
from toolkit.tests.test_e1 import SAMPLES, needs_env

# S1: the owner's own spec, given in the ScanManifest without any confirmation (〈定義：確認清單〉). It is the
# 規格依據 of the 合法例外 that let anyone read announcements (EXCEPTIONS).
S1_PUBLIC = {'id': 'S1-ANNOUNCEMENTS-PUBLIC-READ', 'statement': 'Anyone, signed in or not, may read announcements.',
             'resources': ['announcements'], 'rule': 'allow'}
# Confirmation items the tests rest on: an S2 clause on a resource, or an S1 entry.
OWNER_ITEM, TENANT_ITEM, ANON_ITEM = 'S2-OWNER-ONLY@documents', 'S2-TENANT-ISOLATION@documents', 'S2-ANON-NO-ACCESS@documents'
PUBLIC_ITEM = S1_PUBLIC['id']
# A test rests on the clause its actor is about (〈定義：確認清單〉): of documents, and of announcements.
ITEM_FOR_ACTOR = {'same_tenant_non_owner': OWNER_ITEM, 'other_tenant_user': TENANT_ITEM, 'anonymous': ANON_ITEM}
ANNOUNCEMENT_ITEM = {actor: item.replace('@documents', '@announcements') for actor, item in ITEM_FOR_ACTOR.items()}
ACCEPTED = (OWNER_ITEM, ANON_ITEM, PUBLIC_ITEM)  # TENANT_ITEM is a 合法例外 (EXCEPTIONS)
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
TESTS = [{'test_id': f'{op}-{short}', 'requirement_id': ITEM_FOR_ACTOR[actor], 'owner_ref': 'owner',
          'observation_ref': 'document-row-state-v1', 'actor_ref': actor, **params}
         for op, params in OPERATIONS.items() for short, actor in ACTORS.items()]
# TK-DYN-004: anonymous requests with both API key formats (legacy anon JWT, sb_publishable_).
TESTS += [{'test_id': f'READ-anonymous-{fmt}', 'requirement_id': ANON_ITEM, 'owner_ref': 'owner',
           'observation_ref': 'document-row-state-v1', 'actor_ref': 'anonymous', 'api_key': fmt,
           **OPERATIONS['READ']}
          for fmt in ('anon-jwt', 'publishable')]
# TK-DYN-004: USING (true) on public data is a legitimate read policy, not a finding. Each reader's
# clause on announcements is a 合法例外 allowing its reads (EXCEPTIONS).
PUBLIC_READERS = {'anonymous-anon-jwt': ('anonymous', 'anon-jwt'), 'anonymous-publishable': ('anonymous', 'publishable'),
                  'same-tenant': ('same_tenant_non_owner', 'anon-jwt'), 'other-tenant': ('other_tenant_user', 'anon-jwt')}
TESTS += [{'test_id': f'PUBLIC-READ-{short}', 'template_id': 'public-read-v1',
           'requirement_id': ANNOUNCEMENT_ITEM[actor], 'actor_ref': actor, 'api_key': fmt,
           'resource_ref': 'MARK-PUBLIC-ANNOUNCEMENT'}
          for short, (actor, fmt) in PUBLIC_READERS.items()]
# TK-DYN-003: a document alice shares with tenant B; carol reading it is the allowed case of the 合法例外
# on TENANT_ITEM, so it is legitimate, not a cross-tenant leak.
SHARED_READ = {'test_id': 'SHARED-READ-other-tenant', 'template_id': 'shared-read-v1', 'requirement_id': TENANT_ITEM,
               'actor_ref': 'other_tenant_user', 'api_key': 'anon-jwt', 'resource_ref': 'MARK-A-ALICE-SHARED-TO-B'}
TESTS += [SHARED_READ]
# The 合法例外 of the owner (〈定義：確認清單〉 修改): each item and the allowed tests it lists.
EXCEPTIONS = {TENANT_ITEM: [SHARED_READ['test_id']],
              **{item: [t['test_id'] for t in TESTS if t['requirement_id'] == item] for item in ANNOUNCEMENT_ITEM.values()}}
# An allowed case resting on the S1 entry itself, for the tests about S1 entries.
S1_READ = {**next(t for t in TESTS if t['test_id'] == 'PUBLIC-READ-anonymous-anon-jwt'), 'test_id': 'S1-PUBLIC-READ', 'requirement_id': PUBLIC_ITEM}

EXPECTED = {
    'vulnerable': {'READ-same-tenant': 'failed', 'UPDATE-same-tenant': 'failed', 'DELETE-same-tenant': 'failed',
                   'CREATE-same-tenant': 'passed', 'READ-other-tenant': 'passed', 'UPDATE-other-tenant': 'passed',
                   'DELETE-other-tenant': 'passed', 'CREATE-other-tenant': 'passed',
                   'READ-anonymous-anon-jwt': 'passed', 'READ-anonymous-publishable': 'passed',
                   'PUBLIC-READ-anonymous-anon-jwt': 'passed', 'PUBLIC-READ-anonymous-publishable': 'passed',
                   'PUBLIC-READ-same-tenant': 'passed', 'PUBLIC-READ-other-tenant': 'passed',
                   'SHARED-READ-other-tenant': 'passed'},
}
ALL_PASSED = {t['test_id']: 'passed' for t in TESTS}
# Denial cases (TK-DYN-001); allowed cases are checked in PublicDataEnv.
DENIAL_TESTS = [t for t in TESTS if t['template_id'] in scan.DENIAL_TEMPLATES]


# 〈定義：必要輸入〉 受測範圍: endpoints, resources under test, allowed operations and data scope.
SCOPE = {'endpoints': ['/rest/v1/documents', '/rest/v1/announcements', '/auth/v1/user'],
         'resources': [{'name': 'documents', 'impact': ['confidential']},  # private documents
                       {'name': 'announcements', 'impact': []}],  # public data
         'allowed_operations': ['GET', 'POST', 'PATCH', 'DELETE'],
         'data_scope': 'synthetic sample data of samples/object-authz only'}
# 〈定義：必要輸入〉 執行限制: cost, time, request volume, concurrency, model providers, network allow-list.
LIMITS = {'max_cost_usd': 0, 'max_duration_seconds': 3600, 'max_requests': 500, 'max_concurrency': 1,
          'model_providers': [], 'network_allowlist': ['127.0.0.1']}


EXPIRY = '2099-01-01T00:00:00Z'  # later than every run of these tests (〈定義：確認清單〉 到期)
CONTROL = Path(tempfile.mkdtemp(prefix='maz-control-'))  # the control zone of these tests, outside every sample
atexit.register(shutil.rmtree, CONTROL, ignore_errors=True)


def reviewed_list(source, accepted=ACCEPTED, s1=(S1_PUBLIC,), resources=None, exceptions=EXCEPTIONS):
    """A confirmation list in the control zone where the owner accepted the given items and made the
    exceptions 合法例外, each allowing its tests until EXPIRY (test only: in a real run a person edits the
    list). An item in both is a 合法例外. Returns the ScanManifest reference {path, digest}."""
    from toolkit import confirmation, policy
    doc = confirmation.generate(policy.load_template(), resources or SCOPE['resources'], list(s1))
    for item in doc['items']:
        if item['item_id'] in exceptions:
            item['status'] = 'modified'
            item['review'].update(by='app-owner', at='2026-11-02T09:00:00Z', reason='the owner allows these reads',
                                  basis=PUBLIC_ITEM if item['resource'] == 'announcements' else 'sharing spec §4',
                                  modified_rule='allow', allowed_tests=exceptions[item['item_id']], expiry=EXPIRY)
        elif item['item_id'] in accepted:
            item['status'] = 'accepted'
            item['review'].update(by='app-owner', at='2026-11-02T09:00:00Z')
    path = Path(tempfile.mkdtemp(dir=CONTROL)) / 'confirmation-list.json'
    return {'path': str(path), 'digest': confirmation.write(path, doc, source)}


SAMPLE_IDS = [f'object-authz/{v}' for v in ('vulnerable', 'patched', 'legit', 'lax-update-policy')]
# 〈定義：測試授權紀錄〉 of these tests: every sample version in E1 and every operation of the test templates,
# DELETE on documents through an extra approval, so the delete cases of the E1 runs run under one.
DELETE_APPROVAL = {'approval_id': 'APR-DELETE', 'operations': [{'resource': 'documents', 'methods': ['DELETE']}],
                   'by': 'security-lead', 'at': '2026-01-01T00:00:00Z', 'reason': 'delete cases on the synthetic E1 data',
                   'valid_until': '2098-01-01T00:00:00Z'}
AUTHORIZATION = {'schema_version': '1', 'targets': SAMPLE_IDS, 'environment': 'E1',
                 'data_scope': 'synthetic sample data of samples/object-authz only',
                 'valid_from': '2026-01-01T00:00:00Z', 'valid_until': '2099-01-01T00:00:00Z',
                 'operations': [{'resource': 'documents', 'methods': ['GET', 'POST', 'PATCH']},
                                {'resource': 'announcements', 'methods': ['GET']}],
                 'roles': {'app_owner': 'app-owner', 'operator': 'toolkit-tests'},
                 'issued_by': 'app-owner', 'issued_at': '2026-01-01T00:00:00Z', 'extra_approvals': [DELETE_APPROVAL]}


def authorized(source, doc=AUTHORIZATION):
    """doc written to the control zone (test only: in a real run the app owner issues it). Returns the
    ScanManifest reference {path, digest}."""
    from toolkit import control
    path = Path(tempfile.mkdtemp(dir=CONTROL)) / 'authorization.json'
    return {'path': str(path), 'digest': control.write(path, doc, source)}


def manifest(version):
    from toolkit import e1
    project = SAMPLES / version
    return {
        'schema_version': '1',
        'id': f'manifest-object-authz-{version}',
        'commit': 'test-commit-0001',
        'target': {'project': str(project), 'source_digest': e1.source_digest(project)},
        'requirements': [copy.deepcopy(S1_PUBLIC)],
        'confirmation_list': reviewed_list(project),
        'authorization': authorized(project),
        'scope': copy.deepcopy(SCOPE),
        'limits': copy.deepcopy(LIMITS),
        'tests': copy.deepcopy(TESTS),
    }


def results(rep):
    return {e['test_id']: e['result'] for e in rep['execution_records']}


def judgement_results(rep):
    """Results of the judgement tests (TESTS) in a shared run, without the template's other cases."""
    ids = {t['test_id'] for t in TESTS}
    return {k: v for k, v in results(rep).items() if k in ids}


def shared_plan(template, tests):
    """The S2 template's self-acceptance cases, each on its clause's item for documents, followed by
    the tests no case covers (TK-REQ-008). A test named like a case must be defined like it, since
    only one of them runs; otherwise ValueError names it."""
    plan = [{'test_id': c['case_id'], 'requirement_id': f'{c["clause"]}@documents', **c['test']}
            for c in template['self_acceptance']['cases']]
    cases = {t['test_id']: t for t in plan}
    for t in tests:
        if t['test_id'] not in cases:
            plan.append(t)
        elif t != cases[t['test_id']]:
            raise ValueError(f'test {t["test_id"]!r} is defined differently from the self-acceptance case of that name')
    return plan


_RUNS = {}


def shared_manifest(version):
    """The ScanManifest of the run the judgement tests and the S2 template's self-acceptance share (#43).
    Each clause is accepted on documents in a confirmation list written by this test, as the owner of a
    sample would; the toolkit itself never accepts an item (TK-REQ-009)."""
    from toolkit import policy
    template = policy.load_template()
    m = manifest(version)
    m['id'] = f'manifest-object-authz-shared-{version}'
    m['tests'] = shared_plan(template, TESTS)
    clauses = [f'{c["id"]}@documents' for c in template['clauses']]
    m['confirmation_list'] = reviewed_list(SAMPLES / version, accepted=[*ACCEPTED, *clauses])
    return m


def run_once(version):
    """One scan of shared_manifest(version) per sample version per test session; the stack is destroyed
    after each run."""
    if version not in _RUNS:
        _RUNS[version] = scan.run(shared_manifest(version))
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
        self.assertEqual(judgement_results(self.report), EXPECTED['vulnerable'])

    def test_one_confirmed_finding_per_failed_test(self):
        failed = {e['id']: e['test_id'] for e in self.report['execution_records'] if e['result'] == 'failed'}
        findings = self.report['findings']
        self.assertEqual(sorted(failed[f['execution_record_ids'][0]] for f in findings),
                         ['DELETE-same-tenant', 'READ-same-tenant', 'UPDATE-same-tenant'])
        for f in findings:
            self.assertEqual((f['status'], f['requirement_id'], len(f['execution_record_ids'])),
                             ('confirmed', OWNER_ITEM, 1))
            self.assertEqual(f['fingerprint_version'], 'fp-authz-v1')
            self.assertRegex(f['fingerprint'], r'^sha256:[0-9a-f]{64}$')
        self.assertEqual(len({f['fingerprint'] for f in findings}), 3)  # one problem per operation

    def test_without_a_review_record_every_finding_waits_for_review(self):
        # 〈定義：覆核紀錄〉: the ScanManifest references none, so nobody has decided anything yet.
        self.assertIsNone(self.report['review_record'])
        self.assertEqual([f['review'] for f in self.report['findings']], [{'state': 'pending'}] * 3)
        self.assertEqual(self.report['review_summary'], {'pending': 3, 'overdue': 0, 'approved': 0, 'rejected': 0,
                                                         'evidence_pending': 0})

    def test_only_the_tests_that_ran_under_an_extra_approval_name_it(self):
        # 〈定義：測試授權紀錄〉 報告: DELETE on documents is authorized through APR-DELETE (AUTHORIZATION).
        # The shared run holds the template's delete cases too (shared_plan): every delete case ran under it.
        from toolkit import policy
        deletes = {t['test_id'] for t in shared_plan(policy.load_template(), TESTS) if t['template_id'] == 'cross-user-delete-v1'}
        self.assertTrue({'DELETE-same-tenant', 'DELETE-anonymous-publishable'} <= deletes)
        named = {e['test_id']: e.get('approval_id') for e in self.report['execution_records']}
        self.assertEqual({t for t, a in named.items() if a}, deletes)
        self.assertEqual({named[t] for t in deletes}, {'APR-DELETE'})
        self.assertIn('`APR-DELETE`', self.outcome.markdown)

    def test_requirements_come_from_s1_or_s2_and_the_failures_rest_on_owner_only(self):
        # TK-REQ-005: no requirement comes from the implementation; the leak is judged on S2-OWNER-ONLY.
        self.assertTrue(self.report['requirements'])
        self.assertLessEqual({r['source'] for r in self.report['requirements']}, {'S1', 'S2'})
        failed = {e['requirement_id'] for e in self.report['execution_records'] if e['result'] == 'failed'}
        self.assertEqual(failed, {OWNER_ITEM})

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
class PendingS2VulnerableEnv(unittest.TestCase):
    """TK-REQ-003: a failed test on an S2 clause nobody accepted yet runs, and its finding is at most
    證據待補 (evidence_pending), never 已確認."""

    @classmethod
    def setUpClass(cls):
        m = manifest('vulnerable')
        m['confirmation_list'] = reviewed_list(SAMPLES / 'vulnerable', accepted=[i for i in ACCEPTED if i != OWNER_ITEM])
        m['tests'] = [t for t in m['tests'] if t['test_id'] in ('READ-same-tenant', 'UPDATE-same-tenant', 'DELETE-same-tenant')]
        cls.report = scan.run(m).report

    def test_report_is_valid(self):
        self.assertEqual(report.validate(self.report), [])

    def test_failed_tests_on_the_pending_clause_give_evidence_pending_findings(self):
        self.assertEqual(set(results(self.report).values()), {'failed'})
        self.assertEqual([(f['status'], f['requirement_id']) for f in self.report['findings']],
                         [('evidence_pending', OWNER_ITEM)] * 3)


@needs_env
class PatchedAndLegitRunsEnv(unittest.TestCase):
    def test_no_finding_and_every_test_passes(self):
        for version in ('patched', 'legit'):
            with self.subTest(version=version):
                rep = run_once(version).report
                self.assertEqual(report.validate(rep), [])
                self.assertEqual(rep['status'], 'completed')
                self.assertEqual(judgement_results(rep), ALL_PASSED)
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
        self.assertEqual(judgement_results(self.report), ALL_PASSED)
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


@needs_env
class SharedDocumentEnv(unittest.TestCase):
    """TK-DYN-003: reading a document shared with the reader's tenant is the allowed case of a 合法例外,
    judged legitimate in every sample version, not a cross-tenant leak."""

    def test_the_shared_document_is_readable_in_every_version_and_not_a_finding(self):
        for version in ('vulnerable', 'patched', 'legit', 'lax-update-policy'):
            with self.subTest(version=version):
                rep = run_once(version).report
                e = next(e for e in rep['execution_records'] if e['test_id'] == SHARED_READ['test_id'])
                self.assertEqual((e['result'], e['case_kind'], e['checks']), ('passed', 'allowed', {'access_granted': True}))
                self.assertFalse({i for f in rep['findings'] for i in f['execution_record_ids']} & {e['id']})
                attempt = [ev for ev in e['evidence'] if ev['channel'] == 'actor']
                self.assertEqual([(ev['identity_ref'], ev['response']['status'], ev['response']['rows']) for ev in attempt],
                                 [('other_tenant_user', 200, 1)])


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


def one_reply_server(reply):
    """A loopback server that answers one connection with the raw bytes given, then closes it.
    Returns its base URL."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)

    def serve():
        with srv:
            conn, _ = srv.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(reply)
    threading.Thread(target=serve, daemon=True).start()
    return f'http://127.0.0.1:{srv.getsockname()[1]}'


class BrokenReplies(unittest.TestCase):
    """〈定義：測試結果〉 執行錯誤: a reply that cannot be read is RequestFailed, which run() records as an
    execution error of the case (TK-RUN-001), never an exception that ends the run."""

    def request_to(self, url):
        env = e1.Environment(project_dir=Path('.'), project_id='maz-no-stack', recipe={}, cli='', api_url=url,
                             api_keys={'anon-jwt': 'test-anon-key'})
        return scan._request(env, 'anonymous', 'GET', '/rest/v1/documents', timeout=5)

    def test_error_reply_cut_off_mid_body_is_a_failed_request(self):
        url = one_reply_server(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 100\r\n\r\npartial')
        with self.assertRaises(scan.RequestFailed):
            self.request_to(url)

    def test_reply_that_is_not_utf8_is_a_failed_request(self):
        body = b'\xff\xfe\xfd'
        url = one_reply_server(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n' + body)
        with self.assertRaises(scan.RequestFailed):
            self.request_to(url)


class MissingApiKeys(unittest.TestCase):
    """TK-DYN-004, TK-IDN-003: a request whose API key format the environment does not provide is never sent
    with an empty key; the case is blocked (〈定義：測試結果〉 受阻: 缺少……環境)."""

    def test_request_without_its_key_is_not_sent(self):
        # Nothing listens at this URL: a request that went out would fail as refused (RequestFailed).
        env = e1.Environment(project_dir=Path('.'), project_id='maz-no-stack', recipe={}, cli='',
                             api_url=scan._closed_local_url(), api_keys={'anon-jwt': 'test-anon-key'})
        with self.assertRaises(scan.ApiKeyUnavailable) as raised:
            scan._request(env, 'anonymous', 'GET', '/rest/v1/documents', api_key='publishable', timeout=5)
        self.assertIn('publishable', str(raised.exception))


class SchemaCodes(unittest.TestCase):
    """CODING_STANDARDS.md rule 10: the codes the scan writes are the ones the report schema defines."""

    defs = report.SCHEMA['$defs']

    def test_fault_codes_match_the_schema(self):
        self.assertEqual(set(scan.FAULTS), set(self.defs['execution_record']['properties']['fault']['enum']))

    def test_api_key_formats_match_the_schema(self):
        self.assertEqual(set(scan.API_KEY_FORMATS), set(self.defs['evidence']['properties']['api_key_format']['enum']))

    def test_request_methods_are_in_the_schema(self):
        methods = {t['method'] for t in [*scan.DENIAL_TEMPLATES.values(), *scan.ALLOWED_TEMPLATES.values()]}
        self.assertLessEqual(methods, set(self.defs['evidence']['properties']['request']['properties']['method']['enum']))


class MalformedTestFields(unittest.TestCase):
    """TK-IDN-009 / 〈定義：測試結果〉: a test whose own fields are unusable is blocked before anything
    starts, with the values as given; the run still produces a valid report (TK-EVD-003)."""

    FIELDS = ('test_id', 'template_id', 'requirement_id', 'actor_ref', 'resource_ref')

    def test_unusable_field_blocks_the_test_before_the_environment_starts(self):
        for field in self.FIELDS:
            for value in (None, '', 7):
                with self.subTest(field=field, value=value):
                    m = manifest('vulnerable')
                    m['tests'] = [dict(m['tests'][0], **{field: value})]
                    rep = scan.run(m).report
                    self.assertEqual(report.validate(rep), [])
                    self.assertNotIn('environment', rep)
                    (ex,) = rep['execution_records']
                    self.assertEqual((ex['result'], ex[field]), ('blocked', value))
                    # Rejected by the test's own check, not by a later step such as the BuildRecipe.
                    self.assertIn(field, ex['error'])


def manifest_for_recipe_change(d, change):
    """A full manifest aimed at a copy of the vulnerable sample whose BuildRecipe was changed (in d)."""
    from toolkit.tests.test_e1 import failing_copy
    src = failing_copy(d, recipe_change=change)
    m = manifest('vulnerable')
    m['target'] = {'project': str(src), 'source_digest': e1.source_digest(src)}
    return m


class RequiredInputs(unittest.TestCase):
    """TK-SCP-002: a missing required input is handled as 〈定義：必要輸入〉 says; nothing is started.

    Each category of 〈定義：必要輸入〉, the test that removes it, and what is not covered yet:
      受測範圍      test_missing_commit_blocks_dynamic_testing, test_missing_scope_blocks_dynamic_testing,
                    test_each_part_of_the_scope_is_required (commit, endpoints, resources, operations, data scope)
                    test_each_resource_names_its_high_impact_categories (受測資源 and their 〈定義：高影響類別〉)
      獨立安全需求  ConfirmationListInScan (without a confirmation list one is generated, all pending, and
                    handed over; the list is read only from the control zone with its digest),
                    UnknownRequirement (a test on an unknown or pending item is not run)
      部署資訊      test_missing_deployment_information_blocks_before_start_and_names_the_gap (build method,
                    external services; environment variable names, test substitute services and marking
                    the environment differences are not covered yet)
      測試身分      UnsupportedIdentity (an identity the BuildRecipe lacks is listed as a coverage gap)
      測試資料      test_missing_test_data_is_not_filled_in
      復原方式      NoRecovery, NoRecoveryMixedPlanEnv
      執行限制      test_missing_limits_block_the_run, test_each_limit_is_required_and_no_unlimited_default_is_used,
                    test_limits_must_be_bounded
      測試授權      AuthorizationInScan (missing, not a control-zone reference, unusable, outside its period or
                    targets: nothing is started)
    """

    def assert_blocked_before_start(self, m, reason_part):
        rep = scan.run(m).report
        self.assertEqual(report.validate(rep), [])
        self.assertEqual(rep['status'], 'blocked')
        self.assertIn(reason_part, rep['status_reason'])
        self.assertNotIn('environment', rep)
        self.assertEqual(set(results(rep).values()), {'blocked'})
        return rep

    def assert_recipe_gap_blocks_before_start(self, change, reason_part):
        """A BuildRecipe with one required part removed: the run stops when the recipe is read, before
        anything starts, and the reason names the missing part."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            rep = self.assert_blocked_before_start(manifest_for_recipe_change(d, change), reason_part)
        stages = {s['stage']: s['status'] for s in rep['stages']}
        self.assertEqual(stages['dynamic_execution'], 'blocked')
        return rep

    def test_each_resource_names_its_high_impact_categories(self):
        # 〈定義：必要輸入〉 受測範圍: every resource under test says which 〈定義：高影響類別〉 it involves; an
        # empty list says none. Leaving it out is refused, not taken as "none".
        import tempfile
        cases = {
            'a name only': ('documents', "scope.resources/0 must be an object"),
            'no impact': ({'name': 'documents'}, "scope.resources/0 ('documents').impact"),
            'impact not a list': ({'name': 'documents', 'impact': 'confidential'}, "scope.resources/0 ('documents').impact must be a list"),
            'an unknown category': ({'name': 'documents', 'impact': ['secret']},
                                    "scope.resources/0 ('documents').impact: unknown high-impact category 'secret'"),
            'a category twice': ({'name': 'documents', 'impact': ['confidential', 'confidential']},
                                 "scope.resources/0 ('documents').impact lists 'confidential' twice"),
            'no name': ({'impact': []}, 'scope.resources/0.name'),
        }
        for label, (resource, reason) in cases.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as d:
                m = preflight_manifest(d)
                m['scope']['resources'][0] = resource
                rep = self.assert_blocked_before_start(m, reason)
                self.assertEqual(rep['stages'][0]['status'], 'blocked')
        with self.subTest('a resource twice'), tempfile.TemporaryDirectory() as d:
            m = preflight_manifest(d)
            m['scope']['resources'].append({'name': 'documents', 'impact': []})
            self.assert_blocked_before_start(m, "scope.resources/2 ('documents') is listed twice")
        with self.subTest('well formed'), tempfile.TemporaryDirectory() as d:
            rep = scan.run(preflight_manifest(d)).report  # empty project: passes preflight, stops at the BuildRecipe
            self.assertEqual(rep['stages'][0], {'stage': 'preflight', 'status': 'completed'})

    def test_missing_deployment_information_blocks_before_start_and_names_the_gap(self):
        # 部署資訊: 建置方式 (source_build) and 外部相依服務 (service_init.services). The handling's 受阻項目 is
        # covered: nothing starts and the reason names the missing part. Its 環境差異 is not: see the mapping above.
        for step, setting in (('source_build', None), ('source_build', 'tools'),
                              ('service_init', None), ('service_init', 'services')):
            with self.subTest(step=step, setting=setting):
                def remove(r, step=step, setting=setting):
                    if setting:
                        del r[step][setting]
                    else:
                        del r[step]
                self.assert_recipe_gap_blocks_before_start(remove, step if not setting else f'{step}.{setting}')

    def test_missing_test_data_is_not_filled_in(self):
        # 測試資料: 合成資料／初始化方法 (seed), 擁有權標記 (tenants, accounts), 唯一識別標記 (markers).
        # 不使用正式機敏資料補位: no case runs and no environment starts, so no other data can stand in.
        for setting in (None, 'seed', 'tenants', 'accounts', 'markers'):
            with self.subTest(setting=setting):
                def remove(r, setting=setting):
                    if setting:
                        del r['test_data'][setting]
                    else:
                        del r['test_data']
                self.assert_recipe_gap_blocks_before_start(remove, 'test_data' if not setting else f'test_data.{setting}')

    def test_missing_commit_blocks_dynamic_testing(self):
        # 受測範圍 includes the commit under test; without one, no record can be bound to it (TK-DAT-001).
        for value in ('absent', None, '', '   ', 7):
            with self.subTest(commit=value):
                m = manifest('vulnerable')
                if value == 'absent':
                    del m['commit']
                else:
                    m['commit'] = value
                rep = self.assert_blocked_before_start(m, 'commit')
                self.assertIsNone(rep['commit'])

    def test_missing_scope_blocks_dynamic_testing(self):
        m = manifest('vulnerable')
        del m['scope']
        self.assert_blocked_before_start(m, 'scope')

    def test_each_part_of_the_scope_is_required(self):
        for part in SCOPE:
            with self.subTest(missing=part):
                m = manifest('vulnerable')
                del m['scope'][part]
                self.assert_blocked_before_start(m, f'scope.{part}')

    def test_missing_limits_block_the_run(self):
        m = manifest('vulnerable')
        del m['limits']
        self.assert_blocked_before_start(m, 'limits')

    def test_each_limit_is_required_and_no_unlimited_default_is_used(self):
        for name in LIMITS:
            with self.subTest(missing=name):
                m = manifest('vulnerable')
                del m['limits'][name]
                self.assert_blocked_before_start(m, f'limits.{name}')

    def test_limits_must_be_bounded(self):
        invalid = {'max_duration_seconds': [0, -1, None, 'unlimited'], 'max_requests': [0, 1.5, None],
                   'max_concurrency': [0, None], 'max_cost_usd': [-1, None, 'unlimited'],
                   'model_providers': [None, 'any'], 'network_allowlist': [[], None, '*']}
        for name, values in invalid.items():
            for value in values:
                with self.subTest(limit=name, value=value):
                    m = manifest('vulnerable')
                    m['limits'][name] = value
                    self.assert_blocked_before_start(m, f'limits.{name}')


def preflight_manifest(d):
    """A full manifest aimed at an empty project. Preflight decisions do not depend on the project,
    and without a preflight check the run stops at the BuildRecipe step instead (fast, no Docker)."""
    from toolkit import e1
    m = manifest('vulnerable')
    m['target'] = {'project': d, 'source_digest': e1.source_digest(d)}
    return m


class PreflightOrder(unittest.TestCase):
    """Preflight stops at the first problem it meets (TK-RUN-001): a ScanManifest with two problems is blocked
    for the one found first, in the order of the checks. Only an empty project is needed, so no Docker."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()  # one project for every run, so the reasons name the same paths
        self.addCleanup(self.tmp.cleanup)

    def reason(self, *problems):
        m = preflight_manifest(self.tmp.name)
        missing = {'path': str(CONTROL / 'missing.json'), 'digest': 'sha256:' + '0' * 64}  # in the control zone
        for problem in problems:
            {'input': lambda: m['scope'].pop('endpoints'),
             'override': lambda: m.update(policy_template={}),
             'digest': lambda: m['target'].update(source_digest='sha256:' + '0' * 64),
             'authorization': lambda: m.update(authorization=missing),
             'list': lambda: m.update(confirmation_list=missing),
             'review': lambda: m.update(review_record=missing)}[problem]()
        rep = scan.run(m).report
        self.assertEqual(rep['status'], 'blocked')
        return rep['status_reason']

    def test_the_first_problem_found_is_the_reason(self):
        order = ('input', 'override', 'digest', 'authorization', 'list', 'review')
        reasons = {name: self.reason(name) for name in order}
        self.assertEqual(len(set(reasons.values())), len(order))  # each problem has a reason of its own
        for i, earlier in enumerate(order):
            for later in order[i + 1:]:
                with self.subTest(earlier=earlier, later=later):
                    self.assertEqual(self.reason(later, earlier), reasons[earlier])


class UnknownRequirement(unittest.TestCase):
    """需求不明: a test whose requirement is missing or unconfirmed is not run and never passes (TK-REQ-005)."""

    def errors(self, m):
        rep = scan.run(m).report
        self.assertEqual(report.validate(rep), [])
        self.assertEqual(rep['stages'][0], {'stage': 'preflight', 'status': 'blocked',
                                            'reason': rep['status_reason']})
        return {e['test_id']: (e['result'], e['error']) for e in rep['execution_records']}

    def test_test_citing_an_unknown_requirement_is_blocked(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            m = preflight_manifest(d)
            for t in m['tests']:
                t['requirement_id'] = 'REQ-NOT-IN-THE-LIST'
            for result, error in self.errors(m).values():
                self.assertEqual(result, 'blocked')
                self.assertIn('REQ-NOT-IN-THE-LIST', error)

    def test_pending_s2_tests_go_on_and_pending_s1_tests_are_blocked(self):
        # TK-REQ-003: a pending S2 clause may still be tested (its findings are capped); a pending S1
        # entry blocks. Both stay in the coverage denominator (〈定義：確認清單〉).
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            m = preflight_manifest(d)
            m['confirmation_list'] = reviewed_list(d, accepted=(), exceptions={})
            m['tests'].append(S1_READ)
            rep = scan.run(m).report
            self.assertEqual(report.validate(rep), [])
            for e in rep['execution_records']:
                with self.subTest(e['test_id']):
                    self.assertEqual(e['result'], 'blocked')
                    if e['requirement_id'] == PUBLIC_ITEM:
                        self.assertIn('待確認', e['error'])
                    elif e['template_id'] in scan.ALLOWED_TEMPLATES:  # a pending S2 clause still denies
                        self.assertIn('does not match the rule (TK-REQ-016)', e['error'])
                    else:
                        self.assertIn('BuildRecipe', e['error'])
            self.assertEqual(rep['coverage']['denominator'], len(TESTS) + 1 + len(scan.UNSUPPORTED_SCOPES))


class CaseKindMatchesItem(unittest.TestCase):
    """TK-REQ-016: a test is a denial or an allowed case as its confirmation item's rule says.

    The empty project stops the run at the BuildRecipe step (no Docker): a test that passed every
    confirmation check reaches that step, a mismatched one is blocked before it with its own reason."""

    def test_mismatched_case_kinds_are_blocked_and_matching_ones_go_on(self):
        with tempfile.TemporaryDirectory() as d:
            m = preflight_manifest(d)
            read = next(t for t in m['tests'] if t['test_id'] == 'READ-same-tenant')
            public = next(t for t in m['tests'] if t['test_id'] == 'PUBLIC-READ-other-tenant')
            m['tests'] = [read, public,
                          dict(public, test_id='ALLOWED-on-deny', requirement_id=OWNER_ITEM),
                          dict(read, test_id='DENIAL-on-allow', requirement_id=PUBLIC_ITEM)]
            rep = scan.run(m).report
            self.assertEqual(report.validate(rep), [])
            errors = {e['test_id']: (e['result'], e['error']) for e in rep['execution_records']}
            for test_id in ('ALLOWED-on-deny', 'DENIAL-on-allow'):
                self.assertEqual(errors[test_id][0], 'blocked')
                self.assertIn('does not match the rule (TK-REQ-016)', errors[test_id][1])
            for test_id in ('READ-same-tenant', 'PUBLIC-READ-other-tenant'):
                self.assertEqual(errors[test_id][0], 'blocked')
                self.assertIn('BuildRecipe', errors[test_id][1])
            self.assertEqual(rep['coverage']['denominator'], 4 + len(scan.UNSUPPORTED_SCOPES))


class ConfirmationListInScan(unittest.TestCase):
    """〈定義：確認清單〉 in a run: generated and handed over when missing, read only from the control zone."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.m = preflight_manifest(self.tmp.name)

    def blocked(self, m):
        rep = scan.run(m).report
        self.assertEqual(report.validate(rep), [])
        self.assertEqual(rep['status'], 'blocked')
        self.assertNotIn('environment', rep)
        return rep

    def test_without_a_list_one_is_generated_all_pending_and_handed_over(self):
        from toolkit import confirmation
        path = Path(tempfile.mkdtemp(dir=CONTROL)) / 'new-list.json'
        self.m['confirmation_list'] = {'path': str(path)}
        rep = self.blocked(self.m)
        doc = json.loads(path.read_text(encoding='utf-8'))
        self.assertEqual(confirmation.validate(doc), [])
        self.assertEqual({i['status'] for i in doc['items']}, {'pending'})
        self.assertEqual(sorted(i['item_id'] for i in doc['items']), sorted(
            [f'{c}@{r}' for c in ('S2-OWNER-ONLY', 'S2-TENANT-ISOLATION', 'S2-ANON-NO-ACCESS')
             for r in ('documents', 'announcements')] + [PUBLIC_ITEM]))
        self.assertIn(str(path), rep['status_reason'])
        self.assertIn(confirmation.file_digest(path), rep['status_reason'])
        # Pending S2 items do not stop their tests (TK-REQ-003): this run went on to the BuildRecipe step.
        self.assertEqual(rep['stages'][0], {'stage': 'preflight', 'status': 'completed'})
        for e in rep['execution_records']:  # every allowed case rests on a pending S2 clause, which denies
            self.assertEqual(e['result'], 'blocked')
            self.assertIn('does not match the rule' if e['template_id'] in scan.ALLOWED_TEMPLATES else 'BuildRecipe',
                          e['error'])

    def test_a_list_referenced_with_its_digest_but_missing_is_blocked_not_regenerated(self):
        # A digest means the list existed; generating a new, all-pending one would drop the owner's
        # review states and break the confirmation record (TK-REQ-004). Without a digest, see above.
        folder = Path(tempfile.mkdtemp(dir=CONTROL))
        lost, digest = folder / 'lost-list.json', 'sha256:' + 'ab' * 32
        self.m['confirmation_list'] = {'path': str(lost), 'digest': digest}
        rep = self.blocked(self.m)
        self.assertEqual(rep['stages'][0]['stage'], 'preflight')
        self.assertEqual(rep['stages'][0]['status'], 'blocked')
        self.assertIn(f'{lost} is referenced with digest {digest} but does not exist', rep['status_reason'])
        self.assertEqual(list(folder.iterdir()), [])  # nothing was written
        self.assertNotIn('confirmation_list', rep)

    def test_a_list_that_cannot_be_written_is_blocked_not_a_crash(self):
        blocker = Path(tempfile.mkdtemp(dir=CONTROL)) / 'a-file'
        blocker.write_text('not a directory', encoding='utf-8')
        self.m['confirmation_list'] = {'path': str(blocker / 'confirmation-list.json')}
        self.assertIn('confirmation list', self.blocked(self.m)['status_reason'])

    def test_a_malformed_s2_template_is_blocked_not_a_crash(self):
        from unittest import mock
        from toolkit import policy
        bad = Path(tempfile.mkdtemp(dir=CONTROL)) / 'template.json'
        bad.write_text('{"policy_template_id": "x"}', encoding='utf-8')
        with mock.patch.object(policy, 'TEMPLATE', bad):
            self.assertIn('S2 template', self.blocked(self.m)['status_reason'])

    def test_errors_name_review_states_with_their_spec_labels(self):
        # Spec names (〈定義：確認清單〉 處理狀態), written here, not taken from report.REVIEW_LABELS.
        self.m['confirmation_list'] = reviewed_list(self.tmp.name, accepted=(), exceptions={})
        self.m['tests'].append(S1_READ)
        errors = [e['error'] for e in self.blocked(self.m)['execution_records'] if e['requirement_id'] == PUBLIC_ITEM]
        self.assertTrue(errors and all('待確認' in e for e in errors), errors)

    def test_a_modified_item_is_reported_with_its_modified_rule(self):
        # The run stops at the empty project's BuildRecipe step (no Docker); the report still lists the items.
        from toolkit import confirmation
        ref = self.m['confirmation_list']
        doc = json.loads(Path(ref['path']).read_text(encoding='utf-8'))
        public = next(i for i in doc['items'] if i['item_id'] == PUBLIC_ITEM)
        public['status'] = 'modified'
        public['review'].update(reason='owner restricts reads', basis='spec §2', modified_rule='deny')
        self.m['confirmation_list'] = {'path': ref['path'], 'digest': confirmation.write(ref['path'], doc, self.tmp.name)}
        self.m['tests'].append(S1_READ)
        reported = {r['id']: r for r in scan.run(self.m).report['requirements']}
        self.assertEqual((reported[PUBLIC_ITEM]['status'], reported[PUBLIC_ITEM]['rule']), ('modified', 'deny'))
        self.assertNotIn('allowed_tests', reported[PUBLIC_ITEM]['confirmation'])  # a rewritten rule is no 合法例外
        self.assertEqual(reported[OWNER_ITEM]['rule'], 'deny')
        # A 合法例外 keeps the rule of the tests it does not list, and names those it allows and its expiry.
        self.assertEqual((reported[TENANT_ITEM]['status'], reported[TENANT_ITEM]['rule']), ('modified', 'deny'))
        self.assertEqual({k: reported[TENANT_ITEM]['confirmation'][k] for k in ('allowed_tests', 'expiry')},
                         {'allowed_tests': [SHARED_READ['test_id']], 'expiry': EXPIRY})

    def test_the_report_summarises_review_states_by_source(self):
        # TK-REQ-003 報告列出各類待確認數量; 〈定義：確認清單〉 單人核准 for modified and not applicable items.
        from toolkit import confirmation
        ref = self.m['confirmation_list']
        doc = json.loads(Path(ref['path']).read_text(encoding='utf-8'))
        items = {i['item_id']: i for i in doc['items']}
        items[TENANT_ITEM].update(status='not_applicable')
        items[TENANT_ITEM]['review'].update(reason='single tenant', basis='S1-X')
        items[ANON_ITEM].update(status='modified')
        items[ANON_ITEM]['review'].update(reason='owner wording', basis='spec §3', modified_rule='deny')
        self.m['confirmation_list'] = {'path': ref['path'], 'digest': confirmation.write(ref['path'], doc, self.tmp.name)}
        listed = scan.run(self.m).report['confirmation_list']
        # Six S2 items (three clauses × documents, announcements) and one S1 entry, none out of scope; the
        # three on announcements are 合法例外 (EXCEPTIONS).
        self.assertEqual(listed['summary'], {
            'S1': {'pending': 0, 'accepted': 1, 'modified': 0, 'not_applicable': 0},
            'S2': {'pending': 0, 'accepted': 1, 'modified': 4, 'not_applicable': 1}})
        self.assertEqual(listed['out_of_scope'], 0)
        # In the list's order: high-impact items first, S2-TENANT-ISOLATION@announcements by its clause's cross_tenant.
        self.assertEqual(listed['single_approval'], [ANON_ITEM, 'S2-TENANT-ISOLATION@announcements', TENANT_ITEM,
                                                     'S2-ANON-NO-ACCESS@announcements', 'S2-OWNER-ONLY@announcements'])
        self.assertEqual(listed['s2_template'], doc['s2_template'])
        self.assertEqual(listed['list_version'], doc['list_version'])

    def edit_list(self, change):
        """change(items by id) on the manifest's list, written back and referenced as the owner would."""
        from toolkit import confirmation
        ref = self.m['confirmation_list']
        doc = json.loads(Path(ref['path']).read_text(encoding='utf-8'))
        change({i['item_id']: i for i in doc['items']})
        self.m['confirmation_list'] = {'path': ref['path'], 'digest': confirmation.write(ref['path'], doc, self.tmp.name)}

    def errors(self):
        return {e['test_id']: e['error'] for e in self.blocked(self.m)['execution_records']}

    def test_a_legitimate_exception_lacking_a_part_blocks_the_tests_on_it_and_names_the_part(self):
        # TK-DYN-003: a 合法例外 needs its basis, an allowed-case test and an expiry (〈定義：確認清單〉 修改).
        for name, value, expected in (('basis', None, 'lacks basis'), ('allowed_tests', [], 'lacks allowed_tests'),
                                      ('expiry', None, 'lacks expiry'),
                                      ('expiry', 'next quarter', "its expiry 'next quarter' is not an ISO 8601 UTC time")):
            with self.subTest(name=name, value=value):
                self.m['confirmation_list'] = reviewed_list(self.tmp.name)  # each part on its own
                self.edit_list(lambda items: items[TENANT_ITEM]['review'].update({name: value}))
                errors = self.errors()
                for test_id in (SHARED_READ['test_id'], 'READ-other-tenant'):
                    self.assertIn(expected, errors[test_id])
                self.assertIn('BuildRecipe', errors['READ-same-tenant'])  # another item: not affected

    def test_an_allowed_test_not_in_the_plan_blocks_only_the_allowed_cases_on_the_exception(self):
        # TK-DYN-003: the exception must be shown by its allowed tests; denial cases are judged by deny anyway.
        self.edit_list(lambda items: items[TENANT_ITEM]['review'].update(allowed_tests=[SHARED_READ['test_id'], 'NOT-PLANNED']))
        errors = self.errors()
        self.assertIn("allowed test 'NOT-PLANNED' is not in the test plan", errors[SHARED_READ['test_id']])
        self.assertIn('BuildRecipe', errors['READ-other-tenant'])

    def test_an_expired_exception_is_reset_to_pending_and_its_tests_go_back_to_the_s2_clause(self):
        # 〈定義：確認清單〉 到期: the expiry has come by the run's start; the toolkit resets the item, and the
        # list is written back as a new version for the owner (TK-REQ-004, TK-REQ-009).
        self.edit_list(lambda items: items[TENANT_ITEM]['review'].update(expiry='2026-01-01T00:00:00Z'))
        path = self.m['confirmation_list']['path']
        before = json.loads(Path(path).read_text(encoding='utf-8'))
        rep = self.blocked(self.m)
        after = json.loads(Path(path).read_text(encoding='utf-8'))
        self.assertEqual((after['list_version'], rep['confirmation_list']['updated']), (before['list_version'] + 1, True))
        item = next(i for i in after['items'] if i['item_id'] == TENANT_ITEM)
        self.assertEqual((item['version'], item['status'], item['reset_reason']), (2, 'pending', 'expired'))
        self.assertEqual((item['history'][-1]['status'], item['history'][-1]['review']['expiry']),
                         ('modified', '2026-01-01T00:00:00Z'))
        records = {e['test_id']: e for e in rep['execution_records']}
        # The pending S2 clause denies again: the allowed case no longer matches, the denial cases go on.
        self.assertIn('does not match the rule (TK-REQ-016)', records[SHARED_READ['test_id']]['error'])
        self.assertIn('BuildRecipe', records['READ-other-tenant']['error'])
        self.assertEqual(records['READ-other-tenant']['requirement_version'], 2)
        self.assertNotIn(TENANT_ITEM, rep['confirmation_list']['single_approval'])

    def test_a_legitimate_exception_is_shown_as_approved_by_one_person(self):
        # 〈定義：確認清單〉 單人核准: a 合法例外 relaxes S2, and no second approver exists yet (TK-REQ-014).
        self.assertIn(TENANT_ITEM, self.blocked(self.m)['confirmation_list']['single_approval'])

    def test_items_out_of_scope_are_counted_apart_from_review_states(self):
        self.m['scope']['resources'] = [{'name': 'announcements', 'impact': []}]
        listed = scan.run(self.m).report['confirmation_list']
        self.assertEqual(listed['out_of_scope'], 3)  # the three S2 clauses on documents
        self.assertEqual(listed['summary']['S2'], {'pending': 0, 'accepted': 0, 'modified': 3, 'not_applicable': 0})

    def test_the_list_path_is_required(self):
        for value in (None, {}, {'digest': 'sha256:' + '0' * 64}):
            with self.subTest(value=value):
                m = copy.deepcopy(self.m)
                if value is None:
                    del m['confirmation_list']
                else:
                    m['confirmation_list'] = value
                self.assertIn('confirmation_list.path', self.blocked(m)['status_reason'])

    def test_a_list_inside_the_sample_source_is_refused(self):
        inside = Path(self.tmp.name) / 'confirmation-list.json'
        for ref in ({'path': str(inside)}, {'path': str(inside), 'digest': 'sha256:' + 'ab' * 32}):
            with self.subTest(digest='digest' in ref):  # with a digest, the location is checked before the file
                self.m['confirmation_list'] = ref
                rep = self.blocked(self.m)
                self.assertIn('inside the sample source', rep['status_reason'])
                self.assertFalse(inside.exists())

    def test_an_existing_list_needs_its_digest_and_it_must_match(self):
        ref = self.m['confirmation_list']
        for digest in (None, 'sha256:' + '0' * 64):
            with self.subTest(digest=digest):
                self.m['confirmation_list'] = {'path': ref['path']} if digest is None else {**ref, 'digest': digest}
                self.assertIn('digest', self.blocked(self.m)['status_reason'])

    def test_s1_entries_carry_no_confirmation(self):
        self.m['requirements'][0]['confirmation'] = {'by': 'app-owner', 'at': '2026-11-02T09:00:00Z'}
        self.assertIn('confirmation list', self.blocked(self.m)['status_reason'])

    def test_s1_entries_need_id_statement_resources_and_rule(self):
        for field in ('id', 'statement', 'resources', 'rule'):
            with self.subTest(missing=field):
                m = copy.deepcopy(self.m)
                del m['requirements'][0][field]
                self.assertIn(field, self.blocked(m)['status_reason'])

    def test_an_s1_entry_id_with_an_at_sign_is_refused_before_any_list_is_written(self):
        # "@" belongs to S2 item ids (clause@resource); an S1 id with it could take one's place.
        path = Path(tempfile.mkdtemp(dir=CONTROL)) / 'list.json'
        m = copy.deepcopy(self.m)
        m['confirmation_list'] = {'path': str(path)}
        m['requirements'][0]['id'] = OWNER_ITEM
        rep = self.blocked(m)
        self.assertIn("requirements/0.id 'S2-OWNER-ONLY@documents' must not contain '@'", rep['status_reason'])
        self.assertFalse(path.exists())
        m['requirements'][0]['id'] = 'S1-ANNOUNCEMENTS-PUBLIC-READ'  # without "@": the list is generated
        self.blocked(m)
        self.assertTrue(path.exists())

    def test_an_s1_entry_may_list_high_impact_categories_and_unknown_ones_are_refused(self):
        # TK-REQ-012: requirements[].impact is optional; given, it is checked like a resource's.
        path = Path(tempfile.mkdtemp(dir=CONTROL)) / 'list.json'
        m = copy.deepcopy(self.m)
        m['confirmation_list'] = {'path': str(path)}
        for impact, problem in ((['tenant'], "requirements/0.impact: unknown high-impact category 'tenant'"),
                                ('payment', 'requirements/0.impact must be a list'),
                                (None, 'requirements/0.impact must be a list'),  # optional means left out, not null
                                (['payment', 'payment'], "requirements/0.impact lists 'payment' twice")):
            with self.subTest(impact=impact):
                m['requirements'][0]['impact'] = impact
                self.assertIn(problem, self.blocked(m)['status_reason'])
                self.assertFalse(path.exists())
        m['requirements'][0]['impact'] = ['payment']
        self.blocked(m)
        items = {i['item_id']: i for i in json.loads(path.read_text(encoding='utf-8'))['items']}
        self.assertEqual(items[PUBLIC_ITEM]['impact'], ['payment'])
        self.assertEqual(items[OWNER_ITEM]['impact'], ['confidential'])  # from scope.resources

    def test_the_report_lists_requirements_in_the_plan_order_not_the_lists(self):
        # Only the confirmation list file is sorted (〈定義：確認清單〉 排序); the report keeps the test plan's order.
        path = Path(tempfile.mkdtemp(dir=CONTROL)) / 'list.json'
        self.m['confirmation_list'] = {'path': str(path)}
        rep = self.blocked(self.m)
        planned = list(dict.fromkeys(t['requirement_id'] for t in self.m['tests']))
        listed = [i['item_id'] for i in json.loads(path.read_text(encoding='utf-8'))['items'] if i['item_id'] in planned]
        self.assertNotEqual(listed, planned)  # the two orders differ, so the check below means something
        self.assertEqual([r['id'] for r in rep['requirements']], planned)

    def test_tests_on_incomplete_or_not_applicable_items_are_blocked(self):
        from toolkit import confirmation
        ref = self.m['confirmation_list']
        doc = json.loads(Path(ref['path']).read_text(encoding='utf-8'))
        items = {i['item_id']: i for i in doc['items']}
        items[OWNER_ITEM]['review']['at'] = None                      # accepted, but when?
        items[TENANT_ITEM].update(status='not_applicable')
        items[TENANT_ITEM]['review'].update(reason='single tenant', basis='S1-X')
        items[ANON_ITEM]['review']['by'] = None
        items[ANNOUNCEMENT_ITEM['other_tenant_user']]['review']['by'] = None
        self.m['confirmation_list'] = {'path': ref['path'], 'digest': confirmation.write(ref['path'], doc, self.tmp.name)}
        errors = {e['test_id']: e['error'] for e in self.blocked(self.m)['execution_records']}
        self.assertIn('lacks at', errors['READ-same-tenant'])
        self.assertIn('not_applicable', errors['READ-other-tenant'])
        self.assertIn('lacks by', errors['READ-anonymous-anon-jwt'])
        self.assertIn('lacks by', errors['PUBLIC-READ-other-tenant'])

    def test_tests_on_items_out_of_scope_are_blocked(self):
        # documents leaves the scope: its items are marked out of scope and keep their review state.
        self.m['scope']['resources'] = [{'name': 'announcements', 'impact': []}]
        errors = {e['test_id']: e['error'] for e in self.blocked(self.m)['execution_records']}
        self.assertIn('out of scope', errors['READ-same-tenant'])
        self.assertIn('out of scope', errors['READ-anonymous-anon-jwt'])
        doc = json.loads(Path(self.m['confirmation_list']['path']).read_text(encoding='utf-8'))
        owner = next(i for i in doc['items'] if i['item_id'] == OWNER_ITEM)
        self.assertEqual((owner['out_of_scope'], owner['status']), (True, 'accepted'))

    def test_a_list_from_an_older_scope_is_updated_and_its_new_items_are_pending(self):
        from toolkit import confirmation
        self.m['confirmation_list'] = reviewed_list(self.tmp.name, resources=[{'name': 'documents', 'impact': ['confidential']}])
        before = json.loads(Path(self.m['confirmation_list']['path']).read_text(encoding='utf-8'))
        rep = scan.run(self.m).report
        after = json.loads(Path(self.m['confirmation_list']['path']).read_text(encoding='utf-8'))
        self.assertEqual(after['list_version'], before['list_version'] + 1)
        self.assertEqual({i['item_id']: i['status'] for i in after['items'] if i['item_id'].endswith('@announcements')},
                         {f'{c}@announcements': 'pending' for c in ('S2-OWNER-ONLY', 'S2-TENANT-ISOLATION', 'S2-ANON-NO-ACCESS')})
        self.assertEqual(next(i for i in after['items'] if i['item_id'] == OWNER_ITEM)['status'], 'accepted')
        listed = {k: rep['confirmation_list'][k] for k in ('path', 'digest', 'list_version', 'updated')}
        self.assertEqual(listed, {'path': self.m['confirmation_list']['path'],
                                                    'digest': confirmation.file_digest(self.m['confirmation_list']['path']),
                                                    'list_version': after['list_version'], 'updated': True})


class AuthorizationInScan(unittest.TestCase):
    """〈定義：測試授權紀錄〉 in a run (TK-ENV-001, TK-ENV-002). The empty project stops the run at the
    BuildRecipe step (no Docker): a test the authorization lets through reaches that step."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.m = preflight_manifest(self.tmp.name)

    def run_scan(self, m=None):
        rep = scan.run(m or self.m).report
        self.assertEqual(report.validate(rep), [])
        return rep

    def preflight_blocked(self, reason_part, m=None):
        rep = self.run_scan(m)
        self.assertEqual((rep['status'], rep['stages'][0]['status']), ('blocked', 'blocked'))
        self.assertIn(reason_part, rep['status_reason'])
        self.assertNotIn('environment', rep)
        return rep

    def authorize(self, **changes):
        self.m['authorization'] = authorized(self.tmp.name, {**copy.deepcopy(AUTHORIZATION), **changes})

    def errors(self):
        return {e['test_id']: e for e in self.run_scan()['execution_records']}

    def test_a_run_without_an_authorization_record_is_not_started(self):
        del self.m['authorization']
        self.preflight_blocked('authorization (測試授權) is missing')

    def test_the_authorization_is_referenced_never_given_in_the_manifest(self):
        # TK-ENV-002: whoever writes the ScanManifest cannot authorize the run by writing the record into it.
        for value in (copy.deepcopy(AUTHORIZATION), {'path': self.m['authorization']['path']}, 'approved'):
            with self.subTest(value=type(value).__name__):
                self.m['authorization'] = value
                self.preflight_blocked('authorization (測試授權) must reference a control-zone record by path and digest')

    def test_an_unusable_record_is_not_used(self):
        from toolkit import control
        inside = Path(self.tmp.name) / 'authorization.json'
        inside.write_text(json.dumps(AUTHORIZATION), encoding='utf-8')
        self.m['target']['source_digest'] = e1.source_digest(self.tmp.name)  # the record is now part of the source
        cases = {'inside the sample source': {'path': str(inside), 'digest': control.file_digest(inside)},
                 'the ScanManifest says': {**self.m['authorization'], 'digest': 'sha256:' + '0' * 64},
                 'not a valid test authorization record': authorized(self.tmp.name, {**AUTHORIZATION, 'environment': ''})}
        for reason, ref in cases.items():
            with self.subTest(reason):
                self.m['authorization'] = ref
                self.preflight_blocked(reason)

    def test_a_run_outside_the_authorized_period_is_not_started(self):
        self.authorize(valid_from='2026-01-01T00:00:00Z', valid_until='2026-02-01T00:00:00Z', extra_approvals=[])
        self.preflight_blocked('outside the authorized period 2026-01-01T00:00:00Z to 2026-02-01T00:00:00Z')

    def test_a_sample_or_an_environment_the_record_does_not_cover_is_not_started(self):
        def other_sample(r):
            r['sample'] = 'object-authz/somebody-else'
        with tempfile.TemporaryDirectory() as d:
            m = manifest_for_recipe_change(d, other_sample)
            self.preflight_blocked("sample 'object-authz/somebody-else' is not a target", m)
        self.authorize(environment='E2')
        with tempfile.TemporaryDirectory() as d:
            m = manifest_for_recipe_change(d, lambda r: None)
            m['authorization'] = self.m['authorization']
            self.preflight_blocked("environment 'E1' is not the authorized environment 'E2'", m)

    def test_the_scopes_operations_are_http_methods_of_the_authorization(self):
        self.assertEqual(self.run_scan()['stages'][0]['status'], 'completed')
        for value in (['GET', 'TRUNCATE'], 'GET'):
            with self.subTest(value=value):
                self.m['scope']['allowed_operations'] = value
                self.preflight_blocked("scope.allowed_operations (受測範圍) must list HTTP methods of ['GET', 'POST', 'PATCH', 'DELETE']")

    def test_a_test_outside_the_scope_is_blocked_even_with_an_extra_approval(self):
        self.m['scope']['allowed_operations'] = ['GET']
        self.authorize(extra_approvals=[approval('APR-001', 'documents', 'PATCH')])
        errors = self.errors()
        self.assertIn("PATCH is not in scope.allowed_operations (受測範圍)", errors['UPDATE-same-tenant']['error'])
        self.assertNotIn('approval_id', errors['UPDATE-same-tenant'])
        self.assertIn('BuildRecipe', errors['READ-same-tenant']['error'])

    def test_an_operation_outside_the_authorization_runs_only_with_an_extra_approval(self):
        # TK-ENV-001: DELETE on documents is not authorized; an approval covering it lets the delete cases go on.
        # The record of a test shows its approval only when the test ran (VulnerableRunEnv); here it stops at
        # the BuildRecipe step.
        self.authorize(extra_approvals=[])
        errors = self.errors()
        self.assertIn("DELETE on 'documents' is not in the test authorization", errors['DELETE-same-tenant']['error'])
        self.assertIn('BuildRecipe', errors['UPDATE-same-tenant']['error'])
        self.authorize(extra_approvals=[approval('APR-001', 'documents', 'DELETE')])
        errors = self.errors()
        self.assertIn('BuildRecipe', errors['DELETE-same-tenant']['error'])
        self.assertNotIn('approval_id', errors['DELETE-same-tenant'])

    def test_an_expired_approval_or_one_the_operator_gave_does_not_count(self):
        for given, expected in ((approval('APR-001', 'documents', 'DELETE', valid_until='2026-02-01T00:00:00Z'),
                                 'APR-001 expired at 2026-02-01T00:00:00Z'),
                                (approval('APR-001', 'documents', 'DELETE', by=' Toolkit-Tests'),
                                 "APR-001 was given by the operator ' Toolkit-Tests'")):
            with self.subTest(expected):
                self.authorize(extra_approvals=[given])
                self.assertIn(expected, self.errors()['DELETE-same-tenant']['error'])

    def test_an_approval_claimed_by_the_test_plan_does_not_count(self):
        # TK-ENV-002: a plan, which a model may have written, cannot approve its own tests.
        self.authorize(extra_approvals=[])
        for t in self.m['tests']:
            t.update(approved=True, approval_id='APR-001', note='已核准')
        errors = self.errors()
        self.assertIn('not in the test authorization', errors['DELETE-same-tenant']['error'])
        self.assertNotIn('approval_id', errors['DELETE-same-tenant'])

    def test_the_report_shows_the_authorization_its_unverified_names_and_no_source_changes(self):
        rep = self.run_scan()
        shown = rep['authorization']
        self.assertEqual({k: shown[k] for k in ('path', 'digest')}, self.m['authorization'])
        self.assertEqual({k: shown[k] for k in ('targets', 'environment', 'valid_from', 'valid_until', 'data_scope',
                                                 'roles', 'issued_by', 'issued_at', 'extra_approvals')},
                         {k: AUTHORIZATION[k] for k in ('targets', 'environment', 'valid_from', 'valid_until', 'data_scope',
                                                        'roles', 'issued_by', 'issued_at', 'extra_approvals')})
        self.assertIs(shown['identity_verified'], False)
        self.assertEqual(rep['source_changes'], [])  # TK-ENV-006: the source under test is the pinned one


def approval(approval_id, resource, method, by='security-lead', valid_until='2098-01-01T00:00:00Z'):
    """An extra approval for one operation (〈定義：測試授權紀錄〉)."""
    return {'approval_id': approval_id, 'operations': [{'resource': resource, 'methods': [method]}], 'by': by,
            'at': '2026-01-02T00:00:00Z', 'reason': 'needed for this run', 'valid_until': valid_until}


class ReviewRecordInScan(unittest.TestCase):
    """〈定義：覆核紀錄〉 in a run: an optional control-zone record, referenced by path and digest. The
    empty project stops the run at the BuildRecipe step (no Docker)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.m = preflight_manifest(self.tmp.name)

    def run_scan(self):
        rep = scan.run(self.m).report
        self.assertEqual(report.validate(rep), [])
        return rep

    def test_without_a_review_record_the_report_says_none_was_used(self):
        rep = self.run_scan()
        self.assertIsNone(rep['review_record'])
        self.assertEqual(rep['review_summary'], {'pending': 0, 'overdue': 0, 'approved': 0, 'rejected': 0,
                                                 'evidence_pending': 0})

    RECORD = {'schema_version': '1', 'platform': 'github', 'repo': 'owner/reviews', 'items': []}

    def review_record(self, doc=None):
        from toolkit import control
        path = Path(tempfile.mkdtemp(dir=CONTROL)) / 'review-record.json'
        return {'path': str(path), 'digest': control.write(path, doc or self.RECORD, self.tmp.name)}

    def with_item(self, **changes):
        """The record with one undecided item; changes replace its fields."""
        item = {'review_type': 'candidate_finding', 'fingerprint': 'sha256:' + '3' * 64,
                'fingerprint_version': 'fp-authz-v1', 'issue': 7, 'opened_at': '2026-11-09T01:00:00Z',
                'versions': {'requirement_id': OWNER_ITEM, 'requirement_version': 1, 'commit': 'c', 'run_id': 'r'},
                'decisions': [], 'rejected': [], **changes}
        return {**self.RECORD, 'items': [item]}

    def test_the_review_record_the_manifest_references_is_named_in_the_report(self):
        self.m['review_record'] = self.review_record()
        self.assertEqual(self.run_scan()['review_record'], self.m['review_record'])

    def test_an_unusable_review_record_blocks_the_run_at_preflight(self):
        from toolkit import control
        inside = Path(self.tmp.name) / 'review-record.json'
        inside.write_text(json.dumps(self.RECORD), encoding='utf-8')
        self.m['target']['source_digest'] = e1.source_digest(self.tmp.name)  # the record is now part of the source
        gone = self.review_record()
        Path(gone['path']).unlink()
        cases = {'inside the sample source': {'path': str(inside), 'digest': control.file_digest(inside)},
                 'the ScanManifest says': {**self.review_record(), 'digest': 'sha256:' + '0' * 64},
                 'does not exist': gone,
                 'must reference a control-zone record by path and digest': {'path': str(inside)},
                 'not a valid review record': self.review_record({'schema_version': '1', 'items': 'none'}),
                 'not an ISO 8601 UTC time': self.review_record(self.with_item(opened_at='2026-11-09 01:00')),
                 "reason_comments/0/updated_at: 'x'": self.review_record(self.with_item(decisions=[
                     {'event_id': 1, 'option': 'approve', 'by': {'id': 101, 'login': 'sec-alice'},
                      'at': '2026-11-09T03:00:00Z', 'reason': 'checked',
                      'reason_comments': [{'id': 2, 'updated_at': 'x'}]}]))}
        for reason, ref in cases.items():
            with self.subTest(reason):
                self.m['review_record'] = ref
                rep = self.run_scan()
                self.assertEqual((rep['status'], rep['stages'][0]['status']), ('blocked', 'blocked'))
                self.assertIn('review record', rep['status_reason'])
                self.assertIn(reason, rep['status_reason'])


class RecordsKeepTheItemVersion(unittest.TestCase):
    """TK-REQ-004: every record names the version of the item it rests on; a later version of the item
    leaves the records of earlier reports pointing at the version they were judged on."""

    def test_after_the_item_changes_the_old_report_still_points_at_the_old_version(self):
        with tempfile.TemporaryDirectory() as d:
            m = preflight_manifest(d)
            m['tests'].append(S1_READ)
            first = scan.run(m).report
            m['requirements'][0]['statement'] = 'Only signed-in users may read announcements.'
            second = scan.run(m).report  # the S1 entry changed: its item is now version 2, pending
            for rep, version in ((first, 1), (second, 2)):
                with self.subTest(version=version):
                    self.assertEqual(report.validate(rep), [])
                    public = [e for e in rep['execution_records'] if e['requirement_id'] == PUBLIC_ITEM]
                    self.assertEqual({e['requirement_version'] for e in public}, {version})
            owner = [e['requirement_version'] for e in second['execution_records'] if e['requirement_id'] == OWNER_ITEM]
            self.assertEqual(set(owner), {1})

    def test_a_test_on_an_unknown_requirement_names_no_version(self):
        with tempfile.TemporaryDirectory() as d:
            m = preflight_manifest(d)
            m['tests'][0]['requirement_id'] = 'REQ-NOT-IN-THE-LIST'
            rep = scan.run(m).report
            self.assertEqual(report.validate(rep), [])
            self.assertIsNone(rep['execution_records'][0]['requirement_version'])


class SharedPlan(unittest.TestCase):
    """One plan per sample version holds the judgement tests and the S2 template's self-acceptance
    cases, so both share one E1 run (TK-REQ-008); a case keeps the template's own definition."""

    def test_the_plan_holds_every_case_and_every_test_once(self):
        from toolkit import policy
        plan = shared_plan(policy.load_template(), TESTS)
        ids = [t['test_id'] for t in plan]
        # 16 template cases; the 10 judgement tests of the same name are those cases; 4 public reads and the
        # shared read are judgement tests only.
        self.assertEqual(len(ids), 21)
        self.assertEqual(len(set(ids)), 21)
        self.assertIn('UPDATE-anonymous-publishable', ids)  # a case only the template has
        self.assertIn('PUBLIC-READ-other-tenant', ids)  # a test only the judgement plan has
        case = next(t for t in plan if t['test_id'] == 'READ-same-tenant')
        self.assertEqual((case['requirement_id'], case['resource_ref']), (OWNER_ITEM, 'MARK-A-ALICE-PRIVATE'))

    def test_a_test_named_like_a_case_but_defined_differently_is_refused(self):
        from toolkit import policy
        tests = [dict(t, resource_ref='MARK-A-ALICE-SHARED') if t['test_id'] == 'READ-same-tenant' else t
                 for t in TESTS]
        with self.assertRaisesRegex(ValueError, 'READ-same-tenant'):
            shared_plan(policy.load_template(), tests)


@needs_env
class TemplateSelfAcceptanceEnv(unittest.TestCase):
    """TK-REQ-008: the S2 template is enabled only when its own samples give the expected results."""

    def test_every_sample_version_gives_the_expected_results(self):
        from toolkit import policy
        template = policy.load_template()
        acceptance = template['self_acceptance']
        self.assertEqual(SAMPLES.relative_to(SAMPLES.parents[1]).as_posix(), acceptance['sample'])
        for version in acceptance['versions']:
            with self.subTest(version=version):
                rep = run_once(version).report  # the run the judgement tests use: no E1 of its own (#43)
                self.assertEqual(report.validate(rep), [])
                self.assertEqual(rep['status'], 'completed', rep.get('status_reason'))
                got = results(rep)
                # A case skipped or without a result gives None here, never its expected passed/failed.
                self.assertEqual({c['case_id']: got.get(c['case_id']) for c in acceptance['cases']},
                                 {c['case_id']: c['expected'][version] for c in acceptance['cases']})


class TemplateFromToolkitOnly(unittest.TestCase):
    """TK-REQ-008: the S2 template ships with the toolkit; a ScanManifest cannot supply or replace it."""

    def test_manifest_with_its_own_template_is_blocked_before_start(self):
        for field in ('policy_template', 'policy_template_path'):
            with self.subTest(field=field):
                m = manifest('vulnerable')
                m[field] = {'clauses': []} if field == 'policy_template' else 'my-template.json'
                rep = scan.run(m).report
                self.assertEqual(report.validate(rep), [])
                self.assertEqual(rep['status'], 'blocked')
                self.assertIn(field, rep['status_reason'])
                self.assertIn('toolkit', rep['status_reason'])
                self.assertNotIn('environment', rep)
                self.assertEqual(set(results(rep).values()), {'blocked'})


class UnsupportedIdentity(unittest.TestCase):
    """〈定義：必要輸入〉 測試身分: a matrix cell the recipe has no identity for is a coverage gap."""

    def test_identity_missing_from_the_recipe_is_unsupported(self):
        import tempfile
        from toolkit import e1
        from toolkit.tests.test_e1 import failing_copy
        with tempfile.TemporaryDirectory() as d:
            # The untrusted tool makes the BuildRecipe fail fast if the run ever gets that far.
            src = failing_copy(d, recipe_change=lambda r: r['source_build'].update(tools=['no-such-tool']))
            m = manifest('vulnerable')
            m['target'] = {'project': str(src), 'source_digest': e1.source_digest(src)}
            for t in m['tests']:
                t['actor_ref'] = 'tenant_admin'
            rep = scan.run(m).report
        self.assertEqual(report.validate(rep), [])
        for e in rep['execution_records']:
            self.assertEqual(e['result'], 'unsupported', e)
            self.assertIn('tenant_admin', e['error'])
        gaps = {u['scope'] for u in rep['coverage']['unsupported_items']}
        self.assertIn('identity:tenant_admin', gaps)

    def test_the_gap_stays_when_the_environment_is_blocked(self):
        import tempfile
        from toolkit import e1
        from toolkit.tests.test_e1 import failing_copy
        with tempfile.TemporaryDirectory() as d:
            src = failing_copy(d, recipe_change=lambda r: r['source_build'].update(tools=['no-such-tool']))
            m = manifest('vulnerable')
            m['target'] = {'project': str(src), 'source_digest': e1.source_digest(src)}
            m['tests'][0]['actor_ref'] = 'tenant_admin'  # the other tests can run, so the BuildRecipe step is reached
            rep = scan.run(m).report
        self.assertEqual(report.validate(rep), [])
        dynamic = next(s for s in rep['stages'] if s['stage'] == 'dynamic_execution')
        self.assertEqual(dynamic['status'], 'blocked')
        self.assertIn('source_build', dynamic['reason'])
        gaps = {u['scope'] for u in rep['coverage']['unsupported_items']}
        self.assertIn('identity:tenant_admin', gaps)


class NoRecovery(unittest.TestCase):
    """〈定義：必要輸入〉 復原方式: a test that cannot be restored safely is not run."""

    def test_write_cases_are_not_run_without_a_reset(self):
        import tempfile

        def no_reset(r):
            r['snapshot_reset']['reset_scope'] = 'none'
            r['source_build']['tools'] = ['no-such-tool']  # fail fast if the run ever gets that far
        with tempfile.TemporaryDirectory() as d:
            m = manifest_for_recipe_change(d, no_reset)
            m['tests'] = [t for t in m['tests'] if scan.DENIAL_TEMPLATES.get(t['template_id'], {}).get('writes')]
            rep = scan.run(m).report
        self.assertEqual(report.validate(rep), [])
        self.assertEqual(len(rep['execution_records']), 6)
        for e in rep['execution_records']:
            self.assertEqual(e['result'], 'blocked', e)
            self.assertIn('restored safely', e['error'])


class StagesOfBlockedRuns(unittest.TestCase):
    """TK-RUN-001, 〈定義：工作階段〉 失敗處理: a failed stage stops dependent work and says so."""

    NOT_IMPLEMENTED = ('static_analysis', 'model_review', 'threat_planning')

    def stages(self, rep):
        return {s['stage']: s['status'] for s in rep['stages']}

    def test_preflight_failure_stops_dependent_work(self):
        m = manifest('vulnerable')
        m['target']['source_digest'] = 'sha256:' + '0' * 64
        stages = self.stages(scan.run(m).report)
        self.assertEqual((stages['preflight'], stages['dynamic_execution'], stages['judgement_report']),
                         ('blocked', 'not_run', 'completed'))
        self.assertEqual({stages[s] for s in self.NOT_IMPLEMENTED}, {'not_run'})

    def test_environment_failure_blocks_dynamic_execution(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            stages = self.stages(scan.run(preflight_manifest(d)).report)  # empty project: no BuildRecipe
        self.assertEqual((stages['preflight'], stages['dynamic_execution'], stages['judgement_report']),
                         ('completed', 'blocked', 'completed'))


@needs_env
class UndeterminableCasesEnv(unittest.TestCase):
    """TK-VAL-001 無法判定案例 and TK-IDN-009: lost login, unavailable observer and timeouts never pass.

    The faults are injected on purpose (self-validation); the records say so.
    """

    @classmethod
    def setUpClass(cls):
        m = manifest('patched')
        read = next(t for t in m['tests'] if t['test_id'] == 'READ-other-tenant')
        m['tests'] = [
            dict(read, test_id='READ-normal'),
            dict(read, test_id='READ-observer-down', fault='observer-unavailable'),
            dict(read, test_id='READ-timeout', limits={'timeout_seconds': 0.000001}),
            dict(read, test_id='READ-observer-timeout', fault='observer-timeout'),
            dict(read, test_id='READ-api-unreachable', fault='api-unreachable'),
            # The logout that injects this fault uses the test's time limit, so the injection itself times out.
            dict(read, test_id='READ-injection-timeout', fault='session-revoked', limits={'timeout_seconds': 0.000001}),
            dict(read, test_id='READ-session-revoked', fault='session-revoked'),  # last: the actor stays logged out
        ]
        cls.report = scan.run(m).report
        cls.by_id = {e['test_id']: e for e in cls.report['execution_records']}

    def test_report_is_valid_and_partial(self):
        self.assertEqual(report.validate(self.report), [])
        self.assertEqual(self.report['status'], 'partial')

    def test_normal_case_still_passes(self):
        self.assertEqual(self.by_id['READ-normal']['result'], 'passed')

    def test_revoked_session_is_blocked_on_the_identity_check(self):
        e = self.by_id['READ-session-revoked']
        self.assertEqual((e['result'], e['checks']['identity'], e['fault']), ('blocked', False, 'session-revoked'))

    def test_unavailable_observer_blocks_the_case(self):
        e = self.by_id['READ-observer-down']
        self.assertEqual((e['result'], e['fault']), ('blocked', 'observer-unavailable'))
        self.assertIn('observation failed', e['error'])

    def test_observer_query_timeout_blocks_the_case(self):
        e = self.by_id['READ-observer-timeout']
        self.assertEqual((e['result'], e['fault']), ('blocked', 'observer-timeout'))
        # Blocked by the observation itself, not rejected as an unknown fault before the case runs.
        self.assertIn('observation failed', e['error'])
        self.assertIn('timed out', e['error'])

    def test_refused_connection_is_an_execution_error(self):
        e = self.by_id['READ-api-unreachable']
        self.assertEqual((e['result'], e['fault']), ('error', 'api-unreachable'))
        self.assertIn('request failed', e['error'])

    def test_cases_after_a_refused_connection_still_run(self):
        # The fault is undone after its case: the session-revoked case, which runs later, reaches the API.
        e = self.by_id['READ-session-revoked']
        self.assertEqual(e['checks']['resource_and_control'], True)

    def test_failed_injection_is_an_execution_error_of_its_case_only(self):
        e = self.by_id['READ-injection-timeout']
        self.assertEqual((e['result'], e['fault']), ('error', 'session-revoked'))
        self.assertIn('/auth/v1/logout', e['error'])  # the injection step failed, not the case's own requests
        self.assertIn('READ-session-revoked', self.by_id)  # later cases still ran

    def test_timeout_is_an_execution_error(self):
        e = self.by_id['READ-timeout']
        self.assertEqual(e['result'], 'error')
        self.assertIn('timeout', e['error'])

    def test_stages_record_the_run(self):
        stages = {s['stage']: s['status'] for s in self.report['stages']}
        self.assertEqual((stages['preflight'], stages['dynamic_execution'], stages['judgement_report']),
                         ('completed', 'completed', 'completed'))


@needs_env
class FaultsMakeRunsPartialEnv(unittest.TestCase):
    """TK-RUN-002: each network or observation failure on its own makes the run partial, not completed,
    and the run still reports every case."""

    def run_with(self, faulted):
        m = manifest('patched')
        read = next(t for t in m['tests'] if t['test_id'] == 'READ-other-tenant')
        m['tests'] = [dict(read, test_id='READ-normal'), dict(read, test_id='READ-faulted', **faulted)]
        rep = scan.run(m).report
        self.assertEqual(report.validate(rep), [])
        self.assertEqual(rep['status'], 'partial')
        by_id = {e['test_id']: e for e in rep['execution_records']}
        self.assertEqual(by_id['READ-normal']['result'], 'passed')
        return by_id['READ-faulted']

    def test_refused_connection(self):
        e = self.run_with({'fault': 'api-unreachable'})
        self.assertEqual(e['result'], 'error')
        self.assertIn('request failed', e['error'])

    def test_observer_query_timeout(self):
        e = self.run_with({'fault': 'observer-timeout'})
        self.assertEqual(e['result'], 'blocked')
        self.assertIn('timed out', e['error'])

    def test_failed_injection(self):
        e = self.run_with({'fault': 'session-revoked', 'limits': {'timeout_seconds': 0.000001}})
        self.assertEqual(e['result'], 'error')
        self.assertIn('/auth/v1/logout', e['error'])


@needs_env
class ApiKeyMissingEnv(unittest.TestCase):
    """TK-DYN-004, TK-IDN-003: a case needing an API key format the environment lacks is blocked before it
    sends anything, and says which format is missing. The fault removes the format for that case only."""

    @classmethod
    def setUpClass(cls):
        m = manifest('patched')
        by_id = {t['test_id']: t for t in m['tests']}
        anon = by_id['READ-anonymous-publishable']
        other = by_id['READ-other-tenant']
        m['tests'] = [
            dict(anon, test_id='ANON-normal'),
            # The actor's own format is missing: publishable for the anonymous actor, anon-jwt for the other.
            dict(anon, test_id='ANON-publishable-missing', fault='api-key-missing'),
            dict(other, test_id='OTHER-anon-jwt-missing', fault='api-key-missing'),
            # Only the owner's format is missing: the actor uses publishable, the owner's control anon-jwt.
            dict(anon, test_id='ANON-owner-key-missing', fault='api-key-missing', fault_api_key='anon-jwt'),
            # The owner is the actor: every request uses publishable, so a missing anon-jwt blocks nothing.
            dict(anon, test_id='OWNER-AS-ACTOR', actor_ref='owner', fault='api-key-missing',
                 fault_api_key='anon-jwt'),
            dict(other, test_id='OTHER-normal'),
        ]
        cls.report = scan.run(m).report
        cls.by_id = {e['test_id']: e for e in cls.report['execution_records']}

    def assert_blocked_before_any_request(self, test_id, missing_format):
        e = self.by_id[test_id]
        self.assertEqual((e['result'], e['fault'], e['evidence']), ('blocked', 'api-key-missing', []))
        self.assertIn(repr(missing_format), e['error'])

    def test_report_is_valid_and_partial(self):
        self.assertEqual(report.validate(self.report), [])
        self.assertEqual(self.report['status'], 'partial')

    def test_missing_actor_key_format_blocks_the_case_before_any_request(self):
        self.assert_blocked_before_any_request('ANON-publishable-missing', 'publishable')
        self.assert_blocked_before_any_request('OTHER-anon-jwt-missing', 'anon-jwt')

    def test_missing_owner_key_format_blocks_the_case_before_any_request(self):
        self.assert_blocked_before_any_request('ANON-owner-key-missing', 'anon-jwt')

    def test_a_format_no_request_of_the_case_uses_does_not_block_it(self):
        e = self.by_id['OWNER-AS-ACTOR']
        self.assertNotIn('API key', e['error'] or '')
        self.assertTrue(e['evidence'])

    def test_cases_with_their_keys_are_judged_as_before(self):
        self.assertEqual((self.by_id['ANON-normal']['result'], self.by_id['OTHER-normal']['result']),
                         ('passed', 'passed'))


@needs_env
class NoRecoveryMixedPlanEnv(unittest.TestCase):
    """復原方式 missing: reads still run, writes are not run; the run is partial."""

    def test_reads_run_and_writes_are_blocked(self):
        import tempfile
        from toolkit import e1
        from toolkit.tests.test_e1 import failing_copy
        with tempfile.TemporaryDirectory() as d:
            src = failing_copy(d, version='patched',
                               recipe_change=lambda r: r['snapshot_reset'].update(reset_scope='none'))
            m = manifest('patched')
            m['target'] = {'project': str(src), 'source_digest': e1.source_digest(src)}
            m['tests'] = [t for t in m['tests'] if t['test_id'] in ('READ-same-tenant', 'UPDATE-same-tenant')]
            rep = scan.run(m).report
        self.assertEqual(report.validate(rep), [])
        self.assertEqual(results(rep), {'READ-same-tenant': 'passed', 'UPDATE-same-tenant': 'blocked'})
        self.assertEqual(rep['status'], 'partial')
