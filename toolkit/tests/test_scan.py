"""A scan run, tested through its interface: scan.run(manifest) -> Run(report, markdown).

Environment tests: they start a real E1 stack and are skipped unless MAZ_ENV_TESTS=1.
Expected results follow the sample design (samples/object-authz):
  vulnerable  a same-tenant non-owner can read, change and delete the owner's private document
  patched     only the owner can; legit adds read-only sharing of documents marked shared
Creating a document as someone else is denied in every version (TK-DYN-007).
"""
import copy
import socket
import threading
import unittest
from pathlib import Path

from toolkit import e1, report, scan
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


# 〈定義：必要輸入〉 受測範圍: endpoints, allowed operations and data scope.
SCOPE = {'endpoints': ['/rest/v1/documents', '/rest/v1/announcements', '/auth/v1/user'],
         'allowed_operations': ['GET', 'POST', 'PATCH', 'DELETE'],
         'data_scope': 'synthetic sample data of samples/object-authz only'}
# 〈定義：必要輸入〉 執行限制: cost, time, request volume, concurrency, model providers, network allow-list.
LIMITS = {'max_cost_usd': 0, 'max_duration_seconds': 3600, 'max_requests': 500, 'max_concurrency': 1,
          'model_providers': [], 'network_allowlist': ['127.0.0.1']}


def manifest(version):
    from toolkit import e1
    project = SAMPLES / version
    return {
        'schema_version': '1',
        'id': f'manifest-object-authz-{version}',
        'commit': 'test-commit-0001',
        'target': {'project': str(project), 'source_digest': e1.source_digest(project)},
        'requirements': [copy.deepcopy(REQUIREMENT), copy.deepcopy(PUBLIC_REQUIREMENT)],
        'scope': copy.deepcopy(SCOPE),
        'limits': copy.deepcopy(LIMITS),
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


class RequiredInputs(unittest.TestCase):
    """TK-SCP-002: a missing required input is handled as 〈定義：必要輸入〉 says; nothing is started."""

    def assert_blocked_before_start(self, m, reason_part):
        rep = scan.run(m).report
        self.assertEqual(report.validate(rep), [])
        self.assertEqual(rep['status'], 'blocked')
        self.assertIn(reason_part, rep['status_reason'])
        self.assertNotIn('environment', rep)
        self.assertEqual(set(results(rep).values()), {'blocked'})

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
                t['requirement_id'] = 'REQ-NOT-IN-THE-MANIFEST'
            for result, error in self.errors(m).values():
                self.assertEqual(result, 'blocked')
                self.assertIn('REQ-NOT-IN-THE-MANIFEST', error)

    def test_test_citing_an_unconfirmed_requirement_is_blocked(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            m = preflight_manifest(d)
            for r in m['requirements']:
                del r['confirmation']
            for result, error in self.errors(m).values():
                self.assertEqual(result, 'blocked')
                self.assertIn('not confirmed', error)


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


class NoRecovery(unittest.TestCase):
    """〈定義：必要輸入〉 復原方式: a test that cannot be restored safely is not run."""

    def test_write_cases_are_not_run_without_a_reset(self):
        import tempfile
        from toolkit import e1
        from toolkit.tests.test_e1 import failing_copy

        def no_reset(r):
            r['snapshot_reset']['reset_scope'] = 'none'
            r['source_build']['tools'] = ['no-such-tool']  # fail fast if the run ever gets that far
        with tempfile.TemporaryDirectory() as d:
            src = failing_copy(d, recipe_change=no_reset)
            m = manifest('vulnerable')
            m['target'] = {'project': str(src), 'source_digest': e1.source_digest(src)}
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
