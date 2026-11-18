"""The dynamic half of scan.run(), on a stack that answers from a script (no Docker).

Each test hands scan.run() a `prepare` returning a scripted stack (tests/scripted.py), so the request handling,
the observer's reading of psql output, the fault injection and the judgement all run for real. Expected results
come from the spec (TK-DYN-002, TK-IDN-009, TK-DYN-004), not from the code. What a real policy answers is checked
by the environment tests against a real Supabase stack.
"""
import shutil
import subprocess
import unittest
from pathlib import Path

from toolkit import report, scan
from toolkit.tests import scripted
from toolkit.tests.test_e1 import SAMPLES, failing_copy
from toolkit.tests.test_scan import AUTHORIZATION, authorized, manifest


def one_case(test_id, **changes):
    """The ScanManifest of the sample with one of its planned tests, changed as given."""
    m = manifest('vulnerable')
    test = next(t for t in m['tests'] if t['test_id'] == test_id)
    m['tests'] = [dict(test, **changes)]
    return m


def cases(*specs):
    """The ScanManifest of the sample with these tests in this order: (test_id of the sample's test, its new
    test_id, changes to it)."""
    m = manifest('vulnerable')
    by_id = {t['test_id']: t for t in m['tests']}
    m['tests'] = [dict(by_id[base], test_id=new, **changes) for base, new, changes in specs]
    return m


def run(m, world, **options):
    prepare, lifecycle = scripted.prepare_with(world, **options)
    rep = scan.run(m, prepare=prepare).report
    assert report.validate(rep) == [], report.validate(rep)
    return rep, {e['test_id']: e for e in rep['execution_records']}, lifecycle


class JudgementOnTheResponseAndTheState(unittest.TestCase):
    """TK-DYN-002: a status code is no verdict; the state the observer reads is."""

    def test_a_200_with_an_empty_collection_is_a_pass(self):
        # The contract accepts an empty collection as the denial of a read.
        _, cases, _ = run(one_case('READ-other-tenant'), scripted.World(attempt=(200, [])))
        self.assertEqual(cases['READ-other-tenant']['result'], 'passed')

    def test_a_200_that_returns_the_row_is_a_failure(self):
        row = [{'title': 'MARK-A-ALICE-PRIVATE', 'body': 'b'}]
        _, cases, _ = run(one_case('READ-other-tenant'), scripted.World(attempt=(200, row)))
        self.assertEqual(cases['READ-other-tenant']['result'], 'failed')

    def test_a_403_whose_write_changed_the_state_is_a_failure(self):
        world = scripted.World(attempt=(403, None), mutates=True)
        _, cases, _ = run(one_case('UPDATE-other-tenant'), world)
        self.assertEqual(cases['UPDATE-other-tenant']['result'], 'failed')

    def test_a_403_that_changed_nothing_is_a_pass(self):
        _, cases, _ = run(one_case('UPDATE-other-tenant'), scripted.World(attempt=(403, None)))
        self.assertEqual(cases['UPDATE-other-tenant']['result'], 'passed')


class WhenTheObserverCannotRead(unittest.TestCase):
    """TK-IDN-009: a read that failed or cannot be trusted is no read; the case is blocked, never passed on the
    actor's refusal alone."""

    def blocked_by(self, **world):
        _, cases, _ = run(one_case('READ-other-tenant'), scripted.World(attempt=(403, None), **world))
        e = cases['READ-other-tenant']
        self.assertEqual(e['result'], 'blocked')
        return e['error']

    def test_a_query_that_times_out(self):
        self.assertIn('timed out', self.blocked_by(observer_error=subprocess.TimeoutExpired('psql', 60)))

    def test_a_container_tool_that_cannot_be_started(self):
        error = FileNotFoundError(2, 'No such file')
        self.assertIn('container tool unavailable', self.blocked_by(observer_error=error))

    def test_output_that_is_not_in_the_templates_shape(self):
        self.assertIn('not in the expected shape', self.blocked_by(observer_text='not a count\tdigest'))

    def test_output_that_is_not_text(self):
        error = UnicodeDecodeError('utf-8', b'\xff', 0, 1, 'invalid start byte')
        self.assertIn('not text', self.blocked_by(observer_error=error))


class WhenARequestFails(unittest.TestCase):
    """〈定義：測試結果〉 執行錯誤 and 受阻: a request with no usable reply is an error of its case, and a case whose
    API key format the stack lacks sends nothing."""

    def test_a_request_that_times_out_is_an_execution_error(self):
        world = scripted.World(http_error=scripted.environment.RequestTimeout('GET /rest/v1/documents exceeded 15 s'))
        _, cases, _ = run(one_case('READ-other-tenant'), world)
        self.assertEqual(cases['READ-other-tenant']['result'], 'error')
        self.assertIn('timeout', cases['READ-other-tenant']['error'])

    def test_a_refused_connection_is_an_execution_error(self):
        world = scripted.World(http_error=scripted.environment.RequestFailed('GET /rest/v1/documents: refused'))
        _, cases, _ = run(one_case('READ-other-tenant'), world)
        self.assertEqual(cases['READ-other-tenant']['result'], 'error')
        self.assertIn('request failed', cases['READ-other-tenant']['error'])

    def test_a_missing_api_key_format_blocks_the_case_before_anything_is_sent(self):
        world = scripted.World()
        _, cases, _ = run(one_case('READ-anonymous-publishable'), world, api_keys={'anon-jwt': 'anon-key'})
        e = cases['READ-anonymous-publishable']
        self.assertEqual(e['result'], 'blocked')
        self.assertIn("'publishable'", e['error'])
        self.assertEqual(world.http_calls, [])


class AFaultIsUndoneForTheNextCase(unittest.TestCase):
    """The fault of one case touches that case only: the next one sees the stack as it was."""

    def faulted_then_normal(self, fault):
        m = cases(('READ-other-tenant', 'FAULTED', {'fault': fault}), ('READ-other-tenant', 'NORMAL', {}))
        _, by_id, _ = run(m, scripted.World(attempt=(403, None)))
        return by_id

    def test_each_fault_has_its_effect_and_then_goes_away(self):
        expected = {'observer-unavailable': ('blocked', 'observation failed'),
                    'observer-timeout': ('blocked', 'timed out'),
                    'api-unreachable': ('error', 'request failed'),
                    'api-key-missing': ('blocked', 'API key unavailable')}
        for fault, (result, error) in expected.items():
            with self.subTest(fault):
                by_id = self.faulted_then_normal(fault)
                self.assertEqual(by_id['FAULTED']['result'], result)
                self.assertIn(error, by_id['FAULTED']['error'])
                self.assertEqual(by_id['NORMAL']['result'], 'passed')

    def test_a_revoked_session_blocks_the_identity_check_and_stays_revoked(self):
        by_id = self.faulted_then_normal('session-revoked')
        self.assertEqual((by_id['FAULTED']['result'], by_id['FAULTED']['checks']['identity']), ('blocked', False))
        self.assertEqual(by_id['NORMAL']['result'], 'blocked')  # the actor is logged out for the rest of the run


class ChannelsAndIdentities(unittest.TestCase):
    """TK-IDN-008, TK-IDN-012: each piece of evidence names its channel and identity; the observer reads as
    its own role and nothing here reaches the provisioning identity."""

    def test_evidence_names_the_channel_and_the_identity_that_got_it(self):
        _, cases, _ = run(one_case('READ-other-tenant'), scripted.World(attempt=(403, None)))
        evidence = cases['READ-other-tenant']['evidence']
        by_channel = {c: [e for e in evidence if e['channel'] == c] for c in ('actor', 'observer')}
        self.assertEqual({e['identity_ref'] for e in by_channel['observer']}, {scripted.OBSERVER_ROLE})
        self.assertEqual({e['identity_ref'] for e in by_channel['actor']}, {'owner', 'other_tenant_user'})
        self.assertTrue(all('observation' not in e for e in by_channel['actor']))
        self.assertTrue(all('response' not in e for e in by_channel['observer']))

    def test_every_query_runs_as_the_observer_and_never_as_the_provisioning_identity(self):
        world = scripted.World(attempt=(403, None))
        run(one_case('READ-other-tenant'), world)
        self.assertTrue(world.exec_calls)
        for _, command in world.exec_calls:
            self.assertEqual(command[command.index('-U') + 1], scripted.OBSERVER_ROLE)


class TheStacksLifecycle(unittest.TestCase):
    def test_a_write_case_resets_the_stack_and_the_run_destroys_it(self):
        _, _, lifecycle = run(one_case('UPDATE-other-tenant'), scripted.World(attempt=(403, None)))
        self.assertEqual(lifecycle.calls, ['reset', 'destroy'])

    def test_a_reset_that_fails_stops_the_cases_after_it(self):
        m = cases(('UPDATE-other-tenant', 'FIRST', {}), ('READ-other-tenant', 'SECOND', {}))
        prepare, lifecycle = scripted.prepare_with(scripted.World(attempt=(403, None)), reset_fails=True)
        rep = scan.run(m, prepare=prepare).report
        by_id = {e['test_id']: e for e in rep['execution_records']}
        self.assertEqual(by_id['SECOND']['result'], 'blocked')
        self.assertIn('environment reset failed after FIRST', by_id['SECOND']['error'])
        self.assertEqual(lifecycle.calls, ['reset', 'destroy'])


def passing_read(version='vulnerable'):
    """A one-test plan on a sample, answered the way a correct policy answers: the other tenant's read is denied."""
    m = manifest(version)
    m['tests'] = [next(t for t in m['tests'] if t['test_id'] == 'READ-other-tenant')]
    return m, scripted.World(attempt=(403, []))


class TheCoverageComesFromTheInventory(unittest.TestCase):
    """TK-ARC-004, TK-EVD-008, TK-EVD-009: the report's coverage is what extraction found in the sample and what
    the tests judged, not a fixed plan. Expected numbers are counted from the sample's migrations by hand."""

    def test_the_counts_follow_the_sample_it_was_run_against(self):
        for version, items, rls, judged in (('vulnerable', 14, 5, 3), ('legit', 15, 5, 4)):
            with self.subTest(sample=version):
                m, world = passing_read(version)
                rep, _, _ = run(m, world)
                tp = rep['coverage']['tables_and_policies']
                # the read of documents judges the table and its read policies (3 in vulnerable, 4 with the share rule)
                self.assertEqual((tp['inventoried'], tp['rls_enabled'], tp['without_policy'], tp['unresolved'], tp['judged']),
                                 (items, rls, 0, 0, judged))

    def test_a_complete_inventory_claims_the_whole_scope_and_names_its_rule(self):
        m, world = passing_read()
        cov = run(m, world)[0]['coverage']
        self.assertEqual(cov['inventory'], {'rule': 'sql-rls-v1', 'supported_version': 'postgresql-17',
                                            'loaded': ['supabase-rls'], 'completeness': 'complete', 'unresolved': []})
        self.assertEqual(cov['claim'], 'whole_scope')
        self.assertIn('sql-rls-v1', cov['inventory_source'])

    def test_the_rates_of_one_passed_case(self):
        m, world = passing_read()
        cov = run(m, world)[0]['coverage']
        self.assertEqual((cov['denominator'], cov['executed'], cov['valid_judgements'], cov['unsupported']), (6, 1, 1, 5))
        self.assertAlmostEqual(cov['effective_judgement_rate'], 1 / 6)
        self.assertAlmostEqual(cov['tool_support_rate'], 1 / 6)
        self.assertEqual(cov['required_test_completion_rate'], 1)
        self.assertEqual((cov['excluded'], cov['rejected_exclusions']), ([], []))

    def test_the_denominator_is_the_execution_records_plus_the_unsupported_scopes(self):
        m, world = passing_read()
        rep = run(m, world)[0]
        self.assertEqual(rep['coverage']['denominator'], len(rep['execution_records']) + len(rep['coverage']['unsupported_items']))

    def test_a_project_without_migration_files_is_not_called_complete(self):
        import tempfile
        from toolkit import e1
        with tempfile.TemporaryDirectory() as d:
            shutil.copytree(SAMPLES / 'vulnerable', d, dirs_exist_ok=True, ignore=shutil.ignore_patterns('migrations'))
            m, world = passing_read()
            m['target'] = {'project': d, 'source_digest': e1.source_digest(Path(d))}
            cov = run(m, world)[0]['coverage']
        self.assertEqual(cov['inventory']['completeness'], 'unknown')
        self.assertEqual(cov['inventory']['unresolved'],
                         [{'file': '(project)', 'line': 0, 'reason': 'the project has no supabase/migrations/*.sql files'}])
        self.assertEqual((cov['claim'], cov['tables_and_policies']['inventoried']), ('known_scope_only', 0))

    def test_a_run_blocked_before_the_source_is_verified_does_not_read_the_project(self):
        m, _ = passing_read()
        m['target']['source_digest'] = 'sha256:' + '0' * 64
        cov = scan.run(m).report['coverage']
        self.assertEqual(cov['inventory']['completeness'], 'unknown')
        self.assertEqual([u['line'] for u in cov['inventory']['unresolved']], [0])
        self.assertIn('not read', cov['inventory']['unresolved'][0]['reason'])
        self.assertEqual((cov['claim'], cov['tables_and_policies']['inventoried'], cov['blocked']),
                         ('known_scope_only', 0, 1))


    def test_a_run_blocked_in_preflight_for_any_reason_does_not_read_the_project(self):
        """The source digest matches here; the run is blocked later in preflight (a test names an identity the
        authorization does not know), and the project is still not read: preflight blocked means not read."""
        m, _ = passing_read()
        m['tests'][0]['actor_ref'] = 'nobody'
        rep = scan.run(m).report
        self.assertEqual(rep['stages'][0]['status'], 'blocked')
        cov = rep['coverage']
        self.assertEqual((cov['inventory']['completeness'], cov['claim'], cov['tables_and_policies']['inventoried']),
                         ('unknown', 'known_scope_only', 0))
        self.assertEqual(cov['inventory']['unresolved'][0]['file'], '(project)')


class DuplicateTestIdsAreRefusedInPreflight(unittest.TestCase):
    """TK-ENV-001, TK-RUN-001: each test in ScanManifest.tests has its own test_id; a second test with the
    same test_id blocks preflight instead of overwriting an earlier test's precheck."""

    def test_duplicate_test_id_blocks_preflight_and_never_lets_an_unauthorized_or_unrestorable_test_run(self):
        import tempfile
        from toolkit import e1
        with self.subTest('unauthorized delete before valid read'):
            m = cases(('DELETE-other-tenant', 'SAME-ID', {}), ('READ-other-tenant', 'SAME-ID', {}))
            m['authorization'] = authorized(SAMPLES / 'vulnerable', {**AUTHORIZATION, 'extra_approvals': []})
            world = scripted.World(attempt=(403, []))
            prepare, lifecycle = scripted.prepare_with(world)
            rep = scan.run(m, prepare=prepare).report
            self.assertEqual(report.validate(rep), [])
            self.assertEqual((rep['status'], rep['stages'][0]['status']), ('blocked', 'blocked'))
            self.assertIn('SAME-ID', rep['status_reason'])
            self.assertEqual((world.http_calls, lifecycle.calls), ([], []))
            self.assertEqual([e['result'] for e in rep['execution_records']], ['blocked', 'blocked'])
        with self.subTest('unrestorable write before valid read'), tempfile.TemporaryDirectory() as d:
            src = failing_copy(d, recipe_change=lambda r: r['snapshot_reset'].update(reset_scope='none'))
            m = cases(('UPDATE-other-tenant', 'SAME-ID', {}), ('READ-other-tenant', 'SAME-ID', {}))
            m['target'] = {'project': str(src), 'source_digest': e1.source_digest(src)}
            world = scripted.World(attempt=(403, []))
            prepare, lifecycle = scripted.prepare_with(world)
            rep = scan.run(m, prepare=prepare).report
            self.assertEqual(report.validate(rep), [])
            self.assertEqual((rep['status'], rep['stages'][0]['status']), ('blocked', 'blocked'))
            self.assertIn('SAME-ID', rep['status_reason'])
            self.assertEqual((world.http_calls, lifecycle.calls), ([], []))

    def test_distinct_test_ids_keep_blocking_the_unauthorized_delete_while_the_read_runs(self):
        m = cases(('DELETE-other-tenant', 'DELETE-1', {}), ('READ-other-tenant', 'READ-1', {}))
        m['authorization'] = authorized(SAMPLES / 'vulnerable', {**AUTHORIZATION, 'extra_approvals': []})
        _, by_id, _ = run(m, scripted.World(attempt=(403, [])))
        self.assertEqual((by_id['DELETE-1']['result'], by_id['READ-1']['result']), ('blocked', 'passed'))

    def test_denial_case_without_owner_ref_is_blocked_without_crashing_a_mixed_run(self):
        m = cases(('READ-other-tenant', 'NO-OWNER', {}),
                  ('PUBLIC-READ-other-tenant', 'PUBLIC-READ-other-tenant', {}))
        del m['tests'][0]['owner_ref']
        world = scripted.World(attempt=(200, [{'title': 'MARK-PUBLIC-ANNOUNCEMENT'}]))
        _, by_id, _ = run(m, world)
        self.assertEqual(by_id['NO-OWNER']['result'], 'blocked')
        self.assertIn('owner_ref', by_id['NO-OWNER']['error'])
        self.assertEqual(by_id['PUBLIC-READ-other-tenant']['result'], 'passed')


if __name__ == '__main__':
    unittest.main()
