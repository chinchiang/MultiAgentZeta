"""The dynamic half of scan.run(), on a stack that answers from a script (no Docker).

Each test hands scan.run() a `prepare` returning a scripted stack (tests/scripted.py), so the request handling,
the observer's reading of psql output, the fault injection and the judgement all run for real. Expected results
come from the spec (TK-DYN-002, TK-IDN-009, TK-DYN-004), not from the code. What a real policy answers is checked
by the environment tests against a real Supabase stack.
"""
import subprocess
import unittest

from toolkit import report, scan
from toolkit.tests import scripted
from toolkit.tests.test_scan import manifest


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


if __name__ == '__main__':
    unittest.main()
