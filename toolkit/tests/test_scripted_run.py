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

from toolkit import environment, report, scan
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
    """Run the plan against the world. A plan with a fault to inject is run as the self-validation run it is
    (〈定義：故障注入〉); any other plan as a scan."""
    prepare, lifecycle = scripted.prepare_with(world, **options)
    rep = scan.run(m, prepare=prepare, self_validation=any('fault' in t for t in m['tests'])).report
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


class ADenialAnsweredOutsideTheContract(unittest.TestCase):
    """〈定義：測試結果〉 拒絕案例的契約外回應 and 〈定義：問題狀態〉 (TK-DYN-001, TK-DYN-002): without a disclosure or a
    change, an answer of the application outside the contract fails check 4 and its finding is 證據待補; an
    answer nothing can be judged from is an execution error; a disclosure or a change is 已確認."""

    LEAK = (200, [{'title': 'MARK-A-ALICE-PRIVATE', 'body': 'b'}])

    def outcome(self, attempt, test_id='READ-other-tenant', **world):
        rep, by_id, _ = run(one_case(test_id), scripted.World(attempt=attempt, **world))
        return rep, by_id[test_id]

    def test_an_answer_of_the_application_outside_the_contract_is_a_failure_with_evidence_pending(self):
        for attempt in ((500, {'message': 'boom'}), (500, None), (302, None), (400, b'<html>bad</html>'),
                        (204, None)):
            with self.subTest(attempt=attempt):
                rep, record = self.outcome(attempt)
                self.assertEqual(record['result'], 'failed')
                self.assertEqual((record['checks']['no_disclosure_or_change'], record['checks']['response_and_side_effects']),
                                 (True, False))
                self.assertEqual([f['status'] for f in rep['findings']], ['evidence_pending'])
                self.assertEqual(rep['findings'][0]['execution_record_ids'], [record['id']])

    def test_a_backend_that_is_not_available_is_an_execution_error_without_a_finding(self):
        for status in (502, 503, 504):
            with self.subTest(status=status):
                rep, record = self.outcome((status, None))
                self.assertEqual((record['result'], rep['findings']), ('error', []))

    def test_a_200_that_cannot_be_read_as_the_contracts_collection_is_an_execution_error(self):
        for body in (None, {'message': 'not a list'}, b'<html>ok</html>'):
            with self.subTest(body=body):
                rep, record = self.outcome((200, body))
                self.assertEqual((record['result'], rep['findings']), ('error', []))

    def test_a_disclosure_is_confirmed_whatever_the_status(self):
        rep, record = self.outcome(self.LEAK)
        self.assertEqual((record['result'], [f['status'] for f in rep['findings']]), ('failed', ['confirmed']))

    def test_a_change_behind_an_answer_outside_the_contract_is_confirmed(self):
        rep, record = self.outcome((500, None), test_id='UPDATE-other-tenant', mutates=True)
        self.assertEqual((record['result'], [f['status'] for f in rep['findings']]), ('failed', ['confirmed']))

    def test_one_finding_with_both_kinds_of_record_is_confirmed(self):
        # The same attempt with the two API key formats is one finding: the first answer is only outside the
        # contract, the second discloses the row.
        m = cases(('READ-anonymous-anon-jwt', 'JWT', {}), ('READ-anonymous-publishable', 'PUBLISHABLE', {}))
        world = scripted.World(attempt=(500, None))
        prepare, _ = scripted.prepare_with(world)

        def prepared(project_dir):
            ready = prepare(project_dir)
            request, made = ready.env.request, []

            def then_leak(*args, **kwargs):
                made.append(1)
                if len(made) == 4:  # the second case begins
                    world.attempt = self.LEAK
                return request(*args, **kwargs)
            ready.env.request = then_leak
            return ready
        rep = scan.run(m, prepare=prepared).report
        self.assertEqual(report.validate(rep), [])
        self.assertEqual([e['result'] for e in rep['execution_records']], ['failed', 'failed'])
        self.assertEqual([(f['status'], len(f['execution_record_ids'])) for f in rep['findings']], [('confirmed', 2)])


class AnAllowedCaseWithoutAJudgeableAnswer(unittest.TestCase):
    """〈定義：測試結果〉 允許案例: the access is granted (passed), refused by the application (failed), or the
    reply cannot be judged (execution error); only a real refusal is a failed test."""
    TEST = 'PUBLIC-READ-same-tenant'
    GRANTED = [{'title': 'MARK-PUBLIC-ANNOUNCEMENT'}]

    def result(self, attempt):
        _, by_id, _ = run(one_case(self.TEST), scripted.World(attempt=attempt))
        record = by_id[self.TEST]
        self.assertEqual(record['case_kind'], 'allowed')
        return record['result'], record['checks']

    def test_the_row_the_requirement_allows_is_a_pass(self):
        self.assertEqual(self.result((200, self.GRANTED)), ('passed', {'access_granted': True}))

    def test_a_refusal_by_the_application_is_a_failure(self):
        for attempt in ((403, {'message': 'permission denied'}), (401, None), (200, []), (404, None),
                        (500, {'message': 'internal error'})):
            with self.subTest(attempt=attempt):
                self.assertEqual(self.result(attempt), ('failed', {'access_granted': False}))

    def test_a_backend_the_gateway_reports_unavailable_is_an_execution_error(self):
        for status in (502, 503, 504):
            with self.subTest(status=status):
                self.assertEqual(self.result((status, None)), ('error', {'access_granted': False}))

    def test_a_200_whose_body_is_no_collection_is_an_execution_error(self):
        for body in ({'message': 'ok'}, b'<html>ok</html>', None):
            with self.subTest(body=body):
                self.assertEqual(self.result((200, body)), ('error', {'access_granted': False}))


class ARedirectIsJudgedAsTheAnswer(unittest.TestCase):
    """〈定義：測試結果〉 重新導向: a 3xx is the reply of the request; no case passes on it."""

    def test_a_denial_case_answered_with_a_redirect_does_not_pass(self):
        for status in (301, 302, 303, 307, 308):
            with self.subTest(status=status):
                _, by_id, _ = run(one_case('READ-other-tenant'), scripted.World(attempt=(status, None)))
                record = by_id['READ-other-tenant']
                self.assertNotEqual(record['result'], 'passed')
                self.assertFalse(record['checks']['response_and_side_effects'])

    def test_an_allowed_case_answered_with_a_redirect_is_a_failure(self):
        _, by_id, _ = run(one_case('PUBLIC-READ-same-tenant'), scripted.World(attempt=(302, None)))
        record = by_id['PUBLIC-READ-same-tenant']
        self.assertEqual((record['result'], record['checks']), ('failed', {'access_granted': False}))


class OneFindingPerFingerprint(unittest.TestCase):
    """〈定義：覆核紀錄〉 項目: a run has one FindingRecord per fingerprint, fingerprint version and requirement
    version, with every failed execution record it rests on."""
    LEAK = (200, [{'title': 'MARK-A-ALICE-PRIVATE', 'body': 'b'}])

    def test_the_same_attempt_with_both_key_formats_is_one_finding_with_both_records(self):
        m = cases(('READ-anonymous-anon-jwt', 'JWT', {}), ('READ-anonymous-publishable', 'PUBLISHABLE', {}))
        rep, by_id, _ = run(m, scripted.World(attempt=self.LEAK))
        self.assertEqual((by_id['JWT']['result'], by_id['PUBLISHABLE']['result']), ('failed', 'failed'))
        self.assertEqual(len(rep['findings']), 1)
        self.assertEqual(rep['findings'][0]['execution_record_ids'], [by_id['JWT']['id'], by_id['PUBLISHABLE']['id']])

    def test_attempts_by_different_actors_stay_separate_findings(self):
        m = cases(('READ-anonymous-anon-jwt', 'ANON', {}), ('READ-other-tenant', 'OTHER', {}))
        rep, by_id, _ = run(m, scripted.World(attempt=self.LEAK))
        self.assertEqual(sorted(f['execution_record_ids'] for f in rep['findings']),
                         sorted([[by_id['ANON']['id']], [by_id['OTHER']['id']]]))


class TheRunsLimitsHoldBeforeDispatch(unittest.TestCase):
    """TK-BUD-003, 〈定義：執行限制的執行〉: a case the run's limits leave no room for is not dispatched; it is
    recorded as untested, stays in the denominator, and the run is not completed."""
    DENIED = (403, [])

    def plan(self, n, **limits):
        m = cases(*(('READ-other-tenant', f'CASE-{i}', {}) for i in range(1, n + 1)))
        m['limits'].update(limits)
        return m

    def test_a_case_the_request_limit_cannot_cover_is_not_sent(self):
        world = scripted.World(attempt=self.DENIED)
        rep, by_id, _ = run(self.plan(3, max_requests=10), world)  # a denial case makes five
        self.assertEqual([by_id[f'CASE-{i}']['result'] for i in (1, 2, 3)], ['passed', 'passed', 'untested'])
        self.assertIn('request limit', by_id['CASE-3']['error'])
        self.assertEqual(by_id['CASE-3']['evidence'], [])
        self.assertEqual(len(world.http_calls), 6)  # three actor requests for each of the two cases that ran
        self.assertEqual((rep['limits']['requests'], rep['limits']['max_requests']), (10, 10))

    def test_the_run_is_partial_and_the_case_stays_in_the_denominator(self):
        rep, _, _ = run(self.plan(3, max_requests=10), scripted.World(attempt=self.DENIED))
        self.assertEqual(rep['status'], 'partial')  # TK-RUN-002: not completed
        self.assertIn('execution limit', rep['status_reason'])
        cov = rep['coverage']
        self.assertEqual((cov['executed'], cov['untested'], cov['denominator']), (2, 1, 3 + cov['unsupported']))
        self.assertAlmostEqual(cov['required_test_completion_rate'], 2 / 3)

    def test_a_limit_that_just_covers_the_plan_runs_all_of_it(self):
        rep, by_id, _ = run(self.plan(3, max_requests=15), scripted.World(attempt=self.DENIED))
        self.assertEqual({e['result'] for e in by_id.values()}, {'passed'})
        self.assertEqual((rep['status'], rep['limits']['requests']), ('completed', 15))

    def test_a_case_is_run_whole_or_not_at_all(self):
        # Four requests are left, one short of a denial case: none of them is spent on half a case.
        world = scripted.World(attempt=self.DENIED)
        rep, by_id, _ = run(self.plan(2, max_requests=9), world)
        self.assertEqual([by_id[f'CASE-{i}']['result'] for i in (1, 2)], ['passed', 'untested'])
        self.assertEqual(rep['limits']['requests'], 5)

    def test_a_smaller_case_later_in_the_plan_still_runs(self):
        m = cases(('READ-other-tenant', 'DENIAL-1', {}), ('READ-other-tenant', 'DENIAL-2', {}),
                  ('PUBLIC-READ-same-tenant', 'ALLOWED', {}))
        m['limits']['max_requests'] = 6
        world = scripted.World(attempt=(200, []))
        _, by_id, _ = run(m, world)
        self.assertEqual((by_id['DENIAL-1']['result'], by_id['DENIAL-2']['result']), ('passed', 'untested'))
        self.assertNotEqual(by_id['ALLOWED']['result'], 'untested')  # one request was left, and it needs one

    def test_a_case_the_time_limit_cannot_cover_is_not_dispatched(self):
        ticks = iter(range(0, 10_000, 30))  # every look at the clock is 30 s later
        prepare, _ = scripted.prepare_with(scripted.World(attempt=self.DENIED))
        rep = scan.run(self.plan(6, max_duration_seconds=200), prepare=prepare, clock=lambda: next(ticks)).report
        self.assertEqual(report.validate(rep), [])
        results = [e['result'] for e in rep['execution_records']]
        # A denial case may take 5 requests x 15 s; at 30, 60, 90 and 120 s that fits in 200 s, at 150 s it does not.
        self.assertEqual(results, ['passed'] * 4 + ['untested'] * 2)
        self.assertIn('time limit', rep['execution_records'][4]['error'])
        self.assertEqual(rep['status'], 'partial')
        self.assertEqual(rep['limits']['max_duration_seconds'], 200)
        self.assertGreater(rep['limits']['elapsed_seconds'], 150)

    def test_the_case_time_follows_the_tests_own_timeout(self):
        ticks = iter(range(0, 10_000, 30))
        m = self.plan(1, max_duration_seconds=200)
        m['tests'][0]['limits'] = {'timeout_seconds': 60}  # 5 x 60 s does not fit
        prepare, _ = scripted.prepare_with(scripted.World(attempt=self.DENIED))
        rep = scan.run(m, prepare=prepare, clock=lambda: next(ticks)).report
        self.assertEqual(rep['execution_records'][0]['result'], 'untested')

    def test_ample_limits_change_nothing_and_the_use_is_reported(self):
        rep, by_id, _ = run(self.plan(2), scripted.World(attempt=self.DENIED))
        self.assertEqual({e['result'] for e in by_id.values()}, {'passed'})
        limits = rep['limits']
        self.assertEqual((limits['requests'], limits['max_requests'], limits['concurrency'], limits['max_concurrency']),
                         (10, 500, 1, 1))
        md = report.render_markdown(rep)
        self.assertIn('## 執行限制', md)
        self.assertIn('已用 10，上限 500', md)

    def test_a_revoked_session_costs_its_logout(self):
        rep, by_id, _ = run(one_case('READ-other-tenant', fault='session-revoked'), scripted.World(attempt=self.DENIED))
        self.assertLessEqual(rep['limits']['requests'], 6)
        m = one_case('READ-other-tenant', fault='session-revoked')
        m['limits']['max_requests'] = 5  # the case alone would fit; with the logout it does not
        _, by_id, _ = run(m, scripted.World(attempt=self.DENIED))
        self.assertEqual(by_id['READ-other-tenant']['result'], 'untested')

    def test_a_run_blocked_for_a_missing_limit_reports_it_as_not_stated(self):
        m = self.plan(1)
        del m['limits']['max_requests']
        rep, _, _ = run(m, scripted.World(attempt=self.DENIED))
        self.assertEqual(rep['status'], 'blocked')
        self.assertEqual((rep['limits']['max_requests'], rep['limits']['requests']), (None, 0))
        self.assertIn('上限 （未提供）', report.render_markdown(rep))


class TheRequestCountStopsWhatTheEstimateMissed(unittest.TestCase):
    """The stop behind the count before dispatch: Operations makes no request past its limit."""

    def test_the_request_past_the_limit_is_not_made(self):
        world = scripted.World(attempt=(403, []))
        ops = environment.Operations(scripted.handles(), scripted.Transport(world), scripted.Lifecycle())
        ops.request_limit = 2
        ops.request('owner', 'GET', '/rest/v1/documents?title=eq.MARK-A-ALICE-PRIVATE&select=title')
        ops.observe('MARK-A-ALICE-PRIVATE')
        for attempt in (lambda: ops.request('owner', 'GET', '/rest/v1/documents?title=eq.X&select=title'),
                        lambda: ops.observe('MARK-A-ALICE-PRIVATE')):
            with self.assertRaises(environment.LimitReached):
                attempt()
        self.assertEqual((ops.requests, len(world.http_calls)), (2, 1))

    def test_without_a_limit_requests_are_only_counted(self):
        ops = environment.Operations(scripted.handles(), scripted.Transport(scripted.World()), scripted.Lifecycle())
        for _ in range(3):
            ops.observe('MARK-A-ALICE-PRIVATE')
        self.assertEqual(ops.requests, 3)


class WhenTheObserverCannotRead(unittest.TestCase):
    """TK-IDN-009 and 〈定義：測試結果〉 受阻 (its note on a failed observation): a read that failed or cannot be
    trusted is a missing observation capability, not a tool error; the case is blocked, never passed on the
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


class TheStageStatusWhenCasesDoNotFinish(unittest.TestCase):
    """〈定義：工作階段〉 (its note on stage and run status, TK-RUN-001, TK-RUN-002): a dynamic execution stage that
    ran is completed whatever its cases say; a blocked or errored case shows in its result and in the run's
    status, partial."""

    def stage(self, rep):
        return next(s for s in rep['stages'] if s['stage'] == 'dynamic_execution')

    def test_a_blocked_case_leaves_the_stage_completed_and_the_run_partial(self):
        world = scripted.World(attempt=(403, None), observer_error=subprocess.TimeoutExpired('psql', 60))
        rep, by_id, _ = run(one_case('READ-other-tenant'), world)
        self.assertEqual(by_id['READ-other-tenant']['result'], 'blocked')
        self.assertEqual((self.stage(rep)['status'], rep['status']), ('completed', 'partial'))

    def test_an_errored_case_leaves_the_stage_completed_and_the_run_partial(self):
        world = scripted.World(http_error=environment.RequestTimeout('GET /rest/v1/documents: timed out'))
        rep, by_id, _ = run(one_case('READ-other-tenant'), world)
        self.assertEqual(by_id['READ-other-tenant']['result'], 'error')
        self.assertEqual((self.stage(rep)['status'], rep['status']), ('completed', 'partial'))

    def test_a_reset_that_fails_makes_the_stage_failed(self):
        m = cases(('UPDATE-other-tenant', 'FIRST', {}), ('READ-other-tenant', 'SECOND', {}))
        prepare, _ = scripted.prepare_with(scripted.World(attempt=(403, None)), reset_fails=True)
        rep = scan.run(m, prepare=prepare).report
        self.assertEqual((self.stage(rep)['status'], rep['status']), ('failed', 'partial'))


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

    def test_a_revoked_session_blocks_its_case_and_the_actor_has_a_session_again_afterwards(self):
        m = cases(('READ-other-tenant', 'FAULTED', {'fault': 'session-revoked'}), ('READ-other-tenant', 'NORMAL', {}))
        rep, by_id, lifecycle = run(m, scripted.World(attempt=(403, None)))
        faulted = by_id['FAULTED']
        self.assertEqual((faulted['result'], faulted['checks']['identity']), ('blocked', False))
        logout = faulted['evidence'][0]
        self.assertEqual((logout['injection'], logout['request']['path'], logout['response']['status']),
                         ('applied', '/auth/v1/logout?scope=global', 204))
        self.assertEqual(by_id['NORMAL']['result'], 'passed')  # 〈定義：故障注入〉: the fault stays within its case
        self.assertTrue(by_id['NORMAL']['checks']['identity'])
        self.assertIn('relogin other_tenant_user', lifecycle.calls)

    def injection_that_fails(self, **world):
        m = cases(('READ-other-tenant', 'FAULTED', {'fault': 'session-revoked'}), ('READ-other-tenant', 'NORMAL', {}))
        w = scripted.World(attempt=(403, None))
        prepare, lifecycle = scripted.prepare_with(w)

        def prepared(project_dir):
            ready = prepare(project_dir)
            http = ready.env._transport.http

            def failing_logout(method, url, headers, body, timeout):
                if '/auth/v1/logout' in url:
                    if world.get('status'):
                        return world['status'], b''
                    raise environment.RequestTimeout('POST /auth/v1/logout: timed out')
                return http(method, url, headers, body, timeout)
            ready.env._transport = type('T', (), {'http': staticmethod(failing_logout),
                                                  'docker_exec': ready.env._transport.docker_exec})()
            return ready
        rep = scan.run(m, prepare=prepared, self_validation=True).report
        self.assertEqual(report.validate(rep), [])
        return {e['test_id']: e for e in rep['execution_records']}, lifecycle

    def test_a_logout_that_does_not_complete_blocks_its_case_with_the_evidence_of_the_attempt(self):
        by_id, lifecycle = self.injection_that_fails()
        faulted = by_id['FAULTED']
        self.assertEqual(faulted['result'], 'blocked')
        self.assertIn('fault injection failed', faulted['error'])
        self.assertIn('did not complete', faulted['error'])
        self.assertEqual([(ev['injection'], 'response' in ev) for ev in faulted['evidence']], [('failed', False)])
        # The logout may have reached the auth service all the same: the actor gets a new session.
        self.assertIn('relogin other_tenant_user', lifecycle.calls)
        self.assertEqual(by_id['NORMAL']['result'], 'passed')

    def test_a_logout_that_is_refused_blocks_its_case(self):
        by_id, _ = self.injection_that_fails(status=500)
        faulted = by_id['FAULTED']
        self.assertEqual(faulted['result'], 'blocked')
        self.assertIn('HTTP 500', faulted['error'])
        self.assertEqual(faulted['evidence'][0]['response']['status'], 500)
        self.assertEqual(by_id['NORMAL']['result'], 'passed')

    def test_an_observer_fault_without_an_observer_role_blocks_its_case_and_the_run_goes_on(self):
        m = cases(('READ-other-tenant', 'FAULTED', {'fault': 'observer-unavailable'}),
                  ('READ-other-tenant', 'TIMEOUT', {'fault': 'observer-timeout'}))
        prepare, _ = scripted.prepare_with(scripted.World(attempt=(403, None)))

        def prepared(project_dir):
            ready = prepare(project_dir)
            ready.env._env.observer.clear()
            return ready
        rep = scan.run(m, prepare=prepared, self_validation=True).report
        self.assertEqual(report.validate(rep), [])
        for e in rep['execution_records']:
            with self.subTest(test=e['test_id']):
                self.assertEqual(e['result'], 'blocked')
                self.assertIn('no observer role', e['error'])

    def test_a_fault_that_had_no_effect_is_blocked_not_judged(self):
        # The logout is answered 204 but the session goes on working: the case would pass as if nothing was injected.
        m = cases(('READ-other-tenant', 'FAULTED', {'fault': 'session-revoked'}))
        world = scripted.World(attempt=(403, None))
        prepare, _ = scripted.prepare_with(world)

        def prepared(project_dir):
            ready = prepare(project_dir)
            world.revoked = type('Never', (set,), {'add': lambda self, x: None})()
            return ready
        rep = scan.run(m, prepare=prepared, self_validation=True).report
        self.assertEqual(report.validate(rep), [])
        record = rep['execution_records'][0]
        self.assertEqual(record['result'], 'blocked')
        self.assertIn('had no effect', record['error'])
        self.assertEqual(rep['findings'], [])


class FaultsAreForSelfValidationRunsOnly(unittest.TestCase):
    """〈定義：故障注入〉 (TK-VAL-001): a scan injects nothing; a ScanManifest cannot make a run a self-validation run."""

    def test_a_scan_whose_plan_carries_a_fault_is_blocked_in_preflight_and_starts_nothing(self):
        for field, value in (('fault', 'session-revoked'), ('fault_api_key', 'anon-jwt')):
            with self.subTest(field=field):
                world = scripted.World(attempt=(403, None))
                prepare, lifecycle = scripted.prepare_with(world)
                rep = scan.run(one_case('READ-other-tenant', **{field: value}), prepare=prepare).report
                self.assertEqual(report.validate(rep), [])
                self.assertEqual(rep['status'], 'blocked')
                self.assertIn('self-validation runs of the toolkit only', rep['status_reason'])
                self.assertIn('READ-other-tenant', rep['status_reason'])
                self.assertEqual((world.http_calls, lifecycle.calls), ([], []))
                self.assertNotIn('self_validation', rep)

    def test_a_manifest_field_does_not_turn_self_validation_on(self):
        m = one_case('READ-other-tenant', fault='session-revoked')
        m['self_validation'] = True
        prepare, _ = scripted.prepare_with(scripted.World(attempt=(403, None)))
        self.assertEqual(scan.run(m, prepare=prepare).report['status'], 'blocked')

    def test_a_self_validation_run_says_so_in_the_report_and_the_markdown(self):
        rep, _, _ = run(one_case('READ-other-tenant', fault='observer-timeout'), scripted.World(attempt=(403, None)))
        self.assertIs(rep['self_validation'], True)
        self.assertIn('- **執行類型**：工具包自我驗證（含故障注入，不是對應用的掃描結果）', report.render_markdown(rep))

    def test_a_scan_does_not_say_it(self):
        rep, _, _ = run(one_case('READ-other-tenant'), scripted.World(attempt=(403, None)))
        self.assertNotIn('self_validation', rep)
        self.assertNotIn('執行類型', report.render_markdown(rep))


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


def abort_after(prepare, abort, requests, reason='stopped by the operator (test)'):
    """A `prepare` whose stack asks for the abort once this many actor requests of the cases have gone out."""
    def prepared(project_dir):
        ready = prepare(project_dir)
        ops, made = ready.env, []
        request = ops.request

        def counted(*args, **kwargs):
            answer = request(*args, **kwargs)
            made.append(1)
            if len(made) == requests:
                abort.request(reason)
            return answer
        ops.request = counted
        return ready
    return prepared


class AnAbortedRun(unittest.TestCase):
    """〈定義：中止與清理〉 (TK-RUN-004, TK-RUN-005, TK-RUN-006): the control area stops a run without the test's
    cooperation, in the order of the spec, and the report says so."""

    DENIED = (403, None)

    def plan(self, n=4):
        return cases(*[('READ-other-tenant', f'CASE-{i}', {}) for i in range(1, n + 1)])

    def aborted(self, requests, n=4, world=None, **options):
        world = world or scripted.World(attempt=self.DENIED)
        prepare, lifecycle = scripted.prepare_with(world, **options)
        abort = scan.Abort()
        rep = scan.run(self.plan(n), prepare=abort_after(prepare, abort, requests), abort=abort).report
        self.assertEqual(report.validate(rep), [])
        return rep, [e['result'] for e in rep['execution_records']], world, lifecycle

    def test_an_abort_before_the_environment_is_ready_cancels_every_case_and_destroys_it(self):
        prepare, lifecycle = scripted.prepare_with(scripted.World(attempt=self.DENIED))
        abort = scan.Abort()
        abort.request('stopped by the operator (before the start)')
        rep = scan.run(self.plan(3), prepare=prepare, abort=abort).report
        self.assertEqual(report.validate(rep), [])
        self.assertEqual([e['result'] for e in rep['execution_records']], ['cancelled'] * 3)
        self.assertEqual((rep['status'], rep['abort']['in_flight']), ('cancelled', None))
        self.assertEqual(lifecycle.calls, ['destroy'])
        self.assertEqual(rep['cleanup'], {'environment': 'destroyed', 'leftovers': []})

    def test_the_case_in_flight_ends_at_its_next_request_and_the_later_ones_are_cancelled(self):
        # A denial case makes three actor requests; the abort comes after the first request of the second case.
        rep, results, world, _ = self.aborted(requests=4)
        self.assertEqual(results, ['passed', 'error', 'cancelled', 'cancelled'])
        self.assertEqual(rep['status'], 'cancelled')
        in_flight = rep['execution_records'][1]
        self.assertIn('outcome is unknown', in_flight['error'])
        self.assertEqual(rep['abort']['in_flight'], in_flight['test_id'])
        self.assertIn('not dispatched: the run was aborted', rep['execution_records'][2]['error'])
        self.assertEqual(rep['findings'], [])
        # Nothing of a case went out after the request: only the logouts that revoke the sessions.
        after = world.http_calls[4:]
        self.assertTrue(after)
        self.assertTrue(all('/auth/v1/logout' in url for _, url, _, _ in after), after)

    def test_the_record_has_the_reason_the_source_the_time_and_the_steps_in_order(self):
        rep, _, _, _ = self.aborted(requests=4)
        abort = rep['abort']
        self.assertEqual((abort['source'], abort['reason']), ('operator', 'stopped by the operator (test)'))
        self.assertRegex(abort['requested_at'], r'^\d{4}-\d\d-\d\dT')
        self.assertEqual([s['step'] for s in abort['steps']],
                         ['dispatch_stopped', 'credentials_revoked', 'in_flight_ended', 'evidence_kept',
                          'in_flight_checked', 'environment_isolated'])  # TK-RUN-005, written here by hand
        seconds = [s['seconds'] for s in abort['steps']]
        self.assertEqual(seconds, sorted(seconds))
        self.assertEqual(set(abort['seconds']), {'dispatch_stopped', 'in_flight_ended', 'environment_isolated'})
        self.assertTrue(all(isinstance(v, float) for v in abort['seconds'].values()), abort['seconds'])
        self.assertEqual(abort['limits_seconds'], {'dispatch_stopped': 60, 'in_flight_ended': 60,
                                                   'environment_isolated': 360})
        self.assertEqual(abort['over_limit'], [])
        self.assertTrue(abort['not_covered'])

    def test_the_sessions_are_logged_out_and_the_tokens_are_gone_before_the_stack_is_destroyed(self):
        rep, _, world, lifecycle = self.aborted(requests=4)
        self.assertEqual(set(rep['abort']['sessions'].values()), {'revoked'})
        self.assertEqual(world.revoked, {f'token-{n}' for n in scripted.EMAILS})
        self.assertEqual(lifecycle.calls, ['destroy'])

    def test_a_logout_that_gets_no_answer_is_not_confirmed(self):
        world = scripted.World(attempt=self.DENIED)
        prepare, _ = scripted.prepare_with(world)
        abort = scan.Abort()

        def prepared(project_dir):
            ready = prepare(project_dir)
            world.http_error = environment.RequestFailed('connection refused')  # the API is gone by the abort
            abort.request('stopped by the operator (test)')
            return ready
        rep = scan.run(self.plan(1), prepare=prepared, abort=abort).report
        self.assertEqual(report.validate(rep), [])
        self.assertEqual(set(rep['abort']['sessions'].values()), {'not_confirmed'})

    def test_times_over_the_policys_limits_are_reported(self):
        ticks = iter(range(0, 100_000, 100))  # every look at the clock is 100 s later
        prepare, _ = scripted.prepare_with(scripted.World(attempt=self.DENIED))
        abort = scan.Abort(clock=lambda: next(ticks))
        abort.request('stopped by the operator (test)')
        rep = scan.run(self.plan(1), prepare=prepare, abort=abort).report
        self.assertEqual(report.validate(rep), [])
        self.assertEqual(rep['abort']['over_limit'], ['dispatch_stopped', 'in_flight_ended', 'environment_isolated'])
        self.assertIn('超過上限', scan.run(self.plan(1), prepare=prepare, abort=self.late()).markdown)

    def late(self):
        ticks = iter(range(0, 100_000, 100))
        abort = scan.Abort(clock=lambda: next(ticks))
        abort.request('stopped by the operator (test)')
        return abort

    def test_only_the_first_request_counts(self):
        abort = scan.Abort()
        self.assertTrue(abort.request('first', source='system'))
        self.assertFalse(abort.request('second', source='operator'))
        self.assertEqual((abort.reason, abort.source), ('first', 'system'))

    def test_an_abort_with_no_case_left_to_dispatch_is_recorded_but_the_run_is_not_cancelled(self):
        # The only case is in flight: it ends without an outcome, and nothing was left undispatched.
        rep, results, _, _ = self.aborted(requests=3, n=1)
        self.assertEqual(results, ['error'])
        self.assertEqual(rep['status'], 'partial')
        self.assertEqual((rep['abort']['source'], rep['abort']['in_flight']), ('operator', 'CASE-1'))

    def test_a_run_whose_time_is_used_up_is_aborted_by_the_system(self):
        ticks = iter(range(0, 100_000, 90))
        prepare, _ = scripted.prepare_with(scripted.World(attempt=self.DENIED))
        m = self.plan(4)
        m['limits']['max_duration_seconds'] = 200
        rep = scan.run(m, prepare=prepare, clock=lambda: next(ticks)).report
        self.assertEqual(report.validate(rep), [])
        results = [e['result'] for e in rep['execution_records']]
        self.assertEqual(results[0], 'passed')
        self.assertEqual(results[-1], 'cancelled')
        self.assertNotIn('passed', results[1:])
        self.assertEqual((rep['status'], rep['abort']['source']), ('cancelled', 'system'))
        self.assertIn('time limit', rep['abort']['reason'])

    def test_a_failed_reset_is_an_abort_by_the_system_and_the_later_cases_stay_blocked(self):
        m = cases(('UPDATE-other-tenant', 'FIRST', {}), ('READ-other-tenant', 'SECOND', {}))
        prepare, lifecycle = scripted.prepare_with(scripted.World(attempt=(403, None)), reset_fails=True)
        rep = scan.run(m, prepare=prepare).report
        self.assertEqual(report.validate(rep), [])
        self.assertEqual(rep['execution_records'][1]['result'], 'blocked')  # TK-SBX-010, not cancelled
        self.assertEqual(rep['status'], 'partial')
        self.assertEqual(rep['abort']['source'], 'system')
        self.assertIn('environment reset failed after FIRST', rep['abort']['reason'])
        self.assertEqual(lifecycle.calls, ['reset', 'destroy'])

    def test_a_run_that_is_not_aborted_has_no_abort_record(self):
        rep, _, _ = run(self.plan(1), scripted.World(attempt=self.DENIED))
        self.assertNotIn('abort', rep)
        self.assertEqual(rep['cleanup'], {'environment': 'destroyed', 'leftovers': []})


class WhenTheEnvironmentCannotBeDestroyed(unittest.TestCase):
    """TK-ENV-003, TK-SBX-010: a destroy that leaves something behind is a platform anomaly in the report."""

    def test_the_report_is_still_made_names_what_is_left_and_is_not_completed(self):
        rep, by_id, _ = run(cases(('READ-other-tenant', 'ONLY', {})), scripted.World(attempt=(403, None)),
                            leftovers=['container supabase_db_scripted'])
        self.assertEqual(by_id['ONLY']['result'], 'passed')
        self.assertEqual(rep['cleanup'], {'environment': 'destroy_failed', 'leftovers': ['container supabase_db_scripted']})
        self.assertEqual(rep['status'], 'partial')
        self.assertIn('platform anomaly', rep['status_reason'])
        self.assertIn('container supabase_db_scripted', rep['status_reason'])

    def test_a_destroy_that_raises_is_reported_the_same_way(self):
        prepare, lifecycle = scripted.prepare_with(scripted.World(attempt=(403, None)))

        def broken(env):
            raise OSError('docker: command not found')
        lifecycle.destroy = broken

        def prepared(project_dir):
            ready = prepare(project_dir)
            ready.env._destroy = broken
            return ready
        rep = scan.run(cases(('READ-other-tenant', 'ONLY', {})), prepare=prepared).report
        self.assertEqual(report.validate(rep), [])
        self.assertEqual(rep['cleanup']['environment'], 'destroy_failed')
        self.assertIn('command not found', rep['cleanup']['leftovers'][0])

    def test_an_environment_outside_the_matrix_is_destroyed_and_says_so(self):
        rep, _, lifecycle = run(cases(('READ-other-tenant', 'ONLY', {})), scripted.World(attempt=(403, None)),
                                unsupported=['service rest img:0'])
        self.assertEqual(lifecycle.calls, ['destroy'])
        self.assertEqual(rep['cleanup'], {'environment': 'destroyed', 'leftovers': []})


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


class ExclusionsComeFromTheScanManifest(unittest.TestCase):
    """〈定義：覆蓋面向〉 排除項, TK-EVD-009: scope.exclusions of the ScanManifest reach the coverage record."""
    ROUTES = {'ref': 'nextjs-routes', 'reason': 'the project has no Next.js application', 'confirmed_by': 'owner',
              'version': 'v1'}
    # What READ-other-tenant exercises on the vulnerable sample: the table and its policies for select.
    DOCUMENT_READ = ('public.documents', 'public.documents: members read documents shared with their tenant',
                     'public.documents: tenant members read documents')

    def coverage_with(self, exclusions):
        m, world = passing_read()
        m['scope']['exclusions'] = exclusions
        rep = run(m, world)[0]
        return rep, rep['coverage']

    def test_a_complete_exclusion_takes_its_item_out_of_the_denominator_and_is_reported(self):
        rep, cov = self.coverage_with([self.ROUTES])
        self.assertEqual((cov['denominator'], cov['unsupported']), (5, 4))
        self.assertEqual((cov['excluded'], cov['rejected_exclusions'], cov['excluded_record_ids']), ([self.ROUTES], [], []))
        self.assertIn('nextjs-routes', {u['scope'] for u in cov['unsupported_items']})  # still listed, not hidden
        self.assertIn('排除：`nextjs-routes`', report.render_markdown(rep))

    def test_an_incomplete_or_unknown_exclusion_is_rejected_and_the_item_stays(self):
        for field in ('reason', 'confirmed_by', 'version'):
            for incomplete in ({k: v for k, v in self.ROUTES.items() if k != field}, {**self.ROUTES, field: '  '}):
                with self.subTest(field=field, given=field in incomplete):
                    _, cov = self.coverage_with([incomplete])
                    self.assertEqual((cov['denominator'], cov['excluded']), (6, []))
                    self.assertEqual(cov['rejected_exclusions'], [{'ref': 'nextjs-routes', 'problem': f'missing {field}'}])
        _, cov = self.coverage_with([{**self.ROUTES, 'ref': 'public.no_such_table'}])
        self.assertEqual((cov['denominator'], cov['excluded']), (6, []))
        self.assertEqual(cov['rejected_exclusions'], [{'ref': 'public.no_such_table', 'problem': 'not in the inventory'}])

    def test_excluding_everything_a_test_exercises_leaves_its_record_out_and_names_it(self):
        rep, cov = self.coverage_with([{**self.ROUTES, 'ref': ref} for ref in self.DOCUMENT_READ])
        self.assertEqual(cov['excluded_record_ids'], [rep['execution_records'][0]['id']])
        self.assertEqual((cov['denominator'], cov['executed']), (5, 0))
        self.assertIsNone(cov['required_test_completion_rate'])
        self.assertEqual(cov['states']['required_test_completion_rate'], 'not_applicable')
        self.assertEqual(rep['execution_records'][0]['result'], 'passed')  # the test still ran and is still reported
        self.assertIn('隨排除項移出分母的執行紀錄', report.render_markdown(rep))

    def test_excluding_only_part_of_what_a_test_exercises_keeps_its_record(self):
        _, cov = self.coverage_with([{**self.ROUTES, 'ref': 'public.documents'}])
        self.assertEqual((cov['excluded_record_ids'], cov['denominator'], cov['executed']), ([], 6, 1))

    def test_exclusions_of_the_wrong_shape_block_the_run_in_preflight(self):
        for wrong, said in (('nextjs-routes', 'must be a list'),
                            (['nextjs-routes'], 'scope.exclusions/0 must be an object'),
                            ([{**self.ROUTES, 'ref': ''}], 'scope.exclusions/0.ref'),
                            ([{k: v for k, v in self.ROUTES.items() if k != 'ref'}], 'scope.exclusions/0.ref'),
                            ([{**self.ROUTES, 'reason': 7}], 'reason must be text'),
                            ([{**self.ROUTES, 'approved': True}], 'fields other than')):
            with self.subTest(wrong=wrong):
                m, world = passing_read()
                m['scope']['exclusions'] = wrong
                rep = run(m, world)[0]
                self.assertEqual((rep['status'], rep['stages'][0]['status']), ('blocked', 'blocked'))
                self.assertIn(said, rep['status_reason'])
                self.assertEqual((rep['coverage']['excluded'], world.http_calls), ([], []))

    def test_without_exclusions_nothing_changes(self):
        for exclusions in ([], None):
            with self.subTest(exclusions=exclusions):
                m, world = passing_read()
                if exclusions is not None:
                    m['scope']['exclusions'] = exclusions
                cov = run(m, world)[0]['coverage']
                self.assertEqual((cov['denominator'], cov['excluded'], cov['excluded_record_ids']), (6, [], []))


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


class EnvironmentSupportMatrixAndKnownDifferences(unittest.TestCase):
    """TK-SCP-001, TK-ENV-007, TK-EVD-005, TK-EVD-008: EnvironmentProfile.known_differences and unsupported
    enter the report and Markdown; an out-of-matrix version destroys the stack without sending requests,
    marks runnable cases unsupported, blocks the run and drops whole_scope."""

    def test_supported_environment_carries_known_differences_into_report_and_markdown(self):
        diffs = ['service disabled in this stack: storage', *scripted.DEFAULT_DIFFERENCES]
        prepare, lifecycle = scripted.prepare_with(scripted.World(attempt=(403, [])), known_differences=diffs)
        res = scan.run(one_case('READ-other-tenant'), prepare=prepare)
        rep = res.report
        self.assertEqual(report.validate(rep), [])
        self.assertEqual(rep['status'], 'completed')
        self.assertEqual(rep['coverage']['claim'], 'whole_scope')
        self.assertEqual((rep['environment']['unsupported'], rep['environment']['known_differences']), ([], diffs))
        self.assertEqual(lifecycle.calls, ['destroy'])
        self.assertIn('service disabled in this stack: storage', res.markdown)

    def test_unsupported_environment_version_destroys_stack_without_requests_and_discloses_gap(self):
        bad_ver = 'service rest public.ecr.aws/supabase/postgrest:v0.0.0@sha256:0 (matrix v16.5)'
        m = cases(('DELETE-other-tenant', 'BLOCKED-DELETE', {}), ('READ-other-tenant', 'RUNNABLE-READ', {}))
        m['authorization'] = authorized(SAMPLES / 'vulnerable', {**AUTHORIZATION, 'extra_approvals': []})
        world = scripted.World(attempt=(200, [{'title': 'MARK-A-ALICE-PRIVATE', 'body': 'leaked'}]))
        prepare, lifecycle = scripted.prepare_with(world, unsupported=[bad_ver])
        res = scan.run(m, prepare=prepare)
        rep = res.report
        self.assertEqual(report.validate(rep), [])
        self.assertEqual((world.http_calls, world.exec_calls, lifecycle.calls), ([], [], ['destroy']))
        self.assertEqual(rep['status'], 'blocked')
        self.assertIn(bad_ver, rep['status_reason'])
        dynamic = next(s for s in rep['stages'] if s['stage'] == 'dynamic_execution')
        self.assertEqual(dynamic['status'], 'blocked')
        self.assertEqual(rep['environment']['unsupported'], [bad_ver])
        by_id = {e['test_id']: e for e in rep['execution_records']}
        self.assertEqual(by_id['BLOCKED-DELETE']['result'], 'blocked')  # keeps its preflight authorization block
        self.assertEqual(by_id['RUNNABLE-READ']['result'], 'unsupported')
        self.assertIn(bad_ver, by_id['RUNNABLE-READ']['error'])
        cov = rep['coverage']
        self.assertEqual(cov['claim'], 'known_scope_only')
        self.assertIn(f'environment:{bad_ver}', {u['scope'] for u in cov['unsupported_items']})
        # 2 scheduled tests (1 blocked, 1 unsupported) + 6 unsupported scopes (5 fixed + 1 environment) = 8
        self.assertEqual((cov['denominator'], cov['blocked'], cov['unsupported'], cov['executed']), (8, 1, 7, 0))
        self.assertIn('支援矩陣外版本', res.markdown)
        self.assertIn(bad_ver, res.markdown)


class DisclosureInNonTargetRowsAndNonArrayBodies(unittest.TestCase):
    """TK-DYN-001 item 3, TK-DYN-002, TK-IDN-008: any non-empty row array on a read denial case, or any
    response body (JSON list, JSON object, JSON string or non-JSON text) carrying the target marker under any
    status code, fails no_disclosure_or_change and records a finding without storing raw body secrets."""

    def test_read_denial_with_other_row_or_projected_row_without_title_fails_and_creates_finding(self):
        for label, attempt in (
            ('other-row', (200, [{'title': 'MARK-B-CAROL-PRIVATE', 'body': 'carol secret'}])),
            ('no-title-column', (200, [{'body': 'projected secret without title'}])),
            ('non-empty-list-on-403', (403, [{'id': 'd0000000-0000-4000-8000-0000000000b1'}])),
        ):
            with self.subTest(label):
                rep, by_id, _ = run(one_case('READ-same-tenant'), scripted.World(attempt=attempt))
                rec = by_id['READ-same-tenant']
                self.assertEqual(rec['result'], 'failed')
                self.assertFalse(rec['checks']['no_disclosure_or_change'])
                self.assertEqual(len(rep['findings']), 1)
                self.assertEqual(rep['findings'][0]['status'], 'confirmed')
                self.assertNotIn('secret', str(rep))

    def test_marker_in_json_object_array_or_plain_text_under_any_status_fails_and_creates_finding(self):
        marker = 'MARK-A-ALICE-PRIVATE'
        bodies = (
            ('json-object', {'code': '42501', 'details': {'row': f'denied on {marker}', 'secret': 'RAW-SECRET-BODY'}}),
            ('json-array-nested', [{'error': f'cannot read {marker}'}]),
            ('json-string', f'denied {marker} RAW-SECRET-BODY'),
            ('plain-text', f'Forbidden: row {marker} RAW-SECRET-BODY\n'.encode()),
        )
        for status in (200, 401, 403, 404, 500):
            for kind, payload in bodies:
                with self.subTest(status=status, body=kind):
                    rep, by_id, _ = run(one_case('READ-same-tenant'), scripted.World(attempt=(status, payload)))
                    rec = by_id['READ-same-tenant']
                    self.assertEqual(rec['result'], 'failed')
                    self.assertFalse(rec['checks']['no_disclosure_or_change'])
                    self.assertEqual(len(rep['findings']), 1)
                    self.assertEqual(rep['findings'][0]['status'], 'confirmed')
                    self.assertNotIn('RAW-SECRET-BODY', str(rep))

        # Deeply nested JSON objects exercise iterative _contains_marker(); ultra-deep raw JSON exceeding json.loads()
        # recursion depth raises RequestFailed -> 'error' (never 'passed' and never crashing scan.run()).
        deep = f'leaked {marker}'
        for _ in range(400):
            deep = {'nested': deep}
        rep, by_id, _ = run(one_case('READ-same-tenant'), scripted.World(attempt=(403, deep)))
        self.assertEqual(by_id['READ-same-tenant']['result'], 'failed')
        self.assertFalse(by_id['READ-same-tenant']['checks']['no_disclosure_or_change'])

        ultra_deep = (b'[' * 100000) + b'{"body":"secret"}' + (b']' * 100000)
        rep, by_id, _ = run(one_case('READ-same-tenant'), scripted.World(attempt=(403, ultra_deep)))
        self.assertEqual(by_id['READ-same-tenant']['result'], 'error')
        self.assertIn('nesting limit', by_id['READ-same-tenant']['error'])

        # Write denial case leaking marker in a 403 plain-text error without mutating state also fails item 3.
        rep, by_id, _ = run(one_case('UPDATE-same-tenant'),
                            scripted.World(attempt=(403, f'denied update on {marker}'.encode()), mutates=False))
        self.assertEqual(by_id['UPDATE-same-tenant']['result'], 'failed')
        self.assertFalse(by_id['UPDATE-same-tenant']['checks']['no_disclosure_or_change'])
        self.assertEqual(len(rep['findings']), 1)

    def test_denial_bodies_without_marker_or_rows_do_not_falsely_report_disclosure(self):
        for label, attempt in (
            ('json-error-without-marker', (403, {'code': '42501', 'message': 'permission denied for table documents'})),
            ('plain-text-without-marker', (403, b'Forbidden')),
            ('empty-list-on-403', (403, [])),
        ):
            with self.subTest(label):
                rep, by_id, _ = run(one_case('READ-same-tenant'), scripted.World(attempt=attempt))
                rec = by_id['READ-same-tenant']
                self.assertEqual(rec['result'], 'passed')
                self.assertTrue(rec['checks']['no_disclosure_or_change'])
                self.assertEqual(rep['findings'], [])

        # On a pending S2 clause, a disclosure still fails the test while capping the finding at evidence_pending.
        from toolkit.tests.test_scan import ACCEPTED, OWNER_ITEM, reviewed_list
        m = one_case('READ-same-tenant')
        m['confirmation_list'] = reviewed_list(SAMPLES / 'vulnerable', accepted=[i for i in ACCEPTED if i != OWNER_ITEM])
        rep, by_id, _ = run(m, scripted.World(attempt=(403, b'leaked MARK-A-ALICE-PRIVATE')))
        self.assertEqual(by_id['READ-same-tenant']['result'], 'failed')
        self.assertEqual([f['status'] for f in rep['findings']], ['evidence_pending'])


if __name__ == '__main__':
    unittest.main()
