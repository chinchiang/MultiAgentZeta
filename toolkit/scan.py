"""One scan run, the toolkit's main seam: run(manifest) -> Run(report, markdown), and main(), its command line.

Minimal controller (tracer bullet, #3): prepare the E1 stack from the project's
BuildRecipe, run the manifest's fixed tests, judge them with the observer,
and produce the versioned JSON report plus the Markdown generated from it.
"""
import argparse
import hashlib
import json
import re
import secrets
import signal
import string
import time
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timezone

from toolkit import (authorization, confirmation, control, coverage, e1, environment, extract, inventory, item_rule,
                     observer, policy, report, review)

SOURCE_ID = 'toolkit.scan'
FINGERPRINT_VERSION = 'fp-authz-v1'


@dataclass(frozen=True)
class Run:
    report: dict
    markdown: str


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def _digest(obj):
    return 'sha256:' + hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


class _Records:
    """Creates records that carry the common fields and the tested commit (TK-DAT-001)."""

    def __init__(self, run_id, commit):
        self.run_id, self.commit, self.n = run_id, commit, 0

    def new(self, prefix, **fields):
        self.n += 1
        return {'schema_version': '1', 'run_id': self.run_id, 'id': f'{prefix}-{self.n:04d}', 'created_at': _now(),
                'source_id': SOURCE_ID, 'commit': self.commit, **fields}


@dataclass
class _Listed:
    """〈定義：確認清單〉 as read or handed over in this run: its items by id, and the reference the report
    gives (path, digest, versions, summary). Empty until the list is loaded."""
    items: dict = field(default_factory=dict)
    ref: dict | None = None

    def item(self, test):
        """The item a planned test rests on, or None."""
        return report.listed_item(self.items, test)


@dataclass
class _Granted:
    """〈定義：測試授權紀錄〉 as read in this run. Empty until the record is read."""
    doc: dict | None = None
    ref: dict | None = None

    def report(self):
        """The authorization as the report shows it; the names in it are declared, not verified (TK-HRV-004)."""
        shown = {k: v for k, v in self.doc.items() if k != 'schema_version'}
        return {**self.ref, **shown, 'extra_approvals': self.doc.get('extra_approvals', []), 'identity_verified': False}


@dataclass(frozen=True)
class _Reviewed:
    """〈定義：覆核紀錄〉 as read in this run: the record and the reference the report gives. Empty when the
    ScanManifest references none, so every finding is pending."""
    doc: dict | None = None
    ref: dict | None = None


@dataclass(frozen=True)
class _Precheck:
    """A test's checks before the environment starts: (result, reason) when it cannot run, and the extra
    approval of 〈定義：測試授權紀錄〉 it would run under; a record shows the approval only when its test ran."""
    result: str | None = None
    reason: str | None = None
    approval_id: str | None = None

    @property
    def runnable(self):
        return self.result is None

    def outcome(self, reason, default='blocked'):
        """(result, reason) of a test that does not run: its own when it cannot run, else default for reason."""
        return (default, reason) if self.runnable else (self.result, self.reason)


@dataclass
class _RunState:
    """What one run carries from its start to its report. listed, granted and gaps stay empty until they
    are read; prechecks has an entry per planned test, in plan order, once the tests are checked."""
    manifest: dict
    records: _Records
    listed: _Listed = field(default_factory=_Listed)
    granted: _Granted = field(default_factory=_Granted)
    prechecks: list = field(default_factory=list)  # one _Precheck per planned test, in plan order
    reviewed: _Reviewed = field(default_factory=_Reviewed)
    gaps: list = field(default_factory=list)  # 測試身分 the BuildRecipe cannot provide
    clock: object = time.monotonic  # seconds; the run's time limit is measured with it
    started: float = 0.0  # clock() when the run began
    requests: int = 0  # actor requests and observer reads the run's cases made (執行限制 max_requests)
    self_validation: bool = False  # 〈定義：故障注入〉: only such a run takes tests with a fault

    def elapsed(self):
        return max(0.0, self.clock() - self.started)


API_KEY_FORMATS = ('anon-jwt', 'publishable')


def _api_key_for(test, identity):
    """The API key format a request of this case uses for the identity: the test's format for the actor
    (its requests and its identity check), anon-jwt for any other identity, such as the owner's control
    operation (TK-DYN-004)."""
    return test.get('api_key', 'anon-jwt') if identity == test['actor_ref'] else 'anon-jwt'


def _check_api_keys(ops, test, denial):
    """Raise ApiKeyUnavailable, before the case sends anything, if the environment lacks an API key format
    one of the case's requests uses: the actor's, and for a denial case also the owner's (TK-DYN-004,
    TK-IDN-003)."""
    identities = [test['actor_ref']] + ([test['owner_ref']] if denial else [])
    ops.require_api_keys({_api_key_for(test, i) for i in identities})


# The four checks of a denial case (TK-DYN-001).
CHECKS = ('resource_and_control', 'identity', 'no_disclosure_or_change', 'response_and_side_effects')

# Request targets of denial-case templates, filled in from the test's fields.
RESOURCE_ROWS = '/rest/v1/documents?title=eq.{resource_ref}&select=title,body'
CONTROL_ROWS = '/rest/v1/documents?title=eq.{control_ref}&select=title'
DOCUMENTS = '/rest/v1/documents'

# Denial-case templates (TK-DYN-001). Each one gives:
#   method    HTTP method of both the owner's control operation and the actor's attempt
#   denials   responses the contract accepts as a denial (TK-DYN-002: a status code alone is not enough)
#   control   (path, body) of the owner's control operation, which must succeed on exactly one row
#   attempt   (path, body) of the actor's attempt
#   resource  the resource state the case needs before the attempt and must keep after it
#             (see RESOURCE_STATES)
#   params    typed test parameters beyond resource_ref (always a marker) that the template
#             fills in (TK-IDN-006); every {field} in control and attempt must be one of them
# Write attempts ask for return=minimal, so PostgREST answers 204 whether or not a row
# changed: the verdict on a write rests on the observer's state, not on what the actor sees.
DENIAL_TEMPLATES = {
    'cross-user-read-v1': {'method': 'GET', 'denials': {200, 401, 403, 404}, 'writes': False, 'resource': 'existing',
                           'params': {}, 'control': (RESOURCE_ROWS, None), 'attempt': (RESOURCE_ROWS, None)},
    'cross-user-update-v1': {'method': 'PATCH', 'denials': {204, 401, 403, 404}, 'writes': True,
                             'resource': 'existing', 'params': {'control_ref': 'marker'},
                             'control': (CONTROL_ROWS, {'body': 'owner control'}),
                             'attempt': (RESOURCE_ROWS, {'body': 'tampered by the actor'})},
    'cross-user-delete-v1': {'method': 'DELETE', 'denials': {204, 401, 403, 404}, 'writes': True,
                             'resource': 'existing', 'params': {'control_ref': 'marker'},
                             'control': (CONTROL_ROWS, None), 'attempt': (RESOURCE_ROWS, None)},
    # TK-DYN-007: creating a row in another user's name and tenant.
    'cross-user-create-v1': {'method': 'POST', 'denials': {401, 403}, 'writes': True, 'resource': 'absent',
                             'params': {'control_ref': 'marker', 'claimed_owner_id': 'uuid', 'tenant_id': 'uuid'},
                             'control': (DOCUMENTS, {'tenant_id': '{tenant_id}', 'owner_id': '{claimed_owner_id}',
                                                     'title': '{control_ref}', 'body': 'owner control'}),
                             'attempt': (DOCUMENTS, {'tenant_id': '{tenant_id}', 'owner_id': '{claimed_owner_id}',
                                                     'title': '{resource_ref}', 'body': 'attempt'})},
}

# Resource states a denial case can need (TK-DYN-001 items 1 and 3), from the observer's
# before and after states: (ready before the attempt, changed by the attempt).
RESOURCE_STATES = {
    # A private row that exists and must stay as it was.
    'existing': (lambda before: before['resource_exists'] and not before['shared'],
                 lambda before, after: (after['resource_exists'], after.get('state_digest'))
                 != (True, before['state_digest'])),
    # A row that does not exist and must not appear.
    'absent': (lambda before: not before['resource_exists'],
               lambda before, after: after['resource_exists']),
}


def _fill(value, test):
    """A template path or body with the test's fields filled in."""
    if isinstance(value, dict):
        return {k: _fill(v, test) for k, v in value.items()}
    return value.format(**test) if isinstance(value, str) else value


def _fields(value):
    """The {field} names a template path or body uses."""
    if isinstance(value, dict):
        return {f for v in value.values() for f in _fields(v)}
    return {f for _, f, _, _ in string.Formatter().parse(value) if f} if isinstance(value, str) else set()


# Only typed, validated parameters reach a request path or body (TK-IDN-006). A kind other
# than these would escape validation in _plan_problem, so it is refused here.
PARAM_KINDS = {'marker', 'uuid'}
for _name, _t in DENIAL_TEMPLATES.items():
    _untyped = {f for part in (_t['control'], _t['attempt']) for f in _fields(part)} - {'resource_ref', *_t['params']}
    if _untyped:
        raise ValueError(f'denial template {_name} fills in untyped parameters {sorted(_untyped)}')
    _unknown = set(_t['params'].values()) - PARAM_KINDS
    if _unknown:
        raise ValueError(f'denial template {_name} has parameters of unknown kind {sorted(_unknown)}')


def _timeout(test):
    """Per-test time limit (TestIR limits.timeout_seconds), 15 s by default."""
    return (test.get('limits') or {}).get('timeout_seconds', 15)


def _contains_marker(value, marker):
    """Whether a parsed JSON value or UnparsedBody from the actor channel carries `marker` (TK-DYN-001, TK-IDN-008).
    Iterative so deeply nested untrusted JSON never hits Python's recursion limit."""
    stack = [value]
    while stack:
        cur = stack.pop()
        if isinstance(cur, environment.UnparsedBody):
            if marker in cur.text:
                return True
        elif isinstance(cur, str):
            if marker in cur:
                return True
        elif isinstance(cur, list):
            stack.extend(cur)
        elif isinstance(cur, dict):
            stack.extend(cur.keys())
            stack.extend(cur.values())
    return False


def _disclosed(template, data, marker):
    """TK-DYN-001 item 3 and TK-DYN-002: a whole-row read denial template that returned any row (even another
    user's row or a projection without title), or any denial response body carrying the target marker regardless
    of status code."""
    return (not template['writes'] and isinstance(data, list) and bool(data)) or _contains_marker(data, marker)


def _denial_case(ops, test, evidence):
    """Run one denial case. Appends evidence; returns (result, checks).

    Leaks are judged only from the actor channel; state changes and side effects
    only from the observer channel (TK-IDN-008).
    """
    template = DENIAL_TEMPLATES[test['template_id']]
    method = template['method']
    ready, changed_by = RESOURCE_STATES[template['resource']]
    marker = test['resource_ref']
    checks = dict.fromkeys(CHECKS, False)

    def actor(identity, method, path, body=None, prefer='return=representation'):
        key = _api_key_for(test, identity)
        status, data = ops.request(identity, method, path, body, key, prefer, _timeout(test))
        evidence.append({'channel': 'actor', 'identity_ref': identity, 'api_key_format': key,
                         'request': {'method': method, 'path': path, 'prefer': prefer},
                         'response': {'status': status, 'rows': len(data) if isinstance(data, list) else None}})
        return status, data

    def observe(point):
        state = ops.observe(marker)
        evidence.append({'channel': 'observer', 'identity_ref': ops.observer_role, 'point': point,
                         'observation': state})
        return state

    # 1. The owner's control operation succeeds, and the resource is in the expected state.
    path, body = (_fill(v, test) for v in template['control'])
    status, control_data = actor(test['owner_ref'], method, path, body)
    control_ok = status in (200, 201) and isinstance(control_data, list) and len(control_data) == 1
    before = observe('before')
    checks['resource_and_control'] = control_ok and ready(before)
    if not checks['resource_and_control']:
        return 'blocked', checks

    # 2. The actor's identity is valid, and it is the identity the test expects.
    status, user = actor(test['actor_ref'], 'GET', '/auth/v1/user')
    expected_email = ops.identity_email(test['actor_ref'])
    if expected_email is None:  # an anonymous identity: the request must carry no user session
        checks['identity'] = status in (401, 403) and not ops.has_session(test['actor_ref'])
    else:
        checks['identity'] = status == 200 and isinstance(user, dict) and user.get('email') == expected_email
    if not checks['identity']:
        return 'blocked', checks

    # The attempt, then 3. no leak and no change, and 4. response and side effects.
    path, body = (_fill(v, test) for v in template['attempt'])
    prefer = 'return=minimal' if template['writes'] else 'return=representation'
    status, data = actor(test['actor_ref'], method, path, body, prefer=prefer)
    after = observe('after')
    disclosed = _disclosed(template, data, marker)
    changed = changed_by(before, after)
    checks['no_disclosure_or_change'] = not disclosed and not changed
    response_ok = status in template['denials'] and (status != 200 or data == [])
    side_effect = after['table_digest'] != before['table_digest']
    checks['response_and_side_effects'] = response_ok and not side_effect
    if disclosed or changed or side_effect:
        return 'failed', checks
    if not response_ok:
        # 〈定義：測試結果〉 拒絕案例的契約外回應: no answer the contract can judge is an execution error; any other
        # answer outside the contract is the application's own, and check 4 does not hold.
        unjudgeable = status in BACKEND_UNAVAILABLE or (status == 200 and not isinstance(data, list))
        return ('error' if unjudgeable else 'failed'), checks
    return 'passed', checks


# Allowed-case templates: the requirement permits the access, so the case passes when it is granted. Each is
# on one table (TK-DYN-003, TK-DYN-004): the test names a marker, not the table,
# so a test cannot pick where it is allowed to read (TK-REQ-016).
ALLOWED_TEMPLATES = {'public-read-v1': {'method': 'GET', 'table': 'announcements'},
                     'shared-read-v1': {'method': 'GET', 'table': 'documents'}}


# 〈定義：測試結果〉 允許案例: the gateway reports that the backend behind it is unavailable.
BACKEND_UNAVAILABLE = {502, 503, 504}


def _allowed_case(ops, test, evidence):
    """An allowed-case template: public-read-v1 (e.g. USING (true) on public data, TK-DYN-004) or
    shared-read-v1 (a document shared with the actor's tenant, TK-DYN-003). Returns (result, checks)."""
    template = ALLOWED_TEMPLATES[test['template_id']]
    marker, key = test['resource_ref'], test.get('api_key', 'anon-jwt')
    path = f'/rest/v1/{template["table"]}?title=eq.{marker}&select=title'
    status, data = ops.request(test['actor_ref'], template['method'], path, api_key=key, timeout=_timeout(test))
    rows = data if isinstance(data, list) else None
    evidence.append({'channel': 'actor', 'identity_ref': test['actor_ref'], 'api_key_format': key,
                     'request': {'method': template['method'], 'path': path},
                     'response': {'status': status, 'rows': len(rows) if rows is not None else None}})
    granted = status == 200 and rows == [{'title': marker}]
    if not granted and (status in BACKEND_UNAVAILABLE or (status == 200 and rows is None)):
        # 〈定義：測試結果〉 允許案例: no answer the contract can judge is an execution error, not a refusal.
        return 'error', {'access_granted': False}
    return ('passed' if granted else 'failed'), {'access_granted': granted}


def _side_effect(ex):
    """Whether the observer saw the table change between its two reads of a denial case (TK-DYN-001 第 4 項)."""
    seen = {ev['point']: ev['observation'].get('table_digest') for ev in ex['evidence'] if ev.get('channel') == 'observer'}
    return seen.get('before') != seen.get('after')


def _record_finding(state, findings, test, ex):
    """The FindingRecord of a failed denial case. A run has one finding per fingerprint, fingerprint version and
    requirement version (〈定義：覆核紀錄〉 項目): a case that fails on a finding the run already has, such as the
    same attempt with the other API key format, adds its execution record to that finding.

    〈定義：問題狀態〉: a disclosure or a state change proves the requirement was violated (已確認, as far as the
    confirmation item allows); an answer outside the contract without either points at a risk and proves
    nothing (證據待補). A finding with both kinds of record has the proof."""
    fingerprint, version = _fingerprint(test), _item_version(state.listed, test)
    proven = not ex['checks']['no_disclosure_or_change'] or _side_effect(ex)
    status = item_rule.finding_cap(state.listed.item(test)) if proven else 'evidence_pending'
    for f in findings:
        if (f['fingerprint'], f['fingerprint_version'], f['requirement_version']) == (fingerprint, FINGERPRINT_VERSION,
                                                                                    version):
            f['execution_record_ids'].append(ex['id'])
            if proven:
                f['status'] = status
            return
    findings.append(state.records.new('finding', fingerprint=fingerprint, fingerprint_version=FINGERPRINT_VERSION,
                                      requirement_id=test['requirement_id'], requirement_version=version,
                                      root_cause='object-ownership-not-enforced',
                                      status=status,
                                      evidence_type='dynamic', execution_record_ids=[ex['id']]))


# 〈定義：執行限制的執行〉: the most requests a case makes, actor requests and observer reads together, so that a
# case is dispatched only when the run can afford all of it. A denial case: the owner's control operation,
# the identity check, the attempt, and the observer's reads before and after. An allowed case: the read.
# 〈定義：中止與清理〉 中止時間: the policy's upper bounds, in seconds from the abort request. They follow from the
# toolkit's own timeouts (one request or observer read; stopping the stack) and are to be set from measurement.
ABORT_LIMITS = {'dispatch_stopped': 60, 'in_flight_ended': 60, 'environment_isolated': 360}
ABORT_STEPS = ('dispatch_stopped', 'credentials_revoked', 'in_flight_ended', 'evidence_kept', 'in_flight_checked',
               'environment_isolated')  # TK-RUN-005, in this order


class Abort:
    """The control area's stop signal for one run (TK-RUN-004, 〈定義：中止與清理〉). request() may be called from a
    signal handler or by the run itself; only the first request counts, with its reason, source and time.
    Nothing here waits for a test or a model: the run looks at it before each case and before each request."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.reason = self.source = self.requested_at = None
        self.undispatched = 'cancelled'  # result of the cases not dispatched after it
        self._t0 = None
        self.steps = {}  # step -> (wall time, seconds since the request)
        self.sessions = {}
        self.in_flight = None  # test_id of the case that was running when dispatch stopped

    @property
    def requested(self):
        return self._t0 is not None

    def request(self, reason, source='operator', undispatched='cancelled'):
        if self.requested:
            return False
        self.reason, self.source, self.undispatched = reason, source, undispatched
        self.requested_at, self._t0 = _now(), self.clock()
        return True

    def mark(self, step):
        """Record when a step of the abort was done; the first time only."""
        if step not in self.steps:
            self.steps[step] = (_now(), round(max(0.0, self.clock() - self._t0), 3))

    def record(self):
        """The report's abort record: what was asked, the steps in the order they were done, and the three
        measured times against the policy's limits (TK-RUN-006)."""
        steps = [{'step': s, 'at': self.steps[s][0], 'seconds': self.steps[s][1]} for s in ABORT_STEPS if s in self.steps]
        measured = {name: self.steps[name][1] if name in self.steps else None for name in ABORT_LIMITS}
        return {'source': self.source, 'reason': self.reason, 'requested_at': self.requested_at, 'steps': steps,
                'sessions': dict(self.sessions), 'in_flight': self.in_flight,
                'seconds': measured, 'limits_seconds': dict(ABORT_LIMITS),
                'over_limit': [n for n, v in measured.items() if v is not None and v > ABORT_LIMITS[n]],
                'not_covered': list(ABORT_NOT_COVERED)}


ABORT_NOT_COVERED = (
    'no separate test process exists in this version: the case in flight ends at its next request, it is not killed',
    'a lapsed policy, unexpected outbound connections and resource overuse other than time have no detector that '
    'could trigger an abort (authorization and confirmation are checked in preflight only; outbound connections '
    'are blocked for the whole stack; resource limits are not set, TK-SBX-003)',
    'access tokens stay valid until they expire wherever the same signing secret is used: logging out ends the '
    'session and its refresh token, and the tokens are dropped from memory',
)


def _stop_dispatch(ops, abort):
    """Steps 1 and 2 of TK-RUN-005, once: no further case or request goes out, and the test sessions are
    logged out."""
    if 'dispatch_stopped' in abort.steps:
        return
    abort.mark('dispatch_stopped')
    abort.sessions = ops.revoke_sessions()
    abort.mark('credentials_revoked')


CASE_REQUESTS = {item_rule.DENIAL: 5, item_rule.ALLOWED: 1}
FAULT_REQUESTS = {'session-revoked': 1}  # the logout that revokes the session
CONCURRENCY = 1  # cases run one after another


def _case_requests(test):
    return CASE_REQUESTS[_case_kind(test)] + FAULT_REQUESTS.get(test.get('fault'), 0)


def _limit_reached(state, test):
    """Why the run's limits leave no room for this case, or None (TK-BUD-003, 〈定義：執行限制的執行〉). Checked
    before the case is dispatched: a case is run whole or not at all."""
    limits = state.manifest['limits']
    need, used = _case_requests(test), state.requests
    if used + need > limits['max_requests']:
        return (f'request limit: the case needs up to {need} requests and {used} of max_requests '
                f'{limits["max_requests"]} are used')
    elapsed, seconds = state.elapsed(), need * _timeout(test)
    if elapsed >= limits['max_duration_seconds']:
        return _TimeUsedUp(f'time limit: max_duration_seconds {limits["max_duration_seconds"]} has passed')
    if elapsed + seconds > limits['max_duration_seconds']:
        return (f'time limit: the case may take {seconds:g} s and {elapsed:.0f} s of max_duration_seconds '
                f'{limits["max_duration_seconds"]} have passed')
    return None


class _TimeUsedUp(str):
    """The run's time limit has passed altogether: no later case can fit either, so the system aborts the run
    (TK-RUN-004 資源超限) instead of looking at every remaining case."""


def _limits_report(state):
    """The run's limits as stated and what the run used of them (〈定義：執行限制的執行〉). A limit that is not a
    positive integer, which blocks the run in preflight, is reported as null."""
    stated = state.manifest.get('limits')
    stated = stated if isinstance(stated, dict) else {}

    def limit(name):
        return stated[name] if _is_positive_int(stated.get(name)) else None
    return {'max_requests': limit('max_requests'), 'requests': state.requests,
            'max_duration_seconds': limit('max_duration_seconds'), 'elapsed_seconds': round(state.elapsed(), 3),
            'max_concurrency': limit('max_concurrency'), 'concurrency': CONCURRENCY}


def _authorization_matrix(prepared):
    """Identities and how their credentials travel, as confirmed in the BuildRecipe (TK-IDN-003)."""
    transport = prepared.env.token_transport
    return [{'identity': name, 'transport': transport if ident['login'] == 'ok' else 'none',
             'transport_source': 'BuildRecipe auth.token_transport', 'path': ident['path']}
            for name, ident in prepared.profile['identities'].items()]


def _fingerprint(test):
    # 〈定義：問題指紋〉 for authorization: requirement, root cause, normalized entry, resource type, relation.
    method = DENIAL_TEMPLATES[test['template_id']]['method']
    return _digest({'requirement_id': test['requirement_id'], 'root_cause': 'object-ownership-not-enforced',
                    'entry': f'{method} /rest/v1/documents', 'resource_type': 'documents',
                    'relation': test['actor_ref'], 'algorithm': FINGERPRINT_VERSION})


# Allow-lists (TK-IDN-006): test templates, the observation templates each may use,
# and the typed identifiers their parameters accept.
TEST_TEMPLATES = {**{name: {'document-row-state-v1'} for name in DENIAL_TEMPLATES},
                  **{name: {None} for name in ALLOWED_TEMPLATES}}  # allowed cases make no observation
IDENTIFIER = observer.MARKER
UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')


def _typed_params(template, kind):
    """Names of a template's parameters of one kind ('marker' or 'uuid')."""
    params = DENIAL_TEMPLATES.get(template, {}).get('params', {})
    return [name for name, k in params.items() if k == kind]


@dataclass(frozen=True)
class _TestChecks:
    """The checks of each test before the environment starts, and what they rest on, taken once from the run:
    the confirmation items and the plan, the operations the run and its 〈定義：測試授權紀錄〉 allow, and what
    the BuildRecipe provides: the test identities and whether it can restore what a write case changes. With
    no readable recipe, identities is None and nothing is judged by it: the BuildRecipe step blocks the run."""
    tests: list
    items: dict
    plan: dict
    identities: set | None
    restorable: bool
    allowed_operations: list
    granted: dict
    now: datetime

    @classmethod
    def of(cls, state, recipe, now, items):
        manifest = state.manifest
        return cls(tests=manifest['tests'], items=items, plan=_plan(manifest),
                   identities={i['name'] for i in recipe['auth']['identities']} if recipe else None,
                   restorable=not (recipe and recipe['snapshot_reset'].get('reset_scope') == 'none'),
                   allowed_operations=manifest['scope']['allowed_operations'], granted=state.granted.doc, now=now)

    def precheck(self, test):
        """The _Precheck of a test."""
        reason = _plan_problem(test) or _item_problem(test, self.items, self.plan)
        if reason:
            return _Precheck('blocked', reason)
        approval, reason = self._authorize(test)
        if reason:
            return _Precheck('blocked', reason)
        if not self.restorable and DENIAL_TEMPLATES.get(test['template_id'], {}).get('writes'):
            # An extra approval never lets a test that cannot be restored run (〈定義：測試授權紀錄〉).
            return _Precheck('blocked', 'the BuildRecipe declares no reset (snapshot_reset.reset_scope "none"): '
                                        'a write case cannot be restored safely and is not run (復原方式)', approval)
        reason = self._identity_problem(test)
        return _Precheck('unsupported', reason, approval) if reason else _Precheck(approval_id=approval)

    def _authorize(self, test):
        """(approval_id, reason) of 〈定義：測試授權紀錄〉: the test's method must be in the scope of the run,
        which no approval widens; then its resource × method must be in the authorization or covered by an
        extra approval (TK-ENV-001)."""
        resource, method = test_operation(test)
        if method not in self.allowed_operations:
            return None, (f'{method} is not in scope.allowed_operations (受測範圍): the test is outside the scope of '
                          f'this run, which no approval widens; the test is not run')
        return authorization.operation_problem(self.granted, resource, method, self.now)

    def _identity_problem(self, test):
        """測試身分: an identity the BuildRecipe does not provide is an unsupported matrix cell."""
        if self.identities is None:  # no readable recipe: the BuildRecipe step will block the run
            return None
        for ref in _test_identities(test):
            if ref not in self.identities:
                return f'identity {ref!r} is not in the BuildRecipe: unsupported cell of the authorization matrix'
        return None

    def identity_gaps(self):
        """Coverage gaps for identities the recipe cannot provide."""
        if self.identities is None:
            return []
        names = sorted({ref for t in self.tests for ref in _test_identities(t) if ref not in self.identities})
        return [{'scope': f'identity:{n}', 'reason': 'no such identity in the BuildRecipe (測試身分)'} for n in names]


def _test_identities(test):
    """The valid identity names a test uses: actor_ref, plus owner_ref for a denial case (〈定義：必要輸入〉)."""
    template = test.get('template_id')
    refs = [test.get('actor_ref')] + ([test.get('owner_ref')]
                                      if isinstance(template, str) and template in DENIAL_TEMPLATES else [])
    return [r for r in refs if _nonempty_str(r)]


DENIAL_RESOURCE = 'documents'  # the table every denial-case template works on (RESOURCE_ROWS, CONTROL_ROWS, DOCUMENTS)


def test_operation(test):
    """(resource, HTTP method) of a test, from its template only (〈定義：測試授權紀錄〉): a test cannot name
    what it is authorized for. The template must be allow-listed."""
    template = test['template_id']
    if template in DENIAL_TEMPLATES:
        return DENIAL_RESOURCE, DENIAL_TEMPLATES[template]['method']
    return ALLOWED_TEMPLATES[template]['table'], ALLOWED_TEMPLATES[template]['method']


def _case_kind(test):
    """The case kind of a test's template, or None for a template on no allow-list (blocked by _plan_problem)."""
    template = test.get('template_id')
    if not isinstance(template, str):
        return None
    return item_rule.DENIAL if template in DENIAL_TEMPLATES else item_rule.ALLOWED if template in ALLOWED_TEMPLATES else None


def _plan(manifest):
    """Each planned test_id with its requirement_id and case kind, for the allowed tests of a 合法例外
    (TK-DYN-003)."""
    return {tid: {'requirement_id': t.get('requirement_id'), 'case_kind': _case_kind(t)}
            for t in _planned_tests(manifest) if _nonempty_str(tid := t.get('test_id'))}


def _item_problem(test, items, plan):
    """需求不明: the confirmation item the test rests on must be in the list; the toolkit never infers a
    requirement from the implementation (TK-REQ-005). Whether the item lets the test run is
    confirmation.test_problem (〈定義：確認清單〉, TK-REQ-003, TK-REQ-016)."""
    item = report.listed_item(items, test)
    if item is None:
        return f'requirement {test.get("requirement_id")!r} is not in the confirmation list; requirement unknown, not inferred from the code'
    return confirmation.test_problem(item, test['test_id'], _case_kind(test), items, plan)


S1_FIELDS = ('id', 'statement', 'resources', 'rule')


def _duplicates(pairs):
    """(where, value) for each pair whose value was already seen earlier in pairs."""
    seen, dup = set(), []
    for where, value in pairs:
        if value in seen:
            dup.append((where, value))
        seen.add(value)
    return dup


def _s1_problems(manifest):
    """S1 entries are the owner's spec as input (〈定義：確認清單〉): id, statement, resources and an
    allow/deny rule, optionally the high-impact categories it involves, and no confirmation, which
    belongs in the confirmation list. An id has no "@", so it never equals an S2 item id."""
    if 'requirements' not in manifest:
        return []
    entries = manifest['requirements']
    if not isinstance(entries, list):
        return ['requirements (S1 entries) must be a list']
    problems, ids = [], []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            problems.append(f'requirements/{i} must be an object')
            continue
        problems += [f'requirements/{i}.{name} (S1 entry) is missing' for name in S1_FIELDS if not entry.get(name)]
        eid = entry.get('id')
        if eid and not _nonempty_str(eid):
            problems.append(f'requirements/{i}.id must be a non-empty string')
        elif _nonempty_str(eid):
            if '@' in eid:
                problems.append(f"requirements/{i}.id {eid!r} must not contain '@': it is kept for S2 item "
                                f"ids (clause@resource), which an S1 entry id could otherwise take")
            ids.append((i, eid))
        if entry.get('statement') and not _nonempty_str(entry['statement']):
            problems.append(f'requirements/{i}.statement must be a non-empty string')
        res = entry.get('resources')
        if res:
            if not isinstance(res, list) or not all(_nonempty_str(r) for r in res):
                problems.append(f'requirements/{i}.resources must be a non-empty list of resource names')
            else:
                problems += [f'requirements/{i}.resources lists {r!r} twice' for _, r in _duplicates((i, r) for r in res)]
        if entry.get('rule') and entry['rule'] not in policy.RULES:
            problems.append(f'requirements/{i}.rule must be one of {policy.RULES}')
        if 'impact' in entry:  # optional (TK-REQ-012); given, it is a list of high-impact categories
            problems += policy.impact_problems(entry['impact'], f'requirements/{i}', required=False)
        if 'confirmation' in entry:
            problems.append(f'requirements/{i}.confirmation: S1 entries carry no confirmation; it is given '
                            f'in the confirmation list')
    problems += [f'requirements/{i}.id {eid!r} is listed twice' for i, eid in _duplicates(ids)]
    return problems


@dataclass(frozen=True)
class _PreparedList:
    """A confirmation list read or prepared in memory during preflight, before deciding whether to write it."""
    on_disk: _Listed
    items: dict
    updated: bool
    write: object  # () -> (_Listed, problem)


def _listed_from(path, digest, doc, updated):
    ref = {'path': str(path), 'digest': digest, 'list_version': doc['list_version'], 'updated': updated,
           's2_template': doc['s2_template'], **confirmation.summary(doc)}
    return _Listed({i['item_id']: i for i in doc['items']}, ref)


def _load_confirmation_list(manifest, now):
    """Read the referenced list, or prepare a new one when there is none yet (no digest and no
    file; a list referenced with its digest is read even when its file is gone, TK-REQ-004);
    bring it up to date in memory with the S2 template, the scope and `now` (〈定義：確認清單〉 到期).
    Returns (_PreparedList, None), or (None, problem): writing happens only once preflight passes
    or a test is blocked by an added or changed item of the confirmation list."""
    ref = manifest.get('confirmation_list')
    path = ref.get('path') if isinstance(ref, dict) else None
    if not _nonempty_str(path):
        return None, ('confirmation_list.path (獨立安全需求) is missing: there is no control-zone location '
                      'to read the confirmation list from or hand it over to')
    source, resources, s1 = manifest['target']['project'], manifest['scope']['resources'], manifest.get('requirements') or []
    try:
        template = policy.load_template()
    except (OSError, ValueError, policy.PolicyTemplateInvalid) as e:
        return None, f'the S2 template cannot be used: {e}'
    try:
        control.outside_source(path, source, 'confirmation list')
        if ref.get('digest'):  # the list existed: read it, even when its file is gone (TK-REQ-004)
            existing = confirmation.read(path, ref['digest'], source)
            doc = confirmation.update(existing, template, resources, s1, now=now)
            updated = doc != existing
            on_disk = _listed_from(path, ref['digest'], existing, False)
        elif Path(path).exists():
            return None, f'confirmation_list.digest is missing: the list at {path} is read only with its digest'
        else:
            doc, updated, on_disk = confirmation.generate(template, resources, s1), True, _Listed()
    except (confirmation.ConfirmationListUnusable, OSError) as e:
        return None, f'confirmation list unusable: {e}'
    items = {i['item_id']: i for i in doc['items']}

    def write():
        if not updated:
            return on_disk, None
        try:
            digest = confirmation.write(path, doc, source)
        except (confirmation.ConfirmationListUnusable, OSError) as e:
            return None, f'confirmation list unusable: {e}'
        return _listed_from(path, digest, doc, True), None

    return _PreparedList(on_disk=on_disk, items=items, updated=updated, write=write), None


def _plan_problem(test):
    """Why a test from the manifest cannot run, or None (〈定義：必要輸入〉, TK-IDN-006, TK-IDN-009)."""
    # Fields that name the test in its ExecutionRecord: an unusable one blocks the test before anything
    # starts (TK-IDN-009), instead of reaching the environment. template_id and resource_ref are
    # checked below against their allow-lists.
    for name in ('test_id', 'requirement_id', 'actor_ref'):
        if not _nonempty_str(test.get(name)):
            return f'{name} must be a non-empty string'
    template = test.get('template_id')
    if not isinstance(template, str) or template not in TEST_TEMPLATES:
        return f'template_id {template!r} is not an allow-listed test template'
    if template in DENIAL_TEMPLATES and not _nonempty_str(test.get('owner_ref')):
        return 'owner_ref must be a non-empty string'
    obs = test.get('observation_ref')
    if (obs is not None and not isinstance(obs, str)) or obs not in TEST_TEMPLATES[template]:
        return f'observation_ref {obs!r} is not an allow-listed observation template for {template}'
    for name in ['resource_ref'] + _typed_params(template, 'marker'):
        if not isinstance(test.get(name), str) or not IDENTIFIER.match(test[name]):
            return f'{name} must be a resource marker identifier (A-Z, 0-9, -)'
    if test.get('fault') is not None and test['fault'] not in environment.FAULTS:
        return f'fault must be one of {list(environment.FAULTS)}'
    if 'limits' in test and not isinstance(test['limits'], dict):
        return 'limits must be an object'
    timeout = (test.get('limits') or {}).get('timeout_seconds', 15)
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        return 'limits.timeout_seconds must be a positive number'
    if test.get('api_key', 'anon-jwt') not in API_KEY_FORMATS:
        return f'api_key must be one of {list(API_KEY_FORMATS)}'
    if test.get('fault_api_key') is not None and test['fault_api_key'] not in API_KEY_FORMATS:
        return f'fault_api_key must be one of {list(API_KEY_FORMATS)}'
    for name in _typed_params(template, 'uuid'):
        if not isinstance(test.get(name), str) or not UUID.match(test[name]):
            return f'{name} must be a UUID'
    return None


def _is_positive_int(v):
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


# 〈定義：必要輸入〉 checked from the ScanManifest. Every limit must be stated: a missing or
# unbounded limit is never replaced by an unlimited default (TK-SCP-002).
SCOPE_PARTS = ('endpoints', 'resources', 'allowed_operations', 'data_scope')
LIMIT_RULES = {
    'max_cost_usd': (lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0,
                     'a number >= 0 (0 allows no spending)'),
    'max_duration_seconds': (_is_positive_int, 'a positive integer'),
    'max_requests': (_is_positive_int, 'a positive integer'),
    'max_concurrency': (_is_positive_int, 'a positive integer'),
    'model_providers': (lambda v: isinstance(v, list), 'a list ([] allows no provider)'),
    'network_allowlist': (lambda v: isinstance(v, list) and len(v) > 0 and '*' not in v,
                          'a non-empty list of hosts without wildcards'),
}


def _nonempty_str(v):
    return isinstance(v, str) and bool(v.strip())


def _planned_tests(manifest):
    """The dict entries of manifest['tests'], so a blocked report can still be built when tests is malformed."""
    tests = manifest.get('tests')
    return [t for t in tests if isinstance(t, dict)] if isinstance(tests, list) else []


def _commit(manifest):
    """The source commit under test (受測範圍 of 〈定義：必要輸入〉, TK-SCP-002), or None when the ScanManifest
    names no usable one; None then blocks at preflight, the one place TK-DAT-001 allows a null commit."""
    commit = manifest.get('commit')
    return commit if _nonempty_str(commit) else None


EXCLUSION_KEYS = ('ref', *coverage.EXCLUSION_FIELDS)


def _exclusion_problems(scope):
    """〈定義：覆蓋面向〉 排除項 as the ScanManifest gives them (受測範圍 scope.exclusions, optional): a list of
    objects of ref, reason, confirmed_by and version, each a string when given. A wrong shape blocks the run;
    a missing or blank reason, confirmer or version does not, and the item then stays in the denominator
    (TK-EVD-009)."""
    if 'exclusions' not in scope:
        return []
    exclusions = scope['exclusions']
    if not isinstance(exclusions, list):
        return ['scope.exclusions (受測範圍) must be a list']
    problems = []
    for i, e in enumerate(exclusions):
        where = f'scope.exclusions/{i}'
        if not isinstance(e, dict):
            problems.append(f'{where} must be an object')
        elif not _nonempty_str(e.get('ref')):
            problems.append(f'{where}.ref must be a non-empty string naming an inventory item')
        elif unknown := sorted(set(e) - set(EXCLUSION_KEYS), key=str):
            problems.append(f'{where} has fields other than {", ".join(EXCLUSION_KEYS)}: {unknown}')
        elif wrong := [f for f in coverage.EXCLUSION_FIELDS if e.get(f) is not None and not isinstance(e[f], str)]:
            problems.append(f'{where}: {", ".join(wrong)} must be text')
    return problems


def _exclusions(manifest):
    """The exclusions of a ScanManifest whose shape is right, else none: a run blocked for their shape excludes
    nothing."""
    scope = manifest.get('scope')
    if not isinstance(scope, dict) or 'exclusions' not in scope or _exclusion_problems(scope):
        return []
    return scope['exclusions']


def _input_problems(manifest):
    """Missing or invalid required inputs (〈定義：必要輸入〉, TK-SCP-002) of the ScanManifest; each one blocks the run."""
    problems = []
    if not _nonempty_str(manifest.get('id')):
        problems.append('id (ScanManifest identifier) must be a non-empty string')
    if _commit(manifest) is None:
        problems.append('commit (受測範圍: the source commit under test) is missing: dynamic testing is not started')
    target = manifest.get('target')
    if not isinstance(target, dict):
        problems.append('target (受測範圍) must be an object {project, source_digest}')
    else:
        for part in ('project', 'source_digest'):
            if not _nonempty_str(target.get(part)):
                problems.append(f'target.{part} (受測範圍) must be a non-empty string')
    scope = manifest.get('scope')
    if not isinstance(scope, dict):
        problems.append('scope (受測範圍) is missing: dynamic testing is not started')
    else:
        problems += [f'scope.{p} (受測範圍) is missing' for p in SCOPE_PARTS if not scope.get(p)]
        resources = scope.get('resources')
        if resources and not isinstance(resources, list):
            problems.append('scope.resources (受測範圍) must be a list')
        elif resources:
            problems += _resource_problems(resources)
        problems += _exclusion_problems(scope)
        ops = scope.get('allowed_operations')
        if ops and (not isinstance(ops, list) or any(o not in authorization.METHODS for o in ops)):
            problems.append(f'scope.allowed_operations (受測範圍) must list HTTP methods of {list(authorization.METHODS)}')
    problems += _authorization_ref_problems(manifest)
    limits = manifest.get('limits')
    if not isinstance(limits, dict):
        problems.append('limits (執行限制) are missing: no unlimited default is used')
    else:
        for name, (ok, expected) in LIMIT_RULES.items():
            if name not in limits:
                problems.append(f'limits.{name} (執行限制) is missing: no unlimited default is used')
            elif not ok(limits[name]):
                problems.append(f'limits.{name} must be {expected}, got {limits[name]!r}')
    tests = manifest.get('tests')
    if not isinstance(tests, list):
        problems.append('tests must be a list of test objects')
    else:
        test_ids = []
        for i, t in enumerate(tests):
            if not isinstance(t, dict):
                problems.append(f'tests/{i} must be an object')
            elif _nonempty_str(tid := t.get('test_id')):
                test_ids.append((i, tid))
        problems += [f'tests: duplicate test_id {tid!r}' for _, tid in _duplicates(test_ids)]
    return problems


def _is_ref(ref):
    """A reference to a control-zone record: its path and digest, and nothing else."""
    return (isinstance(ref, dict) and set(ref) == {'path', 'digest'}
            and all(isinstance(v, str) and v for v in ref.values()))


def _authorization_ref_problems(manifest):
    """〈定義：必要輸入〉 測試授權: the ScanManifest references a control-zone record by path and digest and
    never carries the record itself, which whoever writes the ScanManifest could then grant (TK-ENV-002)."""
    if 'authorization' not in manifest:
        return ['authorization (測試授權) is missing: the run is not started']
    ref = manifest['authorization']
    if not _is_ref(ref):
        return ['authorization (測試授權) must reference a control-zone record by path and digest, '
                'never carry the record or an approval itself']
    return []


def _load_review_record(manifest):
    """(_Reviewed, None) for the review record the ScanManifest references, an empty one when it references
    none, or (None, problem) (〈定義：覆核紀錄〉)."""
    if 'review_record' not in manifest:
        return _Reviewed(), None
    ref = manifest['review_record']
    if not _is_ref(ref):
        return None, 'review record: review_record must reference a control-zone record by path and digest'
    try:
        doc = control.read(ref['path'], ref['digest'], manifest['target']['project'], 'review record')
    except control.RecordUnusable as e:
        return None, f'review record unusable: {e}'
    problems = review.validate(doc)
    if problems:
        return None, 'review record unusable: not a valid review record: ' + '; '.join(problems)
    return _Reviewed(doc, dict(ref)), None


def _load_authorization(manifest, now):
    """(_Granted, None) for the referenced record covering a run starting at now, or (None, problem)."""
    ref = manifest['authorization']
    try:
        doc = authorization.read(ref['path'], ref['digest'], manifest['target']['project'])
    except authorization.AuthorizationUnusable as e:
        return None, f'test authorization unusable: {e}'
    problem = authorization.period_problem(doc, now)
    if problem:
        return None, f'test authorization does not cover this run: {problem}'
    return _Granted(doc, dict(ref)), None


def _resource_problems(resources):
    """受測資源 of 〈定義：必要輸入〉: each one is {name, impact}, impact listing the 〈定義：高影響類別〉 it
    involves, [] for none. Refused: a missing impact (never taken as none), a code not in the table, a
    code listed twice, a resource listed twice."""
    problems, names = [], []
    for i, r in enumerate(resources):
        if not isinstance(r, dict):
            problems.append(f'scope.resources/{i} must be an object {{name, impact}}, got {r!r}')
            continue
        name = r.get('name')
        if not (isinstance(name, str) and name):
            problems.append(f'scope.resources/{i}.name (受測資源) is missing')
            continue
        where = f'scope.resources/{i} ({name!r})'
        names.append((where, name))
        problems += policy.impact_problems(r.get('impact'), where)
    problems += [f'{where} is listed twice' for where, _ in _duplicates(names)]
    return problems


TEMPLATE_OVERRIDES = ('policy_template', 'policy_template_path')
FAULT_FIELDS = ('fault', 'fault_api_key')


def _template_override_problems(manifest):
    """TK-REQ-008: the S2 template comes from the toolkit only (toolkit.policy.load_template), which
    never reads the ScanManifest. These field names, the ones a ScanManifest would use to bring a
    template, are refused so the run does not look as if it used them; other unknown fields are
    not checked here."""
    return [f'{name}: the S2 template is provided by the toolkit only; a ScanManifest cannot supply '
            f'or replace it' for name in TEMPLATE_OVERRIDES if name in manifest]


def _item_versions(item, items):
    """Version of `item` and of the S1 entry its review.basis names (if any), or None when absent."""
    if item is None:
        return None
    basis = (item.get('review') or {}).get('basis')
    s1 = items.get(basis) if isinstance(basis, str) else None
    return item['version'], (s1['version'] if s1 and s1['source'] == 'S1' else None)


def _needs_handover(prepared, tests, plan):
    """Whether a generated or updated confirmation list itself introduced a new item block or item version on a
    valid planned test (〈定義：確認清單〉 寫入控制區)."""
    if not prepared.updated:
        return False
    old = prepared.on_disk.items
    for t in tests:
        if _plan_problem(t) is not None or (item := report.listed_item(prepared.items, t)) is None:
            continue
        problem = _item_problem(t, prepared.items, plan)
        if problem is not None and (problem, _item_versions(item, prepared.items)) != (
                _item_problem(t, old, plan), _item_versions(report.listed_item(old, t), old)):
            return True
    return False


def _preflight(state, now):
    """Everything a run checks before it starts the environment, in this order (the first problem found is the
    reason, TK-RUN-001): the required inputs (TK-SCP-002), the S2 template and S1 entries (TK-REQ-008), the
    source digest, then the records of the control zone (authorization, confirmation list, review record), what
    the BuildRecipe provides, and each test. Returns why the run is blocked, or None; the records it read and the
    checks of each test are then in state."""
    manifest = state.manifest
    missing = _input_problems(manifest)
    if missing:
        return 'required inputs missing; nothing was started: ' + '; '.join(missing)
    overrides = _template_override_problems(manifest) + _s1_problems(manifest)
    if overrides:
        return 'nothing was started: ' + '; '.join(overrides)
    faulted = [str(t.get('test_id')) for t in _planned_tests(manifest)
               if isinstance(t, dict) and any(name in t for name in FAULT_FIELDS)]
    if faulted and not state.self_validation:  # 〈定義：故障注入〉: a scan of an application injects nothing
        return ('nothing was started: tests ' + ', '.join(faulted) + ' carry a fault to inject; faults are injected in '
                'self-validation runs of the toolkit only, not in a scan')
    project = manifest['target']['project']
    pinned, actual = manifest['target']['source_digest'], e1.source_digest(project)
    if pinned != actual:
        return (f'source_digest of the ScanManifest ({pinned}) does not match '
                f'the project ({actual}); nothing was started')
    granted, problem = _load_authorization(manifest, now)
    if problem:
        return f'nothing was started: {problem}'
    # A record is stored only once it is read: one that could not be read stays empty in the blocked report.
    state.granted = granted
    prepared_list, problem = _load_confirmation_list(manifest, now)
    if problem:
        return f'nothing was started: {problem}'
    state.listed = prepared_list.on_disk
    reviewed, problem = _load_review_record(manifest)
    if problem:
        return f'nothing was started: {problem}'
    state.reviewed = reviewed
    recipe, _ = e1.load_recipe(project)  # without one, e1.prepare blocks the run at the BuildRecipe step
    if recipe is not None and not _nonempty_str(recipe.get('sample')):
        return 'nothing was started: BuildRecipe sample is missing or not a non-empty string'
    problem = recipe and authorization.target_problem(state.granted.doc, recipe['sample'], e1.MODE)
    if problem:
        return f'nothing was started: test authorization does not cover this run: {problem}'
    checks = _TestChecks.of(state, recipe, now, items=prepared_list.items)
    prechecks = [checks.precheck(t) for t in manifest['tests']]
    runnable = any(p.runnable for p in prechecks)
    if runnable or _needs_handover(prepared_list, manifest['tests'], checks.plan):
        listed, problem = prepared_list.write()
        if problem:
            return f'nothing was started: {problem}'
        state.listed = listed
    elif state.listed.ref is not None and prepared_list.updated:
        prechecks = [_TestChecks.of(state, recipe, now, items=state.listed.items).precheck(t)
                     for t in manifest['tests']]
    state.prechecks, state.gaps = prechecks, checks.identity_gaps()
    if not runnable:
        return 'no test in the ScanManifest can run; nothing was started'
    return None


def _environment_report(profile):
    """The report's environment summary from an EnvironmentProfile (〈定義：核心資料物件與相依紀錄〉, TK-SCP-001,
    TK-ENV-007, TK-EVD-005)."""
    return {
        'mode': profile['mode'],
        'profile_digest': _digest(profile),
        'unsupported': list(profile.get('unsupported') or []),
        'known_differences': list(profile.get('known_differences') or []),
        'isolation': profile.get('isolation') or {},  # 〈定義：E1 隔離〉; an empty record does not validate
    }


def run(manifest, prepare=environment.prepare, clock=time.monotonic, abort=None, self_validation=False):
    """Run the manifest's tests against its project and return the report and its Markdown.

    A run that cannot start (source digest mismatch, BuildRecipe step blocked) is
    reported with status blocked and the reason; every planned test is blocked.
    clock() gives seconds; the run's time limit is measured with it, from here on. abort is the control
    area's stop signal (Abort): once requested, no further case is dispatched and the run ends as
    〈定義：中止與清理〉 says, with a report. self_validation marks a run of the toolkit's own acceptance
    (TK-VAL-001): only then may a test carry a fault to inject (〈定義：故障注入〉). It is not a field of the
    ScanManifest, so the plan of a scan cannot turn it on.
    """
    abort = abort or Abort(clock)
    run_start = datetime.now(timezone.utc)
    run_id = f'run-{run_start:%Y%m%d%H%M%S}-{secrets.token_hex(3)}'
    state = _RunState(manifest, _Records(run_id, _commit(manifest)), clock=clock, started=clock(),
                      self_validation=self_validation)
    problem = _preflight(state, run_start)
    if problem:
        return _blocked(state, problem, stage='preflight')
    project = manifest['target']['project']
    prepared = prepare(project)
    if isinstance(prepared, e1.Blocked):
        return _blocked(state, f'environment blocked at BuildRecipe step {prepared.step}: '
                               f'{prepared.reason}', stage='dynamic_execution')
    ops = prepared.env  # the operations on the stack (toolkit.environment), not its handles
    ops.request_limit = manifest['limits']['max_requests']

    def stop_if_aborted():  # before every request and observer read of a case
        if abort.requested:
            _stop_dispatch(ops, abort)
            raise environment.Aborted(abort.reason)
    ops.before_request = stop_if_aborted
    cleanup = None
    executions, findings = [], []
    stopped = None  # reason the remaining tests cannot run
    undispatched = 0  # cases the run's limits left no room for
    try:
        env_report = _environment_report(prepared.profile)
        if not env_report['unsupported']:
            for test, precheck in zip(manifest['tests'], state.prechecks):
                started, evidence = _now(), []
                if not precheck.runnable or stopped:
                    executions.append(_execution(state, test, started, *precheck.outcome(stopped)))
                    continue
                short = None if abort.requested else _limit_reached(state, test)
                if isinstance(short, _TimeUsedUp):
                    abort.request(str(short), source='system')  # TK-RUN-004 資源超限
                if abort.requested:  # TK-RUN-005 step 1: nothing is dispatched after the request
                    _stop_dispatch(ops, abort)
                    executions.append(_execution(state, test, started, 'cancelled',
                                                 f'not dispatched: the run was aborted ({abort.reason})'))
                    continue
                if short:  # TK-BUD-003: limited before dispatch; the case stays in the denominator, untested
                    executions.append(_execution(state, test, started, 'untested', f'not dispatched: {short}'))
                    undispatched += 1
                    continue
                denial = _case_kind(test) == item_rule.DENIAL
                undo = None
                try:
                    # Inside the case's handling: a failed injection is that case's error, not the run's (TK-RUN-001).
                    undo, injected = ops.inject(test.get('fault'), test['actor_ref'],
                                                test.get('fault_api_key') or test.get('api_key', 'anon-jwt'), _timeout(test))
                    if injected:
                        evidence.append(injected)
                    _check_api_keys(ops, test, denial)
                    if denial:
                        result, checks = _denial_case(ops, test, evidence)
                    else:
                        result, checks = _allowed_case(ops, test, evidence)
                    error = None
                except observer.ObservationFailed as e:
                    result, checks, error = 'blocked', None, f'observation failed: {e}'
                except environment.RequestTimeout as e:
                    result, checks, error = 'error', None, f'timeout: {e}'
                except environment.RequestFailed as e:
                    result, checks, error = 'error', None, f'request failed: {e}'
                except environment.ApiKeyUnavailable as e:
                    result, checks, error = 'blocked', None, f'API key unavailable: {e}'
                except environment.InjectionFailed as e:  # 〈定義：故障注入〉: never judged as if the fault were there
                    result, checks, error = 'blocked', None, f'fault injection failed: {e}'
                    if e.evidence:
                        evidence.append(e.evidence)
                except environment.LimitReached as e:  # the count before dispatch should have held the case back
                    result, checks, error = 'error', None, f'request limit reached inside the case: {e}'
                except environment.Aborted:  # TK-RUN-005 step 5: what it did before the abort is not known
                    result, checks, error = 'error', None, ('aborted in flight: the case did not finish and its '
                                                            'outcome is unknown')
                    abort.in_flight = test['test_id']
                finally:
                    if undo and not abort.requested:  # an aborted run is about to destroy the stack
                        undo()
                    state.requests = ops.requests
                if test.get('fault') and result in ('passed', 'failed'):
                    # 〈定義：故障注入〉: a fault makes its case undeterminable. A verdict means the fault was not
                    # in place, and what was judged is not what the test set out to try.
                    result, error = 'blocked', (f'the injected fault {test["fault"]} had no effect: the case was '
                                                f'judged {result} as if without it')
                ex = _execution(state, test, started, result, error,
                                approval_id=precheck.approval_id)  # it ran under this approval
                if test.get('fault'):
                    ex['fault'] = test['fault']
                ex['case_kind'] = _case_kind(test)
                if checks is not None:
                    ex['checks'] = checks
                ex['evidence'] = [{'id': f'{ex["id"]}-ev{i + 1}', **ev} for i, ev in enumerate(evidence)]
                executions.append(ex)
                if result == 'failed' and denial:  # a failed allowed case is a broken permitted access, not a leak
                    _record_finding(state, findings, test, ex)
                if denial and DENIAL_TEMPLATES[test['template_id']]['writes'] and not abort.requested:
                    reset = ops.reset()
                    if reset:
                        stopped = f'environment reset failed after {test["test_id"]}: {reset.reason}'
                        # TK-RUN-004 清理失敗: an abort by the system; TK-SBX-010 has the later cases blocked
                        abort.request(stopped, source='system', undispatched='blocked')
                        _stop_dispatch(ops, abort)
    finally:
        if abort.requested:
            _stop_dispatch(ops, abort)
            for step in ('in_flight_ended', 'evidence_kept', 'in_flight_checked'):
                abort.mark(step)  # the case in flight has ended; the records made so far go into the report
        cleanup = _clean_up(ops)
        if abort.requested:
            abort.mark('environment_isolated')
    if env_report['unsupported']:
        reason = 'environment outside support matrix (TK-SCP-001): ' + '; '.join(env_report['unsupported'])
        state.gaps = state.gaps + [{'scope': f'environment:{u}', 'reason': 'version outside support matrix (TK-SCP-001)'}
                                   for u in dict.fromkeys(env_report['unsupported'])]
        now = _now()
        executions = [_execution(state, t, now, *p.outcome(reason, 'unsupported'))
                      for t, p in zip(manifest['tests'], state.prechecks)]
        return _finish(state, executions, [], status='blocked', reason=reason,
                       stages=_stages(preflight={'status': 'completed'},
                                      dynamic_execution={'status': 'blocked', 'reason': reason}),
                       environment=env_report, matrix=_authorization_matrix(prepared), cleanup=cleanup,
                       abort=abort.record() if abort.requested else None)
    definite = all(e['result'] in ('passed', 'failed') for e in executions)
    cancelled = sum(e['result'] == 'cancelled' for e in executions)
    aborted = f'aborted by the {abort.source}: {abort.reason}' if abort.requested else ''
    if cancelled:  # TK-RUN-005 step 6: a run that left cases undispatched is cancelled, whatever the others say
        status, reason = 'cancelled', f'{aborted}; {cancelled} cases were not dispatched'
        dynamic = {'status': 'cancelled', 'reason': aborted}
    else:
        dynamic = ({'status': 'failed', 'reason': f'stopped, environment isolated: {stopped}'} if stopped
                   else {'status': 'completed'})
        reason = 'some tests have no definite result'
        if undispatched:
            reason += f'; {undispatched} not dispatched because an execution limit was reached (TK-BUD-003)'
        status, reason = ('completed', '') if definite else ('partial', reason)
    if cleanup['environment'] != 'destroyed':  # TK-ENV-003: a platform anomaly, never a completed run
        anomaly = 'platform anomaly: the environment was not destroyed (' + '; '.join(cleanup['leftovers']) + ')'
        status, reason = ('partial' if status == 'completed' else status), '; '.join(x for x in (reason, anomaly) if x)
    return _finish(state, executions, findings, status=status, reason=reason,
                   stages=_stages(preflight={'status': 'completed'}, dynamic_execution=dynamic),
                   environment=env_report,
                   matrix=_authorization_matrix(prepared), cleanup=cleanup,
                   abort=abort.record() if abort.requested else None)


def _clean_up(ops):
    """Destroy the environment and say whether it is gone (TK-ENV-003, 〈定義：中止與清理〉). A destroy that
    cannot be carried out is a leftover too: the report is still made."""
    try:
        left = ops.destroy()
    except (RuntimeError, OSError) as e:
        left = [f'destroy did not complete: {type(e).__name__}: {e}']
    return {'environment': 'destroy_failed' if left else 'destroyed', 'leftovers': left}


def _item_version(listed, test):
    """The version of the confirmation item the test rests on, or None when there is none (TK-REQ-004)."""
    item = listed.item(test)
    return item['version'] if item else None


def _execution(state, test, started, result, error=None, approval_id=None):
    ex = state.records.new('exec', test_id=test.get('test_id'), template_id=test.get('template_id'),
                           requirement_id=test.get('requirement_id'),
                           requirement_version=_item_version(state.listed, test),
                           actor_ref=test.get('actor_ref'),
                           resource_ref=test.get('resource_ref'), started_at=started, ended_at=_now(),
                           result=result, error=error, evidence=[])
    if approval_id:  # the extra approval a test that ran was let past 〈定義：測試授權紀錄〉 by (TK-ENV-001)
        ex['approval_id'] = approval_id
    return ex


def _handover_note(listed):
    """Where a generated or updated confirmation list waits for the owner's review (交付確認)."""
    ref = listed.ref
    if not (ref and ref['updated']):
        return ''
    return (f'; the confirmation list was handed over for review at {ref["path"]} ({ref["digest"]}): review its '
            f'pending items and reference it in the ScanManifest by this path and digest')


def _requirements(manifest, listed):
    """The confirmation items the planned tests rest on, as the report shows them."""
    used = {i['item_id']: i for t in _planned_tests(manifest) if (i := listed.item(t))}  # each item once, in plan order
    return [item_rule.requirement(i) for i in used.values()]


def _blocked(state, reason, stage='preflight'):
    """Every planned test blocked at `stage`, or held by its own precheck; later stages do not run
    (〈定義：工作階段〉)."""
    now = _now()
    tests = _planned_tests(state.manifest)
    prechecks = state.prechecks if len(state.prechecks) == len(tests) else [_Precheck()] * len(tests)
    executions = [_execution(state, t, now, *p.outcome(reason)) for t, p in zip(tests, prechecks)]
    if stage == 'preflight':
        stages = _stages(preflight={'status': 'blocked', 'reason': reason},
                         dynamic_execution={'status': 'not_run', 'reason': 'preflight blocked; no dependent work'})
    else:
        stages = _stages(preflight={'status': 'completed'}, dynamic_execution={'status': 'blocked', 'reason': reason})
    return _finish(state, executions, [], status='blocked', reason=reason, stages=stages,
                   environment=None, matrix=[])


NOT_IMPLEMENTED = {'status': 'not_run', 'reason': 'stage not implemented in this toolkit version'}


def _stages(preflight, dynamic_execution):
    """The six stages of 〈定義：工作階段〉 with their outcome in this run."""
    return [{'stage': 'preflight', **preflight},
            {'stage': 'static_analysis', **NOT_IMPLEMENTED},
            {'stage': 'model_review', **NOT_IMPLEMENTED},
            {'stage': 'threat_planning', **NOT_IMPLEMENTED},
            {'stage': 'dynamic_execution', **dynamic_execution},
            {'stage': 'judgement_report', 'status': 'completed'}]


# The SQL command a test's HTTP method exercises, for the inventory items it covers (inventory.covers).
COMMAND_OF_METHOD = {'GET': 'select', 'POST': 'insert', 'PATCH': 'update', 'DELETE': 'delete'}
MODULE = 'supabase-rls'  # every test template of this version is judged by this framework module (〈定義：框架模組〉)
NOT_READ = 'preflight blocked; the project files were not read'
NO_MIGRATIONS = 'the project has no supabase/migrations/*.sql files'


def _inventory(state, stages):
    """The inventory of the project under test (〈定義：擷取結果〉): read only once preflight verified the source,
    and not called complete when there is nothing to read (TK-ARC-004). Identity gaps join the unsupported scopes."""
    if stages[0]['status'] != 'completed':
        return inventory.not_read(NOT_READ, extra_unsupported=state.gaps)
    files = extract.read_migrations(state.manifest['target']['project'])
    if not files:
        return inventory.not_read(NO_MIGRATIONS, extra_unsupported=state.gaps)
    return inventory.inventory(files, extra_unsupported=state.gaps)


def _command(test):
    """The SQL command a test exercises, or None when its template is not one of ours."""
    tid = test.get('template_id')
    if not isinstance(tid, str):
        return None
    template = DENIAL_TEMPLATES.get(tid) or ALLOWED_TEMPLATES.get(tid)
    return COMMAND_OF_METHOD[template['method']] if template else None


def _cases(state, executions, inv):
    """The scheduled tests as coverage() takes them: each with its result and the inventory items it exercises.
    A test rests on a confirmation item, which names its resource (S2) or resources (S1)."""
    cases = []
    for test, ex in zip(_planned_tests(state.manifest), executions):
        item = state.listed.item(test)
        resources = [item['resource']] if item and item.get('resource') else list((item or {}).get('resources', []))
        command = _command(test)
        # passed and failed are only given when the precondition and the control held (everything else is blocked)
        cases.append({'id': ex['test_id'], 'record': ex['id'], 'result': ex['result'], 'valid': True, 'module': MODULE,
                      'covers': inventory.covers(inv, resources, command) if command else []})
    return cases


def _finish(state, executions, findings, status, reason, stages, environment, matrix, cleanup=None, abort=None):
    manifest, records, listed = state.manifest, state.records, state.listed
    inv = _inventory(state, stages)
    env_supported = not (environment and environment['unsupported'])
    numbers = coverage.coverage(inv, _cases(state, executions, inv), _exclusions(manifest),
                                environment_supported=env_supported)
    read = not any(u['file'] == '(project)' for u in inv['unresolved'])
    cov_record = records.new(
        'coverage', inventory_source=(f"{inv['rule']} extraction of supabase/migrations/*.sql" if read
                                      else inv['unresolved'][0]['reason']),
        inventory={'rule': inv['rule'], 'supported_version': extract.SUPPORTED_VERSION, 'loaded': inv['loaded'],
                   'completeness': inv['completeness'], 'unresolved': inv['unresolved']},
        unsupported_items=[dict(u) for u in inv['unsupported_items']], **numbers)
    doc = {'schema_version': '1', 'run_id': records.run_id, **({'self_validation': True} if state.self_validation else {}), 'id': f'report-{records.run_id}', 'created_at': _now(),
           'source_id': SOURCE_ID, 'commit': records.commit, 'status': status,
           'manifest': {'id': manifest.get('id'), 'digest': _digest(manifest)},
           'stages': stages, 'requirements': _requirements(manifest, listed), 'authorization_matrix': matrix,
           'execution_records': executions, 'findings': findings, 'coverage': cov_record,
           'limits': _limits_report(state),
           'source_changes': []}  # TK-ENV-006: the source under test is the pinned one (source_digest); v0.1 changes none
    if reason:  # status_reason says why the run is not completed, and what the owner has to do about it
        doc['status_reason'] = reason + _handover_note(listed)
    if environment:
        doc['environment'] = environment
    if cleanup:
        doc['cleanup'] = cleanup
    if abort:
        doc['abort'] = abort
    if listed.ref:
        doc['confirmation_list'] = dict(listed.ref)
    if state.granted.ref:
        doc['authorization'] = state.granted.report()
    # Each finding's review state, as of when the report is made (TK-HRV-010).
    doc = review.apply(doc, state.reviewed.doc, state.reviewed.ref, doc['created_at'])
    problems = report.validate(doc)
    if problems:
        raise RuntimeError('the toolkit produced an invalid report: ' + '; '.join(problems))
    return Run(doc, report.render_markdown(doc))


# --- command line (〈定義：命令列入口〉) -----------------------------------------------

REPORT_JSON, REPORT_MARKDOWN = 'report.json', 'report.md'
# Exit status of main(): a report was written, whatever the run's status; the command line, the ScanManifest
# or the output directory was refused before anything was started; the toolkit itself failed.
EXIT_REPORT, EXIT_REFUSED, EXIT_TOOL_ERROR = 0, 2, 3


class _Refused(Exception):
    """An input the command line does not act on: nothing was started and nothing was written."""


def _read_manifest(path):
    """The ScanManifest in the file at path, or _Refused when there is no such file, it is not JSON or it is
    not an object. What the object lacks is for run()'s preflight to say, in a report (TK-SCP-002)."""
    try:
        manifest = json.loads(Path(path).read_text(encoding='utf-8'))
    except OSError as e:
        raise _Refused(f'the ScanManifest {path} cannot be read: {e.strerror or e}') from e
    except (ValueError, RecursionError) as e:
        raise _Refused(f'the ScanManifest {path} is not valid JSON: {e}') from e
    if not isinstance(manifest, dict):
        raise _Refused(f'the ScanManifest {path} must be a JSON object')
    return manifest


def _output_directory(path, manifest):
    """The directory the report goes to, created and checked before the run so that a run is never made
    whose report cannot be written: outside the source under test, which the code under test could write
    to (TK-SBX-005), and holding no earlier report, which is never overwritten."""
    target = manifest.get('target')
    project = target.get('project') if isinstance(target, dict) else None
    try:
        if _nonempty_str(project):
            control.outside_source(path, project, 'report')
        directory = Path(path)
        directory.mkdir(parents=True, exist_ok=True)
    except control.RecordUnusable as e:
        raise _Refused(str(e)) from e
    except OSError as e:
        raise _Refused(f'the output directory {path} cannot be used: {e.strerror or e}') from e
    existing = [name for name in (REPORT_JSON, REPORT_MARKDOWN) if (directory / name).exists()]
    if existing:
        raise _Refused(f'{directory} already holds {" and ".join(existing)}; a report is not overwritten, '
                       f'give another directory')
    return directory


ABORT_SIGNALS = ('SIGINT', 'SIGTERM')


def _abort_on_signals(abort, err):
    """〈定義：中止與清理〉 操作者中止: the first SIGINT or SIGTERM asks the run to abort, and the run ends with a
    report; a second one forces it to stop at once, without a report (the stack is still stopped). Returns
    the function that puts the earlier handlers back. Outside the main thread no handler can be set."""
    asked = []

    def handle(number, frame):
        name = signal.Signals(number).name
        asked.append(name)
        if len(asked) == 1:
            abort.request(f'stopped by the operator ({name})', source='operator')  # keeps an earlier request, if any
            print(f'abort requested ({name}): no further case is dispatched; the report follows. '
                  f'Send it again to force the run to stop without a report.', file=err)
        else:
            raise KeyboardInterrupt
    earlier = {}
    for name in ABORT_SIGNALS:
        try:
            earlier[name] = signal.signal(getattr(signal, name), handle)
        except (ValueError, OSError, AttributeError):
            pass

    def restore():
        for name, handler in earlier.items():
            signal.signal(getattr(signal, name), handler)
    return restore


def main(argv, out, err, prepare=environment.prepare):
    """The command line of one scan run (〈定義：命令列入口〉): read the ScanManifest, run it, and write the
    JSON report and the Markdown made from it (TK-EVD-003) to the output directory. Everything about the run
    is run()'s; this only reads, writes and reports. The run's status goes to out, why nothing was done or
    what failed goes to err; no credential is printed or written (TK-IDN-005). Returns the exit status."""
    parser = argparse.ArgumentParser(prog='scan_run.py', description='Run one scan from a ScanManifest.')
    parser.add_argument('--manifest', required=True, help='the ScanManifest, a JSON file')
    parser.add_argument('--self-validation', action='store_true',
                        help="a run of the toolkit's own acceptance: only such a run takes tests with a fault to inject")
    parser.add_argument('--out', required=True, help='directory for report.json and report.md, outside the '
                                                     'source under test; an earlier report is not overwritten')
    args = parser.parse_args(argv)
    try:
        manifest = _read_manifest(args.manifest)
        directory = _output_directory(args.out, manifest)
    except _Refused as e:
        print(f'not started: {e}', file=err)
        return EXIT_REFUSED
    abort = Abort()
    restore = _abort_on_signals(abort, err)
    try:
        done = run(manifest, prepare=prepare, abort=abort, self_validation=args.self_validation)
        # Exclusive creation: a report that appeared during the run is not overwritten either.
        with open(directory / REPORT_JSON, 'x', encoding='utf-8', newline='\n') as f:
            f.write(json.dumps(done.report, ensure_ascii=False, indent=2) + '\n')
        with open(directory / REPORT_MARKDOWN, 'x', encoding='utf-8', newline='\n') as f:
            f.write(done.markdown)
    except (RuntimeError, OSError) as e:
        print(f'failed: {type(e).__name__}: {e}', file=err)
        return EXIT_TOOL_ERROR
    except KeyboardInterrupt:  # the second signal: the stack was stopped on the way out, no report is made
        print('interrupted: the run was forced to stop; no report was written', file=err)
        return EXIT_TOOL_ERROR
    finally:
        restore()
    status = done.report['status']
    print(f'run {done.report["run_id"]}: {status} ({report.RUN_LABELS[status]})', file=out)
    if done.report.get('status_reason'):
        print(f'reason: {done.report["status_reason"]}', file=out)
    print(f'report: {directory / REPORT_JSON}', file=out)
    print(f'markdown: {directory / REPORT_MARKDOWN}', file=out)
    return EXIT_REPORT
