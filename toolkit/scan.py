"""One scan run, the toolkit's main seam: run(manifest) -> Run(report, markdown).

Minimal controller (tracer bullet, #3): prepare the E1 stack from the project's
BuildRecipe, run the manifest's fixed tests, judge them with the observer,
and produce the versioned JSON report plus the Markdown generated from it.
"""
import hashlib
import json
import re
import secrets
import socket
import string
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from toolkit import e1, observer, report

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


API_KEY_FORMATS = ('anon-jwt', 'publishable')


class RequestTimeout(Exception):
    """A request exceeded the test's time limit: an execution error, never a pass (〈定義：測試結果〉)."""


def _request(env, identity, method, path, body=None, api_key='anon-jwt', prefer='return=representation',
             timeout=15):
    """An actor request through the data API, as the given identity. Returns (status, parsed body)."""
    headers = {'apikey': env.api_keys.get(api_key, ''), 'Prefer': prefer}
    if identity in env.tokens:
        headers['Authorization'] = 'Bearer ' + env.tokens[identity]['access_token']
    data = json.dumps(body).encode() if body is not None else None
    if data is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(env.api_url + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        with e:
            status, raw = e.code, e.read()
    except (TimeoutError, socket.timeout) as e:
        raise RequestTimeout(f'{method} {path} exceeded {timeout} s') from e
    except urllib.error.URLError as e:
        if isinstance(e.reason, (TimeoutError, socket.timeout)):
            raise RequestTimeout(f'{method} {path} exceeded {timeout} s') from e
        raise
    try:
        return status, json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return status, None


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


# Faults a self-validation test may inject (TK-VAL-001 無法判定案例). Recorded on the ExecutionRecord.
FAULTS = ('session-revoked', 'observer-unavailable')


def _inject(env, test):
    """Apply the test's fault, if any. Returns a function that undoes what can be undone."""
    fault = test.get('fault')
    if fault == 'session-revoked':
        _request(env, test['actor_ref'], 'POST', '/auth/v1/logout?scope=global')
        return lambda: None  # the actor stays logged out for the rest of the run
    if fault == 'observer-unavailable':
        saved = env.observer['password']
        env.observer['password'] = 'wrong-' + secrets.token_hex(8)

        def restore():
            env.observer['password'] = saved
        return restore
    return lambda: None


def _identity_email(env, name):
    return next((i.get('email') for i in env.recipe['auth']['identities'] if i['name'] == name), None)


def _denial_case(env, test, evidence):
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
        key = test.get('api_key', 'anon-jwt') if identity == test['actor_ref'] else 'anon-jwt'
        status, data = _request(env, identity, method, path, body, key, prefer, _timeout(test))
        rows = data if isinstance(data, list) else None
        evidence.append({'channel': 'actor', 'identity_ref': identity, 'api_key_format': key,
                         'request': {'method': method, 'path': path, 'prefer': prefer},
                         'response': {'status': status, 'rows': len(rows) if rows is not None else None}})
        return status, rows, data

    def observe(point):
        state = observer.document_row_state(env, marker)
        evidence.append({'channel': 'observer', 'identity_ref': env.observer['role'], 'point': point,
                         'observation': state})
        return state

    # 1. The owner's control operation succeeds, and the resource is in the expected state.
    path, body = (_fill(v, test) for v in template['control'])
    status, rows, _ = actor(test['owner_ref'], method, path, body)
    control_ok = status in (200, 201) and rows is not None and len(rows) == 1
    before = observe('before')
    checks['resource_and_control'] = control_ok and ready(before)
    if not checks['resource_and_control']:
        return 'blocked', checks

    # 2. The actor's identity is valid, and it is the identity the test expects.
    status, _, user = actor(test['actor_ref'], 'GET', '/auth/v1/user')
    expected_email = _identity_email(env, test['actor_ref'])
    if expected_email is None:  # an anonymous identity: the request must carry no user session
        checks['identity'] = status in (401, 403) and test['actor_ref'] not in env.tokens
    else:
        checks['identity'] = status == 200 and isinstance(user, dict) and user.get('email') == expected_email
    if not checks['identity']:
        return 'blocked', checks

    # The attempt, then 3. no leak and no change, and 4. response and side effects.
    path, body = (_fill(v, test) for v in template['attempt'])
    prefer = 'return=minimal' if template['writes'] else 'return=representation'
    status, rows, _ = actor(test['actor_ref'], method, path, body, prefer=prefer)
    after = observe('after')
    disclosed = any(isinstance(r, dict) and r.get('title') == marker for r in rows or [])
    changed = changed_by(before, after)
    checks['no_disclosure_or_change'] = not disclosed and not changed
    response_ok = status in template['denials'] and (status != 200 or rows == [])
    side_effect = after['table_digest'] != before['table_digest']
    checks['response_and_side_effects'] = response_ok and not side_effect
    if disclosed or changed or side_effect:
        return 'failed', checks
    if not response_ok:
        return 'error', checks
    return 'passed', checks


# Allowed-case templates: the requirement permits the access, so the case passes when it is granted.
ALLOWED_TEMPLATES = {'public-read-v1': {'table': 'announcements'}}


def _allowed_case(env, test, evidence):
    """Template public-read-v1 (e.g. USING (true) on public data, TK-DYN-004). Returns (result, checks)."""
    marker, key = test['resource_ref'], test.get('api_key', 'anon-jwt')
    path = f'/rest/v1/{ALLOWED_TEMPLATES[test["template_id"]]["table"]}?title=eq.{marker}&select=title'
    status, data = _request(env, test['actor_ref'], 'GET', path, api_key=key, timeout=_timeout(test))
    rows = data if isinstance(data, list) else None
    evidence.append({'channel': 'actor', 'identity_ref': test['actor_ref'], 'api_key_format': key,
                     'request': {'method': 'GET', 'path': path},
                     'response': {'status': status, 'rows': len(rows) if rows is not None else None}})
    granted = status == 200 and rows == [{'title': marker}]
    return ('passed' if granted else 'failed'), {'access_granted': granted}


def _authorization_matrix(prepared):
    """Identities and how their credentials travel, as confirmed in the BuildRecipe (TK-IDN-003)."""
    transport = prepared.env.recipe['auth']['token_transport']
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


def _identity_problem(test, identities):
    """測試身分: an identity the BuildRecipe does not provide is an unsupported matrix cell."""
    if identities is None:  # no readable recipe: the BuildRecipe step will block the run
        return None
    for ref in (test.get('actor_ref'), test.get('owner_ref')):
        if ref and ref not in identities:
            return f'identity {ref!r} is not in the BuildRecipe: unsupported cell of the authorization matrix'
    return None


def _test_problem(test, manifest, identities, restorable=True):
    """(result, reason) for a test that cannot run, or None."""
    reason = _plan_problem(test) or _requirement_problem(test, manifest)
    if reason:
        return 'blocked', reason
    if not restorable and DENIAL_TEMPLATES.get(test['template_id'], {}).get('writes'):
        return 'blocked', ('the BuildRecipe declares no reset (snapshot_reset.reset_scope "none"): '
                           'a write case cannot be restored safely and is not run (復原方式)')
    reason = _identity_problem(test, identities)
    return ('unsupported', reason) if reason else None


def _identity_gaps(manifest, identities):
    """Coverage gaps for identities the recipe cannot provide."""
    if identities is None:
        return []
    names = sorted({ref for t in manifest['tests'] for ref in (t.get('actor_ref'), t.get('owner_ref'))
                    if ref and ref not in identities})
    return [{'scope': f'identity:{n}', 'reason': 'no such identity in the BuildRecipe (測試身分)'} for n in names]


def _requirement_problem(test, manifest):
    """需求不明: the test's requirement must be in the manifest and confirmed. The toolkit never
    infers a requirement from the implementation (TK-REQ-005); confirmation itself is #9."""
    rid = test.get('requirement_id')
    req = next((r for r in manifest.get('requirements') or [] if r.get('id') == rid), None)
    if req is None:
        return f'requirement {rid!r} is not in the ScanManifest; requirement unknown, not inferred from the code'
    c = req.get('confirmation') or {}
    if not (c.get('by') and c.get('at') and c.get('version')):
        return f'requirement {rid!r} is not confirmed (by, at, version); the test is not run'
    return None


def _plan_problem(test):
    """Why a test from the manifest cannot run, or None."""
    template = test.get('template_id')
    if template not in TEST_TEMPLATES:
        return f'template_id {template!r} is not an allow-listed test template'
    if test.get('observation_ref') not in TEST_TEMPLATES[template]:
        return f'observation_ref {test.get("observation_ref")!r} is not an allow-listed observation template for {template}'
    for name in ['resource_ref'] + _typed_params(template, 'marker'):
        if not isinstance(test.get(name), str) or not IDENTIFIER.match(test[name]):
            return f'{name} must be a resource marker identifier (A-Z, 0-9, -)'
    if test.get('fault') is not None and test['fault'] not in FAULTS:
        return f'fault must be one of {list(FAULTS)}'
    timeout = (test.get('limits') or {}).get('timeout_seconds', 15)
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        return 'limits.timeout_seconds must be a positive number'
    if test.get('api_key', 'anon-jwt') not in API_KEY_FORMATS:
        return f'api_key must be one of {list(API_KEY_FORMATS)}'
    for name in _typed_params(template, 'uuid'):
        if not isinstance(test.get(name), str) or not UUID.match(test[name]):
            return f'{name} must be a UUID'
    return None


def _is_positive_int(v):
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


# 〈定義：必要輸入〉 checked from the ScanManifest. Every limit must be stated: a missing or
# unbounded limit is never replaced by an unlimited default (TK-SCP-002).
SCOPE_PARTS = ('endpoints', 'allowed_operations', 'data_scope')
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


def _input_problems(manifest):
    """Missing or invalid required inputs of the ScanManifest; each one blocks the run."""
    problems = []
    scope = manifest.get('scope')
    if not isinstance(scope, dict):
        problems.append('scope (受測範圍) is missing: dynamic testing is not started')
    else:
        problems += [f'scope.{p} (受測範圍) is missing' for p in SCOPE_PARTS if not scope.get(p)]
    limits = manifest.get('limits')
    if not isinstance(limits, dict):
        problems.append('limits (執行限制) are missing: no unlimited default is used')
    else:
        for name, (ok, expected) in LIMIT_RULES.items():
            if name not in limits:
                problems.append(f'limits.{name} (執行限制) is missing: no unlimited default is used')
            elif not ok(limits[name]):
                problems.append(f'limits.{name} must be {expected}, got {limits[name]!r}')
    return problems


def run(manifest):
    """Run the manifest's tests against its project and return the report and its Markdown.

    A run that cannot start (source digest mismatch, BuildRecipe step blocked) is
    reported with status blocked and the reason; every planned test is blocked.
    """
    run_id = f'run-{datetime.now(timezone.utc):%Y%m%d%H%M%S}-{secrets.token_hex(3)}'
    records = _Records(run_id, manifest['commit'])
    missing = _input_problems(manifest)
    if missing:
        return _blocked(manifest, records, 'required inputs missing; nothing was started: ' + '; '.join(missing),
                        stage='preflight')
    project = manifest['target']['project']
    pinned, actual = manifest['target']['source_digest'], e1.source_digest(project)
    if pinned != actual:
        return _blocked(manifest, records, f'source_digest of the ScanManifest ({pinned}) does not match '
                                           f'the project ({actual}); nothing was started', stage='preflight')
    recipe, _ = e1.load_recipe(project)
    identities = {i['name'] for i in recipe['auth']['identities']} if recipe else None
    restorable = not (recipe and recipe['snapshot_reset'].get('reset_scope') == 'none')
    problems = {t['test_id']: _test_problem(t, manifest, identities, restorable) for t in manifest['tests']}
    gaps = _identity_gaps(manifest, identities)
    if all(problems.values()):
        return _blocked(manifest, records, 'no test in the ScanManifest can run; nothing was started',
                        per_test=problems, stage='preflight', gaps=gaps)
    prepared = e1.prepare(project)
    if isinstance(prepared, e1.Blocked):
        return _blocked(manifest, records, f'environment blocked at BuildRecipe step {prepared.step}: '
                                           f'{prepared.reason}', stage='dynamic_execution')
    executions, findings = [], []
    stopped = None  # reason the remaining tests cannot run
    try:
        for test in manifest['tests']:
            started, evidence = _now(), []
            problem = problems[test['test_id']] or (('blocked', stopped) if stopped else None)
            if problem:
                executions.append(_execution(records, test, started, *problem))
                continue
            denial = test['template_id'] in DENIAL_TEMPLATES
            undo = _inject(prepared.env, test)
            try:
                if denial:
                    result, checks = _denial_case(prepared.env, test, evidence)
                else:
                    result, checks = _allowed_case(prepared.env, test, evidence)
                error = None
            except observer.ObservationFailed as e:
                result, checks, error = 'blocked', None, f'observation failed: {e}'
            except RequestTimeout as e:
                result, checks, error = 'error', None, f'timeout: {e}'
            finally:
                undo()
            ex = _execution(records, test, started, result, error)
            if test.get('fault'):
                ex['fault'] = test['fault']
            ex['case_kind'] = 'denial' if denial else 'allowed'
            if checks is not None:
                ex['checks'] = checks
            ex['evidence'] = [{'id': f'{ex["id"]}-ev{i + 1}', **ev} for i, ev in enumerate(evidence)]
            executions.append(ex)
            if result == 'failed' and denial:  # a failed allowed case is a broken permitted access, not a leak
                findings.append(records.new('finding', fingerprint=_fingerprint(test),
                                            fingerprint_version=FINGERPRINT_VERSION,
                                            requirement_id=test['requirement_id'],
                                            root_cause='object-ownership-not-enforced', status='confirmed',
                                            evidence_type='dynamic', execution_record_ids=[ex['id']]))
            if denial and DENIAL_TEMPLATES[test['template_id']]['writes']:
                reset = e1.reset(prepared.env)
                if isinstance(reset, e1.Blocked):
                    stopped = f'environment reset failed after {test["test_id"]}: {reset.reason}'
    finally:
        e1.destroy(prepared.env)
    definite = all(e['result'] in ('passed', 'failed') for e in executions)
    dynamic = ({'status': 'failed', 'reason': f'stopped, environment isolated: {stopped}'} if stopped
               else {'status': 'completed'})
    return _finish(manifest, records, executions, findings, gaps=gaps,
                   status='completed' if definite else 'partial',
                   reason='' if definite else 'some tests have no definite result',
                   stages=_stages(preflight={'status': 'completed'}, dynamic_execution=dynamic),
                   environment={'mode': prepared.profile['mode'], 'profile_digest': _digest(prepared.profile)},
                   matrix=_authorization_matrix(prepared))


def _execution(records, test, started, result, error=None):
    return records.new('exec', test_id=test['test_id'], template_id=test['template_id'],
                       requirement_id=test['requirement_id'], actor_ref=test['actor_ref'],
                       resource_ref=test['resource_ref'], started_at=started, ended_at=_now(),
                       result=result, error=error, evidence=[])


def _blocked(manifest, records, reason, per_test=None, stage='preflight', gaps=()):
    """Every planned test blocked at `stage`; later stages do not run (〈定義：工作階段〉)."""
    now = _now()
    per_test = per_test or {}
    executions = [_execution(records, t, now, *(per_test.get(t['test_id']) or ('blocked', reason)))
                  for t in manifest['tests']]
    if stage == 'preflight':
        stages = _stages(preflight={'status': 'blocked', 'reason': reason},
                         dynamic_execution={'status': 'not_run', 'reason': 'preflight blocked; no dependent work'})
    else:
        stages = _stages(preflight={'status': 'completed'}, dynamic_execution={'status': 'blocked', 'reason': reason})
    return _finish(manifest, records, executions, [], status='blocked', reason=reason, stages=stages, gaps=gaps,
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


# TK-DYN-004 access paths that no v0.1 template covers yet. They stay in the report and
# in the denominator as unsupported, instead of disappearing (AG-07).
UNSUPPORTED_SCOPES = [
    {'scope': 'rls-functions', 'reason': 'no template for functions (RPC, SECURITY DEFINER) yet; '
                                         'includes writes whose response looks like a denial'},
    {'scope': 'rls-views', 'reason': 'no template for views yet'},
    {'scope': 'rls-column-privileges', 'reason': 'no template for column-level privileges or masking yet'},
]


def _finish(manifest, records, executions, findings, status, reason, stages, environment, matrix, gaps=()):
    counts = {k: sum(e['result'] == k for e in executions)
              for k in ('passed', 'failed', 'blocked', 'untested', 'unsupported')}
    coverage = records.new('coverage', inventory_source='fixed test plan in the ScanManifest (tracer bullet)',
                           denominator=len(manifest['tests']) + len(UNSUPPORTED_SCOPES),
                           executed=counts['passed'] + counts['failed'],
                           valid_judgements=counts['passed'] + counts['failed'], blocked=counts['blocked'],
                           untested=counts['untested'], unsupported=counts['unsupported'] + len(UNSUPPORTED_SCOPES),
                           unsupported_items=[dict(u) for u in UNSUPPORTED_SCOPES] + [dict(g) for g in gaps])
    doc = {'schema_version': '1', 'run_id': records.run_id, 'id': f'report-{records.run_id}', 'created_at': _now(),
           'source_id': SOURCE_ID, 'commit': manifest['commit'], 'status': status,
           'manifest': {'id': manifest['id'], 'digest': _digest(manifest)},
           'stages': stages, 'requirements': manifest['requirements'], 'authorization_matrix': matrix,
           'execution_records': executions, 'findings': findings, 'coverage': coverage}
    if reason:
        doc['status_reason'] = reason
    if environment:
        doc['environment'] = environment
    problems = report.validate(doc)
    if problems:
        raise RuntimeError('the toolkit produced an invalid report: ' + '; '.join(problems))
    return Run(doc, report.render_markdown(doc))
