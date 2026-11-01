"""One scan run, the toolkit's main seam: run(manifest) -> Run(report, markdown).

Minimal controller (tracer bullet, #3): prepare the E1 stack from the project's
BuildRecipe, run the manifest's fixed tests, judge them with the observer,
and produce the versioned JSON report plus the Markdown generated from it.
"""
import hashlib
import json
import re
import secrets
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


def _request(env, identity, method, path, body=None, api_key='anon-jwt', prefer='return=representation'):
    """An actor request through the data API, as the given identity. Returns (status, parsed body)."""
    headers = {'apikey': env.api_keys.get(api_key, ''), 'Prefer': prefer}
    if identity in env.tokens:
        headers['Authorization'] = 'Bearer ' + env.tokens[identity]['access_token']
    data = json.dumps(body).encode() if body is not None else None
    if data is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(env.api_url + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        with e:
            status, raw = e.code, e.read()
    try:
        return status, json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return status, None


# The four checks of a denial case (TK-DYN-001).
CHECKS = ('resource_and_control', 'identity', 'no_disclosure_or_change', 'response_and_side_effects')

# Denial-case templates: the HTTP method of the attempt, and the responses that the
# contract accepts as a denial (TK-DYN-002: a status code alone is not enough).
DENIAL_TEMPLATES = {
    'cross-user-read-v1': {'method': 'GET', 'denials': {200, 401, 403, 404}, 'writes': False},
    # Write attempts ask for return=minimal, so PostgREST answers 204 whether or not a row
    # changed: the verdict on a write rests on the observer's state, not on what the actor sees.
    'cross-user-update-v1': {'method': 'PATCH', 'denials': {204, 401, 403, 404}, 'writes': True},
    'cross-user-delete-v1': {'method': 'DELETE', 'denials': {204, 401, 403, 404}, 'writes': True},
    'cross-user-create-v1': {'method': 'POST', 'denials': {401, 403}, 'writes': True},
}


def _identity_email(env, name):
    return next((i.get('email') for i in env.recipe['auth']['identities'] if i['name'] == name), None)


def _denial_case(env, test, evidence):
    """Run one denial case. Appends evidence; returns (result, checks).

    Leaks are judged only from the actor channel; state changes and side effects
    only from the observer channel (TK-IDN-008).
    """
    template = DENIAL_TEMPLATES[test['template_id']]
    marker = test['resource_ref']
    rows_path = f'/rest/v1/documents?title=eq.{marker}&select=title,body'
    checks = dict.fromkeys(CHECKS, False)

    def actor(identity, method, path, body=None, prefer='return=representation'):
        key = test.get('api_key', 'anon-jwt') if identity == test['actor_ref'] else 'anon-jwt'
        status, data = _request(env, identity, method, path, body, key, prefer)
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
    owner = test['owner_ref']
    if test['template_id'] == 'cross-user-read-v1':
        status, rows, _ = actor(owner, 'GET', rows_path)
    elif test['template_id'] == 'cross-user-create-v1':
        status, rows, _ = actor(owner, 'POST', '/rest/v1/documents', {
            'tenant_id': test['tenant_id'], 'owner_id': test['claimed_owner_id'],
            'title': test['control_ref'], 'body': 'owner control'})
    else:
        control_path = f'/rest/v1/documents?title=eq.{test["control_ref"]}&select=title'
        if template['method'] == 'PATCH':
            status, rows, _ = actor(owner, 'PATCH', control_path, {'body': 'owner control'})
        else:
            status, rows, _ = actor(owner, 'DELETE', control_path)
    control_ok = status in (200, 201) and rows is not None and len(rows) == 1
    before = observe('before')
    if test['template_id'] == 'cross-user-create-v1':
        resource_ok = not before['resource_exists']
    else:
        resource_ok = before['resource_exists'] and not before['shared']
    checks['resource_and_control'] = control_ok and resource_ok
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
    minimal = 'return=minimal'
    if test['template_id'] == 'cross-user-create-v1':
        status, rows, _ = actor(test['actor_ref'], 'POST', '/rest/v1/documents', {
            'tenant_id': test['tenant_id'], 'owner_id': test['claimed_owner_id'], 'title': marker, 'body': 'attempt'},
            prefer=minimal)
    elif template['method'] == 'PATCH':
        status, rows, _ = actor(test['actor_ref'], 'PATCH', rows_path, {'body': 'tampered by the actor'}, prefer=minimal)
    elif template['method'] == 'DELETE':
        status, rows, _ = actor(test['actor_ref'], 'DELETE', rows_path, prefer=minimal)
    else:
        status, rows, _ = actor(test['actor_ref'], 'GET', rows_path)
    after = observe('after')
    disclosed = any(isinstance(r, dict) and r.get('title') == marker for r in rows or [])
    if test['template_id'] == 'cross-user-create-v1':
        changed = after['resource_exists']
    else:
        changed = (after['resource_exists'], after.get('state_digest')) != (True, before['state_digest'])
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
    status, data = _request(env, test['actor_ref'], 'GET', path, api_key=key)
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
MARKER_PARAMS = {'cross-user-update-v1': ['control_ref'], 'cross-user-delete-v1': ['control_ref'],
                 'cross-user-create-v1': ['control_ref']}
UUID_PARAMS = {'cross-user-create-v1': ['claimed_owner_id', 'tenant_id']}


def _plan_problem(test):
    """Why a test from the manifest cannot run, or None."""
    template = test.get('template_id')
    if template not in TEST_TEMPLATES:
        return f'template_id {template!r} is not an allow-listed test template'
    if test.get('observation_ref') not in TEST_TEMPLATES[template]:
        return f'observation_ref {test.get("observation_ref")!r} is not an allow-listed observation template for {template}'
    for name in ['resource_ref'] + MARKER_PARAMS.get(template, []):
        if not isinstance(test.get(name), str) or not IDENTIFIER.match(test[name]):
            return f'{name} must be a resource marker identifier (A-Z, 0-9, -)'
    if test.get('api_key', 'anon-jwt') not in API_KEY_FORMATS:
        return f'api_key must be one of {list(API_KEY_FORMATS)}'
    for name in UUID_PARAMS.get(template, []):
        if not isinstance(test.get(name), str) or not UUID.match(test[name]):
            return f'{name} must be a UUID'
    return None


def run(manifest):
    """Run the manifest's tests against its project and return the report and its Markdown.

    A run that cannot start (source digest mismatch, BuildRecipe step blocked) is
    reported with status blocked and the reason; every planned test is blocked.
    """
    run_id = f'run-{datetime.now(timezone.utc):%Y%m%d%H%M%S}-{secrets.token_hex(3)}'
    records = _Records(run_id, manifest['commit'])
    project = manifest['target']['project']
    pinned, actual = manifest['target']['source_digest'], e1.source_digest(project)
    if pinned != actual:
        return _blocked(manifest, records, f'source_digest of the ScanManifest ({pinned}) does not match '
                                           f'the project ({actual}); nothing was started')
    problems = {t['test_id']: _plan_problem(t) for t in manifest['tests']}
    if all(problems.values()):
        return _blocked(manifest, records, 'no test in the ScanManifest can run; nothing was started',
                        per_test=problems)
    prepared = e1.prepare(project)
    if isinstance(prepared, e1.Blocked):
        return _blocked(manifest, records, f'environment blocked at BuildRecipe step {prepared.step}: '
                                           f'{prepared.reason}')
    executions, findings = [], []
    stopped = None  # reason the remaining tests cannot run
    try:
        for test in manifest['tests']:
            started, evidence = _now(), []
            problem = problems[test['test_id']] or stopped
            if problem:
                executions.append(_execution(records, test, started, 'blocked', problem))
                continue
            denial = test['template_id'] in DENIAL_TEMPLATES
            try:
                if denial:
                    result, checks = _denial_case(prepared.env, test, evidence)
                else:
                    result, checks = _allowed_case(prepared.env, test, evidence)
                error = None
            except observer.ObservationFailed as e:
                result, checks, error = 'blocked', None, f'observation failed: {e}'
            ex = _execution(records, test, started, result, error)
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
    return _finish(manifest, records, executions, findings, status='completed' if definite else 'partial',
                   reason='' if definite else 'some tests have no definite result',
                   environment={'mode': prepared.profile['mode'], 'profile_digest': _digest(prepared.profile)},
                   matrix=_authorization_matrix(prepared))


def _execution(records, test, started, result, error=None):
    return records.new('exec', test_id=test['test_id'], template_id=test['template_id'],
                       requirement_id=test['requirement_id'], actor_ref=test['actor_ref'],
                       resource_ref=test['resource_ref'], started_at=started, ended_at=_now(),
                       result=result, error=error, evidence=[])


def _blocked(manifest, records, reason, per_test=None):
    now = _now()
    per_test = per_test or {}
    executions = [_execution(records, t, now, 'blocked', per_test.get(t['test_id']) or reason)
                  for t in manifest['tests']]
    return _finish(manifest, records, executions, [], status='blocked', reason=reason, environment=None, matrix=[])


# TK-DYN-004 access paths that no v0.1 template covers yet. They stay in the report and
# in the denominator as unsupported, instead of disappearing (AG-07).
UNSUPPORTED_SCOPES = [
    {'scope': 'rls-functions', 'reason': 'no template for functions (RPC, SECURITY DEFINER) yet; '
                                         'includes writes whose response looks like a denial'},
    {'scope': 'rls-views', 'reason': 'no template for views yet'},
    {'scope': 'rls-column-privileges', 'reason': 'no template for column-level privileges or masking yet'},
]


def _finish(manifest, records, executions, findings, status, reason, environment, matrix):
    counts = {k: sum(e['result'] == k for e in executions)
              for k in ('passed', 'failed', 'blocked', 'untested', 'unsupported')}
    coverage = records.new('coverage', inventory_source='fixed test plan in the ScanManifest (tracer bullet)',
                           denominator=len(manifest['tests']) + len(UNSUPPORTED_SCOPES),
                           executed=counts['passed'] + counts['failed'],
                           valid_judgements=counts['passed'] + counts['failed'], blocked=counts['blocked'],
                           untested=counts['untested'], unsupported=counts['unsupported'] + len(UNSUPPORTED_SCOPES),
                           unsupported_items=[dict(u) for u in UNSUPPORTED_SCOPES])
    doc = {'schema_version': '1', 'run_id': records.run_id, 'id': f'report-{records.run_id}', 'created_at': _now(),
           'source_id': SOURCE_ID, 'commit': manifest['commit'], 'status': status,
           'manifest': {'id': manifest['id'], 'digest': _digest(manifest)},
           'requirements': manifest['requirements'], 'authorization_matrix': matrix,
           'execution_records': executions, 'findings': findings, 'coverage': coverage}
    if reason:
        doc['status_reason'] = reason
    if environment:
        doc['environment'] = environment
    problems = report.validate(doc)
    if problems:
        raise RuntimeError('the toolkit produced an invalid report: ' + '; '.join(problems))
    return Run(doc, report.render_markdown(doc))
