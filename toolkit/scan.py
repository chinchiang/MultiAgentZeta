"""One scan run, the toolkit's main seam: run(manifest) -> Run(report, markdown).

Minimal controller (tracer bullet, #3): prepare the E1 stack from the project's
BuildRecipe, run the manifest's fixed tests, judge them with the observer,
and produce the versioned JSON report plus the Markdown generated from it.
"""
import hashlib
import json
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


def _get(env, identity, path):
    """An actor request through the data API, as the given identity. Returns (status, rows)."""
    headers = {'apikey': env.anon_key}
    if identity in env.tokens:
        headers['Authorization'] = 'Bearer ' + env.tokens[identity]['access_token']
    req = urllib.request.Request(env.api_url + path, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or 'null')
    except urllib.error.HTTPError as e:
        with e:
            return e.code, None


def _cross_user_read(env, test, evidence):
    """Template cross-user-read-v1. Appends evidence and returns the test result: passed, failed or blocked."""
    marker = test['resource_ref']
    path = f'/rest/v1/documents?select=title,body&title=eq.{marker}'

    def observe():
        state = observer.document_row_state(env, marker)
        evidence.append({'channel': 'observer', 'identity_ref': env.observer['role'], 'observation': state})
        return state

    def actor(identity, request_path):
        status, rows = _get(env, identity, request_path)
        evidence.append({'channel': 'actor', 'identity_ref': identity,
                         'request': {'method': 'GET', 'path': request_path},
                         'response': {'status': status, 'rows': len(rows) if isinstance(rows, list) else None}})
        return status, rows

    before = observe()
    if not before['resource_exists'] or before['shared']:
        return 'blocked'
    status, rows = actor(test['owner_ref'], path)
    if status != 200 or not rows:
        return 'blocked'  # positive control: the owner must be able to read it
    status, _user = actor(test['actor_ref'], '/auth/v1/user')
    if status != 200:
        return 'blocked'  # the actor's session must be valid
    status, rows = actor(test['actor_ref'], path)
    after = observe()
    if after.get('state_digest') != before['state_digest']:
        return 'failed'
    if status == 200 and any(r.get('title') == marker for r in rows or []):
        return 'failed'
    return 'passed' if status in (200, 401, 403, 404) else 'error'


def _authorization_matrix(prepared):
    """Identities and how their credentials travel, as confirmed in the BuildRecipe (TK-IDN-003)."""
    transport = prepared.env.recipe['auth']['token_transport']
    return [{'identity': name, 'transport': transport if ident['login'] == 'ok' else 'none',
             'transport_source': 'BuildRecipe auth.token_transport', 'path': ident['path']}
            for name, ident in prepared.profile['identities'].items()]


def _fingerprint(test):
    # 〈定義：問題指紋〉 for authorization: requirement, root cause, normalized entry, resource type, relation.
    return _digest({'requirement_id': test['requirement_id'], 'root_cause': 'object-ownership-not-enforced',
                    'entry': 'GET /rest/v1/documents', 'resource_type': 'documents',
                    'relation': test['actor_ref'], 'algorithm': FINGERPRINT_VERSION})


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
    prepared = e1.prepare(project)
    if isinstance(prepared, e1.Blocked):
        return _blocked(manifest, records, f'environment blocked at BuildRecipe step {prepared.step}: '
                                           f'{prepared.reason}')
    executions, findings = [], []
    try:
        for test in manifest['tests']:
            started, evidence = _now(), []
            result = _cross_user_read(prepared.env, test, evidence)
            ex = _execution(records, test, started, result)
            ex['evidence'] = [{'id': f'{ex["id"]}-ev{i + 1}', **ev} for i, ev in enumerate(evidence)]
            executions.append(ex)
            if result == 'failed':
                findings.append(records.new('finding', fingerprint=_fingerprint(test),
                                            fingerprint_version=FINGERPRINT_VERSION,
                                            requirement_id=test['requirement_id'],
                                            root_cause='object-ownership-not-enforced', status='confirmed',
                                            evidence_type='dynamic', execution_record_ids=[ex['id']]))
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


def _blocked(manifest, records, reason):
    now = _now()
    executions = [_execution(records, t, now, 'blocked', reason) for t in manifest['tests']]
    return _finish(manifest, records, executions, [], status='blocked', reason=reason, environment=None, matrix=[])


def _finish(manifest, records, executions, findings, status, reason, environment, matrix):
    counts = {k: sum(e['result'] == k for e in executions)
              for k in ('passed', 'failed', 'blocked', 'untested', 'unsupported')}
    coverage = records.new('coverage', inventory_source='fixed test plan in the ScanManifest (tracer bullet)',
                           denominator=len(manifest['tests']), executed=counts['passed'] + counts['failed'],
                           valid_judgements=counts['passed'] + counts['failed'], blocked=counts['blocked'],
                           untested=counts['untested'], unsupported=counts['unsupported'])
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
