"""The test authorization record (〈定義：測試授權紀錄〉, TK-ENV-001, TK-ENV-002).

The app owner authorizes what a run may test: targets, environment, period, resource × method
operations and the people responsible. The record lives in the control zone (toolkit.control), so
nothing the tested code, its data, its responses or a model writes can authorize or approve anything.
An operation the record does not list runs only with an extra approval covering it. The names in
the record are declared, not verified (TK-HRV-004 is later); the report says so.
"""
import json
from collections import Counter
from pathlib import Path

import jsonschema

from toolkit import control

SCHEMA = json.loads((Path(__file__).parent / 'schemas' / 'authorization-v1.json').read_text(encoding='utf-8'))
# HTTP methods of scope.allowed_operations and of the record's operations; the schema lists the same.
METHODS = ('GET', 'POST', 'PATCH', 'DELETE')


class AuthorizationUnusable(Exception):
    """The record cannot be used: not in the control zone, missing, another digest, unreadable or invalid."""


def _time_problems(doc):
    problems = []
    times = [(name, doc.get(name)) for name in ('valid_from', 'valid_until', 'issued_at')]
    for n, a in enumerate(doc.get('extra_approvals') or []):
        times += [(f'extra_approvals/{n}.{name}', a.get(name)) for name in ('at', 'valid_until')]
    for name, value in times:
        if value is not None and control.utc_time(value) is None:
            problems.append(f'{name} {value!r} is not an ISO 8601 UTC time such as 2027-05-01T00:00:00Z')
    if problems:
        return problems
    until = control.utc_time(doc['valid_until'])
    if control.utc_time(doc['valid_from']) >= until:
        problems.append('valid_from must be earlier than valid_until')
    for n, a in enumerate(doc.get('extra_approvals') or []):
        if control.utc_time(a['valid_until']) > until:
            problems.append(f'extra_approvals/{n}.valid_until must not be later than valid_until: an approval '
                            f'ends with the record')
    return problems


def _repeated(values):
    return [v for v, k in Counter(values).items() if k > 1]


def validate(doc):
    """Problems of an authorization record (〈定義：測試授權紀錄〉 格式): the schema, then the times (ISO 8601 UTC, valid_from before
    valid_until, no approval outliving the record), a resource listed twice in one operations list and
    an approval_id used twice. An empty list means the record can be used."""
    validator = jsonschema.Draft202012Validator(SCHEMA)
    problems = [f'{"/".join(map(str, e.absolute_path)) or "(record)"}: {e.message}' for e in validator.iter_errors(doc)]
    if problems:
        return problems
    problems = _time_problems(doc)
    lists = [('operations', doc['operations'])]
    lists += [(f'extra_approvals/{n}.operations', a['operations']) for n, a in enumerate(doc.get('extra_approvals', []))]
    problems += [f'{where} lists resource {r!r} twice' for where, ops in lists for r in _repeated(o['resource'] for o in ops)]
    problems += [f'approval_id {i!r} is used twice' for i in _repeated(a['approval_id'] for a in doc.get('extra_approvals', []))]
    return problems


def read(path, digest, source_root):
    """The record at path, from the control zone with its digest, after validate()."""
    try:
        doc = control.read(path, digest, source_root, 'test authorization record')
    except control.RecordUnusable as e:
        raise AuthorizationUnusable(str(e)) from e
    problems = validate(doc)
    if problems:
        raise AuthorizationUnusable(f'{path} is not a valid test authorization record: {"; ".join(problems[:3])}')
    return doc


def period_problem(doc, now):
    """Why the record does not cover a run starting at now, or None: now must be in [valid_from, valid_until)
    (〈定義：測試授權紀錄〉 涵蓋這次執行)."""
    if control.utc_time(doc['valid_from']) <= now < control.utc_time(doc['valid_until']):
        return None
    return (f'the run starts at {now:%Y-%m-%dT%H:%M:%SZ}, outside the authorized period {doc["valid_from"]} '
            f'to {doc["valid_until"]}')


def target_problem(doc, sample, environment):
    """Why the record does not cover the sample (its BuildRecipe sample id) in environment, or None
    (〈定義：測試授權紀錄〉 涵蓋這次執行)."""
    if sample not in doc['targets']:
        return f'sample {sample!r} is not a target of the test authorization ({", ".join(doc["targets"])})'
    if environment != doc['environment']:
        return f'environment {environment!r} is not the authorized environment {doc["environment"]!r}'
    return None


def _covers(operations, resource, method):
    return any(o['resource'] == resource and method in o['methods'] for o in operations)


def same_person(a, b):
    """Whether two declared names are the same person: compared without surrounding spaces or case, so
    "Tester " cannot approve the run of "tester" (〈定義：測試授權紀錄〉 額外核准). The names are not verified."""
    return a.strip().casefold() == b.strip().casefold()


def operation_problem(doc, resource, method, now):
    """(approval_id, problem) for method on resource in a run starting at now (〈定義：測試授權紀錄〉 涵蓋每個
    測試, TK-ENV-001).

    An operation the record lists needs nothing: (None, None). Another one runs with an extra approval
    covering it, still valid at now and not given by the operator, whose id is returned; without one
    the problem says why each approval covering it does not count."""
    if _covers(doc['operations'], resource, method):
        return None, None
    reasons = []
    for a in doc.get('extra_approvals', []):
        if not _covers(a['operations'], resource, method):
            continue
        if control.utc_time(a['valid_until']) <= now:
            reasons.append(f'{a["approval_id"]} expired at {a["valid_until"]}')
        elif same_person(a['by'], doc['roles']['operator']):
            reasons.append(f'{a["approval_id"]} was given by the operator {a["by"]!r}, who cannot approve their own run')
        else:
            return a['approval_id'], None
    problem = f'{method} on {resource!r} is not in the test authorization and no extra approval covers it'
    return None, problem + (f' ({"; ".join(reasons)})' if reasons else '') + ' (TK-ENV-001); the test is not run'
