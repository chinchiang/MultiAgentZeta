"""The confirmation list (〈定義：確認清單〉, TK-REQ-001, TK-REQ-004, TK-REQ-009).

An item is an S2 clause applied to one resource in scope ("S2 條文 × 資源") or one S1 entry the
application owner provided; nothing is derived from the implementation (TK-REQ-005). The toolkit
only adds items, resets them to pending or marks them out of scope; it never writes accepted,
modified or not_applicable (TK-REQ-009). Review state codes follow toolkit/schemas; their
Chinese labels live in report.py.
"""
import hashlib
import json
from pathlib import Path

import jsonschema

from toolkit import policy

PENDING = 'pending'
REVIEW_FIELDS = ('by', 'at', 'reason', 'basis', 'modified_rule', 'allowed_tests', 'expiry')


def _empty_review():
    return {name: [] if name == 'allowed_tests' else None for name in REVIEW_FIELDS}


def _s2_items(template, resources):
    return [{'item_id': f'{c["id"]}@{r}', 'source': 'S2', 'clause_id': c['id'], 'resource': r,
             'statement': c['statement'], 'rule': c['rule']}
            for c in template['clauses'] for r in resources]


def _s1_items(entries):
    return [{'item_id': e['id'], 'source': 'S1', 'resources': list(e['resources']),
             'statement': e['statement'], 'rule': e['rule']} for e in entries]


def generate(template, resources, s1_entries):
    """A new confirmation list: every item pending, review fields empty, version 1 (TK-REQ-001)."""
    items = [{**item, 'version': 1, 'status': PENDING, 'review': _empty_review(), 'out_of_scope': False}
             for item in _s2_items(template, resources) + _s1_items(s1_entries)]
    return {'schema_version': '1', 'list_version': 1,
            's2_template': {'policy_template_id': template['policy_template_id'], 'version': template['version'],
                            'digest': policy.template_digest(template)},
            'items': items}


CONTENT = ('statement', 'rule', 'resources')  # what makes an item's text; a change means a new version


def _content(item):
    return {k: item.get(k) for k in CONTENT}


def update(existing, template, resources, s1_entries):
    """The list after the S2 template or the scope changed (〈定義：確認清單〉 更新).

    New items are added as pending; an item whose text is unchanged keeps its review state; an
    item whose text changed gets the next version, back at pending, with the previous version kept
    in its history (TK-REQ-004); an item no longer produced is marked out of scope and keeps its
    review state. list_version goes up only when something changed.
    """
    fresh = {i['item_id']: i for i in _s2_items(template, resources) + _s1_items(s1_entries)}
    items = []
    for old in existing['items']:
        new = fresh.pop(old['item_id'], None)
        if new is None:
            items.append({**old, 'out_of_scope': True})
        elif _content(new) == _content(old):
            items.append({**old, 'out_of_scope': False})
        else:
            previous = {k: v for k, v in old.items() if k not in ('history', 'out_of_scope')}
            items.append({**new, 'version': old['version'] + 1, 'status': PENDING, 'review': _empty_review(),
                          'out_of_scope': False, 'history': old.get('history', []) + [previous]})
    items += [{**i, 'version': 1, 'status': PENDING, 'review': _empty_review(), 'out_of_scope': False}
              for i in fresh.values()]
    doc = {**existing, 's2_template': generate(template, [], [])['s2_template'], 'items': items}
    if doc != existing:
        doc['list_version'] = existing['list_version'] + 1
    return doc


SCHEMA_FILE = Path(__file__).with_name('schemas') / 'confirmation-list-v1.json'
with open(SCHEMA_FILE, encoding='utf-8') as _f:
    SCHEMA = json.load(_f)
# 〈定義：確認清單〉: the fields each review state needs, besides who and when.
REQUIRED_REVIEW = {'pending': (), 'accepted': ('by', 'at'),
                   'modified': ('by', 'at', 'reason', 'basis', 'modified_rule'),
                   'not_applicable': ('by', 'at', 'reason', 'basis')}


def validate(doc):
    """Structural problems of a confirmation list (schema); an empty list means it can be read."""
    validator = jsonschema.Draft202012Validator(SCHEMA)
    return [f'{"/".join(map(str, e.absolute_path)) or "(list)"}: {e.message}' for e in validator.iter_errors(doc)]


def review_problem(item):
    """Why an item's review state is incomplete, or None (〈定義：確認清單〉, TK-SCP-003).

    A modification that permits what S2 denies is a 合法例外 and also needs an allowed-case test
    and an expiry condition (TK-DYN-003).
    """
    review = item['review']
    missing = [name for name in REQUIRED_REVIEW[item['status']] if not review.get(name)]
    if item['status'] == 'modified' and review.get('modified_rule') == 'allow' and item['rule'] == 'deny':
        missing += [name for name in ('allowed_tests', 'expiry') if not review.get(name)]
    if missing:
        return f'confirmation item {item["item_id"]!r} is {item["status"]} but lacks {", ".join(missing)}'
    return None


class ConfirmationListUnusable(Exception):
    """The confirmation list cannot be used: inside the sample source, digest mismatch, unreadable or invalid."""


def _outside_source(path, source_root):
    path, root = Path(path).resolve(), Path(source_root).resolve()
    if path == root or root in path.parents:
        raise ConfirmationListUnusable(f'{path} is inside the sample source; the confirmation list belongs in '
                                       f'the control zone')
    return path


def file_digest(path):
    return 'sha256:' + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, doc, source_root):
    """Write the list to the control zone and return its digest, for the ScanManifest to reference."""
    path = _outside_source(path, source_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return file_digest(path)


def read(path, digest, source_root):
    """The list at path, after checking where it is, its digest and its structure."""
    path = _outside_source(path, source_root)
    try:
        actual = file_digest(path)
        doc = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as e:
        raise ConfirmationListUnusable(f'{path} cannot be read: {e}') from e
    if actual != digest:
        raise ConfirmationListUnusable(f'digest of {path} is {actual}, the ScanManifest says {digest}')
    problems = validate(doc)
    if problems:
        raise ConfirmationListUnusable(f'{path} is not a valid confirmation list: {"; ".join(problems[:3])}')
    return doc
