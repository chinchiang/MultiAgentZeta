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

from toolkit import policy, report

PENDING = report.PENDING
REVIEW_FIELDS = ('by', 'at', 'reason', 'basis', 'modified_rule', 'allowed_tests', 'expiry')


def _empty_review():
    return {name: [] if name == 'allowed_tests' else None for name in REVIEW_FIELDS}


def _impact(*lists):
    """The union of high-impact category lists, in the order of 〈定義：高影響類別〉."""
    found = {c for codes in lists for c in codes}
    return [c for c in policy.IMPACT_CATEGORIES if c in found]


def _s2_items(template, resources):
    return [{'item_id': s2_item_id(c['id'], r['name']), 'source': 'S2', 'clause_id': c['id'], 'resource': r['name'],
             'statement': c['statement'], 'rule': c['rule'], 'impact': _impact(c['impact'], r['impact'])}
            for c in template['clauses'] for r in resources]


def _s1_items(entries, resources):
    """S1 entries with at least one of their resources in scope; the others are out of scope. An item's
    categories are its entry's optional ones and those of its resources in scope."""
    impact = {r['name']: r['impact'] for r in resources}
    return [{'item_id': e['id'], 'source': 'S1', 'resources': list(e['resources']),
             'statement': e['statement'], 'rule': e['rule'],
             'impact': _impact(e.get('impact', []), *(impact[r] for r in e['resources'] if r in impact))}
            for e in entries if set(e['resources']) & set(impact)]


def _new(item, out_of_scope=False):
    return {**item, 'version': 1, 'status': PENDING, 'review': _empty_review(), 'out_of_scope': out_of_scope}


def _ordered(items):
    """The list's order (〈定義：確認清單〉 排序): items in scope with a high-impact category, then the other
    items in scope, then items out of scope; by item_id within each. Neither review state nor the tests
    resting on an item count, so the order changes only with the scope or the categories."""
    return sorted(items, key=lambda i: (2 if i['out_of_scope'] else 0 if i.get('impact') else 1, i['item_id']))


def _template_ref(template):
    return {'policy_template_id': template['policy_template_id'], 'version': template['version'],
            'digest': policy.template_digest(template)}


def generate(template, resources, s1_entries):
    """A new confirmation list: every item pending, review fields empty, version 1 (TK-REQ-001).

    resources are the resources under test as scope.resources gives them, {name, impact}.
    """
    in_scope = _s2_items(template, resources) + _s1_items(s1_entries, resources)
    produced = {i['item_id'] for i in in_scope}
    unknown = [{'name': r, 'impact': []} for e in s1_entries for r in e['resources']]  # not under test: no categories
    out = [i for i in _s1_items(s1_entries, unknown) if i['item_id'] not in produced]
    return {'schema_version': '1', 'list_version': 1, 's2_template': _template_ref(template),
            'items': _ordered([_new(i) for i in in_scope] + [_new(i, out_of_scope=True) for i in out])}


CONTENT = ('statement', 'rule', 'resources')  # what makes an item's text; a change means a new version


def _content(item):
    return {k: item.get(k) for k in CONTENT}


def update(existing, template, resources, s1_entries):
    """The list after the S2 template or the scope changed (〈定義：確認清單〉 更新).

    New items are added as pending; an item whose text is unchanged keeps its review state; an
    item whose text changed gets the next version, back at pending, with the previous version kept
    in its history (TK-REQ-004); an item no longer produced (its resource left the scope, its S2 clause
    left the template, or its S1 entry is no longer given) is marked out of scope and keeps its review
    state and version; produced again, it is back in scope, kept or given a new version as above.
    The whole list is sorted again; list_version goes up only when something other than the order
    changed. An item's high-impact categories are worked
    out again; they are not part of its text, so a change keeps its version and review state. An item
    out of scope keeps its last ones: its resources under test, and with them their categories, are gone.
    """
    fresh = {i['item_id']: i for i in _s2_items(template, resources) + _s1_items(s1_entries, resources)}
    clauses = {c['id']: c['impact'] for c in template['clauses']}
    entries = {e['id']: e.get('impact', []) for e in s1_entries}
    items = []
    for old in existing['items']:
        new = fresh.pop(old['item_id'], None)
        if new is None:  # keeps its last categories; a list written before items had them gets those still declared
            declared = clauses.get(old['clause_id'], []) if old['source'] == 'S2' else entries.get(old['item_id'], [])
            items.append({'impact': _impact(declared), **old, 'out_of_scope': True})
        elif _content(new) == _content(old):
            items.append({**old, 'impact': new['impact'], 'out_of_scope': False})
        else:
            previous = {k: v for k, v in old.items() if k not in ('history', 'out_of_scope', 'impact')}
            items.append({**new, 'version': old['version'] + 1, 'status': PENDING, 'review': _empty_review(),
                          'out_of_scope': False, 'history': old.get('history', []) + [previous]})
    items += [_new(i) for i in fresh.values()]
    doc = {**existing, 's2_template': _template_ref(template), 'items': _ordered(items)}
    if doc != {**existing, 'items': _ordered(existing['items'])}:  # a new order alone is no change
        doc['list_version'] = existing['list_version'] + 1
    return doc


SCHEMA_FILE = Path(__file__).with_name('schemas') / 'confirmation-list-v1.json'
with open(SCHEMA_FILE, encoding='utf-8') as _f:
    SCHEMA = json.load(_f)
# 〈定義：確認清單〉: the fields each review state needs, besides who and when.
REQUIRED_REVIEW = {report.PENDING: (), report.ACCEPTED: ('by', 'at'),
                   report.MODIFIED: ('by', 'at', 'reason', 'basis', 'modified_rule'),
                   report.NOT_APPLICABLE: ('by', 'at', 'reason', 'basis')}


def s2_item_id(clause_id, resource):
    """The id of an S2 clause applied to a resource, 「S2 條文 × 資源」 of 〈定義：確認清單〉; S1 entry ids
    have no @, so the two never collide (schema, scan._s1_problems)."""
    return f'{clause_id}@{resource}'


def validate(doc):
    """Structural problems of a confirmation list: the schema, and an S2 item id that is not its own
    clause_id@resource, which the schema cannot express. An empty list means it can be read."""
    validator = jsonschema.Draft202012Validator(SCHEMA)
    problems = [f'{"/".join(map(str, e.absolute_path)) or "(list)"}: {e.message}' for e in validator.iter_errors(doc)]
    if problems:
        return problems
    versions = [(f'items/{n}', i) for n, i in enumerate(doc['items'])]
    versions += [(f'items/{n}/history/{k}', h) for n, i in enumerate(doc['items']) for k, h in enumerate(i.get('history', []))]
    return [f'{where}/item_id: {v["item_id"]!r} is not {s2_item_id(v["clause_id"], v["resource"])!r}'
            for where, v in versions if v['source'] == 'S2' and v['item_id'] != s2_item_id(v['clause_id'], v['resource'])]


STATUSES = report.REVIEW_STATES
SINGLE_APPROVAL = (report.MODIFIED, report.NOT_APPLICABLE)  # they relax or rewrite S2; no second approver yet (TK-REQ-014)


def summary(doc):
    """What the report says about the list (TK-REQ-003 各類待確認數量, 〈定義：確認清單〉 單人核准).

    Items out of scope are counted apart: out of scope is not a review state, and those items count
    as neither pending nor reviewed.
    """
    in_scope = [i for i in doc['items'] if not i['out_of_scope']]
    return {'summary': {source: {status: sum(i['source'] == source and i['status'] == status for i in in_scope)
                                 for status in STATUSES}
                        for source in ('S1', 'S2')},
            'out_of_scope': len(doc['items']) - len(in_scope),
            'single_approval': [i['item_id'] for i in in_scope if i['status'] in SINGLE_APPROVAL]}


def effective_rule(item):
    """The allow/deny rule that applies: a modified item's rewritten rule replaces the original
    (〈定義：確認清單〉 修改)."""
    if item['status'] == report.MODIFIED and item['review'].get('modified_rule'):
        return item['review']['modified_rule']
    return item['rule']


def test_problem(item, case_kind):
    """Why a test of case_kind ('denial' or 'allowed') cannot run on item, or None.

    The item must be testable (report.untestable) and carry the fields its review state needs; then
    the case kind must match its allow/deny rule, a modified item's rewritten rule included, so an
    access is allowed only by the item, never by picking an allowed-case template (TK-REQ-016).
    """
    rid = item['item_id']
    reason = report.untestable(item)
    if reason:
        return f'confirmation item {rid!r} {reason}; the test is not run'
    problem = review_problem(item)  # before the rule: a modification lacking its rule has no rule to match
    if problem:
        return problem
    rule = effective_rule(item)
    if report.RULE_FOR_CASE[case_kind] != rule:
        return (f'confirmation item {rid!r} has rule {rule!r} but the test is a {case_kind} case: '
                f'the case kind does not match the rule (TK-REQ-016); the test is not run')
    return None


finding_cap = report.finding_cap  # one rule for the run and for report.validate() (TK-REQ-003)


def review_problem(item):
    """Why an item's review state is incomplete, or None (〈定義：確認清單〉, TK-SCP-003).

    A modification that permits what S2 denies is a 合法例外 and also needs an allowed-case test
    and an expiry condition (TK-DYN-003).
    """
    review = item['review']
    missing = [name for name in REQUIRED_REVIEW[item['status']] if not review.get(name)]
    if item['status'] == report.MODIFIED and review.get('modified_rule') == policy.ALLOW and item['rule'] == policy.DENY:
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
    if not path.exists():
        # Not "no list yet": a new, all-pending list would drop the owner's review states (TK-REQ-004).
        raise ConfirmationListUnusable(f'{path} is referenced with digest {digest} but does not exist; '
                                       f'restore the file')
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
