"""The confirmation list (〈定義：確認清單〉, TK-REQ-001, TK-REQ-004, TK-REQ-009).

An item is an S2 clause applied to one resource in scope ("S2 條文 × 資源") or one S1 entry the
application owner provided; nothing is derived from the implementation (TK-REQ-005). The toolkit
only adds items, resets them to pending or marks them out of scope; it never writes accepted,
modified or not_applicable (TK-REQ-009). Review state codes follow toolkit/schemas; their
Chinese labels live in report.py.
"""
import hashlib
import json
import re
from datetime import datetime, timezone
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


def update(existing, template, resources, s1_entries, *, now):
    """The list after the S2 template or the scope changed (〈定義：確認清單〉 更新), and with the 合法例外
    whose expiry has come by `now` reset (〈定義：確認清單〉 到期).

    New items are added as pending; an item whose text is unchanged keeps its review state; an
    item whose text changed gets the next version, back at pending, with the previous version kept
    in its history (TK-REQ-004); an item no longer produced (its resource left the scope, its S2 clause
    left the template, or its S1 entry is no longer given) is marked out of scope and keeps its review
    state and version; produced again, it is back in scope, kept or given a new version as above.
    The whole list is sorted again; list_version goes up only when something other than the order
    changed. An item's high-impact categories are worked
    out again; they are not part of its text, so a change keeps its version and review state. An item
    out of scope keeps its last ones: its resources under test, and with them their categories, are gone.
    A 合法例外 whose expiry time is not later than `now` (an aware datetime) gets the next version, back at
    pending with reset_reason "expired", and the previous version, the owner's review in it, goes to its
    history (TK-REQ-004).
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
            items.append(_next_version(old, **new, out_of_scope=False))
    items += [_new(i) for i in fresh.values()]
    items = [_expired(i) if _has_expired(i, now) else i for i in items]
    doc = {**existing, 's2_template': _template_ref(template), 'items': _ordered(items)}
    if doc != {**existing, 'items': _ordered(existing['items'])}:  # a new order alone is no change
        doc['list_version'] = existing['list_version'] + 1
    return doc


def _next_version(old, **fields):
    """The item's next version with `fields`, pending with an empty review; the old version, with its
    review and how it came about, goes to the history (TK-REQ-004)."""
    previous = {k: v for k, v in old.items() if k not in ('history', 'out_of_scope', 'impact')}
    current = {k: v for k, v in old.items() if k != 'reset_reason'}
    return {**current, **fields, 'version': old['version'] + 1, 'status': PENDING, 'review': _empty_review(),
            'history': old.get('history', []) + [previous]}


RESET_EXPIRED = 'expired'  # reset_reason of a version made because a 合法例外 expired (〈定義：確認清單〉 到期)


def _has_expired(item, now):
    """〈定義：確認清單〉 到期: a 合法例外 in scope whose expiry is not later than now. An item out of scope keeps
    its review state and version (〈定義：確認清單〉 更新); back in scope, its expiry is judged again."""
    expiry = expiry_time(item['review']) if is_exception(item) and not item['out_of_scope'] else None
    return expiry is not None and expiry <= now


def _expired(item):
    """〈定義：確認清單〉 到期: the 合法例外 goes back to pending, its review kept in the history."""
    return _next_version(item, reset_reason=RESET_EXPIRED)


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


def is_exception(item):
    """A 合法例外: a modification that permits what the item's rule denies (〈定義：確認清單〉 修改, TK-DYN-003)."""
    return (item['status'] == report.MODIFIED and item['rule'] == policy.DENY
            and item['review'].get('modified_rule') == policy.ALLOW)


def base_rule(item):
    """The allow/deny rule of the tests on item that no 合法例外 allows (〈定義：確認清單〉 修改): a 合法例外
    keeps the item's rule; another modification's rewritten rule replaces the original."""
    if item['status'] == report.MODIFIED and item['review'].get('modified_rule') and not is_exception(item):
        return item['review']['modified_rule']
    return item['rule']


def rule_for(item, test_id, case_kind):
    """The allow/deny rule test_id, a test of case_kind, is judged by (〈定義：確認清單〉 修改): a 合法例外
    allows only the allowed cases its allowed_tests lists; every other test keeps base_rule."""
    allowed_tests = item['review']['allowed_tests'] if is_exception(item) else []
    return report.rule_for(base_rule(item), allowed_tests, test_id, case_kind)


# 〈定義：確認清單〉 到期: the expiry of a 合法例外 is an ISO 8601 UTC time such as 2027-05-01T00:00:00Z.
EXPIRY = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$')


def expiry_time(review):
    """The expiry of a 合法例外 as an aware datetime, or None when it is not an ISO 8601 UTC time or no
    such time; then the exception lacks its expiry (〈定義：確認清單〉 到期)."""
    value = review.get('expiry')
    if not isinstance(value, str) or not EXPIRY.match(value):
        return None
    try:
        return datetime.fromisoformat(value[:-1]).replace(tzinfo=timezone.utc)
    except ValueError:  # the right shape but no such time, e.g. February 30
        return None


def test_problem(item, test_id, case_kind, items, plan):
    """Why test_id, a test of case_kind ('denial' or 'allowed'), cannot run on item, or None.

    The item must be testable (report.untestable) and its review complete (review_problem); then
    the case kind must match the rule the test is judged by (rule_for), so an access is allowed only
    by the item, never by picking an allowed-case template (TK-REQ-016). An allowed case on a 合法例外
    also needs each test the exception lists to be an allowed case on it in the plan (TK-DYN-003);
    a denial case is judged by deny whatever the exception lists, so that does not block it.
    """
    rid = item['item_id']
    reason = report.untestable(item)
    if reason:
        return f'confirmation item {rid!r} {reason}; the test is not run'
    problem = review_problem(item, items)  # before the rule: a modification lacking its rule has no rule to match
    if problem:
        return problem
    rule = rule_for(item, test_id, case_kind)
    if report.RULE_FOR_CASE[case_kind] != rule:
        return (f'confirmation item {rid!r} has rule {rule!r} for test {test_id!r} but the test is a {case_kind} '
                f'case: the case kind does not match the rule (TK-REQ-016); the test is not run')
    if case_kind == report.ALLOWED and is_exception(item):
        problems = [p for t in item['review']['allowed_tests'] if (p := _allowed_test_problem(rid, t, plan))]
        if problems:
            return f'confirmation item {rid!r} is a 合法例外 but {"; ".join(problems)} (TK-DYN-003); the test is not run'
    return None


finding_cap = report.finding_cap  # one rule for the run and for report.validate() (TK-REQ-003)


def review_problem(item, items):
    """Why an item's review state is incomplete, or None (〈定義：確認清單〉, TK-SCP-003).

    items are the list's items by id. A modification or not-applicable needs a usable basis
    (_basis_problem). A 合法例外 also needs allowed-case tests and an expiry time (TK-DYN-003).
    """
    review, rid, status = item['review'], item['item_id'], item['status']
    missing = [name for name in REQUIRED_REVIEW[status] if not review.get(name)]
    exception = is_exception(item)
    if exception:
        missing += [name for name in ('allowed_tests', 'expiry') if not review.get(name)]
    if missing:
        return f'confirmation item {rid!r} is {status} but lacks {", ".join(missing)}'
    problem = _basis_problem(review['basis'], items) if status in SINGLE_APPROVAL else None
    if problem:
        return f'confirmation item {rid!r} is {status} but {problem}'
    if exception and expiry_time(review) is None:
        return (f'confirmation item {rid!r} is a 合法例外 but its expiry {review["expiry"]!r} is not an ISO 8601 '
                f'UTC time such as 2027-05-01T00:00:00Z (TK-DYN-003)')
    return None


def _basis_problem(basis, items):
    """Why basis is no 規格依據, or None: an S1 entry id names that entry, which must be in scope and
    reviewed; any other text is the owner's spec text and must not be blank (〈定義：確認清單〉)."""
    entry = items.get(basis)
    if entry is not None and entry['source'] == 'S1':
        if entry['out_of_scope']:
            return f'its basis, S1 entry {basis!r}, is out of scope'
        if entry['status'] not in report.REVIEWED:
            return (f'its basis, S1 entry {basis!r}, is {entry["status"]} ({report.REVIEW_LABELS[entry["status"]]}), '
                    f'neither accepted nor modified')
        return None
    return None if basis.strip() else 'its basis is blank'


def _allowed_test_problem(rid, test_id, plan):
    """Why test_id cannot show the 合法例外 of item rid, or None (TK-DYN-003). plan maps each planned
    test_id to its requirement_id and case_kind."""
    planned = plan.get(test_id)
    if planned is None:
        return f'allowed test {test_id!r} is not in the test plan'
    if planned['requirement_id'] != rid:
        return f'allowed test {test_id!r} rests on {planned["requirement_id"]!r}, not on this item'
    if planned['case_kind'] != report.ALLOWED:
        return f'allowed test {test_id!r} is not an allowed case'
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
