"""The rule a confirmation item imposes on a test and on a finding (〈定義：確認清單〉).

One home for the rules that a run and report.validate() both apply, so they cannot disagree
(TK-REQ-003, TK-REQ-016, TK-DYN-003). Every function takes an item in the report's shape, a
requirements[] entry: status, source, out_of_scope, the rule that judges the item's tests, and
confirmation.allowed_tests of a 合法例外. confirmation.requirement() turns a confirmation-list item
into this shape. Codes follow toolkit/schemas; their Chinese labels live in report.py (CODING_STANDARDS §10).
"""
from toolkit import policy

# 〈定義：確認清單〉 處理狀態 of a confirmation item, in the order of its table; not a finding state. Both
# schemas list the same codes (test_confirmation.EnumsAgreeWithSchemas); report.REVIEW_LABELS names them.
PENDING, ACCEPTED, MODIFIED, NOT_APPLICABLE = REVIEW_STATES = ('pending', 'accepted', 'modified', 'not_applicable')
REVIEWED = (ACCEPTED, MODIFIED)
# case_kind of an ExecutionRecord and the allow/deny rule each one tests (TK-REQ-016).
DENIAL, ALLOWED = CASE_KINDS = ('denial', 'allowed')
RULE_FOR_CASE = {DENIAL: policy.DENY, ALLOWED: policy.ALLOW}


def _allowed_tests(item):
    return (item.get('confirmation') or {}).get('allowed_tests') or []


def is_exception(item):
    """A 合法例外: a modification that permits what the item's rule denies and lists the tests it allows
    (〈定義：確認清單〉 修改, TK-DYN-003). The report keeps only the rule that judges the item's other tests,
    which is the original deny for an exception, so the rewritten allow is not visible here; a report of
    a run lists allowed_tests for no other item."""
    return item.get('status') == MODIFIED and item.get('rule') == policy.DENY and bool(_allowed_tests(item))


def rule_for(item, test_id, case_kind):
    """The allow/deny rule test_id, a test of case_kind, is judged by (〈定義：確認清單〉 修改): a 合法例外
    allows only the allowed cases its allowed_tests lists; every other test, a denial case it lists
    included, keeps the item's rule (TK-DYN-003)."""
    if case_kind == ALLOWED and is_exception(item) and test_id in _allowed_tests(item):
        return policy.ALLOW
    return item.get('rule')


def untestable(item, labels):
    """Why tests on item must be blocked, or None: out of scope, not applicable, or a pending S1
    entry (〈定義：確認清單〉, TK-REQ-003). A pending S2 clause may still be tested. labels names the
    review states in Chinese (report.REVIEW_LABELS); only report.py defines them."""
    status = item.get('status')
    if item.get('out_of_scope'):
        return 'is out of scope'
    if status == NOT_APPLICABLE:
        return f'is {status} ({labels[status]})'
    if status == PENDING and item.get('source') == 'S1':
        return f'is an S1 entry still pending ({labels[status]}) until it is reviewed (TK-REQ-003)'
    return None


def finding_cap(item):
    """The highest finding status (問題狀態) a failed test on item may give: only an accepted or
    modified item gives 已確認; an S2 clause nobody accepted yet gives at most 證據待補 (TK-REQ-003)."""
    return 'confirmed' if item.get('status') in REVIEWED else 'evidence_pending'
