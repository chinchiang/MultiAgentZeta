"""Coverage and the effective judgement rate (〈定義：覆蓋面向〉, TK-EVD-008, TK-EVD-009, TK-SCP-006).

`coverage(inventory, cases, exclusions)` is pure: the inventory (toolkit.inventory) and the scheduled cases in,
the numbers of the coverage record out. Nothing blocked, failed to run or unsupported leaves the denominator.
"""

from toolkit import extract
from toolkit import inventory as inventory_module

EXECUTED = ('passed', 'failed')
RESULTS = EXECUTED + ('blocked', 'error', 'untested', 'cancelled', 'unsupported')  # 〈定義：測試結果〉 and 取消
EXCLUSION_FIELDS = ('reason', 'confirmed_by', 'version')  # TK-EVD-009: all three, besides the item itself


def _key(item):
    """What an exclusion names: the ref of an inventoried item, the scope of an unsupported one."""
    return item['ref'] if item['state'] == 'inventoried' else item['scope']


def _exclusions(items, exclusions):
    """The exclusions that hold (their item keys) and the ones refused, each with its problem."""
    known = {_key(i) for i in items}
    accepted, refused = [], []
    for e in exclusions:
        missing = [f for f in EXCLUSION_FIELDS if not str(e.get(f) or '').strip()]
        if e['ref'] not in known:
            refused.append({'ref': e['ref'], 'problem': 'not in the inventory'})
        elif missing:
            refused.append({'ref': e['ref'], 'problem': 'missing ' + ', '.join(missing)})
        else:
            accepted.append(e)
    return accepted, refused


def _state(denominator, any_excluded):
    return 'measured' if denominator else ('not_applicable' if any_excluded else 'insufficient_data')


def coverage(inventory, cases, exclusions=(), *, environment_supported=True):
    """The coverage record's numbers for the scheduled cases against the inventory.

    A case is {'id', 'result', 'valid', 'module', 'covers'}: its result (passed, failed, blocked, error,
    untested, cancelled or unsupported), whether its precondition and control held, the framework module whose
    judge it needs, and the inventory items it exercises. The denominator is the scheduled cases plus the
    unsupported scopes of the inventory; a case whose module is not loaded is counted as unsupported and never
    as a valid judgement, so removing a module cannot raise the rate (TK-SCP-006). When the runtime environment
    has versions outside the support matrix (`environment_supported` false, TK-SCP-001), `claim` stays
    'known_scope_only'.
    """
    extract.require_codefacts(inventory['facts'])
    unknown = [c for c in cases if c['result'] not in RESULTS]
    if unknown:  # TK-EVD-008: a result no count knows would be dropped silently
        raise ValueError('; '.join(f"case {c['id']!r} has the unknown result {c['result']!r}" for c in unknown))
    loaded = set(inventory['loaded'])
    accepted, refused = _exclusions(inventory['items'], exclusions)
    left_out = {e['ref'] for e in accepted}
    unsupported_scopes = [i for i in inventory['items'] if i['state'] == 'unsupported' and _key(i) not in left_out]
    cases = [c for c in cases if not (c['covers'] and set(c['covers']) <= left_out)]
    judged = [c for c in cases if c['module'] in loaded]
    unjudged = [c for c in cases if c['module'] not in loaded]
    executed = [c for c in judged if c['result'] in EXECUTED]
    valid = [c for c in executed if c['valid']]
    unsupported = len(unsupported_scopes) + len(unjudged) + sum(c['result'] == 'unsupported' for c in judged)
    denominator = len(cases) + len(unsupported_scopes)
    return {
        'denominator': denominator,
        'executed': len(executed),
        'valid_judgements': len(valid),
        'blocked': sum(c['result'] == 'blocked' for c in judged),
        'errors': sum(c['result'] == 'error' for c in judged),
        'untested': sum(c['result'] == 'untested' for c in judged),
        'cancelled': sum(c['result'] == 'cancelled' for c in judged),
        'unsupported': unsupported,
        'effective_judgement_rate': len(valid) / denominator if denominator else None,
        # Pending confirmation (〈定義：覆蓋面向〉): the supported share of the denominator, and the share of the
        # scheduled cases that reached a passed or failed result.
        'tool_support_rate': (denominator - unsupported) / denominator if denominator else None,
        'required_test_completion_rate': len(executed) / len(cases) if cases else None,
        'states': {'effective_judgement_rate': _state(denominator, bool(accepted)),
                   'tool_support_rate': _state(denominator, bool(accepted)),
                   'required_test_completion_rate': _state(len(cases), bool(accepted))},
        'claim': ('whole_scope' if inventory['completeness'] == 'complete' and environment_supported
                  else 'known_scope_only'),
        'tables_and_policies': _tables_and_policies(inventory, valid),
        'excluded': accepted,
        'rejected_exclusions': refused,
    }


def _tables_and_policies(inventory, valid):
    """The counts of the 資料表與政策 row: what was inventoried, how many tables have row level security and
    how many of those no policy covers, what is unresolved, and the items a valid case exercised. A table's
    row level security is what its last enable or disable statement left it."""
    facts = inventory['facts']
    with_rls = {table for table, enabled in inventory_module.rls_state(inventory).items() if enabled}
    with_policy = {f['table'] for f in facts if f['kind'] == 'policy'}
    inventoried = {i['ref'] for i in inventory['items'] if i['state'] == 'inventoried'}
    return {'inventoried': len(inventoried), 'rls_enabled': len(with_rls), 'without_policy': len(with_rls - with_policy),
            'unresolved': len(inventory['unresolved']),
            'judged': len(inventoried & {ref for c in valid for ref in c['covers']})}
