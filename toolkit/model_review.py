"""The model review path (#13): the tasks a project gives and the slice of each, assembled from CodeFacts
(〈定義：審查任務的單位〉, TK-REV-001, TK-REV-002, TK-REV-003).

Everything here is pure and deterministic: no model is called and nothing is read from disk. v0.1 reviews the
database global task, one task per inventoried table with its policies (TK-REV-002 stays deferred in the spec;
this is the one part the sample can exercise). Entry tasks follow the inventory's entry items; v0.1 extraction
finds none, so only hand-written inventories have them.
"""
import hashlib
import json

from toolkit import extract, inventory as inventory_module


def review_tasks(inventory):
    """The review tasks of an inventory: an entry task for each inventoried entry, then a database task for
    each inventoried table, both in inventory order (TK-REV-001: the tasks follow the inventory)."""
    inventoried = [i for i in inventory['items'] if i['state'] == 'inventoried']
    return ([{'kind': 'entry', 'id': f"entry:{i['ref']}", 'unit': i['ref']} for i in inventoried if i['scope'] == 'entry']
            + [{'kind': 'database', 'id': f"database:{i['ref']}", 'unit': i['ref']}
               for i in inventoried if i['scope'] == 'rls-table'])


TASK_KINDS = ('entry', 'database')


def slice_of(task, inventory):
    """The slice of a task: what the model is sent, assembled from CodeFacts in a fixed order, with the digest of
    its content (TK-REV-003). The same inventory gives the same slice and digest, whatever the order of the files.

    A database slice holds the table, whether it has row level security, its policies as written, and all
    unresolved content of the inventory in a fixed order, so a gap the model cannot see is still disclosed
    even when it came from a migration file that yielded no CodeFact (TK-ARC-004). Only extracted CodeFacts
    and known task kinds ('entry', 'database') are accepted (TK-DAT-007, 〈定義：審查任務的單位〉)."""
    kind = task.get('kind') if isinstance(task, dict) else None
    if kind not in TASK_KINDS:
        raise ValueError(f'unknown review task kind {kind!r}; expected one of {TASK_KINDS}')
    not_facts = [p for f in inventory['facts']
                 for p in (extract.codefact_problems(f) if isinstance(f, dict) else ['CodeFact must be an object'])]
    if not_facts:  # TK-DAT-007: only extraction makes a CodeFact; anything else is refused before assembling a slice
        raise ValueError('the inventory holds something that is not a CodeFact: ' + '; '.join(not_facts))
    if kind == 'entry':
        content = {'task': task['id'], 'kind': 'entry', 'entry': task['unit'], 'unresolved': []}
    else:
        table = task['unit']
        facts = [f for f in inventory['facts']
                 if (f['kind'] == 'table' and f['name'] == table) or (f['kind'] in ('rls', 'policy') and f['table'] == table)]
        policies = [{k: f[k] for k in ('name', 'permissive', 'command', 'roles', 'using', 'with_check', 'source')}
                    for f in facts if f['kind'] == 'policy']
        unresolved = sorted((dict(u) for u in inventory['unresolved']),
                            key=lambda u: (u['file'], u['line'], u['reason']))
        content = {'task': task['id'], 'kind': 'database', 'table': table,
                   'rls_enabled': inventory_module.rls_state(inventory).get(table, False), 'policies': policies,
                   'unresolved': unresolved}
    content |= {'rule': inventory['rule'], 'supported_version': extract.SUPPORTED_VERSION}
    canonical = json.dumps(content, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    return {**content, 'digest': 'sha256:' + hashlib.sha256(canonical.encode('utf-8')).hexdigest()}
