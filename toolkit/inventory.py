"""The inventory of a project: what extraction found, plus what no loaded framework module can see
(〈定義：框架模組〉, 〈定義：擷取結果〉, TK-SCP-006, TK-ARC-004).

`inventory(files, modules)` is the denominator's source: one item per extracted table and policy, and one item
per scope that is unsupported. Unsupported scopes stay in the inventory (TK-SCP-006: without a module the
capability is listed as unsupported and coverage does not rise); it only reads text.
"""
from toolkit import extract

NO_MODULE = 'framework module not loaded'

# The framework modules and their declarations (〈定義：框架模組〉, TK-SCP-006): the capability a loaded module
# gives, its extraction rule versions, recognizable structures, evidence, test templates, judges, known
# limitations (what it cannot see) and self-acceptance samples.
MODULES = {
    'supabase-rls': {
        'capability': 'rls-tables-and-policies',
        'versions': [extract.RULE],
        'structures': ['supabase/migrations/*.sql'],
        'evidence': ['migration file text'],
        'templates': ['nextjs-supabase-object-authz'],
        'judges': ['denial cases and allowed cases (spec chapter 7)'],
        'self_acceptance': [f'samples/object-authz/{v}' for v in ('vulnerable', 'patched', 'legit', 'lax-update-policy')],
        'limitations': [
            {'scope': 'rls-functions', 'reason': 'no template for functions (RPC, SECURITY DEFINER) yet; '
                                                 'includes writes whose response looks like a denial'},
            {'scope': 'rls-views', 'reason': 'no template for views yet'},
            {'scope': 'rls-column-privileges', 'reason': 'no template for column-level privileges or masking yet'},
        ],
    },
}
# Surfaces no v0.1 module covers: listed as unsupported, and routes and Server Actions need supplementary
# observation because no extraction rule resolves them (TK-ARC-004).
UNCOVERED = [
    {'scope': 'nextjs-routes', 'reason': NO_MODULE + '; dynamic routes need supplementary observation',
     'needs_supplement': True},
    {'scope': 'nextjs-server-actions', 'reason': NO_MODULE + '; Server Actions need supplementary observation',
     'needs_supplement': True},
]
DEFAULT_MODULES = tuple(MODULES)


def inventory(files, modules=DEFAULT_MODULES):
    """The inventory of files with the given framework modules loaded: facts, unresolved content, items, and
    the completeness of what was found ('complete', or 'unknown' when anything is unresolved)."""
    found = extract.extract_facts(files) if 'supabase-rls' in modules else {'facts': [], 'unresolved': []}
    items = []
    for fact in found['facts']:
        if fact['kind'] == 'table':
            items.append({'scope': 'rls-table', 'ref': fact['name'], 'state': 'inventoried'})
        elif fact['kind'] == 'policy':
            items.append({'scope': 'rls-policy', 'ref': f"{fact['table']}: {fact['name']}", 'state': 'inventoried'})
    # What a module cannot see stays listed whether or not it is loaded; a module that is not loaded adds its
    # whole capability as unsupported, so removing a module never takes anything out of the inventory.
    unsupported = ([{'scope': MODULES[m]['capability'], 'reason': NO_MODULE} for m in MODULES if m not in modules]
                   + [dict(u) for m in MODULES for u in MODULES[m]['limitations']] + [dict(u) for u in UNCOVERED])
    items += [{**u, 'state': 'unsupported'} for u in unsupported]
    complete = not found['unresolved'] and all(m in modules for m in MODULES)
    return {'rule': extract.RULE, 'facts': found['facts'], 'unresolved': found['unresolved'], 'items': items,
            'unsupported_items': unsupported, 'completeness': 'complete' if complete else 'unknown'}
