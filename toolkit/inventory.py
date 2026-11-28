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
        'self_acceptance': [f'samples/object-authz/{v}' for v in ('vulnerable', 'patched', 'legit', 'lax-update-policy',
                                                                    'leaky-denial', 'side-effect-on-denial')],
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


def inventory(files, modules=DEFAULT_MODULES, extra_unsupported=()):
    """The inventory of files with the given framework modules loaded: facts, unresolved content, items, and
    the completeness of what was found ('complete', or 'unknown' when anything is unresolved or a module is
    not loaded). extra_unsupported are scopes the run itself knows it cannot test (an identity gap): they join
    the unsupported scopes."""
    found = extract.extract_facts(files) if 'supabase-rls' in modules else {'facts': [], 'unresolved': []}
    return _assemble(found, modules, extra_unsupported)


def not_read(reason, modules=DEFAULT_MODULES, extra_unsupported=()):
    """The inventory of a project that was not read (a run blocked before its source was verified): nothing is
    inventoried and the inventory is unknown, with the reason as its one unresolved entry."""
    found = {'facts': [], 'unresolved': [{'file': '(project)', 'line': 0, 'reason': reason}]}
    return _assemble(found, modules, extra_unsupported)


def _assemble(found, modules, extra_unsupported):
    items = []
    for fact in found['facts']:
        if fact['kind'] == 'table':
            items.append({'scope': 'rls-table', 'ref': fact['name'], 'state': 'inventoried'})
        elif fact['kind'] == 'policy':
            items.append({'scope': 'rls-policy', 'ref': f"{fact['table']}: {fact['name']}", 'state': 'inventoried'})
    # What a module cannot see stays listed whether or not it is loaded; a module that is not loaded adds its
    # whole capability as unsupported, so removing a module never takes anything out of the inventory.
    unsupported = ([{'scope': MODULES[m]['capability'], 'reason': NO_MODULE} for m in MODULES if m not in modules]
                   + [dict(u) for m in MODULES for u in MODULES[m]['limitations']] + [dict(u) for u in UNCOVERED]
                   + [dict(u) for u in extra_unsupported])
    items += [{**u, 'state': 'unsupported'} for u in unsupported]
    complete = not found['unresolved'] and all(m in modules for m in MODULES)
    return {'rule': extract.RULE, 'loaded': [m for m in MODULES if m in modules], 'facts': found['facts'],
            'unresolved': found['unresolved'], 'items': items, 'unsupported_items': unsupported,
            'completeness': 'complete' if complete else 'unknown'}


DEFAULT_SCHEMA = 'public'  # a resource name without a schema is read as public.<name>: the schema the data API exposes


def covers(inventory, resources, command):
    """The inventoried items that a test of these resources with this SQL command (select, insert, update or
    delete) exercises: each resource's table, and the policies on it for that command or for all commands.

    The refs are those of inventory['items'], in the order the inventory has them; what the inventory does
    not hold (a table that was not extracted, a module that is not loaded) is not covered."""
    inventoried = {i['ref'] for i in inventory['items'] if i['state'] == 'inventoried'}
    refs = []
    for table in dict.fromkeys(r if '.' in r else f'{DEFAULT_SCHEMA}.{r}' for r in resources):
        if table not in inventoried:
            continue
        refs.append(table)
        refs += [ref for f in inventory['facts']
                 if f['kind'] == 'policy' and f['table'] == table and f['command'] in (command, 'all')
                 and (ref := f"{table}: {f['name']}") in inventoried]
    return refs


def rls_state(inventory):
    """Whether each table has row level security, as its last enable or disable statement left it: table -> bool.
    The facts come in migration order (file path, then line), so the last one decides."""
    state = {}
    for fact in inventory['facts']:
        if fact['kind'] == 'rls':
            state[fact['table']] = fact['enabled']
    return state
