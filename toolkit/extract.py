"""Deterministic extraction of facts from a project's SQL migrations (〈定義：擷取結果〉, TK-ARC-004).

`extract_facts(files)` reads only text: it never runs SQL and never calls a model, and one input gives one
result, sorted by file and line. `files` maps a project-relative path to the file's text.
"""
import re
from pathlib import Path

RULE = 'sql-rls-v1'  # the extraction rule and its version (〈定義：擷取結果〉)
SUPPORTED_VERSION = 'postgresql-17'  # the PostgreSQL major version the rule is written for; the support matrix's database image
MIGRATIONS = re.compile(r'(?:^|/)supabase/migrations/[^/]+\.sql$')

_IDENT = r'(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)'
_QUALIFIED = re.compile(rf'({_IDENT})\s*\.\s*({_IDENT})')
_CREATE_TABLE = re.compile(rf'create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?({_IDENT}(?:\s*\.\s*{_IDENT})?)',
                           re.I)


_DOLLAR = re.compile(r'\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$')


def _is_e_quote(text, i):
    """Whether single quote at i starts a PostgreSQL E'...' escaped string (the E not ending a longer word)."""
    return (text[i] == "'" and i > 0 and text[i - 1] in 'eE'
            and not (i > 1 and (text[i - 2].isalnum() or text[i - 2] in '_$')))


def _quoted_end(text, i):
    """End index (exclusive) of a '...' / E'...' / "..." / $tag$...$tag$ literal starting at i,
    -1 when i starts one that is never closed, or None when i does not start one."""
    c = text[i]
    if c in ('"', "'"):  # a quoted identifier or a string: a doubled quote inside is a literal quote
        escapes = _is_e_quote(text, i)
        end = i + 1
        while end < len(text):
            if escapes and text[end] == '\\':
                end += 2
            elif text[end] == c and text[end + 1:end + 2] == c:
                end += 2
            elif text[end] == c:
                return end + 1
            else:
                end += 1
        return -1
    if c == '$' and not (i and (text[i - 1].isalnum() or text[i - 1] in '_$')) and (m := _DOLLAR.match(text, i)):
        tag = m.group(0)
        end = text.find(tag, i + len(tag))
        return -1 if end < 0 else end + len(tag)
    return None


def _statements(text):
    """The statements of one SQL file as (line of the first token, text without comments), in file order, and
    the line where a string, comment or $-quote is never closed (None when all are). Quoted text, quoted
    identifiers and $-quoted bodies are kept whole, so a ';' or a keyword inside them is not seen."""
    out, buf, line, start, i = [], [], 1, None, 0
    while i < len(text):
        c = text[i]
        if text.startswith('--', i):
            while i < len(text) and text[i] != '\n':
                i += 1
            continue
        if text.startswith('/*', i):  # block comments nest in PostgreSQL
            depth, end = 1, i + 2
            while end < len(text) and depth:
                if text.startswith('/*', end):
                    depth, end = depth + 1, end + 2
                elif text.startswith('*/', end):
                    depth, end = depth - 1, end + 2
                else:
                    end += 1
            if depth:
                return out, line
            if start is not None:
                buf.append(' ')
            line += text.count('\n', i, end)
            i = end
            continue
        q_end = _quoted_end(text, i)
        if q_end == -1:
            return out, line
        if q_end is not None:
            seg = text[i:q_end]
        elif c == ';':
            if start is not None:
                out.append((start, ''.join(buf).strip()))
            buf, start = [], None
            i += 1
            continue
        else:
            seg = c
        if start is None and not seg.isspace():
            start = line
        if start is not None:
            buf.append(seg)
        line += seg.count('\n')
        i += len(seg)
    if start is not None and ''.join(buf).strip():
        out.append((start, ''.join(buf).strip()))
    return out, None


_CREATE_POLICY = re.compile(rf'create\s+policy\s+({_IDENT})\s+on\s+({_IDENT}(?:\s*\.\s*{_IDENT})?)', re.I)


def _masked(text):
    """(text with quoted parts and everything inside parentheses blanked, whether its parentheses balance).

    Blanking lets keywords be found at the top level; each depth-0 parenthesis stays and every character keeps
    its position ('~' is neither whitespace nor a word character, so word boundaries around keywords stay intact).
    Parentheses balance when none is closed before it is opened and none is left open."""
    out, depth, lowest, i = [], 0, 0, 0
    while i < len(text):
        q_end = _quoted_end(text, i)
        if q_end == -1:
            return ''.join(out) + '~' * (len(text) - i), False
        if q_end is not None:
            if _is_e_quote(text, i) and depth == 0:
                out[-1] = '~'
            out.append(('~' if depth == 0 else ' ') * (q_end - i))
            i = q_end
            continue
        c = text[i]
        if c == '(':
            out.append('(' if depth == 0 else ' ')
            depth += 1
        elif c == ')':
            depth -= 1
            lowest = min(lowest, depth)
            out.append(')' if depth == 0 else ' ')
        else:
            out.append(c if depth == 0 else ' ')
        i += 1
    return ''.join(out), depth == 0 and lowest == 0



def _split_top_commas(text, masked):
    """Slices of `text` separated by top-level commas (commas still present in `masked`)."""
    parts, start = [], 0
    for m in re.finditer(',', masked):
        parts.append(text[start:m.start()])
        start = m.end()
    parts.append(text[start:])
    return parts


_ROLE = re.compile(rf'{_IDENT}$')
_POLICY_TAIL = re.compile(
    r'\s*(?:as\s+(permissive|restrictive)\b\s*)?'
    r'(?:for\s+(all|select|insert|update|delete)\b\s*)?'
    r'(?:to\s+(.+?)\s*)?'
    r'(?:using\s*(\(\s*\))\s*)?'
    r'(?:with\s+check\s*(\(\s*\))\s*)?$',
    re.I | re.S,
)


def _policy(m, statement):
    """The policy fact of a create policy statement; None when it cannot be read (unbalanced parentheses,
    unknown clause, malformed role list, or a USING or WITH CHECK without a parenthesized condition)."""
    rest = statement[m.end():]
    masked, balanced = _masked(rest)
    if not balanced:
        return None
    clauses = _POLICY_TAIL.fullmatch(masked)
    if not clauses:
        return None
    if clauses.group(3) is not None:
        raw_roles = [r.strip() for r in _split_top_commas(rest[clauses.start(3):clauses.end(3)],
                                                          masked[clauses.start(3):clauses.end(3)])]
        if not raw_roles or not all(_ROLE.fullmatch(r) for r in raw_roles):
            return None
        roles = [_unquote(r) for r in raw_roles]
    else:
        roles = ['public']
    using = rest[clauses.start(4) + 1:clauses.end(4) - 1].strip() if clauses.group(4) else None
    with_check = rest[clauses.start(5) + 1:clauses.end(5) - 1].strip() if clauses.group(5) else None
    return {'kind': 'policy', 'name': _unquote_name(m.group(1)), 'table': _qualified(m.group(2)),
            'permissive': (clauses.group(1) or 'permissive').lower() == 'permissive',
            'command': (clauses.group(2) or 'all').lower(), 'roles': roles,
            'using': using, 'with_check': with_check}


def _unquote_name(ident):
    """A policy name keeps its case: an unquoted name is folded to lower case by PostgreSQL."""
    return ident[1:-1].replace('""', '"') if ident.startswith('"') else ident.lower()


def _unquote(ident):
    return ident[1:-1].replace('""', '"') if ident.startswith('"') else ident.lower()


def _qualified(name):
    m = _QUALIFIED.fullmatch(name.strip())
    return f'{_unquote(m.group(1))}.{_unquote(m.group(2))}' if m else None


_NO_SCHEMA = 'table name has no schema'
_UNTRACKED = 'statement changes a table or policy that is not tracked'
_ALTER_TABLE = re.compile(
    rf'alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?({_IDENT}(?:\s*\.\s*{_IDENT})?)(?:\s*\*)?\s+(.*)$',
    re.I | re.S,
)
_ENABLE_OR_DISABLE_RLS = re.compile(r'(enable|disable)\s+row\s+level\s+security$', re.I)
_CHANGES_UNTRACKED = re.compile(r'(?:(?:no\s+)?force\s+row\s+level\s+security|rename\b|set\s+schema\b)', re.I)
_FUNCTION = re.compile(r'create\s+(?:or\s+replace\s+)?(?:function|procedure)\b', re.I)
_MAY_CHANGE = re.compile(r'create\s+table|create\s+policy|row\s+level\s+security', re.I)
_DROPS_OR_ALTERS = re.compile(r'(?:drop\s+(?:table|policy|schema)\b|alter\s+(?:policy|schema)\b)', re.I)


def _alter_table(m):
    """(facts, reason) of an ALTER TABLE statement, split by top-level commas (〈定義：擷取結果〉, TK-ARC-004)."""
    body = m.group(2).strip()
    masked, balanced = _masked(body)
    if not balanced:
        return [], _UNTRACKED
    actions = [a.strip() for a in _split_top_commas(masked, masked)]
    if any(not a for a in actions):
        return [], _UNTRACKED
    rls_states = []
    for action in actions:
        rls = _ENABLE_OR_DISABLE_RLS.fullmatch(action)
        if rls:
            rls_states.append(rls.group(1).lower() == 'enable')
        elif _CHANGES_UNTRACKED.match(action) or re.search(r'\brow\s+level\s+security\b', action, re.I):
            return [], _UNTRACKED
    if not rls_states:
        return [], None
    table = _qualified(m.group(1))
    if not table:
        return [], _NO_SCHEMA
    return [{'kind': 'rls', 'table': table, 'enabled': enabled} for enabled in rls_states], None


def _read(statement):
    """(facts, reason) for one statement; ([], None) for a statement that does not touch tables, row level
    security or policies."""
    if re.match(r'do\b', statement, re.I):
        return [], 'do block runs SQL that is not read'
    if _FUNCTION.match(statement):  # the body is not read; it matters only if it may change tables or policies
        return [], ('function or procedure body may change tables or policies and is not read'
                    if _MAY_CHANGE.search(statement) else None)
    if _DROPS_OR_ALTERS.match(statement):
        return [], _UNTRACKED
    m = _CREATE_TABLE.match(statement)
    if m:
        table = _qualified(m.group(1))
        return ([{'kind': 'table', 'name': table}], None) if table else ([], _NO_SCHEMA)
    if re.match(r'create\s+policy\b', statement, re.I):
        m = _CREATE_POLICY.match(statement)
        if not m:
            return [], 'policy statement not understood'
        if not _qualified(m.group(2)):
            return [], _NO_SCHEMA
        policy = _policy(m, statement)
        return ([policy], None) if policy else ([], 'policy statement not understood')
    if re.match(r'alter\s+table\b', statement, re.I):
        m = _ALTER_TABLE.match(statement)
        return _alter_table(m) if m else ([], _UNTRACKED)
    return [], None


def _is_nonempty_str(v):
    return isinstance(v, str) and bool(v)


def _is_qualified_table(v):
    return isinstance(v, str) and '.' in v[1:-1]


def _is_opt_str(v):
    return v is None or isinstance(v, str)


POLICY_COMMANDS = ('select', 'insert', 'update', 'delete', 'all')  # 〈定義：擷取結果〉
_BOOL_CHECK = (lambda v: isinstance(v, bool), 'a boolean')
_TABLE_CHECK = (_is_qualified_table, 'a schema.table string')

# What an extracted fact must carry, by kind, and nothing else (〈定義：擷取結果〉, TK-DAT-007). A model's
# confidence or rationale, or a reference to an execution or an observation, are not extracted and have no place here.
_FACT_CHECKS = {
    'table': {'name': _TABLE_CHECK},
    'rls': {'table': _TABLE_CHECK, 'enabled': _BOOL_CHECK},
    'policy': {
        'name': (_is_nonempty_str, 'a non-empty string'),
        'table': _TABLE_CHECK,
        'permissive': _BOOL_CHECK,
        'command': (lambda v: v in POLICY_COMMANDS, f'one of {POLICY_COMMANDS}'),
        'roles': (lambda v: isinstance(v, list) and bool(v) and all(_is_nonempty_str(r) for r in v),
                  'a non-empty list of role names'),
        'using': (_is_opt_str, 'a string or null'),
        'with_check': (_is_opt_str, 'a string or null'),
    },
}
FACT_FIELDS = {k: set(v) for k, v in _FACT_CHECKS.items()}
REGISTERED_RULES = (RULE,)
COMMON_FIELDS = {'kind', 'source', 'method', 'supported_version'}


def codefact_problems(record):
    """Why record is not a CodeFact (〈定義：擷取結果〉, TK-DAT-007); empty when it is.

    A CodeFact comes from a registered extraction rule, is of a kind the rule extracts, has all and only the
    fields of that kind with valid values, and has a source location with a positive line number. What a model
    proposed or an observation showed fails these checks, so it cannot be stored as a CodeFact.
    """
    if not isinstance(record, dict):
        return ['CodeFact must be an object']
    kind = record.get('kind')
    if not isinstance(kind, str) or kind not in FACT_FIELDS:
        return [f"kind {kind!r} is not extracted by {RULE}"]
    problems = []
    if record.get('method') not in REGISTERED_RULES:
        problems.append(f"method {record.get('method')!r} is not a registered extraction rule")
    source = record.get('source')
    if not (isinstance(source, dict) and _is_nonempty_str(source.get('file'))
            and isinstance(source.get('line'), int) and not isinstance(source.get('line'), bool)
            and source['line'] >= 1):
        problems.append('source needs a file and an integer line')
    elif set(source) != {'file', 'line'}:
        problems += [f"source field {k!r} is not part of a CodeFact source"
                     for k in sorted(set(source) - {'file', 'line'})]
    if record.get('supported_version') != SUPPORTED_VERSION:
        problems.append(f"supported_version {record.get('supported_version')!r} is not {SUPPORTED_VERSION!r}")
    allowed = FACT_FIELDS[kind] | COMMON_FIELDS
    problems += [f"field {k!r} is not part of an extracted {kind} fact" for k in sorted(set(record) - allowed)]
    for field, (ok, expected) in _FACT_CHECKS[kind].items():
        if field not in record:
            problems.append(f"missing field {field!r} of an extracted {kind} fact")
        elif not ok(record[field]):
            problems.append(f"field {field!r} of an extracted {kind} fact must be {expected}")
    return problems


def require_codefacts(facts):
    """Raise ValueError when `facts` is not a list of valid CodeFacts (〈定義：擷取結果〉, TK-DAT-007)."""
    if not isinstance(facts, list):
        raise ValueError('facts must be a list of CodeFacts')
    not_facts = [p for f in facts for p in codefact_problems(f)]
    if not_facts:  # TK-DAT-007: only extraction makes a CodeFact; anything else is refused
        raise ValueError('the inventory holds something that is not a CodeFact: ' + '; '.join(not_facts))


def read_migrations(project):
    """The SQL migrations of a project as extract_facts takes them: project-relative path -> text, in path order;
    None for a file that cannot be read or decoded (extract_facts lists it as unresolved). A project without
    supabase/migrations gives nothing."""
    root, found = Path(project), {}
    for path in sorted(root.glob('supabase/migrations/*.sql')):
        try:
            found[path.relative_to(root).as_posix()] = path.read_text(encoding='utf-8')
        except (UnicodeDecodeError, OSError):
            found[path.relative_to(root).as_posix()] = None
    return found


def extract_facts(files):
    """The facts and the unresolved content of every SQL migration in files.

    Returns {'rule', 'facts', 'unresolved'}: each fact has its kind, source file and line and the rule that
    produced it; each unresolved entry has file, line and reason (line 0: the whole file). Unresolved content
    is listed, never taken as absent (TK-ARC-004), and makes the inventory incomplete (〈定義：覆蓋面向〉).
    """
    facts, unresolved = [], []
    for path in sorted(p for p in files if MIGRATIONS.search(p)):
        if not isinstance(files[path], str):
            unresolved.append({'file': path, 'line': 0, 'reason': 'file could not be read'})
            continue
        statements, never_closed = _statements(files[path])
        for line, statement in statements:
            found, reason = _read(statement)
            for fact in found:
                facts.append({**fact, 'source': {'file': path, 'line': line}, 'method': RULE,
                              'supported_version': SUPPORTED_VERSION})
            if reason:
                unresolved.append({'file': path, 'line': line, 'reason': reason})
        if never_closed:
            unresolved.append({'file': path, 'line': never_closed, 'reason': 'string, comment or $-quote is never closed'})
    return {'rule': RULE, 'facts': facts, 'unresolved': unresolved}
