"""Deterministic extraction of facts from a project's SQL migrations (〈定義：擷取結果〉, TK-ARC-004).

`extract_facts(files)` reads only text: it never runs SQL and never calls a model, and one input gives one
result, sorted by file and line. `files` maps a project-relative path to the file's text.
"""
import re

RULE = 'sql-rls-v1'  # the extraction rule and its version (〈定義：擷取結果〉)
MIGRATIONS = re.compile(r'(?:^|/)supabase/migrations/[^/]+\.sql$')

_IDENT = r'(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)'
_QUALIFIED = re.compile(rf'({_IDENT})\s*\.\s*({_IDENT})')
_CREATE_TABLE = re.compile(rf'create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?({_IDENT}(?:\s*\.\s*{_IDENT})?)',
                           re.I)


_DOLLAR = re.compile(r'\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$')


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
            line += text.count('\n', i, end)
            i = end
            continue
        if c in ('"', "'"):  # a quoted identifier or a string: a doubled quote inside is a literal quote
            # E'...' (the E not the end of a longer word) also takes backslash escapes; an ordinary string does not
            escapes = (c == "'" and i > 0 and text[i - 1] in 'eE'
                       and not (i > 1 and (text[i - 2].isalnum() or text[i - 2] in '_$')))
            end = i + 1
            while end < len(text):
                if escapes and text[end] == '\\':
                    end += 2
                elif text[end] == c and text[end + 1:end + 2] == c:
                    end += 2
                elif text[end] == c:
                    break
                else:
                    end += 1
            if end >= len(text):
                return out, line
            seg = text[i:end + 1]
        elif c == '$' and not (i and (text[i - 1].isalnum() or text[i - 1] in '_$')) and _DOLLAR.match(text, i):
            tag = _DOLLAR.match(text, i).group(0)
            end = text.find(tag, i + len(tag))
            if end < 0:
                return out, line
            seg = text[i:end + len(tag)]
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
    its position. Parentheses balance when none is closed before it is opened and none is left open."""
    out, depth, quote, lowest = [], 0, None, 0
    for c in text:
        if quote:
            out.append('_')
            quote = None if c == quote else quote
        elif c in ('"', "'"):
            out.append('_')
            quote = c
        elif c == '(':
            out.append('(' if depth == 0 else ' ')
            depth += 1
        elif c == ')':
            depth -= 1
            lowest = min(lowest, depth)
            out.append(')' if depth == 0 else ' ')
        else:
            out.append(c if depth == 0 else ' ')
    return ''.join(out), depth == 0 and lowest == 0



def _condition(rest, masked, keyword):
    """The text inside the parentheses after keyword (USING or WITH CHECK), as written; None when the
    keyword is absent; False when the keyword is there without a parenthesized condition."""
    m = re.search(rf'\b{keyword}\b', masked, re.I)
    if not m:
        return None
    after = masked[m.end():].lstrip()
    if not after.startswith('('):
        return False
    open_at = m.end() + len(masked[m.end():]) - len(after)
    return rest[open_at + 1:masked.index(')', open_at)].strip()


def _policy(m, statement):
    """The policy fact of a create policy statement; None when it cannot be read (unbalanced parentheses, or a
    USING or WITH CHECK without a parenthesized condition)."""
    rest = statement[m.end():]
    masked, balanced = _masked(rest)
    if not balanced:
        return None
    using, with_check = _condition(rest, masked, 'using'), _condition(rest, masked, r'with\s+check')
    if using is False or with_check is False:
        return None
    command = re.search(r'\bfor\s+(all|select|insert|update|delete)\b', masked, re.I)
    to = re.search(r'\bto\s+(.+?)(?=\s+(?:using|with)\b|$)', masked, re.I | re.S)
    roles = [_unquote(r.strip()) for r in rest[to.start(1):to.end(1)].split(',')] if to else ['public']
    return {'kind': 'policy', 'name': _unquote_name(m.group(1)), 'table': _qualified(m.group(2)),
            'command': command.group(1).lower() if command else 'all', 'roles': roles,
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
_ALTER_TABLE = re.compile(rf'alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?({_IDENT}(?:\s*\.\s*{_IDENT})?)\s+(.*)$', re.I | re.S)
_ENABLE_OR_DISABLE_RLS = re.compile(r'(enable|disable)\s+row\s+level\s+security$', re.I)
_CHANGES_UNTRACKED = re.compile(r'(?:(?:no\s+)?force\s+row\s+level\s+security|rename\b)', re.I)
_DROPS_OR_ALTERS = re.compile(r'(?:drop\s+(?:table|policy)\b|alter\s+policy\b)', re.I)


def _read(statement):
    """The fact one statement gives, or the reason it cannot be read; (None, None) for a statement that does not
    touch tables, row level security or policies."""
    if re.match(r'do\b', statement, re.I):
        return None, 'do block runs SQL that is not read'
    if _DROPS_OR_ALTERS.match(statement):
        return None, _UNTRACKED
    m = _CREATE_TABLE.match(statement)
    if m:
        return ({'kind': 'table', 'name': _qualified(m.group(1))}, None) if _qualified(m.group(1)) else (None, _NO_SCHEMA)
    if re.match(r'create\s+policy\b', statement, re.I):
        m = _CREATE_POLICY.match(statement)
        if not m:
            return None, 'policy statement not understood'
        if not _qualified(m.group(2)):
            return None, _NO_SCHEMA
        policy = _policy(m, statement)
        return (policy, None) if policy else (None, 'policy statement not understood')
    m = _ALTER_TABLE.match(statement)
    if m:
        clause = m.group(2).strip()
        rls = _ENABLE_OR_DISABLE_RLS.fullmatch(clause)
        if rls:
            if not _qualified(m.group(1)):
                return None, _NO_SCHEMA
            return {'kind': 'rls', 'table': _qualified(m.group(1)), 'enabled': rls.group(1).lower() == 'enable'}, None
        if _CHANGES_UNTRACKED.match(clause):
            return None, _UNTRACKED
    return None, None


# What an extracted fact may carry, by kind: nothing else rides along (TK-DAT-007). A model's confidence or
# rationale, or a reference to an execution or an observation, are not extracted and have no place here.
FACT_FIELDS = {
    'table': {'name'},
    'rls': {'table', 'enabled'},
    'policy': {'name', 'table', 'command', 'roles', 'using', 'with_check'},
}
REGISTERED_RULES = (RULE,)


def codefact_problems(record):
    """Why record is not a CodeFact (TK-DAT-007); empty when it is.

    A CodeFact comes from a registered extraction rule, is of a kind the rule extracts, has only the fields of
    that kind and a source location. What a model proposed or an observation showed fails these checks, so it
    cannot be stored as a CodeFact; it belongs in ThreatIR or in an observation record.
    """
    if record.get('kind') not in FACT_FIELDS:
        return [f"kind {record.get('kind')!r} is not extracted by {RULE}"]
    problems = []
    if record.get('method') not in REGISTERED_RULES:
        problems.append(f"method {record.get('method')!r} is not a registered extraction rule")
    source = record.get('source')
    if not (isinstance(source, dict) and isinstance(source.get('file'), str) and source['file']
            and isinstance(source.get('line'), int) and not isinstance(source.get('line'), bool)):
        problems.append('source needs a file and an integer line')
    allowed = FACT_FIELDS[record['kind']] | {'kind', 'source', 'method'}
    problems += [f"field {k!r} is not part of an extracted {record['kind']} fact" for k in sorted(set(record) - allowed)]
    return problems


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
            fact, reason = _read(statement)
            if fact:
                facts.append({**fact, 'source': {'file': path, 'line': line}, 'method': RULE})
            elif reason:
                unresolved.append({'file': path, 'line': line, 'reason': reason})
        if never_closed:
            unresolved.append({'file': path, 'line': never_closed, 'reason': 'string, comment or $-quote is never closed'})
    return {'rule': RULE, 'facts': facts, 'unresolved': unresolved}
