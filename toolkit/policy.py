"""The S2 default policy template (〈定義：需求來源〉, TK-REQ-008).

The template ships with the toolkit: load_template() takes no path, so neither a
ScanManifest nor the project under test can supply or replace it.
"""
import hashlib
import json
from pathlib import Path

TEMPLATE = Path(__file__).with_name('policy-templates') / 'nextjs-supabase-object-authz.json'
TEMPLATE_FIELDS = ('template_id', 'version', 'stack', 'clauses', 'self_acceptance')
RESULTS = ('passed', 'failed')  # a self-acceptance case has a definite expected result
CLAUSE_FIELDS = ('id', 'statement', 'rule', 'actors')
RULES = ('deny', 'allow')  # the allow/deny rule of a confirmation item (〈定義：確認清單〉)


class PolicyTemplateInvalid(Exception):
    """The S2 template is malformed; it is not used (TK-REQ-008)."""


def load_template():
    """The toolkit's S2 template for Next.js + Supabase object authorization, validated."""
    with open(TEMPLATE, encoding='utf-8') as f:
        template = json.load(f)
    validate(template)
    return template


def validate(template):
    """Raise PolicyTemplateInvalid naming the first problem: a missing field, a duplicate clause id,
    a rule other than deny/allow, or self-acceptance that does not cover the template (TK-REQ-008):
    a case naming an unknown clause, a case without a passed/failed result for every sample
    version, or a clause without a case."""
    for field in TEMPLATE_FIELDS:
        if not template.get(field):
            raise PolicyTemplateInvalid(f'template field {field!r} is missing')
    seen = set()
    for i, clause in enumerate(template['clauses']):
        for field in CLAUSE_FIELDS:
            if not clause.get(field):
                raise PolicyTemplateInvalid(f'clauses/{i}: field {field!r} is missing')
        if clause['rule'] not in RULES:
            raise PolicyTemplateInvalid(f'clauses/{i}: rule must be one of {RULES}, got {clause["rule"]!r}')
        if clause['id'] in seen:
            raise PolicyTemplateInvalid(f'clauses/{i}: clause id {clause["id"]!r} is used twice')
        seen.add(clause['id'])
    acceptance = template['self_acceptance']
    versions = acceptance.get('versions') or []
    if not versions or not acceptance.get('cases'):
        raise PolicyTemplateInvalid('self_acceptance needs sample versions and cases')
    for i, case in enumerate(acceptance['cases']):
        if case.get('clause') not in seen:
            raise PolicyTemplateInvalid(f'self_acceptance/cases/{i}: unknown clause {case.get("clause")!r}')
        expected = case.get('expected') or {}
        for version in versions:
            if expected.get(version) not in RESULTS:
                raise PolicyTemplateInvalid(f'self_acceptance/cases/{i}: expected result for {version!r} must be '
                                            f'one of {RESULTS}, got {expected.get(version)!r}')
    uncovered = seen - {c['clause'] for c in acceptance['cases']}
    if uncovered:
        raise PolicyTemplateInvalid(f'self_acceptance has no case for clause(s) {sorted(uncovered)}')


def template_digest(template):
    """sha256 of the template's canonical JSON: key order and whitespace do not count, content does."""
    canonical = json.dumps(template, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    return 'sha256:' + hashlib.sha256(canonical.encode('utf-8')).hexdigest()
