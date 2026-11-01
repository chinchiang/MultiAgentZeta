"""The S2 default policy template (〈定義：需求來源〉, TK-REQ-008).

The template ships with the toolkit: load_template() takes no path, so neither a
ScanManifest nor the project under test can supply or replace it.
"""
import hashlib
import json
from pathlib import Path

TEMPLATE = Path(__file__).with_name('policy-templates') / 'nextjs-supabase-object-authz.json'
TEMPLATE_FIELDS = ('policy_template_id', 'version', 'stack', 'clauses', 'self_acceptance')
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
    """Raise PolicyTemplateInvalid naming the first problem (TK-REQ-008): a malformed structure or
    missing field, a duplicate clause id, a rule other than deny/allow, or self-acceptance that does
    not cover the template: a case naming an unknown clause, a repeated case_id, a case without a
    passed/failed result for every sample version, or a clause without a case."""
    def need(ok, message):
        if not ok:
            raise PolicyTemplateInvalid(message)

    need(isinstance(template, dict), 'the template must be an object')
    for field in TEMPLATE_FIELDS:
        need(template.get(field), f'template field {field!r} is missing')
    need(isinstance(template['clauses'], list), 'clauses must be a list')
    seen = set()
    for i, clause in enumerate(template['clauses']):
        need(isinstance(clause, dict), f'clauses/{i} must be an object')
        for field in CLAUSE_FIELDS:
            need(clause.get(field), f'clauses/{i}: field {field!r} is missing')
        need(clause['rule'] in RULES, f'clauses/{i}: rule must be one of {RULES}, got {clause["rule"]!r}')
        need(clause['id'] not in seen, f'clauses/{i}: clause id {clause["id"]!r} is used twice')
        seen.add(clause['id'])
    acceptance = template['self_acceptance']
    need(isinstance(acceptance, dict), 'self_acceptance must be an object')
    versions, cases = acceptance.get('versions'), acceptance.get('cases')
    need(isinstance(versions, list) and versions and isinstance(cases, list) and cases,
         'self_acceptance needs a list of sample versions and a list of cases')
    case_ids = set()
    for i, case in enumerate(cases):
        need(isinstance(case, dict), f'self_acceptance/cases/{i} must be an object')
        for field in ('case_id', 'clause', 'test', 'expected'):
            need(case.get(field), f'self_acceptance/cases/{i}: field {field!r} is missing')
        need(case['clause'] in seen, f'self_acceptance/cases/{i}: unknown clause {case["clause"]!r}')
        need(case['case_id'] not in case_ids, f'self_acceptance/cases/{i}: case_id {case["case_id"]!r} is used twice')
        case_ids.add(case['case_id'])
        need(isinstance(case['test'], dict) and isinstance(case['expected'], dict),
             f'self_acceptance/cases/{i}: test and expected must be objects')
        for version in versions:
            need(case['expected'].get(version) in RESULTS,
                 f'self_acceptance/cases/{i}: expected result for {version!r} must be one of {RESULTS}, '
                 f'got {case["expected"].get(version)!r}')
    uncovered = seen - {c['clause'] for c in cases}
    need(not uncovered, f'self_acceptance has no case for clause(s) {sorted(uncovered)}')


def template_digest(template):
    """The template version's content digest (TK-REQ-008): sha256 of its canonical JSON, so key order
    and whitespace do not count and content does. Tests pin it per version."""
    canonical = json.dumps(template, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    return 'sha256:' + hashlib.sha256(canonical.encode('utf-8')).hexdigest()
