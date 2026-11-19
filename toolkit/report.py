"""Report contract of a scan run: validate(report) and render_markdown(report).

The JSON report is the native format (TK-EVD-003); its structure is the versioned
JSON Schema in schemas/report-v1.json. validate() also checks the conditions that
span records, which JSON Schema cannot express.
"""
import json
import re
from pathlib import Path

import jsonschema

from toolkit import control, item_rule, policy

SCHEMA = json.loads((Path(__file__).parent / 'schemas' / 'report-v1.json').read_text(encoding='utf-8'))


def _schema_problems(doc):
    validator = jsonschema.Draft202012Validator(SCHEMA)
    return [f'{"/".join(map(str, e.absolute_path)) or "(report)"}: {e.message}' for e in validator.iter_errors(doc)]


def _list(doc, key):
    value = doc.get(key) if isinstance(doc, dict) else None
    return value if isinstance(value, list) else []


def _records(doc):
    """(label, record) of every record inside the report."""
    for key in ('execution_records', 'findings'):
        for i, r in enumerate(_list(doc, key)):
            yield f'{key}/{i}', r
    if isinstance(doc, dict) and isinstance(doc.get('coverage'), dict):
        yield 'coverage', doc['coverage']


STAGES = ('preflight', 'static_analysis', 'model_review', 'threat_planning', 'dynamic_execution', 'judgement_report')


def _cross_record_problems(doc):
    problems = []
    listed = {s.get('stage') for s in _list(doc, 'stages') if isinstance(s, dict)}
    if isinstance(doc, dict) and 'stages' in doc:
        problems += [f'stages: stage {s!r} of 〈定義：工作階段〉 is not listed' for s in STAGES if s not in listed]
    if isinstance(doc, dict):
        for label, r in _records(doc):
            for field in ('run_id', 'commit'):
                if isinstance(r, dict) and field in r and field in doc and r[field] != doc[field]:
                    problems.append(f'{label}: {field} {r[field]!r} differs from the report ({doc[field]!r}); '
                                    'every record belongs to this run and its tested commit')
    results = {r.get('id'): r.get('result') for r in _list(doc, 'execution_records') if isinstance(r, dict)}
    for i, f in enumerate(_list(doc, 'findings')):
        if not isinstance(f, dict) or f.get('status') != 'confirmed':
            continue
        ids = f.get('execution_record_ids') or []
        if not any(results.get(x) == 'failed' for x in ids):
            problems.append(f'findings/{i}: a confirmed finding needs a failed execution record; '
                            f'execution_record_ids {ids} do not include one')
    return (problems + _requirement_problems(doc) + _approval_problems(doc)
            + _review_problems(doc) + _environment_problems(doc) + _coverage_problems(doc))


def _environment_problems(doc):
    """Environment summary and versions outside the support matrix (〈定義：核心資料物件與相依紀錄〉, 〈定義：工作階段〉,
    TK-SCP-001, TK-ENV-007, TK-EVD-005, TK-EVD-008, TK-EVD-009): environment is required once dynamic_execution
    completed or failed (or status is completed/partial) and omitted when dynamic_execution is not_run; when
    environment.unsupported is non-empty, dynamic_execution and overall status must be blocked, no test can run
    beyond blocked/unsupported, coverage cannot claim whole_scope, and every unsupported environment entry must
    appear in coverage.unsupported_items."""
    if not isinstance(doc, dict):
        return []
    stages = {s.get('stage'): s.get('status') for s in _list(doc, 'stages') if isinstance(s, dict)}
    has_env = 'environment' in doc
    problems = []
    if not has_env and (doc.get('status') in ('completed', 'partial')
                        or stages.get('dynamic_execution') in ('completed', 'failed')):
        problems.append('environment: required when status is completed/partial or dynamic_execution ran '
                        '(〈定義：核心資料物件與相依紀錄〉, TK-EVD-005)')
    if has_env and stages.get('dynamic_execution') == 'not_run':
        problems.append("environment: must be omitted when dynamic_execution is 'not_run' "
                        "(〈定義：核心資料物件與相依紀錄〉)")
    env = doc.get('environment')
    unsupported = env.get('unsupported') if isinstance(env, dict) else None
    if not (isinstance(unsupported, list) and unsupported):
        return problems
    if doc.get('status') != 'blocked':
        problems.append(f"environment: status must be 'blocked' when environment.unsupported is non-empty, "
                        f"not {doc.get('status')!r} (TK-SCP-001, TK-ENV-007)")
    for s in _list(doc, 'stages'):
        if isinstance(s, dict) and s.get('stage') == 'dynamic_execution' and s.get('status') != 'blocked':
            problems.append(f"stages: dynamic_execution must be 'blocked' when environment.unsupported is non-empty, "
                            f"not {s.get('status')!r} (TK-SCP-001, 〈定義：工作階段〉)")
    for i, e in enumerate(_list(doc, 'execution_records')):
        if isinstance(e, dict) and e.get('result') not in ('blocked', 'unsupported'):
            problems.append(f"execution_records/{i}: result cannot be {e.get('result')!r} when environment.unsupported "
                            f"is non-empty; no test runs against an unverified environment (TK-SCP-001, TK-ENV-007)")
    cov = doc.get('coverage') if isinstance(doc.get('coverage'), dict) else {}
    if cov.get('claim') == 'whole_scope':
        problems.append("coverage: claim cannot be 'whole_scope' when environment.unsupported is non-empty "
                        "(TK-SCP-001, TK-EVD-009)")
    scopes = {i.get('scope') for i in _list(cov, 'unsupported_items') if isinstance(i, dict)}
    problems += [f"coverage: unsupported_items lacks 'environment:{u}' from environment.unsupported "
                 f"(TK-SCP-001, TK-EVD-008)"
                 for u in dict.fromkeys(u for u in unsupported if isinstance(u, str))
                 if f'environment:{u}' not in scopes]
    return problems


COVERAGE_CLASSES = ('executed', 'blocked', 'errors', 'untested', 'cancelled', 'unsupported')


def _count(cov, name):
    value = cov.get(name)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _coverage_problems(doc):
    """The numbers of the coverage record that the schema cannot tie together (〈定義：覆蓋面向〉, TK-EVD-008,
    TK-EVD-009): the classes add up to the denominator, which is the execution records plus the unsupported
    scopes; a rate is what its numbers give, and over a zero denominator it is none, never full coverage."""
    cov = doc.get('coverage') if isinstance(doc, dict) else None
    if not isinstance(cov, dict):
        return []
    problems = []
    den, executed, valid = _count(cov, 'denominator'), _count(cov, 'executed'), _count(cov, 'valid_judgements')
    classes = [_count(cov, c) for c in COVERAGE_CLASSES]
    records, items, excluded = _list(doc, 'execution_records'), cov.get('unsupported_items'), cov.get('excluded')
    if executed is not None and valid is not None and valid > executed:
        problems.append(f'coverage: valid_judgements {valid} is more than executed {executed}')
    if den is not None and None not in classes and sum(classes) != den:
        problems.append(f'coverage: {", ".join(COVERAGE_CLASSES)} add up to {sum(classes)}, not the denominator {den}')
    if den is not None and isinstance(items, list) and isinstance(excluded, list):
        expected = len(records) + len(items)  # an exclusion can only take items out
        if (not excluded and den != expected) or den > expected:
            problems.append(f'coverage: denominator {den} is not the {len(records)} execution records plus the '
                            f'{len(items)} unsupported scopes ({"at most " if excluded else ""}{expected})')
    states = cov.get('states') if isinstance(cov.get('states'), dict) else {}
    unsupported = _count(cov, 'unsupported')
    wanted = {  # what each rate is, when it can be told: None means the report does not say
        'effective_judgement_rate': valid / den if den and valid is not None else None,
        'tool_support_rate': (den - unsupported) / den if den and unsupported is not None else None,
        'required_test_completion_rate': (executed / len(records) if records and executed is not None and excluded == []
                                          else None)}
    # A rate with nothing to divide by has no number, and says why (TK-EVD-009): not applicable when something was
    # excluded, insufficient data when not. The completion rate has no cases to divide by when no record exists
    # and nothing was excluded.
    has_excluded = isinstance(excluded, list) and bool(excluded)
    zero = {name: den == 0 for name in wanted}
    zero['required_test_completion_rate'] = den == 0 or (excluded == [] and not records)
    for name, number in wanted.items():
        rate, state = cov.get(name), states.get(name)
        if zero[name]:
            if rate is not None:
                problems.append(f'coverage: {name} {rate!r} is over a zero denominator and must be none, never full coverage '
                                f'(TK-EVD-009)')
            expected = 'not_applicable' if has_excluded else 'insufficient_data'
            if state is not None and state != expected:
                problems.append(f'coverage: {name} is {state!r} over a zero denominator; it is {expected!r} when '
                                f'{"something was" if has_excluded else "nothing was"} excluded (TK-EVD-009)')
        elif state == 'measured' and rate is None:
            problems.append(f'coverage: {name} is measured but has no number')
        elif state in ('not_applicable', 'insufficient_data') and rate is not None:
            problems.append(f'coverage: {name} is {state} but has the number {rate!r}')
        elif isinstance(rate, (int, float)) and number is not None and abs(rate - number) > 1e-9:
            problems.append(f'coverage: {name} {rate!r} is not {number!r}, what its numbers give')
    inv = cov.get('inventory') if isinstance(cov.get('inventory'), dict) else {}
    if cov.get('claim') == 'whole_scope' and inv.get('completeness') != 'complete':
        problems.append(f"coverage: claim 'whole_scope' needs a complete inventory, but it is {inv.get('completeness')!r} (TK-EVD-009)")
    return problems


def _review_problems(doc):
    """A decision only ever makes a finding's status more cautious: one sent back for evidence is not
    confirmed (〈定義：覆核紀錄〉 目前的決定)."""
    problems = []
    summary = doc.get('review_summary') if isinstance(doc, dict) else None
    if isinstance(summary, dict):
        states = [f['review'].get('state') for f in _list(doc, 'findings')
                  if isinstance(f, dict) and isinstance(f.get('review'), dict)]
        problems += [f'review_summary: {s} is {n}, but {states.count(s)} findings are in that review state '
                     f'(〈定義：覆核紀錄〉 報告)' for s, n in summary.items() if isinstance(n, int) and n != states.count(s)]

    for i, f in enumerate(_list(doc, 'findings')):
        review = f.get('review') if isinstance(f, dict) else None
        if not isinstance(review, dict):
            continue
        decision = review.get('decision') if isinstance(review.get('decision'), dict) else {}
        state, option = review.get('state'), decision.get('option')
        if doc.get('review_record') is None and (state != 'pending' or decision or 'opened_at' in review):
            problems.append(f'findings/{i}: review_record is null, so no review started and nobody decided '
                            f'anything: the review is pending with no start and no decision (〈定義：覆核紀錄〉)')
        elif state in WAITING_STATES and decision:
            problems.append(f'findings/{i}: review state {state} has a decision; a decided review is in the '
                            f'state its decision leaves (〈定義：覆核紀錄〉)')
        elif state in DECISION_STATES.values() and DECISION_STATES.get(option) != state:
            problems.append(f'findings/{i}: review state {state} does not match its decision {option!r} '
                            f'(〈定義：覆核紀錄〉)')
        problems += [f'findings/{i}: review {where} {value!r} is not an ISO 8601 UTC time (〈定義：覆核紀錄〉)'
                     for where, value in (('opened_at', review.get('opened_at')), ('decision at', decision.get('at')))
                     if value is not None and control.utc_time(value) is None]

    def sent_back(f):
        decision = f.get('review', {}).get('decision') if isinstance(f.get('review'), dict) else None
        return isinstance(decision, dict) and decision.get('option') == 'evidence_pending'
    return problems + [f'findings/{i}: its current review decision is evidence_pending, so its status is '
                       f'evidence_pending, not confirmed (〈定義：覆核紀錄〉)'
                       for i, f in enumerate(_list(doc, 'findings'))
                       if isinstance(f, dict) and f.get('status') == 'confirmed' and sent_back(f)]


def _approval_problems(doc):
    """An execution record names only an extra approval the report's authorization holds (〈定義：測試授權紀錄〉)."""
    granted = doc.get('authorization') if isinstance(doc, dict) else None
    approvals = granted.get('extra_approvals') if isinstance(granted, dict) else None
    ids = {a.get('approval_id') for a in approvals if isinstance(a, dict)} if isinstance(approvals, list) else set()
    return [f'execution_records/{i}: approval_id {e["approval_id"]!r} is not an extra approval of the authorization '
            f'(TK-ENV-001)'
            for i, e in enumerate(_list(doc, 'execution_records'))
            if isinstance(e, dict) and 'approval_id' in e and e['approval_id'] not in ids]


def listed_item(items, record):
    """The item a record or a planned test rests on, by its requirement_id, or None: the one lookup the
    toolkit and validate() share. items maps ids to confirmation-list items or requirements[] entries."""
    rid = record.get('requirement_id') if isinstance(record, dict) else None
    return items.get(rid) if isinstance(rid, str) else None


REVIEW_LABELS = dict(zip(item_rule.REVIEW_STATES, ('待確認', '接受', '修改', '不適用')))


def _requirement_problems(doc):
    """Records against the confirmation items the report lists: version (TK-REQ-004), blocked tests
    (〈定義：確認清單〉), case kind against the rule (TK-REQ-016) and the finding cap (TK-REQ-003)."""
    items = {r.get('id'): r for r in _list(doc, 'requirements') if isinstance(r, dict) and isinstance(r.get('id'), str)}
    problems = []
    for i, e in enumerate(_list(doc, 'execution_records')):
        item = listed_item(items, e)
        if item is None:
            continue
        version = (item.get('confirmation') or {}).get('version')
        if e.get('requirement_version') != version:
            problems.append(f'execution_records/{i}: requirement_version {e.get("requirement_version")!r} differs '
                            f'from version {version!r} of {item["id"]!r} in requirements (TK-REQ-004)')
        if e.get('result') == 'blocked':
            continue
        reason = item_rule.untestable(item, REVIEW_LABELS)
        if reason:
            problems.append(f'execution_records/{i}: {item["id"]!r} {reason}; a test on it must be blocked, '
                            f'not {e.get("result")!r} (〈定義：確認清單〉)')
        kind = e.get('case_kind', item_rule.DENIAL)
        rule = item_rule.rule_for(item, e.get('test_id'), kind)
        if e.get('result') in ('passed', 'failed') and item_rule.RULE_FOR_CASE.get(kind) != rule:
            problems.append(f'execution_records/{i}: a {kind} case on {item["id"]!r} (rule {rule!r} for '
                            f'{e.get("test_id")!r}) must be blocked, not {e.get("result")!r} (TK-REQ-016)')
    for i, f in enumerate(_list(doc, 'findings')):
        item = listed_item(items, f)
        if item and f.get('status') == 'confirmed' and item_rule.finding_cap(item) != 'confirmed':
            problems.append(f'findings/{i}: {item["id"]!r} is {item.get("status")!r}; a finding on it is at most '
                            f'evidence_pending, not confirmed (TK-REQ-003)')
    return problems


def validate(doc):
    """Problems with a report, as human-readable strings; [] means valid."""
    return _schema_problems(doc) + _cross_record_problems(doc)


# Spec names for the codes used in the JSON report.
RUN_LABELS = {'pending': '待執行', 'running': '執行中', 'completed': '完整完成', 'partial': '部分完成',
              'blocked': '受阻', 'failed': '失敗', 'cancelled': '已取消'}
RESULT_LABELS = {'passed': '通過', 'failed': '未通過', 'blocked': '受阻', 'error': '執行錯誤',
                 'untested': '未測試', 'unsupported': '不支援'}
FINDING_LABELS = {'confirmed': '已確認', 'evidence_pending': '證據待補', 'not_reproduced': '本次未重現',
                  'excluded': '已排除', 'fixed_pending_regression': '已修復待回歸', 'regression_passed': '回歸通過'}
COMPLETED_NOTE = ('「完整完成」表示計畫內的測試都取得明確結果；只對本次範圍與條件有效，'
                  '不代表應用沒有漏洞（TK-RUN-002）。')


def _confirmation_summary(listed):
    """TK-REQ-003 各類待確認數量 by source, for the list version they come from (TK-REQ-004), and the
    items approved by one person (〈定義：確認清單〉 單人核准)."""
    t = listed['s2_template']
    lines = ['', '## 確認狀態摘要', '',
             f'- **確認清單**：`{listed["path"]}` v{listed["list_version"]}（`{listed["digest"]}`）'
             + ('；本次產生或更新，待負責人處理：處理其中待確認的項目，再以此路徑與摘要更新 ScanManifest 的引用'
                if listed['updated'] else ''),
             f'- **S2 範本**：`{t["policy_template_id"]}` v{t["version"]}（`{t["digest"]}`）', '',
             '| 來源 | ' + ' | '.join(REVIEW_LABELS.values()) + ' |',
             '| :--- |' + ' ---: |' * len(REVIEW_LABELS)]
    for source, counts in listed['summary'].items():
        lines.append(f'| {source} | ' + ' | '.join(str(counts[s]) for s in REVIEW_LABELS) + ' |')
    lines += ['', f'- 範圍外 {listed["out_of_scope"]} 項（不是處理狀態，不計入上表）']
    if listed['single_approval']:
        lines.append('- 單人核准（修改與不適用，尚無第二人核准，TK-REQ-014）：'
                     + '、'.join(f'`{i}`' for i in listed['single_approval']))
    return lines


def _operations(ops):
    """Resource × HTTP method operations of 〈定義：測試授權紀錄〉 as one line."""
    return '；'.join(f'`{o["resource"]}` ' + '、'.join(o['methods']) for o in ops)


def _authorization_section(doc):
    """〈定義：測試授權紀錄〉: what the run was authorized for, by whom (declared, not verified), and the extra
    approvals its tests ran under (TK-ENV-001); and the source changes made for it (TK-ENV-006)."""
    a = doc['authorization']
    lines = ['', '## 測試授權', '',
             f'- **授權紀錄**：`{a["path"]}`（`{a["digest"]}`）',
             '- **目標**：' + '、'.join(f'`{t}`' for t in a['targets']) + f'（{a["environment"]}）',
             f'- **期間**：{a["valid_from"]} 至 {a["valid_until"]}',
             f'- **資料範圍**：{a["data_scope"]}',
             '- **允許操作**：' + _operations(a['operations']),
             f'- **簽發**：{a["issued_by"]} {a["issued_at"]}；應用負責人 {a["roles"]["app_owner"]}，執行者 {a["roles"]["operator"]}'
             '（身分未經驗證：是宣告的名稱，TK-HRV-004 的經驗證身分目前只用於覆核紀錄）']
    used = {}
    for e in doc['execution_records']:
        if e.get('approval_id'):
            used.setdefault(e['approval_id'], []).append(e.get('test_id', e['id']))
    for ap in a['extra_approvals']:
        tests = '、'.join(f'`{t}`' for t in used.get(ap['approval_id'], [])) or '（本次未使用）'
        lines.append(f'- **額外核准** `{ap["approval_id"]}`：{ap["by"]} {ap["at"]}，至 {ap["valid_until"]}；'
                     + _operations(ap['operations'])
                     + f'；理由：{ap["reason"]}；用於 {tests}')
    lines.append('- 測試用原始碼變更：無（受測原始碼即 `source_digest` 釘選的版本）')
    return lines


# 〈定義：覆核紀錄〉: the options of 候選問題覆核 and the 覆核狀態 each one leaves; a finding with no decision
# is pending, or overdue past its deadline. toolkit.review and validate() share these.
DECISION_STATES = {'approve': 'approved', 'reject': 'rejected', 'evidence_pending': 'evidence_pending'}
WAITING_STATES = ('pending', 'overdue')
FINDING_REVIEW_STATES = WAITING_STATES + tuple(DECISION_STATES.values())  # in the report's order
# 〈定義：覆核紀錄〉 報告: 覆核狀態 and the options of 候選問題覆核.
FINDING_REVIEW_LABELS = {'pending': '待覆核', 'overdue': '逾期覆核', 'approved': '已核准', 'rejected': '已退回',
                       'evidence_pending': '已轉證據待補'}
OPTION_LABELS = {'approve': '核准', 'reject': '退回', 'evidence_pending': '轉證據待補'}
REVIEW_TYPE_LABELS = {'candidate_finding': '候選問題覆核'}  # 〈定義：覆核類型〉


def render_review_issue(finding, doc, option_of_label):
    """Title and body of the issue a finding's review is made on (〈定義：覆核紀錄〉 工單). option_of_label maps
    each predefined platform label to its option. The fingerprint is shown to people, never searched."""
    title = f'{REVIEW_TYPE_LABELS["candidate_finding"]}：{finding["requirement_id"]}'
    options = '、'.join(f'`{label}`（{OPTION_LABELS[option]}）' for label, option in option_of_label.items())
    body = (f'- 指紋：`{finding["fingerprint"]}`（{finding["fingerprint_version"]}）\n'
            f'- 需求：`{finding["requirement_id"]}` 第 {finding["requirement_version"]} 版\n'
            f'- 提交：`{doc["commit"]}`，執行：`{doc["run_id"]}`\n\n'
            f'決定方式：先留言寫下理由，再加上其中一個標籤：{options}。留言本身不算決定。')
    return title, body


def _inline(text):
    """Single-line escaped text safe in Markdown prose (no line break and no raw HTML, TK-EVD-002)."""
    return ' '.join(str(text).split()).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _code(text):
    """Single-line Markdown code span that untrusted backticks or HTML cannot break out of (TK-EVD-002)."""
    s = ' '.join(str(text).split())
    ticks = max((len(m.group(0)) for m in re.finditer(r'`+', s)), default=0)
    fence = '`' * (ticks + 1)
    pad = ' ' if not s or s[0] in '` ' or s[-1] in '` ' else ''
    return f'{fence}{pad}{s}{pad}{fence}'


def _cell(text):
    """Free text (a reviewer's comment) inside one Markdown table cell: no line break, no cell border, and no
    HTML, which a renderer would act on (a comment opener hides the rest of the report)."""
    return _inline(text).replace('|', '\\|')


def _environment_section(env):
    """〈定義：核心資料物件與相依紀錄〉 EnvironmentProfile: support-matrix warnings (TK-SCP-001) and known
    differences from E2 or production (TK-ENV-007, TK-EVD-005)."""
    lines = ['', '## 測試環境與差異', '']
    if not env:
        lines.append('- **測試環境**：本次執行未建立測試環境，尚無環境差異紀錄')
        return lines
    lines.append(f'- **環境模式**：`{env["mode"]}`（`{env["profile_digest"]}`）')
    if env['unsupported']:
        lines.append('- **支援矩陣外版本（不支援，TK-SCP-001）**：')
        lines += [f'  - {_inline(u)}' for u in env['unsupported']]
    if env['known_differences']:
        lines.append('- **環境差異（TK-ENV-007、TK-EVD-005）**：')
        lines += [f'  - {_inline(d)}' for d in env['known_differences']]
    else:
        lines.append('- **環境差異**：（無宣告差異）')
    return lines


def _waiting_first(finding):
    """Sort key: findings waiting for review (待覆核, 逾期覆核) first, the longest wait first, those with no
    issue opened yet after them; decided findings last. sorted() keeps the report's order among equals."""
    review = finding['review']
    if review['state'] not in WAITING_STATES:
        return 2, 0
    opened = control.utc_time(review.get('opened_at'))
    return (1, 0) if opened is None else (0, opened.timestamp())


def _review_section(doc):
    """〈定義：覆核紀錄〉 報告: the record used, the count per review state and each finding's review."""
    ref = doc['review_record']
    lines = ['', '## 覆核', '',
             f'- **覆核紀錄**：`{ref["path"]}`（`{ref["digest"]}`）' if ref
             else '- **覆核紀錄**：這次執行沒有使用覆核紀錄，每一筆問題都待覆核',
             '- **數量**：' + '、'.join(f'{FINDING_REVIEW_LABELS[k]} {n}' for k, n in doc['review_summary'].items())]
    if not doc['findings']:
        return lines
    lines += ['', '| 問題 | 覆核狀態 | 開始覆核 | 目前的決定 |', '| :--- | :--- | :--- | :--- |']
    for f in sorted(doc['findings'], key=_waiting_first):
        r = f['review']
        d = r.get('decision')
        decided = (f'{OPTION_LABELS[d["option"]]}：{d["by"]["login"]}（帳號 {d["by"]["id"]}）{d["at"]}；'
                   f'理由：{_cell(d["reason"])}' if d else '—')
        lines.append(f'| `{f["id"]}` | {FINDING_REVIEW_LABELS[r["state"]]} | {r.get("opened_at", "—")} | {decided} |')
    return lines


# 〈定義：覆蓋面向〉 in Chinese: the completeness of the inventory, what the report claims to cover, the rates and what
# a rate with no number is called (TK-EVD-009).
COMPLETENESS_LABELS = {'complete': '完整', 'unknown': '未知'}
CLAIM_LABELS = {'whole_scope': '整個範圍', 'known_scope_only': '只涵蓋已知範圍'}
RATE_LABELS = {'effective_judgement_rate': '有效判定率', 'tool_support_rate': '工具支援率',
               'required_test_completion_rate': '必要測試完成率'}
RATE_STATE_LABELS = {'not_applicable': '不適用', 'insufficient_data': '資料不足'}


def _coverage_lines(c):
    """The 覆蓋 section: counts, rates (a rate with no number says why, never a percentage), the tables and
    policies, and the unresolved, unsupported, excluded and refused-exclusion items one by one."""
    inv, tp = c['inventory'], c['tables_and_policies']
    rates = '；'.join(f"{RATE_LABELS[name]}：" + (f'{c[name] * 100:.1f}%' if c['states'][name] == 'measured'
                                                else RATE_STATE_LABELS[c['states'][name]]) for name in RATE_LABELS)
    lines = ['', '## 覆蓋', '', f'- 盤點來源：{c["inventory_source"]}',
             f'- 盤點完整性：{COMPLETENESS_LABELS[inv["completeness"]]}；宣告範圍：{CLAIM_LABELS[c["claim"]]}；'
             f'擷取規則 {inv["rule"]}、支援版本 {inv["supported_version"]}',
             f'- 分母 {c["denominator"]}、已執行 {c["executed"]}、有效判定 {c["valid_judgements"]}、受阻 {c["blocked"]}、'
             f'錯誤 {c["errors"]}、未測 {c["untested"]}、取消 {c["cancelled"]}、不支援 {c["unsupported"]}',
             f'- {rates}',
             f'- 資料表與政策：已盤點 {tp["inventoried"]}、已啟用 RLS {tp["rls_enabled"]}、尚無政策 {tp["without_policy"]}、'
             f'未解析 {tp["unresolved"]}、已判定 {tp["judged"]}']
    lines += [f'  - 未解析：`{u["file"]}{":" + str(u["line"]) if u["line"] else ""}`（{u["reason"]}）' for u in inv['unresolved']]
    lines += [f'  - 不支援：{_code(u["scope"])}（{_inline(u["reason"])}'
              f'{"；需補充觀測" if u.get("needs_supplement") else ""}）'
              for u in c['unsupported_items']]
    lines += [f'  - 排除：`{e["ref"]}`（{e["reason"]}；確認者 {e["confirmed_by"]}、版本 {e["version"]}）' for e in c['excluded']]
    lines += [f'  - 被拒絕的排除：`{r["ref"]}`（{r["problem"]}）' for r in c['rejected_exclusions']]
    return lines


def render_markdown(doc):
    """Markdown for human review, generated from a valid JSON report. Raises ValueError if invalid."""
    problems = validate(doc)
    if problems:
        raise ValueError('invalid report: ' + '; '.join(problems))
    # TK-DAT-001: a report blocked at preflight may name no commit.
    commit_text = f'`{doc["commit"]}`' if doc['commit'] is not None else '（未提供）'
    lines = [f'# 執行報告 `{doc["run_id"]}`', '',
             f'- **整體執行狀態**：{RUN_LABELS[doc["status"]]}（`{doc["status"]}`）'
             + (f'；原因：{_inline(doc["status_reason"])}' if doc.get('status_reason') else ''),
             f'- **受測提交**：{commit_text}',
             f'- **報告建立時間**：{doc["created_at"]}']
    if doc.get('environment'):
        lines.append(f'- **環境模式**：{doc["environment"].get("mode", "")}')
    if doc['status'] == 'completed':
        lines += ['', f'> {COMPLETED_NOTE}']

    if doc.get('requirements'):
        lines += ['', '## 安全需求（確認項目）', '', '| 確認項目 | 來源 | 內容 | 處理狀態 | 確認者 |',
                  '| :--- | :--- | :--- | :--- | :--- |']
        for r in doc['requirements']:
            c = r['confirmation']
            state = REVIEW_LABELS[r['status']] + ('（範圍外）' if r['out_of_scope'] else '')
            if c.get('allowed_tests'):
                state += ('（合法例外：放行 ' + '、'.join(f'`{t}`' for t in c['allowed_tests'])
                          + f'，到期 {c.get("expiry", "（未填）")}）')
            who = f'{c["by"]} {c["at"]}' if c['by'] else '（未確認）'
            lines.append(f'| `{r["id"]}` v{c["version"]} | {r["source"]} | {r["statement"]} | {state} | {who} |')

    if doc.get('confirmation_list'):
        lines += _confirmation_summary(doc['confirmation_list'])

    if doc.get('authorization'):
        lines += _authorization_section(doc)

    lines += _environment_section(doc.get('environment'))

    if doc.get('authorization_matrix'):
        lines += ['', '## 授權矩陣中的身分', '', '| 身分 | 傳遞方式 | 路徑 |', '| :--- | :--- | :--- |']
        for m in doc['authorization_matrix']:
            lines.append(f'| `{m["identity"]}` | {m.get("transport", "")} | {m.get("path", "")} |')

    lines += ['', '## 測試結果', '', '| 測試 | 行為者 | 資源 | 結果 |', '| :--- | :--- | :--- | :--- |']
    for e in doc['execution_records']:
        lines.append(f'| `{e.get("test_id", e["id"])}` | `{e.get("actor_ref", "")}` | `{e.get("resource_ref", "")}` '
                     f'| {RESULT_LABELS[e["result"]]} |')

    lines += ['', '## 問題紀錄', '']
    if doc['findings']:
        lines += ['| 問題 | 狀態 | 需求 | 根因 | 指紋 |', '| :--- | :--- | :--- | :--- | :--- |']
        for f in doc['findings']:
            label = FINDING_LABELS.get(f.get('status'), f.get('status', ''))
            lines.append(f'| `{f["id"]}` | {label} | `{f.get("requirement_id", "")}` | {f.get("root_cause", "")} '
                         f'| `{f.get("fingerprint", "")}`（{f.get("fingerprint_version", "")}） |')
    else:
        lines.append('本次計畫內的測試未產生問題紀錄；這只代表上列測試的結果，不涵蓋計畫以外的範圍。')

    lines += _review_section(doc)

    lines += _coverage_lines(doc['coverage'])
    lines.append('')
    return '\n'.join(lines)
