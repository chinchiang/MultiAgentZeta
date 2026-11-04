"""Report contract of a scan run: validate(report) and render_markdown(report).

The JSON report is the native format (TK-EVD-003); its structure is the versioned
JSON Schema in schemas/report-v1.json. validate() also checks the conditions that
span records, which JSON Schema cannot express.
"""
import json
from pathlib import Path

import jsonschema

from toolkit import policy

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
    return problems + _requirement_problems(doc) + _approval_problems(doc)


def _approval_problems(doc):
    """An execution record names only an extra approval the report's authorization holds (〈定義：測試授權紀錄〉)."""
    granted = doc.get('authorization') if isinstance(doc, dict) else None
    approvals = granted.get('extra_approvals') if isinstance(granted, dict) else None
    ids = {a.get('approval_id') for a in approvals if isinstance(a, dict)} if isinstance(approvals, list) else set()
    return [f'execution_records/{i}: approval_id {e["approval_id"]!r} is not an extra approval of the authorization '
            f'(TK-ENV-001)'
            for i, e in enumerate(_list(doc, 'execution_records'))
            if isinstance(e, dict) and 'approval_id' in e and e['approval_id'] not in ids]


# Rules on confirmation items shared by the toolkit and validate(), so that a run and the check of its
# report cannot disagree. An item is a confirmation-list item or a requirements[] entry: both carry
# source, status and out_of_scope. Codes follow toolkit/schemas.
# 〈定義：確認清單〉 處理狀態 of a confirmation item, in the order of its table; not a finding state. Both
# schemas list the same codes (test_confirmation.EnumsAgreeWithSchemas); REVIEW_LABELS names them.
PENDING, ACCEPTED, MODIFIED, NOT_APPLICABLE = REVIEW_STATES = ('pending', 'accepted', 'modified', 'not_applicable')
REVIEWED = (ACCEPTED, MODIFIED)
# case_kind of an ExecutionRecord and the allow/deny rule each one tests (TK-REQ-016).
DENIAL, ALLOWED = CASE_KINDS = ('denial', 'allowed')
RULE_FOR_CASE = {DENIAL: policy.DENY, ALLOWED: policy.ALLOW}


def rule_for(rule, allowed_tests, test_id, case_kind):
    """The rule a test of case_kind is judged by on an item with rule and the allowed_tests of its 合法例外:
    an allowed case it lists is allowed; every other test, a denial case it lists included, keeps the
    rule (〈定義：確認清單〉 修改, TK-DYN-003)."""
    return policy.ALLOW if case_kind == ALLOWED and test_id in allowed_tests else rule


def untestable(item):
    """Why tests on item must be blocked, or None: out of scope, not applicable, or a pending S1
    entry (〈定義：確認清單〉, TK-REQ-003). A pending S2 clause may still be tested."""
    status = item.get('status')
    if item.get('out_of_scope'):
        return 'is out of scope'
    if status == NOT_APPLICABLE:
        return f'is {status} ({REVIEW_LABELS[status]})'
    if status == PENDING and item.get('source') == 'S1':
        return f'is an S1 entry still pending ({REVIEW_LABELS[status]}) until it is reviewed (TK-REQ-003)'
    return None


def finding_cap(item):
    """The highest finding status (問題狀態) a failed test on item may give: only an accepted or
    modified item gives 已確認; an S2 clause nobody accepted yet gives at most 證據待補 (TK-REQ-003)."""
    return 'confirmed' if item.get('status') in REVIEWED else 'evidence_pending'


def listed_item(items, record):
    """The item a record or a planned test rests on, by its requirement_id, or None: the one lookup the
    toolkit and validate() share. items maps ids to confirmation-list items or requirements[] entries."""
    rid = record.get('requirement_id') if isinstance(record, dict) else None
    return items.get(rid) if isinstance(rid, str) else None


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
        reason = untestable(item)
        if reason:
            problems.append(f'execution_records/{i}: {item["id"]!r} {reason}; a test on it must be blocked, '
                            f'not {e.get("result")!r} (〈定義：確認清單〉)')
        kind = e.get('case_kind', DENIAL)
        # Only a modified item can be a 合法例外 (〈定義：確認清單〉 修改); allowed_tests on another one count for nothing.
        allowed_tests = ((item.get('confirmation') or {}).get('allowed_tests') or []) if item.get('status') == MODIFIED else []
        rule = rule_for(item.get('rule'), allowed_tests, e.get('test_id'), kind)
        if e.get('result') in ('passed', 'failed') and RULE_FOR_CASE.get(kind) != rule:
            problems.append(f'execution_records/{i}: a {kind} case on {item["id"]!r} (rule {rule!r} for '
                            f'{e.get("test_id")!r}) must be blocked, not {e.get("result")!r} (TK-REQ-016)')
    for i, f in enumerate(_list(doc, 'findings')):
        item = listed_item(items, f)
        if item and f.get('status') == 'confirmed' and finding_cap(item) != 'confirmed':
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
REVIEW_LABELS = dict(zip(REVIEW_STATES, ('待確認', '接受', '修改', '不適用')))
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
             '| 來源 | ' + ' | '.join(REVIEW_LABELS.values()) + ' |', '| :--- |' + ' ---: |' * len(REVIEW_LABELS)]
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
             '（身分未經驗證，TK-HRV-004 尚未實作）']
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


def render_markdown(doc):
    """Markdown for human review, generated from a valid JSON report. Raises ValueError if invalid."""
    problems = validate(doc)
    if problems:
        raise ValueError('invalid report: ' + '; '.join(problems))
    # TK-DAT-001: a report blocked at preflight may name no commit.
    commit_text = f'`{doc["commit"]}`' if doc['commit'] is not None else '（未提供）'
    lines = [f'# 執行報告 `{doc["run_id"]}`', '',
             f'- **整體執行狀態**：{RUN_LABELS[doc["status"]]}（`{doc["status"]}`）'
             + (f'；原因：{doc["status_reason"]}' if doc.get('status_reason') else ''),
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

    c = doc['coverage']
    lines += ['', '## 覆蓋', '', f'- 盤點來源：{c.get("inventory_source", "")}',
              f'- 分母 {c.get("denominator")}、已執行 {c.get("executed")}、有效判定 {c.get("valid_judgements")}、'
              f'受阻 {c.get("blocked")}、未測 {c.get("untested")}、不支援 {c.get("unsupported")}']
    for u in c.get('unsupported_items', []):
        lines.append(f'  - 不支援：`{u["scope"]}`（{u["reason"]}）')
    lines.append('')
    return '\n'.join(lines)
