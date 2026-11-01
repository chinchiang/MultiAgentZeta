"""Report contract of a scan run: validate(report) and render_markdown(report).

The JSON report is the native format (TK-EVD-003); its structure is the versioned
JSON Schema in schemas/report-v1.json. validate() also checks the conditions that
span records, which JSON Schema cannot express.
"""
import json
from pathlib import Path

import jsonschema

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


def render_markdown(doc):
    """Markdown for human review, generated from a valid JSON report. Raises ValueError if invalid."""
    problems = validate(doc)
    if problems:
        raise ValueError('invalid report: ' + '; '.join(problems))
    lines = [f'# 執行報告 `{doc["run_id"]}`', '',
             f'- **整體執行狀態**：{RUN_LABELS[doc["status"]]}（`{doc["status"]}`）'
             + (f'；原因：{doc["status_reason"]}' if doc.get('status_reason') else ''),
             f'- **受測提交**：`{doc["commit"]}`',
             f'- **報告建立時間**：{doc["created_at"]}']
    if doc.get('environment'):
        lines.append(f'- **環境模式**：{doc["environment"].get("mode", "")}')
    if doc['status'] == 'completed':
        lines += ['', f'> {COMPLETED_NOTE}']

    if doc.get('requirements'):
        lines += ['', '## 安全需求', '', '| 需求 | 內容 | 確認 |', '| :--- | :--- | :--- |']
        for r in doc['requirements']:
            c = r.get('confirmation') or {}
            lines.append(f'| `{r["id"]}` | {r.get("statement", "")} | {c.get("by", "未確認")} {c.get("at", "")} |')

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
