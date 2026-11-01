# Domain Docs

Before exploring or naming a domain concept, read:

- **`GLOSSARY.md`**: short definitions. Its 「見」 column points at the full definition (〈定義：〇〇〉 or a `TK-` requirement) in `docs/toolkit/spec.md`; read it when the short one is not enough.
- **`docs/adr/`**: ADRs that touch the area you are working in.

## Use the glossary's vocabulary

When your output names a domain concept (issue title, proposal, hypothesis, test name, doc text), use the glossary term; replace any wording listed under 「避免」 with that term. In code and schemas, the English identifiers in `toolkit/schemas/` are authoritative.

A concept missing from the glossary means either invented language (reconsider) or a real gap (note it for `/domain-modeling`).

## Flag ADR conflicts

When your output contradicts an existing ADR, say so explicitly:

> _Contradicts ADR-0002 (Python as default language), but worth reopening because…_
