# Remediation payload specification

## Purpose
AutoHelpDesk technicians depend on remediation cards to translate analyzer findings into steps they can execute immediately. This guide explains how remediation payloads flow from heuristics into the HTML report so writers can deliver consistent, copy-friendly guidance. Following the specification below prevents plaintext dumps and keeps copy buttons, language badges, and conditional logic intact for frontline use.

## Rendering pipeline overview
The analyzer builds each issue card in three stages that determine whether remediation guidance renders as rich HTML or escaped text. Understanding the hand-off between these functions helps you select the right payload shape for every heuristic.
- `Add-CategoryIssue` stores `Remediation`, `RemediationScript`, and payload metadata (including the `flags.hasEvidence` and `flags.hasData` booleans) on the issue object before it reaches the composer.【F:Analyzers/AnalyzerCommon.ps1†L254-L364】
- `Get-IssueCardContent` pulls remediation text or scripts from explicit fields or embedded evidence properties, trimming whitespace so the renderer receives clean strings.【F:Analyzers/HtmlComposer.ps1†L394-L463】
- `New-IssueCardHtml` assembles the remediation context, evaluates structured steps, and emits `<details>` markup that either contains rich step cards or the legacy plaintext fallback.【F:Modules/Common.psm1†L1053-L1269】

## Remediation fields and flags
Clear ownership of remediation fields ensures technicians see commands with copy buttons instead of raw markdown. Heuristics should only populate the elements they need so flags stay truthful in downstream exports.
- `Remediation` accepts either a structured JSON array (preferred) or legacy text; values are trimmed when added to the issue payload.【F:Analyzers/AnalyzerCommon.ps1†L353-L355】
- `RemediationScript` is for a single PowerShell block and automatically renders with a toolbar, badge, and copy button when present.【F:Modules/Common.psm1†L1247-L1269】
- `Payload.flags` exposes `hasEvidence` and `hasData` booleans to downstream tooling; there is no automatic `hasRemediation` flag in this envelope, so only populate remediation fields when guidance exists.【F:Analyzers/AnalyzerCommon.ps1†L322-L345】
- The composer logs `HasRemediation` and `HasRemediationScript` for debugging, but those booleans are derived from the presence of the trimmed strings rather than exported via the payload schema.【F:Analyzers/HtmlComposer.ps1†L520-L538】
- Optional `RemediationContext` properties, card titles, severity, evidence rows, and payload/meta objects are merged into a lookup table so tokens within structured steps can reference live data (for example, `{{Title}}`).【F:Modules/Common.psm1†L1067-L1105】

## Structured remediation steps format
Structured steps unlock headings, paragraphs, code cards, and conditional logic without writing custom HTML. Supply a JSON array where each element is a hashtable-like object with optional fields.
- The renderer first checks whether the remediation string starts with `[` and, if so, attempts to parse it as JSON before falling back to the legacy formatter.【F:Modules/Common.psm1†L1029-L1050】
- Each step is normalized to a PowerShell object so properties such as `title`, `content`, `type`, `lang`, and `if` can be read safely.【F:Modules/Common.psm1†L884-L938】
- Supported `type` values are `code`, `note`, or any other string (defaulting to plain text). `code` steps generate copy-enabled code cards, optionally honoring a custom `lang` badge and CSS class.【F:Modules/Common.psm1†L927-L977】
- `Resolve-RemediationTemplateText` replaces `{{Token}}` placeholders inside `title`, `content`, and `lang` fields with data from the remediation context so steps stay personalized.【F:Modules/Common.psm1†L715-L736】【F:Modules/Common.psm1†L907-L935】
- `if` expressions support simple boolean algebra (`and`, `or`, `not`, comparison operators) evaluated against the context table, letting you hide steps when prerequisites are missing.【F:Modules/Common.psm1†L891-L915】【F:Modules/Common.psm1†L739-L858】

## Legacy fallback behavior
Legacy remediation strings are still accepted, but they are escaped into a single paragraph with `<br>` separators and no syntax highlighting. Markdown fences, bold markers, or inline code will appear literally, which is why older heuristics such as the battery health check produce hard-to-read plaintext blocks.【F:Modules/Common.psm1†L986-L1026】【F:Analyzers/Heuristics/Hardware/Battery.ps1†L1-L27】 Updating those payloads to structured steps or a `RemediationScript` immediately restores copy buttons and language badges.

## Implementation prompt
Use the following authoring prompt whenever you add or revise remediation guidance so every card lands in the structured pipeline. Share it in design docs or pull request descriptions to keep contributors aligned.
```
When implementing or updating a remediation for an AutoHelpDesk heuristic:
1. Populate the `-Remediation` parameter with a JSON array of step objects. Each step should include `title`, `content`, and `type` (`"code"` for commands, default for narrative text). Use `lang` when the code is not PowerShell.
2. Add an `if` property when a step only applies under certain conditions, referencing remediation context keys such as severity, title, or payload data.
3. Reserve `-RemediationScript` for a single PowerShell block that should always render with a copy button.
4. Avoid legacy Markdown blobs; if you need notes, create a step with `"type": "note"` so it renders with the correct styling.
5. Verify the rendered HTML to confirm copy buttons appear and that placeholders like `{{Title}}` resolve correctly.
```

## Examples
These references show the difference between structured and legacy payloads so you can pattern-match quickly.
- The Exploit Protection mitigation emits a structured remediation array with two PowerShell `code` steps and a narrative staging step, producing headings and copyable blocks in the report.【F:Analyzers/Heuristics/Security/Security.DeviceProtection.ps1†L347-L365】
- The hardware battery heuristic still ships a legacy Markdown blob, so the renderer escapes the fences instead of creating PowerShell cards—use this as a before-state when planning a cleanup.【F:Analyzers/Heuristics/Hardware/Battery.ps1†L1-L27】

## Known misformatted remediation steps
Some heuristics still squeeze list-style bullets into a single `text` step, which forces the renderer to emit a paragraph with `<br>` separators instead of rich list markup. The entries below call out each payload so maintainers can prioritize follow-up fixes within their respective components.
- `Analyzers/Heuristics/Hardware/Battery.ps1` — The “Symptoms” step uses newline-delimited sentences to mimic bullets, so each symptom collapses into one paragraph instead of a structured checklist.【F:Analyzers/Heuristics/Hardware/Battery.ps1†L1-L12】
- `Analyzers/Heuristics/Storage/Storage.Helpers.ps1` — The “Fix” step includes hyphen-prefixed guidance within the same string, preventing the remediation from rendering as a proper list of storage actions.【F:Analyzers/Heuristics/Storage/Storage.Helpers.ps1†L9-L22】
- `Analyzers/Heuristics/Security/Security.DeviceProtection.ps1` — The “Fix (pick one)” step starts with newline-separated dash bullets, so Smart App Control and WDAC options appear as a single block of text instead of discrete list items.【F:Analyzers/Heuristics/Security/Security.DeviceProtection.ps1†L1-L19】
