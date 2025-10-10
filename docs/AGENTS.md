# Repository-wide agent instructions

- Every issue card emitted by analyzers or report components must include a single, plain-English sentence summarizing the real-world impact for technicians or end users. Keep this line concise (one sentence) and ensure it clearly conveys the consequence of the issue.
- When editing heuristics, analyzers, or report templates, verify that any new or updated issue cards follow this plain-English explanation requirement. If the collected data cannot supply enough context, note that in the explanation.
- Refer to the "Issue card authoring conventions" section of `README.md` for additional background.
- Documentation-focused pull requests must satisfy the "Doc Update Definition of Done" criteria below before merge approval.

## Doc Update Definition of Done

### Summary
Doc PRs must leave written guidance clearer than they found it, align with live product behavior, and document reviewer-visible outcomes within two business days of change request receipt. The acceptance criteria below define the minimum bar for merge readiness.

- Updated content accurately reflects current feature behavior and terminology.
- Every new or modified section includes context for technicians or end users in no more than five sentences.
- Screenshots or examples older than 180 days are either refreshed or explicitly dated.
- Reviewer feedback left within one business day is acknowledged or resolved within the next business day.

### Signals
- Markdown, reStructuredText, or HTML files changed without accompanying code updates.
- Doc updates that mention new workflows, UI text, or support procedures.
- Review threads requesting clarity, screenshots, or timelines on documentation PRs.

### Detection
- Use `findstr /C:"Doc Update Definition of Done" docs\AGENTS.md` in Windows Command Prompt to confirm these criteria are defined for contributors.
- During review, verify diff statistics (e.g., `git diff --stat`) show impacted documentation files and that acceptance criteria above are met.

### Heuristic Mapping
- **DocUpdateCompleteness** heuristic: flags documentation PRs lacking explicit impact statements, current screenshots, or reviewer follow-up acknowledgments.

### Remediation
- Align doc text with the live product by validating terminology against the UI or API responses before merging.
- Refresh or annotate any example older than 180 days, or replace it with a current screenshot.
- Confirm within two business days that reviewer comments received within one business day are resolved, clarified, or explicitly scheduled for follow-up.
- Re-run the Windows verification command above to ensure this DoD remains discoverable after edits.

### References
- `README.md` — Issue card authoring conventions and broader style guidance.
- Internal support playbooks or release notes describing the current product behavior.
