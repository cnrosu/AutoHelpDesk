# Repository-wide agent instructions

- Every issue card emitted by analyzers or report components must include a single, plain-English sentence summarizing the real-world impact for technicians or end users. Keep this line concise (one sentence) and ensure it clearly conveys the consequence of the issue.
- When editing heuristics, analyzers, or report templates, verify that any new or updated issue cards follow this plain-English explanation requirement. If the collected data cannot supply enough context, note that in the explanation.
- Refer to the "Issue card authoring conventions" section of `README.md` for additional background.

## Heuristic Authoring Checklist
1) Signals to Collect
2) Evaluation Logic
3) Thresholds & Severity
4) Evidence Rendering
5) Remediation
6) References
7) Test Notes

### Pull Requests
When submitting pull requests that modify heuristics, analyzers, or reporting content, authors must paste the Heuristic Authoring Checklist into the PR description and fill out every item. See `.github/PULL_REQUEST_TEMPLATE.md` for additional guidance (or note that it is coming soon if the template is not yet available).
