# Reporting

The Reporting layer contains the HTML composition pipeline and shared presentation assets used by the analyzers.

## Contents

- `HtmlComposer.ps1` – renders the diagnostics report markup after heuristic evaluation.
- `styles/` – base and layout CSS merged into analyzer outputs alongside scenario-specific styles from `AutoL1/styles/`.

## Usage

`Analyzers/Analyze-Diagnostics.ps1` dot-sources `HtmlComposer.ps1` and concatenates the CSS files in `Reporting/styles/` with the Device Health report stylesheet when building output. Update these files to change the shared presentation layer without touching heuristic logic.
