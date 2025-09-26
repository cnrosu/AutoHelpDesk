#!/usr/bin/env python3
"""Export What Looks Good and potential issue heuristics from the legacy analyzer."""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List

LEGACY_PATH = Path('AutoL1/Analyze-Diagnostics.ps1')
OUTPUT_PATH = Path('docs/legacy-heuristics.json')


def split_args(argument_text: str) -> List[str]:
    tokens: List[str] = []
    current: List[str] = []
    in_single = False
    in_double = False
    depth = 0
    i = 0
    length = len(argument_text)

    while i < length:
        ch = argument_text[i]
        if ch == '`':
            # Preserve escaped characters by copying the next character verbatim.
            current.append(ch)
            if i + 1 < length:
                i += 1
                current.append(argument_text[i])
        elif ch == "'" and not in_double:
            in_single = not in_single
            current.append(ch)
        elif ch == '"' and not in_single:
            in_double = not in_double
            current.append(ch)
        elif ch in '([{' and not in_single and not in_double:
            depth += 1
            current.append(ch)
        elif ch in ')]}' and not in_single and not in_double:
            if depth > 0:
                depth -= 1
            current.append(ch)
        elif ch.isspace() and not in_single and not in_double and depth == 0:
            if current:
                tokens.append(''.join(current).strip())
                current = []
        else:
            current.append(ch)
        i += 1

    if current:
        tokens.append(''.join(current).strip())
    return [t for t in tokens if t]


def clean_token(token: str) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
        return token[1:-1]
    return token


@dataclass
class GoodEntry:
    category: str
    message: str
    evidence_expression: str | None
    note: str | None
    source_line: int


@dataclass
class IssueEntry:
    severity: str
    category: str
    message: str
    evidence_expression: str | None
    extra_arguments: List[str]
    source_line: int


def main() -> None:
    script_text = LEGACY_PATH.read_text(encoding='utf-8')
    what_looks_good: List[GoodEntry] = []
    potential_issues: List[IssueEntry] = []

    for line_number, raw_line in enumerate(script_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('function Add-Normal') or line.startswith('function Add-Issue'):
            continue

        if 'Add-Normal' in raw_line:
            call_index = raw_line.index('Add-Normal')
            arguments = raw_line[call_index + len('Add-Normal'):].strip()
            while arguments.endswith('}'):
                arguments = arguments[:-1].rstrip()
            if not arguments:
                continue
            parts = split_args(arguments)
            if len(parts) < 2:
                continue
            category = clean_token(parts[0])
            if category.startswith('$'):
                continue
            message = clean_token(parts[1])
            evidence = clean_token(parts[2]) if len(parts) >= 3 else None
            note = clean_token(parts[3]) if len(parts) >= 4 else None
            what_looks_good.append(
                GoodEntry(
                    category=category,
                    message=message,
                    evidence_expression=evidence,
                    note=note,
                    source_line=line_number,
                )
            )

        if 'Add-Issue' in raw_line:
            call_index = raw_line.index('Add-Issue')
            arguments = raw_line[call_index + len('Add-Issue'):].strip()
            while arguments.endswith('}'):
                arguments = arguments[:-1].rstrip()
            if not arguments:
                continue
            parts = split_args(arguments)
            if len(parts) < 3:
                continue
            severity = clean_token(parts[0])
            category = clean_token(parts[1])
            if category.startswith('$'):
                continue
            message = clean_token(parts[2])
            evidence = clean_token(parts[3]) if len(parts) >= 4 else None
            extras = [clean_token(p) for p in parts[4:]] if len(parts) > 4 else []
            potential_issues.append(
                IssueEntry(
                    severity=severity,
                    category=category,
                    message=message,
                    evidence_expression=evidence,
                    extra_arguments=extras,
                    source_line=line_number,
                )
            )

    payload = {
        'generatedAt': datetime.now(timezone.utc).isoformat(),
        'sourceFile': str(LEGACY_PATH),
        'whatLooksGood': [asdict(entry) for entry in what_looks_good],
        'potentialIssues': [asdict(entry) for entry in potential_issues],
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
