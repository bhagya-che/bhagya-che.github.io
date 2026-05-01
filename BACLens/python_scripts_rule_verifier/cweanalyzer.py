#!/usr/bin/env python3
"""
cweanalyzer.py

CWE-oriented broken-access-control scanner for tutorial code snippets.
The analyzer reads all rule definitions from cwe_rules.json.

Input CSV requirements:
  - code column
  - url and heading columns are recommended. If missing, they are created.

Example:
  python cweanalyzer.py --input genai-spring-secure.csv \
      --rules cwe_rules.json \
      --output cwe_findings.csv \
      --summary cwe_summary.csv
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import pandas as pd


RegexFlags = re.IGNORECASE | re.MULTILINE | re.DOTALL


def load_rules(path: str | Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        rules = json.load(f)
    if "rules" not in rules:
        raise ValueError("CWE rules JSON must contain a top-level 'rules' list.")
    validate_rules(rules)
    return rules


def validate_rules(rules_doc: Dict[str, Any]) -> None:
    errors: List[str] = []
    for idx, rule in enumerate(rules_doc.get("rules", [])):
        for key in ("patterns", "anti_patterns"):
            for pattern in rule.get(key, []):
                try:
                    re.compile(pattern, RegexFlags)
                except re.error as exc:
                    errors.append(f"Rule {idx} {rule.get('cwe_id', rule.get('id'))} {key}: {pattern!r}: {exc}")
    if errors:
        raise ValueError("Invalid regex patterns:\n" + "\n".join(errors))


def aggregate_code_data(df_raw: pd.DataFrame) -> pd.DataFrame:
    if "code" not in df_raw.columns:
        raise ValueError("Input CSV must contain a 'code' column.")

    df = df_raw.copy()
    if "url" not in df.columns:
        df["url"] = "unknown"
    if "heading" not in df.columns:
        df["heading"] = "unknown"

    return (
        df.dropna(subset=["code"])
        .groupby(["url", "heading"], sort=False)
        .agg(combined_code=("code", lambda x: "\n".join(map(str, x))))
        .reset_index()
    )


def line_number_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def bounded_window(text: str, start: int, end: int, window_lines: int) -> Tuple[str, int, int]:
    """Return a line-bounded code window around a regex match."""
    lines = text.splitlines()
    if not lines:
        return text, 1, 1

    start_line = line_number_for_offset(text, start)
    end_line = line_number_for_offset(text, end)
    lo = max(1, start_line - window_lines)
    hi = min(len(lines), end_line + window_lines)
    snippet = "\n".join(lines[lo - 1:hi])
    return snippet, lo, hi


def pattern_matches(patterns: Iterable[str], text: str) -> List[re.Match[str]]:
    matches: List[re.Match[str]] = []
    for pattern in patterns:
        matches.extend(list(re.finditer(pattern, text, RegexFlags)))
    return matches


def has_antipattern(anti_patterns: Iterable[str], text: str) -> bool:
    return any(re.search(pattern, text, RegexFlags) for pattern in anti_patterns)


def scan_code(code: str, rules_doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    matching_cfg = rules_doc.get("matching", {})
    window_lines = int(matching_cfg.get("window_lines", 6))

    for rule in rules_doc.get("rules", []):
        patterns = rule.get("patterns", [])
        anti_patterns = rule.get("anti_patterns", [])

        for pattern in patterns:
            for m in re.finditer(pattern, code, RegexFlags):
                window, start_line, end_line = bounded_window(code, m.start(), m.end(), window_lines)
                if anti_patterns and has_antipattern(anti_patterns, window):
                    continue

                matched_text = " ".join(m.group(0).split())
                findings.append({
                    "cwe_id": rule.get("cwe_id", rule.get("id", "")),
                    "cwe_name": rule.get("name", ""),
                    "ruleset": rule.get("ruleset", rules_doc.get("ruleset", "")),
                    "category": rule.get("category", ""),
                    "severity": rule.get("severity", ""),
                    "confidence": rule.get("confidence", "heuristic"),
                    "why": rule.get("why", ""),
                    "matched_pattern": pattern,
                    "matched_text": matched_text[:240],
                    "match_line": line_number_for_offset(code, m.start()),
                    "window_start_line": start_line,
                    "window_end_line": end_line,
                    "match_snippet": window[:1200],
                    "references": json.dumps(rule.get("references", []), ensure_ascii=False),
                    "notes": " | ".join(rule.get("notes", [])),
                })

    # Deduplicate exact same CWE/pattern/window in grouped code.
    unique: Dict[Tuple[str, str, int, int], Dict[str, Any]] = {}
    for finding in findings:
        key = (
            finding["cwe_id"],
            finding["matched_pattern"],
            finding["window_start_line"],
            finding["window_end_line"],
        )
        unique[key] = finding
    return list(unique.values())


def analyze(df_raw: pd.DataFrame, rules_doc: Dict[str, Any]) -> pd.DataFrame:
    df = aggregate_code_data(df_raw)
    rows: List[Dict[str, Any]] = []

    for _, row in df.iterrows():
        code = str(row["combined_code"])
        for finding in scan_code(code, rules_doc):
            rows.append({
                "url": row["url"],
                "heading": row["heading"],
                "combined_code": code,
                **finding,
            })

    if not rows:
        return pd.DataFrame(columns=[
            "url", "heading", "cwe_id", "cwe_name", "ruleset", "category",
            "severity", "confidence", "why", "matched_pattern", "matched_text",
            "match_line", "window_start_line", "window_end_line", "match_snippet",
            "references", "notes", "combined_code"
        ])

    cols = [
        "url", "heading", "cwe_id", "cwe_name", "ruleset", "category",
        "severity", "confidence", "why", "matched_pattern", "matched_text",
        "match_line", "window_start_line", "window_end_line", "match_snippet",
        "references", "notes", "combined_code"
    ]
    return pd.DataFrame(rows)[cols]


def summarize(df_results: pd.DataFrame) -> pd.DataFrame:
    if df_results.empty:
        return pd.DataFrame(columns=["ruleset", "cwe_id", "cwe_name", "findings", "affected_groups"])
    return (
        df_results
        .groupby(["ruleset", "cwe_id", "cwe_name"], dropna=False)
        .agg(
            findings=("cwe_id", "count"),
            affected_groups=("url", "nunique"),
        )
        .reset_index()
        .sort_values(["ruleset", "findings"], ascending=[True, False])
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan tutorial snippets for CWE-mapped BAC patterns.")
    parser.add_argument("--input", required=True, help="Input CSV with a code column.")
    parser.add_argument("--rules", default="cwe_rules.json", help="CWE JSON rules file.")
    parser.add_argument("--output", required=True, help="Output findings CSV path.")
    parser.add_argument("--summary", default=None, help="Optional output summary CSV path.")
    args = parser.parse_args()

    rules_doc = load_rules(args.rules)
    df_raw = pd.read_csv(args.input)
    df_results = analyze(df_raw, rules_doc)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    df_results.to_csv(args.output, index=False)
    print(f"Saved {len(df_results):,} findings to {args.output}")

    if args.summary:
        summary = summarize(df_results)
        Path(args.summary).parent.mkdir(parents=True, exist_ok=True)
        summary.to_csv(args.summary, index=False)
        print(f"Saved summary to {args.summary}")


if __name__ == "__main__":
    main()
