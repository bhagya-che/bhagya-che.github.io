#!/usr/bin/env python3
"""
acanalyzer.py

Access-control matrix and BAC-pattern analyzer for login/registration/dashboard
learning artifacts. The analyzer reads its extraction and inference rules from
access_control_rules.json.

Input CSV requirements:
  - code column
  - url and heading columns are recommended. If missing, they are created.

Example:
  python acanalyzer.py --input genai-spring-secure.csv \
      --rules access_control_rules.json \
      --output access_control_results.csv
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
    if "matrix" not in rules or "authorization_patterns" not in rules:
        raise ValueError("Access-control rules JSON must contain 'matrix' and 'authorization_patterns'.")
    validate_regexes(rules)
    return rules


def validate_regexes(obj: Any, path: str = "$") -> None:
    """Fail fast if a pattern in the JSON is not a valid Python regex."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            validate_regexes(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            validate_regexes(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        # Compile strings only in known regex-bearing paths to avoid compiling URLs/descriptions.
        if any(token in path for token in ("patterns", "include_patterns", "context_patterns", "requires")):
            re.compile(obj, RegexFlags)


def any_match(patterns: Iterable[str], text: str) -> bool:
    return any(re.search(pattern, text, RegexFlags) for pattern in patterns)


def find_matches(patterns: Iterable[str], text: str) -> List[str]:
    matches: List[str] = []
    for pattern in patterns:
        for m in re.finditer(pattern, text, RegexFlags):
            snippet = " ".join(m.group(0).split())
            if snippet and snippet not in matches:
                matches.append(snippet[:240])
    return matches


def aggregate_code_data(df_raw: pd.DataFrame, rules: Dict[str, Any]) -> pd.DataFrame:
    if "code" not in df_raw.columns:
        raise ValueError("Input CSV must contain a 'code' column.")

    df = df_raw.copy()
    if "url" not in df.columns:
        df["url"] = "unknown"
    if "heading" not in df.columns:
        df["heading"] = "unknown"

    df = (
        df.dropna(subset=["code"])
        .groupby(["url", "heading"], sort=False)
        .agg(code=("code", lambda x: "\n".join(map(str, x))))
        .reset_index()
        .rename(columns={"url": "tutorial"})
    )

    include_patterns = rules.get("auth_context", {}).get("include_patterns", [])
    if include_patterns:
        mask = (
            df["tutorial"].astype(str).apply(lambda x: any_match(include_patterns, x))
            | df["heading"].astype(str).apply(lambda x: any_match(include_patterns, x))
            | df["code"].astype(str).apply(lambda x: any_match(include_patterns, x))
        )
        df = df[mask].copy()

    return df


def extract_labeled_items(rule_items: List[Dict[str, Any]], text: str) -> Tuple[str, str]:
    labels: List[str] = []
    evidence: List[str] = []
    for item in rule_items:
        patterns = item.get("patterns", [])
        if "requires" in item:
            matched = all(any_match([p], text) for p in item["requires"])
            ev = []
            if matched:
                ev = item["requires"]
        else:
            ev = find_matches(patterns, text)
            matched = bool(ev)
        if matched:
            labels.append(item["label"])
            evidence.extend(ev if isinstance(ev, list) else [str(ev)])
    label_out = ", ".join(sorted(set(labels))) if labels else "Undefined/Implicit"
    evidence_out = " | ".join(sorted(set(map(str, evidence)))) if evidence else "None"
    return label_out, evidence_out


def detect_authorization_family(family_rules: List[Dict[str, Any]], text: str) -> Tuple[str, str]:
    labels: List[str] = []
    evidence: List[str] = []
    for item in family_rules:
        ev = find_matches(item.get("patterns", []), text)
        if ev:
            labels.append(item["label"])
            evidence.extend(ev)
    if labels:
        return "Yes", " | ".join(sorted(set(labels + evidence)))
    return "No", "None"


def infer_bac(row: pd.Series, rules: Dict[str, Any]) -> Tuple[str, str, str, str]:
    text = str(row["code"])
    family_status = {
        "rbac": row.get("RBAC yes/no") == "Yes",
        "abac_ownership": row.get("ABAC yes/no") == "Yes",
        "workflow_context": row.get("Contextual BAC yes/no") == "Yes",
    }

    findings: List[str] = []
    cwes: List[str] = []
    severities: List[str] = []
    refs: List[str] = []

    for rule in rules.get("bac_inference_rules", []):
        context_patterns = rule.get("context_patterns", [])
        missing = rule.get("required_missing", [])
        if context_patterns and not all(any_match([p], text) for p in context_patterns):
            continue
        if any(family_status.get(family, False) for family in missing):
            continue

        findings.append(f"{rule.get('bac_class', 'BAC')}: {rule.get('name', rule['id'])}")
        cwes.extend(rule.get("cwe_ids", []))
        severities.append(rule.get("severity", "review"))
        ref_values = rule.get("references", {}).values()
        refs.extend(ref_values)

    if findings:
        return (
            " | ".join(findings),
            ", ".join(sorted(set(cwes))),
            ", ".join(sorted(set(severities))),
            " | ".join(sorted(set(refs))),
        )

    if row.get("RBAC yes/no") == "Yes" or row.get("ABAC yes/no") == "Yes":
        return ("Secure/Proper Access Control Signal Present", "", "info", "")
    return ("No Specific BAC Detected (Review Manually)", "", "low", "")


def analyze(df_raw: pd.DataFrame, rules: Dict[str, Any]) -> pd.DataFrame:
    df = aggregate_code_data(df_raw, rules)
    if df.empty:
        return pd.DataFrame()

    matrix = rules["matrix"]
    auth_patterns = rules["authorization_patterns"]

    subjects, subject_ev = [], []
    objects, object_ev = [], []
    operations, operation_ev = [], []

    for code in df["code"].astype(str):
        s, se = extract_labeled_items(matrix.get("subjects", []), code)
        o, oe = extract_labeled_items(matrix.get("objects", []), code)
        op, ope = extract_labeled_items(matrix.get("operations", []), code)
        subjects.append(s)
        subject_ev.append(se)
        objects.append(o)
        object_ev.append(oe)
        operations.append(op)
        operation_ev.append(ope)

    df["matrix-subject"] = subjects
    df["matrix-subject evidence"] = subject_ev
    df["matrix-object"] = objects
    df["matrix-object evidence"] = object_ev
    df["matrix-operation"] = operations
    df["matrix-operation evidence"] = operation_ev

    rbac_results = [detect_authorization_family(auth_patterns.get("rbac", []), str(code)) for code in df["code"]]
    abac_results = [detect_authorization_family(auth_patterns.get("abac_ownership", []), str(code)) for code in df["code"]]
    context_results = [detect_authorization_family(auth_patterns.get("workflow_context", []), str(code)) for code in df["code"]]

    df["RBAC yes/no"], df["RBAC pattern matched"] = zip(*rbac_results)
    df["ABAC yes/no"], df["ABAC pattern matched"] = zip(*abac_results)
    df["Contextual BAC yes/no"], df["Contextual BAC pattern matched"] = zip(*context_results)

    bac_results = [infer_bac(row, rules) for _, row in df.iterrows()]
    df["BAC type"], df["BAC CWE IDs"], df["BAC severity"], df["BAC references"] = zip(*bac_results)

    cols = [
        "tutorial", "heading", "code",
        "matrix-subject", "matrix-subject evidence",
        "matrix-object", "matrix-object evidence",
        "matrix-operation", "matrix-operation evidence",
        "RBAC yes/no", "RBAC pattern matched",
        "ABAC yes/no", "ABAC pattern matched",
        "Contextual BAC yes/no", "Contextual BAC pattern matched",
        "BAC type", "BAC CWE IDs", "BAC severity", "BAC references",
    ]
    return df[cols]


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze access-control matrix and BAC patterns.")
    parser.add_argument("--input", required=True, help="Input CSV with a code column.")
    parser.add_argument("--rules", default="access_control_rules.json", help="Access-control JSON rules file.")
    parser.add_argument("--output", required=True, help="Output CSV path.")
    args = parser.parse_args()

    rules = load_rules(args.rules)
    df_raw = pd.read_csv(args.input)
    result = analyze(df_raw, rules)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(args.output, index=False)
    print(f"Saved {len(result):,} analyzed rows to {args.output}")


if __name__ == "__main__":
    main()
