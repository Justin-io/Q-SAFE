#!/usr/bin/env python3
"""Evaluate Q-SAFE against a labelled local corpus; no samples are uploaded or executed."""
from __future__ import annotations
import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from qsafe import scan_file

def calculate_metrics(rows):
    tp = fp = tn = fn = 0
    families = defaultdict(lambda: {"detected": 0, "missed": 0})
    for row in rows:
        actual = row["label"]
        predicted = row["prediction"]
        if actual == "malicious" and predicted == "malicious":
            tp += 1
        elif actual == "benign" and predicted == "malicious":
            fp += 1
        elif actual == "benign" and predicted == "benign":
            tn += 1
        elif actual == "malicious" and predicted == "benign":
            fn += 1
        if actual == "malicious":
            family = row.get("family") or "unspecified"
            families[family]["detected" if predicted == "malicious" else "missed"] += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    family_results = {
        family: {
            **counts,
            "recall": counts["detected"] / (counts["detected"] + counts["missed"])
            if counts["detected"] + counts["missed"] else 0.0,
        }
        for family, counts in sorted(families.items())
    }
    return {
        "confusion_matrix": {"true_positive": tp, "false_positive": fp, "true_negative": tn, "false_negative": fn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "specificity": round(specificity, 4),
        "f1": round(f1, 4),
        "family_recall": family_results,
    }

def evaluate_manifest(manifest_path: Path, threshold: int = 40):
    manifest_path = manifest_path.expanduser().resolve()
    evaluated, skipped = [], []
    with manifest_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"path", "label"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError("CSV must contain path,label columns and may contain family")
        for line_number, item in enumerate(reader, start=2):
            label = (item.get("label") or "").strip().lower()
            if label not in {"benign", "malicious"}:
                skipped.append({"line": line_number, "path": item.get("path"), "reason": "label must be benign or malicious"})
                continue
            raw_path = Path((item.get("path") or "").strip()).expanduser()
            path = raw_path if raw_path.is_absolute() else manifest_path.parent / raw_path
            result = scan_file(path)
            if result["status"] != "scanned":
                skipped.append({"line": line_number, "path": str(path), "reason": result.get("error") or result["status"]})
                continue
            prediction = "malicious" if result["analysis"]["score"] >= threshold else "benign"
            evaluated.append({
                "path": str(path),
                "sha256": result["sha256"],
                "label": label,
                "prediction": prediction,
                "score": result["analysis"]["score"],
                "verdict": result["analysis"]["verdict"],
                "family": (item.get("family") or "").strip() or "unspecified",
            })
    return {
        "tool": "Q-SAFE-EVAL",
        "threshold": threshold,
        "manifest": str(manifest_path),
        "evaluated": len(evaluated),
        "skipped": skipped,
        "metrics": calculate_metrics(evaluated),
        "samples": evaluated,
    }

def main(argv=None):
    parser = argparse.ArgumentParser(description="Measure Q-SAFE detection performance on a labelled CSV corpus")
    parser.add_argument("manifest", help="CSV with path,label[,family] columns")
    parser.add_argument("--threshold", type=int, default=40, help="score threshold 0-100; default 40")
    parser.add_argument("--json", help="write full evaluation JSON")
    args = parser.parse_args(argv)
    if not 0 <= args.threshold <= 100:
        parser.error("threshold must be between 0 and 100")
    try:
        report = evaluate_manifest(Path(args.manifest), args.threshold)
    except (OSError, ValueError, csv.Error) as exc:
        print(f"Q-SAFE-EVAL error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"evaluated": report["evaluated"], "skipped": len(report["skipped"]), "threshold": report["threshold"], **report["metrics"]}, indent=2))
    if args.json:
        output = Path(args.json).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
