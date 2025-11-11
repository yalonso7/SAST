from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List


def write_json(findings: List[Dict[str, Any]], output_dir: str, filename: str = "findings.json") -> str:
    out_path = Path(output_dir) / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, sort_keys=True)
    return str(out_path)


def write_csv(findings: List[Dict[str, Any]], output_dir: str, filename: str = "findings.csv") -> str:
    out_path = Path(output_dir) / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not findings:
        # Write header only
        with out_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["check_id", "title", "severity", "owasp_category", "project_id", "resource_id", "description", "remediation", "details"])
        return str(out_path)

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["check_id", "title", "severity", "owasp_category", "project_id", "resource_id", "description", "remediation", "details"])
        for item in findings:
            writer.writerow([
                item.get("check_id"),
                item.get("title"),
                item.get("severity"),
                item.get("owasp_category"),
                item.get("project_id"),
                item.get("resource_id"),
                item.get("description"),
                item.get("remediation"),
                json.dumps(item.get("details", {})),
            ])
    return str(out_path)