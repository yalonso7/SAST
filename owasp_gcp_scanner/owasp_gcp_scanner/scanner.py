from __future__ import annotations

import argparse
import concurrent.futures
import json
from pathlib import Path
from typing import Any, Dict, List

import yaml

from .client.gcp import GCPClient
from .checks.base import Finding, Check
from .checks.iam_overpermission import IAMOverpermission
from .checks.storage_public import StoragePublicAccess
from .checks.firewall_open_ports import FirewallOpenPorts
from .checks.sql_public_ip import SQLPublicIP
from .checks.gke_abac import GKEABAC
from .checks.logging_retention import LoggingRetention
from .reporting import reporters


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def select_projects(client: GCPClient, cfg: Dict[str, Any]) -> List[str]:
    include = set(cfg.get("include_projects") or [])
    exclude = set(cfg.get("exclude_projects") or [])
    projects: List[str] = []
    if include:
        projects = [p for p in include if p not in exclude]
    else:
        projects = [p["projectId"] for p in client.list_projects() if p["projectId"] not in exclude]
    return sorted(projects)


def run_checks_for_project(client: GCPClient, checks: List[Check], project_id: str) -> List[Finding]:
    findings: List[Finding] = []
    for chk in checks:
        try:
            findings.extend(chk.run(client, project_id))
        except Exception as e:
            findings.append(Finding(
                check_id=chk.id,
                title=f"Check failed: {chk.title}",
                severity="low",
                owasp_category=chk.owasp_category,
                project_id=project_id,
                resource_id=project_id,
                description="Check execution failed.",
                remediation="Verify API enablement and IAM permissions; review error details.",
                details={"error": str(e)}
            ))
    return findings


def serialize_findings(findings: List[Finding]) -> List[Dict[str, Any]]:
    return [
        {
            "check_id": f.check_id,
            "title": f.title,
            "severity": f.severity,
            "owasp_category": f.owasp_category,
            "project_id": f.project_id,
            "resource_id": f.resource_id,
            "description": f.description,
            "remediation": f.remediation,
            "details": f.details,
        }
        for f in findings
    ]


def main():
    parser = argparse.ArgumentParser(description="OWASP-aligned GCP misconfiguration scanner")
    parser.add_argument("--config", default=str(Path(__file__).parent / "config" / "default.yaml"), help="Path to YAML config")
    parser.add_argument("--output-format", nargs="*", default=None, help="Output formats: json csv")
    args = parser.parse_args()

    cfg = load_config(args.config)
    output_dir = cfg.get("output_dir", "owasp_gcp_scanner/output")
    output_formats = args.output_format or cfg.get("output_format", ["json"])  # allow CLI override
    workers = int(cfg.get("concurrent_workers", 8))

    client = GCPClient()
    projects = select_projects(client, cfg)

    checks: List[Check] = [
        IAMOverpermission(),
        StoragePublicAccess(),
        FirewallOpenPorts(),
        SQLPublicIP(),
        GKEABAC(),
        LoggingRetention(),
    ]

    all_findings: List[Finding] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futs = [executor.submit(run_checks_for_project, client, checks, pid) for pid in projects]
        for fut in concurrent.futures.as_completed(futs):
            all_findings.extend(fut.result())

    ser = serialize_findings(all_findings)

    if "json" in output_formats:
        reporters.write_json(ser, output_dir)
    if "csv" in output_formats:
        reporters.write_csv(ser, output_dir)

    print(json.dumps({"projects": len(projects), "findings": len(ser), "output_dir": output_dir, "formats": output_formats}, indent=2))


if __name__ == "__main__":
    main()