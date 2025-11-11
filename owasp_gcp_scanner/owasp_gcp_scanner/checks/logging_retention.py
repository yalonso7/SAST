from __future__ import annotations

from typing import List

from .base import Check, Finding


class LoggingRetention(Check):
    id = "LOG-001"
    title = "Logging sinks absent or misconfigured (indicative)"
    severity = "low"
    owasp_category = "A09: Security Logging and Monitoring Failures"

    def run(self, client, project_id: str) -> List[Finding]:
        findings: List[Finding] = []
        sinks = client.list_project_log_sinks(project_id)
        if not sinks:
            findings.append(Finding(
                check_id=self.id,
                title=self.title,
                severity=self.severity,
                owasp_category=self.owasp_category,
                project_id=project_id,
                resource_id=project_id,
                description="No log sinks detected. Ensure audit logs retention and export to SIEM.",
                remediation="Create sinks to BigQuery/Cloud Storage/SIEM; verify audit logs coverage.",
                details={}
            ))
        return findings