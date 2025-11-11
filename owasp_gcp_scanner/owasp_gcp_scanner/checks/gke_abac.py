from __future__ import annotations

from typing import List

from .base import Check, Finding


class GKEABAC(Check):
    id = "GKE-001"
    title = "GKE clusters with legacy ABAC enabled"
    severity = "medium"
    owasp_category = "A05: Security Misconfiguration"

    def run(self, client, project_id: str) -> List[Finding]:
        findings: List[Finding] = []
        for cluster in client.list_gke_clusters(project_id):
            name = cluster.get("name", "unknown")
            abac = (cluster.get("legacyAbac", {}) or {}).get("enabled", False)
            if abac:
                findings.append(Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    owasp_category=self.owasp_category,
                    project_id=project_id,
                    resource_id=name,
                    description="Legacy ABAC is enabled on GKE cluster.",
                    remediation="Disable ABAC and rely on RBAC with least privilege.",
                    details={"legacyAbac": cluster.get("legacyAbac")}
                ))
        return findings