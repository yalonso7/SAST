from __future__ import annotations

from typing import List

from .base import Check, Finding


class SQLPublicIP(Check):
    id = "SQL-001"
    title = "Cloud SQL instances with public IPv4 enabled"
    severity = "medium"
    owasp_category = "A05: Security Misconfiguration"

    def run(self, client, project_id: str) -> List[Finding]:
        findings: List[Finding] = []
        for inst in client.list_sql_instances(project_id):
            name = inst.get("name", "unknown")
            settings = inst.get("settings", {})
            ip_cfg = settings.get("ipConfiguration", {})
            ipv4_enabled = bool(ip_cfg.get("ipv4Enabled", False))
            auth_nets = ip_cfg.get("authorizedNetworks", [])
            open_anywhere = any(n.get("value") in ("0.0.0.0/0", "::/0") for n in auth_nets)

            if ipv4_enabled and (not auth_nets or open_anywhere):
                findings.append(Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    owasp_category=self.owasp_category,
                    project_id=project_id,
                    resource_id=name,
                    description="Cloud SQL public IP enabled with weak or missing allowlist.",
                    remediation="Disable public IP or restrict authorized networks and require SSL.",
                    details={"ipv4Enabled": ipv4_enabled, "authorizedNetworks": auth_nets}
                ))
        return findings