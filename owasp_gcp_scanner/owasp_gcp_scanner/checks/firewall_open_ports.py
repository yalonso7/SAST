from __future__ import annotations

from typing import List

from .base import Check, Finding


class FirewallOpenPorts(Check):
    id = "FW-001"
    title = "Open firewall to 0.0.0.0/0 for SSH/RDP"
    severity = "high"
    owasp_category = "A05: Security Misconfiguration"

    OPEN_CIDR = "0.0.0.0/0"
    SENSITIVE_PORTS = {"22", "3389"}

    def run(self, client, project_id: str) -> List[Finding]:
        findings: List[Finding] = []
        for rule in client.list_firewall_rules(project_id):
            src_ranges = set(rule.get("sourceRanges", []))
            if self.OPEN_CIDR in src_ranges and rule.get("allowed"):
                allowed = rule.get("allowed", [])
                for a in allowed:
                    ip_protocol = a.get("IPProtocol")
                    ports = set(a.get("ports", []))
                    if ip_protocol == "tcp" and (ports & self.SENSITIVE_PORTS):
                        findings.append(Finding(
                            check_id=self.id,
                            title=self.title,
                            severity=self.severity,
                            owasp_category=self.owasp_category,
                            project_id=project_id,
                            resource_id=rule.get("name", "unknown"),
                            description="Firewall allows SSH/RDP from the internet.",
                            remediation="Restrict sources, use IAP/Bastion, or remove open ingress rules.",
                            details={"protocol": ip_protocol, "ports": list(ports), "sourceRanges": list(src_ranges)}
                        ))
        return findings