from __future__ import annotations

from typing import List

from .base import Check, Finding


class IAMOverpermission(Check):
    id = "IAM-001"
    title = "Over-permissive IAM bindings (owner/editor or public)"
    severity = "high"
    owasp_category = "A01: Broken Access Control"

    PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
    DANGEROUS_ROLES = {"roles/owner", "roles/editor"}

    def run(self, client, project_id: str) -> List[Finding]:
        findings: List[Finding] = []
        policy = client.get_project_iam(project_id)
        for b in policy.get("bindings", []):
            role = b.get("role", "")
            members = set(b.get("members", []))

            # Public access at project IAM
            if members & self.PUBLIC_MEMBERS:
                findings.append(Finding(
                    check_id=self.id,
                    title=self.title,
                    severity=self.severity,
                    owasp_category=self.owasp_category,
                    project_id=project_id,
                    resource_id=project_id,
                    description=f"Public member(s) bound at project IAM for role {role}.",
                    remediation="Remove public principals from IAM. Use dedicated identities and least privilege.",
                    details={"role": role, "members": list(members)}
                ))

            # Owners/Editors assigned to service accounts
            if role in self.DANGEROUS_ROLES:
                sa_members = [m for m in members if m.startswith("serviceAccount:")]
                if sa_members:
                    findings.append(Finding(
                        check_id=self.id,
                        title=self.title,
                        severity=self.severity,
                        owasp_category=self.owasp_category,
                        project_id=project_id,
                        resource_id=project_id,
                        description=f"Service accounts assigned {role}, violating least privilege.",
                        remediation="Replace primitive roles with granular roles. Consider IAM Conditions.",
                        details={"role": role, "service_accounts": sa_members}
                    ))

        return findings