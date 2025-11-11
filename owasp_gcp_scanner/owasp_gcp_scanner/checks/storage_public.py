from __future__ import annotations

from typing import List

from .base import Check, Finding


class StoragePublicAccess(Check):
    id = "STO-001"
    title = "Public access on Storage buckets"
    severity = "high"
    owasp_category = "A05: Security Misconfiguration"

    PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}

    def run(self, client, project_id: str) -> List[Finding]:
        findings: List[Finding] = []
        for bucket in client.list_buckets(project_id):
            name = bucket.name
            try:
                policy = client.get_bucket_iam(name)
                bindings = policy.get("bindings", [])
                for b in bindings:
                    members = set(b.get("members", []))
                    if members & self.PUBLIC_MEMBERS:
                        findings.append(Finding(
                            check_id=self.id,
                            title=self.title,
                            severity=self.severity,
                            owasp_category=self.owasp_category,
                            project_id=project_id,
                            resource_id=name,
                            description="Bucket has public IAM members bound.",
                            remediation="Enable Public Access Prevention and remove public principals.",
                            details={"role": b.get("role"), "members": list(members)}
                        ))

                uba = client.is_bucket_uba_enabled(name)
                if uba is False:
                    findings.append(Finding(
                        check_id=self.id,
                        title="Uniform bucket-level access disabled",
                        severity="medium",
                        owasp_category=self.owasp_category,
                        project_id=project_id,
                        resource_id=name,
                        description="Uniform bucket-level access is disabled.",
                        remediation="Enable uniform bucket-level access for consistent IAM control.",
                        details={"uniform_bucket_level_access": uba}
                    ))
            except Exception as e:
                findings.append(Finding(
                    check_id=self.id,
                    title="Bucket IAM read failed",
                    severity="low",
                    owasp_category=self.owasp_category,
                    project_id=project_id,
                    resource_id=name,
                    description="Failed to read bucket IAM policy.",
                    remediation="Ensure storage IAM read permissions and API access.",
                    details={"error": str(e)}
                ))

        return findings