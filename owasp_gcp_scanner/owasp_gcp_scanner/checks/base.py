from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    owasp_category: str
    project_id: str
    resource_id: str
    description: str
    remediation: str
    details: Dict[str, Any]


class Check:
    id: str = ""
    title: str = ""
    severity: str = "medium"
    owasp_category: str = ""

    def run(self, client, project_id: str) -> List[Finding]:
        raise NotImplementedError