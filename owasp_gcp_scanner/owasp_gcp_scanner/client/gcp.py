from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.cloud import storage


class GCPClient:
    def __init__(self, user_agent: str = "owasp-gcp-scanner/0.1.0", max_retries: int = 3, backoff: float = 1.2):
        self._user_agent = user_agent
        self._max_retries = max_retries
        self._backoff = backoff

        # Lazy-init clients to avoid unnecessary API calls on startup
        self._crm = None
        self._compute = None
        self._sqladmin = None
        self._container = None
        self._logging = None
        self._storage_client = None

    def _get(self, service_name: str, version: str):
        return build(service_name, version, cache_discovery=False)

    @property
    def crm(self):
        if not self._crm:
            self._crm = self._get("cloudresourcemanager", "v1")
        return self._crm

    @property
    def compute(self):
        if not self._compute:
            self._compute = self._get("compute", "v1")
        return self._compute

    @property
    def sqladmin(self):
        if not self._sqladmin:
            self._sqladmin = self._get("sqladmin", "v1beta4")
        return self._sqladmin

    @property
    def container(self):
        if not self._container:
            self._container = self._get("container", "v1")
        return self._container

    @property
    def logging(self):
        if not self._logging:
            self._logging = self._get("logging", "v2")
        return self._logging

    @property
    def storage_client(self):
        if not self._storage_client:
            self._storage_client = storage.Client()
        return self._storage_client

    def _execute_with_retry(self, request):
        attempt = 0
        while True:
            try:
                return request.execute()
            except HttpError as e:
                attempt += 1
                if attempt > self._max_retries:
                    raise
                time.sleep(self._backoff ** attempt)

    # Projects
    def list_projects(self, filter_active: bool = True) -> List[Dict[str, Any]]:
        resp = self._execute_with_retry(self.crm.projects().list())
        projects = resp.get("projects", [])
        if filter_active:
            projects = [p for p in projects if p.get("lifecycleState") == "ACTIVE"]
        return projects

    def get_project_iam(self, project_id: str) -> Dict[str, Any]:
        return self._execute_with_retry(self.crm.projects().getIamPolicy(resource=project_id, body={}))

    # Storage
    def list_buckets(self, project_id: str):
        return list(self.storage_client.list_buckets(project=project_id))

    def get_bucket_iam(self, bucket_name: str) -> Dict[str, Any]:
        bucket = self.storage_client.bucket(bucket_name)
        policy = bucket.get_iam_policy(requested_policy_version=3)
        # Convert policy to a dict for consistency
        return {
            "bindings": [
                {"role": b["role"], "members": list(b["members"])} for b in policy.bindings
            ]
        }

    def is_bucket_uba_enabled(self, bucket_name: str) -> Optional[bool]:
        bucket = self.storage_client.bucket(bucket_name)
        try:
            bucket.reload()
            cfg = bucket.iam_configuration
            return bool(getattr(cfg, "uniform_bucket_level_access_enabled", False))
        except Exception:
            return None

    # Compute Engine Firewalls
    def list_firewall_rules(self, project_id: str) -> List[Dict[str, Any]]:
        resp = self._execute_with_retry(self.compute.firewalls().list(project=project_id))
        return resp.get("items", [])

    # Cloud SQL
    def list_sql_instances(self, project_id: str) -> List[Dict[str, Any]]:
        resp = self._execute_with_retry(self.sqladmin.instances().list(project=project_id))
        return resp.get("items", [])

    # GKE
    def list_gke_clusters(self, project_id: str, location: str = "-") -> List[Dict[str, Any]]:
        # location '-' searches all zones/regions
        parent = f"projects/{project_id}/locations/{location}"
        resp = self._execute_with_retry(self.container.projects().locations().clusters().list(parent=parent))
        return resp.get("clusters", [])

    # Logging
    def list_project_log_sinks(self, project_id: str) -> List[Dict[str, Any]]:
        parent = f"projects/{project_id}"
        resp = self._execute_with_retry(self.logging.projects().sinks().list(parent=parent))
        return resp.get("sinks", [])