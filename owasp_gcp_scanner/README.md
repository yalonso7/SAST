# OWASP-Aligned GCP Misconfiguration Scanner

This project provides a Python-based scanner aligned with the OWASP Top 10, focusing on GCP misconfigurations and vulnerabilities. It aims to help security teams quickly identify high-impact risks across Google Cloud projects with pragmatic checks, concurrency, and reporting (JSON/CSV).

# Goals

- Map practical GCP misconfiguration checks to OWASP Top 10 categories
- Prioritize Broken Access Control and Security Misconfiguration findings
- Support multi-project scans with concurrency and basic rate limiting
- Export actionable findings in JSON and CSV formats

# OWASP Mapping (Examples)

- A01 Broken Access Control: Over-permissive IAM (project-level, storage, service accounts)
- A02 Cryptographic Failures: KMS key rotation and encryption-at-rest checks (planned)
- A03 Injection: Placeholder for Cloud Functions/Run input validation checks (planned)
- A05 Security Misconfiguration: Public buckets, open firewalls, public SQL instances
- A07 Identification & Authentication Failures: OS Login enforcement (planned), SA key hygiene
- A09 Logging & Monitoring Failures: Audit logs misconfiguration and retention checks
- A10 SSRF: Public endpoints without appropriate controls (planned)

# Quick Start

1. Ensure you have Application Default Credentials configured: `gcloud auth application-default login`.
2. Install dependencies:
   ```
   pip install -r owasp_gcp_scanner/requirements.txt
   ```
3. Configure projects and options in `owasp_gcp_scanner/config/default.yaml`.
4. Run the scanner:
   ```
   python -m owasp_gcp_scanner --config owasp_gcp_scanner/config/default.yaml --output-format json csv
   ```

Outputs are saved under the configured `output_dir`.

# Design Overview

- `client/` provides a minimal GCP client wrapper using the Google Discovery API and storage client.
- `checks/` contains modular checks. Each check returns findings with severity, category, resource, and remediation.
- `scanner.py` orchestrates projects, runs checks concurrently, and writes reports.
- `reporting/` writes JSON and CSV outputs.

# Notes

- Some checks require specific APIs enabled (Compute, SQL Admin, Container, Cloud Resource Manager, Logging).
- The scanner emphasizes safe reads; it does not modify any configuration.
- Concurrency uses ThreadPoolExecutor with simple throttling to remain respectful of API quotas.