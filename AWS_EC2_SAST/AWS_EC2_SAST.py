#!/usr/bin/env python3
"""
AWS EC2 SAST Tool
A static application security testing tool for AWS EC2 URLs
targeting OWASP Top 10 vulnerabilities.
"""

import re
import os
import json
import argparse
import requests
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
import hashlib
import ssl
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    url: str
    evidence: str
    recommendation: str
    owasp_category: str

class URLAnalyzer:
    """Analyzes AWS EC2 URLs or IP addresses for security vulnerabilities"""
    
    def __init__(self, target: str, timeout: int = 10):
        # Check if the target is an IP address without scheme
        if self._is_ip_address(target) and "://" not in target:
            # Default to http scheme for IP addresses
            self.url = f"http://{target}"
        elif "://" not in target:
            # Add default scheme for any target without one
            self.url = f"http://{target}"
        else:
            self.url = target
            
        self.timeout = timeout
        self.headers = {}
        self.response = None
        self.parsed_url = urlparse(self.url)
        self.hostname = self.parsed_url.netloc
        self.path = self.parsed_url.path
        self.scheme = self.parsed_url.scheme
        self.original_target = target
    
    def _is_ip_address(self, text: str) -> bool:
        """Check if the given text is an IP address"""
        # Simple IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$'
        # Simple IPv6 pattern
        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(:\d+)?$'
        
        return bool(re.match(ipv4_pattern, text) or re.match(ipv6_pattern, text))
    
    def analyze(self) -> Dict[str, Any]:
        """Perform a comprehensive analysis of the URL"""
        try:
            self.response = requests.get(
                self.url, 
                headers={"User-Agent": "AWS-EC2-SAST-Scanner/1.0"}, 
                timeout=self.timeout,
                verify=True
            )
            
            result = {
                "url": self.url,
                "status_code": self.response.status_code,
                "headers": dict(self.response.headers),
                "tls_info": self._get_tls_info(),
                "server_info": self.response.headers.get("Server", "Unknown"),
                "content_type": self.response.headers.get("Content-Type", "Unknown"),
                "cookies": [{"name": c.name, "secure": c.secure, "httponly": c.has_nonstandard_attr("httponly")} 
                           for c in self.response.cookies],
                "security_headers": self._analyze_security_headers(),
                "body_sample": self.response.text[:1000] if self.response.text else ""
            }
            
            return result
        except requests.exceptions.RequestException as e:
            return {
                "url": self.url,
                "error": str(e),
                "status_code": None,
                "headers": {},
                "tls_info": self._get_tls_info(),
                "server_info": "Unknown",
                "content_type": "Unknown",
                "cookies": [],
                "security_headers": {},
                "body_sample": ""
            }
    
    def _get_tls_info(self) -> Dict[str, Any]:
        """Get TLS/SSL information for the host"""
        if self.scheme != "https":
            return {"enabled": False}
        
        try:
            hostname = self.hostname.split(':')[0]
            port = 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    return {
                        "enabled": True,
                        "version": ssock.version(),
                        "cipher_suite": cipher[0],
                        "cert_expiry": cert.get("notAfter", "Unknown"),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "subject": dict(x[0] for x in cert.get("subject", []))
                    }
        except Exception as e:
            return {
                "enabled": True,
                "error": str(e)
            }
    
    def _analyze_security_headers(self) -> Dict[str, Any]:
        """Analyze security-related HTTP headers"""
        if not self.response:
            return {}
        
        headers = self.response.headers
        security_headers = {
            "content_security_policy": headers.get("Content-Security-Policy"),
            "x_content_type_options": headers.get("X-Content-Type-Options"),
            "x_frame_options": headers.get("X-Frame-Options"),
            "x_xss_protection": headers.get("X-XSS-Protection"),
            "strict_transport_security": headers.get("Strict-Transport-Security"),
            "referrer_policy": headers.get("Referrer-Policy"),
            "permissions_policy": headers.get("Permissions-Policy"),
            "access_control_allow_origin": headers.get("Access-Control-Allow-Origin")
        }
        
        return security_headers

class VulnerabilityDetector:
    """Main vulnerability detection engine for AWS EC2 endpoints"""
    
    def __init__(self):
        self.rules = self._load_detection_rules()
    
    def _load_detection_rules(self) -> Dict[str, Dict[str, Any]]:
        """Load vulnerability detection rules based on OWASP Top 10"""
        return {
            'A01': {
                'name': 'Broken Access Control',
                'owasp_category': 'A01:2021 - Broken Access Control',
                'severity': Severity.HIGH,
                'checks': [
                    self._check_public_s3_references,
                    self._check_iam_references_in_code,
                    self._check_cors_misconfiguration
                ],
                'description': 'Broken access control vulnerabilities',
                'recommendation': 'Implement least privilege with fine-grained permissions, use IAM Access Analyzer, and ensure proper access controls'
            },
            'A02': {
                'name': 'Cryptographic Failures',
                'owasp_category': 'A02:2021 - Cryptographic Failures',
                'severity': Severity.HIGH,
                'checks': [
                    self._check_tls_version,
                    self._check_weak_ciphers,
                    self._check_certificate_issues,
                    self._check_missing_security_headers
                ],
                'description': 'Cryptographic failures including weak TLS, insecure certificates, or missing security headers',
                'recommendation': 'Use AWS Certificate Manager, enforce HTTPS with strong TLS, and enable proper security headers'
            },
            'A03': {
                'name': 'Injection',
                'owasp_category': 'A03:2021 - Injection',
                'severity': Severity.CRITICAL,
                'checks': [
                    self._check_sql_injection_vectors,
                    self._check_command_injection_vectors,
                    self._check_ssrf_vectors
                ],
                'description': 'Potential injection vulnerabilities including SQL, command, or SSRF',
                'recommendation': 'Deploy AWS WAF with managed rules, use API Gateway for input validation, and implement proper input sanitization'
            },
            'A04': {
                'name': 'Insecure Design',
                'owasp_category': 'A04:2021 - Insecure Design',
                'severity': Severity.MEDIUM,
                'checks': [
                    self._check_insecure_api_endpoints,
                    self._check_debug_information_exposure
                ],
                'description': 'Insecure design issues including exposed API endpoints or debug information',
                'recommendation': 'Follow AWS Well-Architected Framework security best practices and implement defense in depth'
            },
            'A05': {
                'name': 'Security Misconfiguration',
                'owasp_category': 'A05:2021 - Security Misconfiguration',
                'severity': Severity.HIGH,
                'checks': [
                    self._check_default_credentials,
                    self._check_directory_listing,
                    self._check_server_information_disclosure
                ],
                'description': 'Security misconfigurations including default credentials, directory listing, or information disclosure',
                'recommendation': 'Use AWS Config for tracking configuration changes, implement AWS Security Hub, and use infrastructure as code'
            },
            'A06': {
                'name': 'Vulnerable and Outdated Components',
                'owasp_category': 'A06:2021 - Vulnerable and Outdated Components',
                'severity': Severity.MEDIUM,
                'checks': [
                    self._check_outdated_server_software,
                    self._check_vulnerable_components
                ],
                'description': 'Outdated or vulnerable server components',
                'recommendation': 'Use Amazon Inspector for vulnerability assessment, implement automated patching, and use managed services'
            },
            'A07': {
                'name': 'Identification and Authentication Failures',
                'owasp_category': 'A07:2021 - Identification and Authentication Failures',
                'severity': Severity.HIGH,
                'checks': [
                    self._check_weak_authentication,
                    self._check_insecure_cookies
                ],
                'description': 'Authentication weaknesses including weak mechanisms or insecure cookies',
                'recommendation': 'Use AWS IAM for identity management, implement Amazon Cognito, and enforce MFA'
            },
            'A08': {
                'name': 'Software and Data Integrity Failures',
                'owasp_category': 'A08:2021 - Software and Data Integrity Failures',
                'severity': Severity.MEDIUM,
                'checks': [
                    self._check_insecure_deserialization,
                    self._check_unsigned_code
                ],
                'description': 'Software and data integrity issues including insecure deserialization',
                'recommendation': 'Use AWS CodePipeline for secure CI/CD, implement AWS Signer, and use KMS for cryptographic verification'
            },
            'A09': {
                'name': 'Security Logging and Monitoring Failures',
                'owasp_category': 'A09:2021 - Security Logging and Monitoring Failures',
                'severity': Severity.MEDIUM,
                'checks': [
                    self._check_logging_mechanisms
                ],
                'description': 'Insufficient logging and monitoring',
                'recommendation': 'Enable AWS CloudTrail, GuardDuty, and VPC Flow Logs for comprehensive monitoring'
            },
            'A10': {
                'name': 'Server-Side Request Forgery (SSRF)',
                'owasp_category': 'A10:2021 - Server-Side Request Forgery (SSRF)',
                'severity': Severity.HIGH,
                'checks': [
                    self._check_ssrf_vulnerabilities
                ],
                'description': 'Server-Side Request Forgery vulnerabilities',
                'recommendation': 'Implement proper input validation, use VPC endpoints, and restrict EC2 instance metadata access'
            }
        }
    
    # A01: Broken Access Control
    def _check_public_s3_references(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        if "body_sample" in analysis and analysis["body_sample"]:
            # Look for public S3 bucket references
            s3_pattern = r'https?://[a-zA-Z0-9.-]+\.s3\.amazonaws\.com'
            matches = re.findall(s3_pattern, analysis["body_sample"])
            
            if matches:
                findings.append(Finding(
                    rule_id='A01-S3-PUBLIC',
                    title='Public S3 Bucket Reference',
                    description='Public S3 bucket reference found in page content',
                    severity=Severity.MEDIUM,
                    url=analysis["url"],
                    evidence=str(matches),
                    recommendation='Ensure S3 buckets have proper access controls and are not publicly accessible',
                    owasp_category='A01:2021 - Broken Access Control'
                ))
        
        return findings
    
    def _check_iam_references_in_code(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        if "body_sample" in analysis and analysis["body_sample"]:
            # Look for IAM credentials or keys
            iam_patterns = [
                r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
                r'aws_access_key_id',
                r'aws_secret_access_key'
            ]
            
            for pattern in iam_patterns:
                matches = re.findall(pattern, analysis["body_sample"])
                if matches:
                    findings.append(Finding(
                        rule_id='A01-IAM-EXPOSURE',
                        title='IAM Credential Exposure',
                        description='Potential IAM credentials or references exposed in page content',
                        severity=Severity.CRITICAL,
                        url=analysis["url"],
                        evidence=str(matches),
                        recommendation='Remove exposed IAM credentials and use IAM roles instead of hardcoded credentials',
                        owasp_category='A01:2021 - Broken Access Control'
                    ))
                    break
        
        return findings
    
    def _check_cors_misconfiguration(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        if "security_headers" in analysis and analysis["security_headers"]:
            cors_header = analysis["security_headers"].get("access_control_allow_origin")
            
            if cors_header == "*":
                findings.append(Finding(
                    rule_id='A01-CORS-MISCONFIG',
                    title='CORS Misconfiguration',
                    description='Access-Control-Allow-Origin header is set to wildcard (*)',
                    severity=Severity.MEDIUM,
                    url=analysis["url"],
                    evidence=f'Access-Control-Allow-Origin: {cors_header}',
                    recommendation='Restrict CORS to specific origins instead of using wildcard',
                    owasp_category='A01:2021 - Broken Access Control'
                ))
        
        return findings
    
    # A02: Cryptographic Failures
    def _check_tls_version(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        if "tls_info" in analysis and analysis["tls_info"].get("enabled", False):
            tls_version = analysis["tls_info"].get("version")
            
            if tls_version and ("TLSv1.0" in tls_version or "TLSv1.1" in tls_version):
                findings.append(Finding(
                    rule_id='A02-WEAK-TLS',
                    title='Weak TLS Version',
                    description=f'Server is using outdated TLS version: {tls_version}',
                    severity=Severity.HIGH,
                    url=analysis["url"],
                    evidence=f'TLS Version: {tls_version}',
                    recommendation='Enforce TLS 1.2 or higher using AWS Certificate Manager and CloudFront security policies',
                    owasp_category='A02:2021 - Cryptographic Failures'
                ))
        elif "scheme" in analysis and analysis["scheme"] == "http":
            findings.append(Finding(
                rule_id='A02-NO-TLS',
                title='Missing TLS Encryption',
                description='Server is using unencrypted HTTP instead of HTTPS',
                severity=Severity.HIGH,
                url=analysis["url"],
                evidence='URL uses HTTP scheme',
                recommendation='Enforce HTTPS using AWS Certificate Manager and configure redirection from HTTP to HTTPS',
                owasp_category='A02:2021 - Cryptographic Failures'
            ))
        
        return findings
    
    def _check_weak_ciphers(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        if "tls_info" in analysis and analysis["tls_info"].get("enabled", False):
            cipher = analysis["tls_info"].get("cipher_suite", "")
            weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL"]
            
            for weak in weak_ciphers:
                if weak in cipher:
                    findings.append(Finding(
                        rule_id='A02-WEAK-CIPHER',
                        title='Weak Cipher Suite',
                        description=f'Server is using weak cipher suite: {cipher}',
                        severity=Severity.HIGH,
                        url=analysis["url"],
                        evidence=f'Cipher Suite: {cipher}',
                        recommendation='Configure strong cipher suites in AWS CloudFront or ALB security policies',
                        owasp_category='A02:2021 - Cryptographic Failures'
                    ))
                    break
        
        return findings
    
    def _check_certificate_issues(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        if "tls_info" in analysis and analysis["tls_info"].get("enabled", False):
            if "error" in analysis["tls_info"]:
                findings.append(Finding(
                    rule_id='A02-CERT-ERROR',
                    title='Certificate Error',
                    description='SSL/TLS certificate has errors',
                    severity=Severity.HIGH,
                    url=analysis["url"],
                    evidence=analysis["tls_info"]["error"],
                    recommendation='Use AWS Certificate Manager to provision and manage certificates',
                    owasp_category='A02:2021 - Cryptographic Failures'
                ))
        
        return findings
    
    def _check_missing_security_headers(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        if "security_headers" in analysis:
            headers = analysis["security_headers"]
            
            # Check for missing security headers
            important_headers = {
                "strict_transport_security": "Strict-Transport-Security",
                "content_security_policy": "Content-Security-Policy",
                "x_content_type_options": "X-Content-Type-Options",
                "x_frame_options": "X-Frame-Options"
            }
            
            for key, header_name in important_headers.items():
                if not headers.get(key):
                    findings.append(Finding(
                        rule_id='A02-MISSING-HEADER',
                        title=f'Missing {header_name} Header',
                        description=f'The {header_name} security header is missing',
                        severity=Severity.MEDIUM,
                        url=analysis["url"],
                        evidence=f'Missing header: {header_name}',
                        recommendation=f'Add {header_name} header through AWS CloudFront or ALB response headers policy',
                        owasp_category='A02:2021 - Cryptographic Failures'
                    ))
        
        return findings
    
    # A03: Injection
    def _check_sql_injection_vectors(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        parsed_url = urlparse(analysis["url"])
        query = parsed_url.query
        
        # Check for potential SQL injection parameters
        sql_injection_params = ["id", "user_id", "product_id", "category", "query", "search"]
        sql_injection_chars = ["'", "\"", ";", "--", "/*", "*/", "OR 1=1", "OR '1'='1"]
        
        for param in sql_injection_params:
            if f"{param}=" in query:
                findings.append(Finding(
                    rule_id='A03-SQL-INJECTION',
                    title='Potential SQL Injection Vector',
                    description=f'URL contains parameter ({param}) that could be vulnerable to SQL injection',
                    severity=Severity.HIGH,
                    url=analysis["url"],
                    evidence=f'Parameter: {param} in query string',
                    recommendation='Implement AWS WAF with SQL injection rules and use parameterized queries',
                    owasp_category='A03:2021 - Injection'
                ))
                break
        
        return findings
    
    def _check_command_injection_vectors(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        parsed_url = urlparse(analysis["url"])
        query = parsed_url.query
        
        # Check for potential command injection parameters
        cmd_injection_params = ["cmd", "exec", "command", "run", "script", "ping", "host"]
        
        for param in cmd_injection_params:
            if f"{param}=" in query:
                findings.append(Finding(
                    rule_id='A03-CMD-INJECTION',
                    title='Potential Command Injection Vector',
                    description=f'URL contains parameter ({param}) that could be vulnerable to command injection',
                    severity=Severity.HIGH,
                    url=analysis["url"],
                    evidence=f'Parameter: {param} in query string',
                    recommendation='Implement AWS WAF and use API Gateway for input validation',
                    owasp_category='A03:2021 - Injection'
                ))
                break
        
        return findings
    
    def _check_ssrf_vectors(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        parsed_url = urlparse(analysis["url"])
        query = parsed_url.query
        
        # Check for potential SSRF parameters
        ssrf_params = ["url", "uri", "link", "src", "dest", "redirect", "return", "next", "site", "html", "file", "reference", "ref"]
        
        for param in ssrf_params:
            if f"{param}=" in query:
                findings.append(Finding(
                    rule_id='A03-SSRF',
                    title='Potential SSRF Vector',
                    description=f'URL contains parameter ({param}) that could be vulnerable to SSRF',
                    severity=Severity.HIGH,
                    url=analysis["url"],
                    evidence=f'Parameter: {param} in query string',
                    recommendation='Implement proper input validation and use VPC endpoints to restrict EC2 instance metadata access',
                    owasp_category='A03:2021 - Injection'
                ))
                break
        
        return findings
    
    # A04: Insecure Design
    def _check_insecure_api_endpoints(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        parsed_url = urlparse(analysis["url"])
        path = parsed_url.path.lower()
        
        # Check for potentially insecure API endpoints
        insecure_endpoints = ["/api/", "/graphql", "/v1/", "/v2/", "/swagger", "/api-docs"]
        
        for endpoint in insecure_endpoints:
            if endpoint in path:
                findings.append(Finding(
                    rule_id='A04-INSECURE-API',
                    title='Potentially Exposed API Endpoint',
                    description=f'URL contains a potentially exposed API endpoint: {endpoint}',
                    severity=Severity.MEDIUM,
                    url=analysis["url"],
                    evidence=f'Path contains: {endpoint}',
                    recommendation='Secure API endpoints with proper authentication and authorization using AWS API Gateway',
                    owasp_category='A04:2021 - Insecure Design'
                ))
                break
        
        return findings
    
    def _check_debug_information_exposure(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        if "body_sample" in analysis and analysis["body_sample"]:
            # Check for debug information exposure
            debug_patterns = [
                r'stack trace',
                r'debug=true',
                r'exception in thread',
                r'syntax error',
                r'error:',
                r'warning:',
                r'undefined variable',
                r'traceback',
                r'<\?php'
            ]
            
            for pattern in debug_patterns:
                if re.search(pattern, analysis["body_sample"], re.IGNORECASE):
                    findings.append(Finding(
                        rule_id='A04-DEBUG-INFO',
                        title='Debug Information Exposure',
                        description='Page contains potential debug information or error messages',
                        severity=Severity.MEDIUM,
                        url=analysis["url"],
                        evidence=f'Debug pattern found: {pattern}',
                        recommendation='Disable debug information in production and implement proper error handling',
                        owasp_category='A04:2021 - Insecure Design'
                    ))
                    break
        
        return findings
    
    # A05: Security Misconfiguration
    def _check_default_credentials(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        parsed_url = urlparse(analysis["url"])
        path = parsed_url.path.lower()
        
        # Check for default admin pages
        admin_pages = ["/admin", "/login", "/wp-admin", "/administrator", "/phpmyadmin", "/console", "/dashboard"]
        
        for page in admin_pages:
            if path.endswith(page) or page + "/" in path:
                findings.append(Finding(
                    rule_id='A05-DEFAULT-CREDS',
                    title='Potential Default Admin Page',
                    description=f'URL contains a potential admin page: {page}',
                    severity=Severity.MEDIUM,
                    url=analysis["url"],
                    evidence=f'Path contains: {page}',
                    recommendation='Secure admin interfaces with strong authentication and use AWS IAM for access control',
                    owasp_category='A05:2021 - Security Misconfiguration'
                ))
                break
        
        return findings
    
    def _check_directory_listing(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        if "body_sample" in analysis and analysis["body_sample"]:
            # Check for directory listing
            if "Index of /" in analysis["body_sample"] and "<title>Index of" in analysis["body_sample"]:
                findings.append(Finding(
                    rule_id='A05-DIR-LISTING',
                    title='Directory Listing Enabled',
                    description='Server has directory listing enabled',
                    severity=Severity.MEDIUM,
                    url=analysis["url"],
                    evidence='Page contains "Index of /" in title',
                    recommendation='Disable directory listing in server configuration',
                    owasp_category='A05:2021 - Security Misconfiguration'
                ))
        
        return findings
    
    def _check_server_information_disclosure(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        if "server_info" in analysis and analysis["server_info"] != "Unknown":
            server_info = analysis["server_info"]
            
            # Check if server header reveals detailed version information
            if re.search(r'[0-9]', server_info):
                findings.append(Finding(
                    rule_id='A05-SERVER-DISCLOSURE',
                    title='Server Information Disclosure',
                    description='Server header reveals detailed version information',
                    severity=Severity.LOW,
                    url=analysis["url"],
                    evidence=f'Server: {server_info}',
                    recommendation='Configure AWS CloudFront or ALB to remove or modify the Server header',
                    owasp_category='A05:2021 - Security Misconfiguration'
                ))
        
        return findings
    
    # A06: Vulnerable and Outdated Components
    def _check_outdated_server_software(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        if "server_info" in analysis and analysis["server_info"] != "Unknown":
            server_info = analysis["server_info"]
            
            # Check for known outdated server versions
            outdated_patterns = [
                r'Apache/2\.[0-3]',
                r'nginx/1\.[0-9]\.',
                r'IIS/[5-7]',
                r'PHP/[1-5]',
                r'tomcat/[1-7]'
            ]
            
            for pattern in outdated_patterns:
                if re.search(pattern, server_info, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id='A06-OUTDATED-SERVER',
                        title='Outdated Server Software',
                        description=f'Server is running outdated software: {server_info}',
                        severity=Severity.HIGH,
                        url=analysis["url"],
                        evidence=f'Server: {server_info}',
                        recommendation='Update server software to the latest version or use AWS managed services',
                        owasp_category='A06:2021 - Vulnerable and Outdated Components'
                    ))
                    break
        
        return findings
    
    def _check_vulnerable_components(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        if "body_sample" in analysis and analysis["body_sample"]:
            # Check for known vulnerable components
            vulnerable_patterns = [
                r'jquery-1\.[0-9]\.[0-9]',
                r'jquery-2\.[0-9]\.[0-9]',
                r'bootstrap-3\.[0-3]',
                r'angular\.js/1\.[2-5]',
                r'react-[0-9]\.[0-9]\.[0-9]'
            ]
            
            for pattern in vulnerable_patterns:
                if re.search(pattern, analysis["body_sample"], re.IGNORECASE):
                    findings.append(Finding(
                        rule_id='A06-VULNERABLE-COMPONENT',
                        title='Potentially Vulnerable Component',
                        description='Page includes potentially outdated or vulnerable JavaScript library',
                        severity=Severity.MEDIUM,
                        url=analysis["url"],
                        evidence=f'Pattern found: {pattern}',
                        recommendation='Update client-side libraries to the latest versions',
                        owasp_category='A06:2021 - Vulnerable and Outdated Components'
                    ))
                    break
        
        return findings
    
    # A07: Identification and Authentication Failures
    def _check_weak_authentication(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        parsed_url = urlparse(analysis["url"])
        path = parsed_url.path.lower()
        
        # Check for authentication endpoints
        auth_endpoints = ["/login", "/signin", "/auth", "/oauth"]
        
        for endpoint in auth_endpoints:
            if endpoint in path:
                # Check if HTTPS is used
                if parsed_url.scheme != "https":
                    findings.append(Finding(
                        rule_id='A07-INSECURE-AUTH',
                        title='Insecure Authentication Endpoint',
                        description='Authentication endpoint is using HTTP instead of HTTPS',
                        severity=Severity.HIGH,
                        url=analysis["url"],
                        evidence=f'Auth endpoint {endpoint} using HTTP',
                        recommendation='Use HTTPS for all authentication endpoints and implement AWS Cognito',
                        owasp_category='A07:2021 - Identification and Authentication Failures'
                    ))
                break
        
        return findings
    
    def _check_insecure_cookies(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        if "cookies" in analysis and analysis["cookies"]:
            for cookie in analysis["cookies"]:
                # Check for session or auth cookies without secure flag
                if any(auth_name in cookie["name"].lower() for auth_name in ["session", "auth", "token", "jwt", "id"]):
                    if not cookie.get("secure", False):
                        findings.append(Finding(
                            rule_id='A07-INSECURE-COOKIE',
                            title='Insecure Authentication Cookie',
                            description=f'Authentication cookie {cookie["name"]} is missing the Secure flag',
                            severity=Severity.MEDIUM,
                            url=analysis["url"],
                            evidence=f'Cookie: {cookie["name"]} missing Secure flag',
                            recommendation='Set Secure and HttpOnly flags for all sensitive cookies',
                            owasp_category='A07:2021 - Identification and Authentication Failures'
                        ))
                    
                    if not cookie.get("httponly", False):
                        findings.append(Finding(
                            rule_id='A07-INSECURE-COOKIE',
                            title='Insecure Authentication Cookie',
                            description=f'Authentication cookie {cookie["name"]} is missing the HttpOnly flag',
                            severity=Severity.MEDIUM,
                            url=analysis["url"],
                            evidence=f'Cookie: {cookie["name"]} missing HttpOnly flag',
                            recommendation='Set Secure and HttpOnly flags for all sensitive cookies',
                            owasp_category='A07:2021 - Identification and Authentication Failures'
                        ))
        
        return findings
    
    # A08: Software and Data Integrity Failures
    def _check_insecure_deserialization(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        if "body_sample" in analysis and analysis["body_sample"]:
            # Check for potential insecure deserialization patterns
            deser_patterns = [
                r'ObjectInputStream',
                r'readObject',
                r'deserialize',
                r'pickle\.loads',
                r'yaml\.load',
                r'eval\('
            ]
            
            for pattern in deser_patterns:
                if re.search(pattern, analysis["body_sample"], re.IGNORECASE):
                    findings.append(Finding(
                        rule_id='A08-INSECURE-DESER',
                        title='Potential Insecure Deserialization',
                        description='Page contains code that may perform insecure deserialization',
                        severity=Severity.HIGH,
                        url=analysis["url"],
                        evidence=f'Pattern found: {pattern}',
                        recommendation='Use safe deserialization methods and validate data integrity',
                        owasp_category='A08:2021 - Software and Data Integrity Failures'
                    ))
                    break
        
        return findings
    
    def _check_unsigned_code(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        if "body_sample" in analysis and analysis["body_sample"]:
            # Check for unsigned scripts loaded from external domains
            script_pattern = r'<script\s+src=["\']https?://(?!amazonaws\.com)[^"\']+["\']'
            matches = re.findall(script_pattern, analysis["body_sample"])
            
            if matches:
                findings.append(Finding(
                    rule_id='A08-UNSIGNED-CODE',
                    title='Unsigned External Scripts',
                    description='Page loads scripts from external domains without integrity verification',
                    severity=Severity.MEDIUM,
                    url=analysis["url"],
                    evidence=str(matches[:3]),  # Limit evidence to first 3 matches
                    recommendation='Use Subresource Integrity (SRI) for external scripts and AWS Signer for code signing',
                    owasp_category='A08:2021 - Software and Data Integrity Failures'
                ))
        
        return findings
    
    # A09: Security Logging and Monitoring Failures
    def _check_logging_mechanisms(self, analysis: Dict[str, Any]) -> List[Finding]:
        # This is a limited check since we can't directly assess logging from a URL scan
        findings = []
        
        # Check for debug parameters that might disable logging
        parsed_url = urlparse(analysis["url"])
        query = parsed_url.query
        
        debug_params = ["debug=1", "log=0", "logging=false", "trace=0"]
        
        for param in debug_params:
            if param in query.lower():
                findings.append(Finding(
                    rule_id='A09-LOGGING-FAILURE',
                    title='Potential Logging Bypass',
                    description='URL contains parameters that might disable logging or monitoring',
                    severity=Severity.MEDIUM,
                    url=analysis["url"],
                    evidence=f'Query parameter: {param}',
                    recommendation='Enable AWS CloudTrail, GuardDuty, and VPC Flow Logs for comprehensive monitoring',
                    owasp_category='A09:2021 - Security Logging and Monitoring Failures'
                ))
                break
        
        return findings
    
    # A10: Server-Side Request Forgery (SSRF)
    def _check_ssrf_vulnerabilities(self, analysis: Dict[str, Any]) -> List[Finding]:
        findings = []
        parsed_url = urlparse(analysis["url"])
        query = parsed_url.query
        
        # Check for potential SSRF parameters with values
        ssrf_patterns = [
            r'url=https?://',
            r'uri=https?://',
            r'path=https?://',
            r'src=https?://',
            r'dest=https?://',
            r'redirect=https?://',
            r'return=https?://',
            r'next=https?://'
        ]
        
        for pattern in ssrf_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                findings.append(Finding(
                    rule_id='A10-SSRF',
                    title='Potential SSRF Vulnerability',
                    description='URL contains parameters that could be exploited for SSRF attacks',
                    severity=Severity.HIGH,
                    url=analysis["url"],
                    evidence=f'Pattern found: {pattern}',
                    recommendation='Implement proper input validation, use VPC endpoints, and restrict EC2 instance metadata access',
                    owasp_category='A10:2021 - Server-Side Request Forgery (SSRF)'
                ))
                break
        
        return findings
    
    def detect_vulnerabilities(self, analysis: Dict[str, Any]) -> List[Finding]:
        """Detect vulnerabilities in the given URL analysis"""
        findings = []
        
        for rule_id, rule in self.rules.items():
            for check in rule['checks']:
                findings.extend(check(analysis))
        
        return findings

class ReportGenerator:
    """Generate security reports in various formats"""
    
    @staticmethod
    def generate_json_report(findings: List[Finding], url: str) -> Dict[str, Any]:
        """Generate JSON format report"""
        return {
            'url': url,
            'timestamp': '2024-01-01T00:00:00Z',  # Would use actual timestamp
            'total_findings': len(findings),
            'findings': [
                {
                    'rule_id': f.rule_id,
                    'title': f.title,
                    'description': f.description,
                    'severity': f.severity.value,
                    'url': f.url,
                    'evidence': f.evidence,
                    'recommendation': f.recommendation,
                    'owasp_category': f.owasp_category
                }
                for f in findings
            ]
        }
    
    @staticmethod
    def generate_text_report(findings: List[Finding], url: str) -> str:
        """Generate human-readable text report"""
        if not findings:
            return f"No vulnerabilities found in {url}\n"
        
        report = f"\n{'='*80}\n"
        report += f"AWS EC2 SECURITY ANALYSIS REPORT\n"
        report += f"URL: {url}\n"
        report += f"Total Findings: {len(findings)}\n"
        report += f"{'='*80}\n\n"
        
        # Group findings by severity
        severity_groups = {}
        for finding in findings:
            severity = finding.severity.value
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(finding)
        
        # Display findings by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in severity_groups:
                report += f"\n{severity} SEVERITY FINDINGS:\n"
                report += f"{'-' * 40}\n"
                
                for finding in severity_groups[severity]:
                    report += f"\n[{finding.rule_id}] {finding.title}\n"
                    report += f"URL: {finding.url}\n"
                    report += f"Evidence: {finding.evidence}\n"
                    report += f"Description: {finding.description}\n"
                    report += f"Category: {finding.owasp_category}\n"
                    report += f"Recommendation: {finding.recommendation}\n"
                    report += f"{'-' * 40}\n"
        
        return report

class AWSEC2SASTTool:
    """Main SAST tool class for AWS EC2 URLs and IP addresses"""
    
    def __init__(self):
        self.detector = VulnerabilityDetector()
        self.report_generator = ReportGenerator()
    
    def scan_url(self, url: str, timeout: int = 10) -> List[Finding]:
        """Scan a single URL or IP address"""
        try:
            analyzer = URLAnalyzer(url, timeout)
            analysis = analyzer.analyze()
            return self.detector.detect_vulnerabilities(analysis)
        except Exception as e:
            print(f"Error scanning target {url}: {str(e)}")
            return []
    
    def scan_urls(self, urls: List[str], max_workers: int = 5) -> Dict[str, List[Finding]]:
        """Scan multiple URLs or IP addresses in parallel"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(self.scan_url, url): url for url in urls}
            for future in future_to_url:
                url = future_to_url[future]
                try:
                    findings = future.result()
                    if findings:
                        results[url] = findings
                except Exception as e:
                    print(f"Error processing target {url}: {str(e)}")
        
        return results
    
    def scan_urls_from_file(self, filepath: str, max_workers: int = 5) -> Dict[str, List[Finding]]:
        """Scan URLs or IP addresses from a file"""
        try:
            with open(filepath, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            
            return self.scan_urls(targets, max_workers)
        except Exception as e:
            print(f"Error reading targets from file {filepath}: {str(e)}")
            return {}
    
    def generate_report(self, findings: Dict[str, List[Finding]], output_format: str = 'text') -> str:
        """Generate a comprehensive report"""
        if output_format == 'json':
            all_findings = []
            for url, url_findings in findings.items():
                for finding in url_findings:
                    finding_dict = self.report_generator.generate_json_report([finding], url)
                    all_findings.extend(finding_dict['findings'])
            
            return json.dumps({
                'total_urls_scanned': len(findings),
                'total_findings': len(all_findings),
                'findings': all_findings
            }, indent=2)
        
        else:  # text format
            report = f"\n{'='*100}\n"
            report += f"AWS EC2 SECURITY ANALYSIS - SUMMARY REPORT\n"
            report += f"{'='*100}\n"
            report += f"URLs scanned: {len(findings)}\n"
            report += f"Total findings: {sum(len(f) for f in findings.values())}\n"
            report += f"{'='*100}\n"
            
            for url, url_findings in findings.items():
                report += self.report_generator.generate_text_report(url_findings, url)
            
            return report

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='AWS EC2 SAST Tool')
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('--url', help='Single URL or IP address to scan')
    target_group.add_argument('--ip', help='Single IP address to scan (shorthand for --url)')
    target_group.add_argument('--file', help='File containing URLs or IP addresses to scan (one per line)')
    
    parser.add_argument('--output', '-o', help='Output file for report')
    parser.add_argument('--format', '-f', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('--timeout', '-t', type=int, default=10,
                       help='Timeout in seconds for HTTP requests (default: 10)')
    parser.add_argument('--workers', '-w', type=int, default=5,
                       help='Number of worker threads for parallel scanning (default: 5)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    tool = AWSEC2SASTTool()
    
    # Handle the target (URL or IP)
    target = args.url or args.ip
    
    if target:
        findings = {target: tool.scan_url(target, args.timeout)}
    else:
        findings = tool.scan_urls_from_file(args.file, args.workers)
    
    report = tool.generate_report(findings, args.format)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)

if __name__ == '__main__':
    main()