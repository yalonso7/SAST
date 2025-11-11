The tool is designed to scan AWS EC2 URLs for security vulnerabilities related to the OWASP Top 10 (2021) categories.


pip install -r requirements.txt

necessary dependencies:

- requests>=2.28.0 - For making HTTP requests to scan URLs
- urllib3>=1.26.0 - Required by requests for HTTP operations
- argparse>=1.4.0 - For command-line argument parsing
- typing>=3.7.4 - For type annotations
- dataclasses>=0.8 (for Python < 3.7) - For data class functionality
These dependencies will ensure that your AWS EC2 SAST tool runs properly. You can install them using:

Here's what the tool can do:

1. 1.
   Scan individual URLs or multiple URLs from a file
2. 2.
   Detect vulnerabilities across all OWASP Top 10 categories:
   
   - A01: Broken Access Control
   - A02: Cryptographic Failures
   - A03: Injection
   - A04: Insecure Design
   - A05: Security Misconfiguration
   - A06: Vulnerable and Outdated Components
   - A07: Identification and Authentication Failures
   - A08: Software and Data Integrity Failures
   - A09: Security Logging and Monitoring Failures
   - A10: Server-Side Request Forgery (SSRF)
3. 3.
   Generate comprehensive reports in text or JSON format
4. 4.
   Perform parallel scanning of multiple URLs for efficiency
To use the tool, you can run it with the following commands:

```
# Scan a single URL
python AWS_EC2_SAST.py --url https://
example-ec2.amazonaws.com

# Scan multiple URLs from a file
python AWS_EC2_SAST.py --file urls.txt

# Generate a JSON report
python AWS_EC2_SAST.py --url https://
example-ec2.amazonaws.com --format json 
--output report.json

# Adjust timeout and worker threads
python AWS_EC2_SAST.py --file urls.txt 
--timeout 15 --workers 10


IP'scan

python AWS_EC2_SAST.py --ip 192.168.1.1
python AWS_EC2_SAST.py --url example.com
python AWS_EC2_SAST.py --file ips_and_urls.txt
```
The tool follows a similar structure to the Solitude_SAST tool but is specifically tailored for AWS EC2 endpoints with checks relevant to cloud infrastructure security.