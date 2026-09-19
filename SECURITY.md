# Security Policy

## Supported Versions

Security updates are actively applied to the latest major and minor release versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Security Model & Guarantees

`DockerWard` audits container runtime configurations directly via the Docker Engine API (`/var/run/docker.sock`). To maintain security integrity:

1. **Read-Only Inspection**: `DockerWard` evaluates live container metadata and configurations without modifying running container state or executing intrusive operations unless explicitly requested via remediation commands.
2. **Deterministic Evaluation**: Rules evaluated against the **CIS Docker Benchmark v1.6.0** are fail-closed; ambiguous configurations default to non-compliant warnings.
3. **Structured SARIF Output**: Security findings exported to OASIS SARIF 2.1.0 format adhere to deterministic schema validation for integration into GitHub Code Scanning and enterprise SIEM/SOAR pipelines.

---

## Reporting a Vulnerability

We take the security of `DockerWard` and the environments it monitors seriously. If you identify a security vulnerability (such as socket privilege escalation, improper rule evaluation, or dependency flaws):

1. **Do NOT report security vulnerabilities through public GitHub issues.**
2. Send an encrypted or confidential email to **h3n.eth@gmail.com** with the subject line:
   `[SECURITY VULNERABILITY] DockerWard - <Summary>`
3. Include detailed information:
   - A clear description of the vulnerability.
   - Steps or proof-of-concept (PoC) scripts to reproduce the issue.
   - Potential impact on the Docker daemon or host operating system.
   - Any suggested mitigations or patches.

### Response Timelines

- **Initial Acknowledgement**: Within 48 hours.
- **Triage & Verification**: Within 5 business days.
- **Fix & Coordinated Release**: Addressed in the earliest possible release following verification.

Thank you for practicing responsible disclosure and keeping the container ecosystem secure.
