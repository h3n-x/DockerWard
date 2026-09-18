"""Security finding and severity level data models."""

from enum import StrEnum
from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Normalized security risk severity levels aligned with CVSS and SARIF."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Finding(BaseModel):
    """Structured security policy violation detected during runtime container inspection."""

    rule_id: str = Field(description="Unique rule code (e.g. 'WARD-001')")
    benchmark_ref: str = Field(description="Benchmark mapping reference (e.g. 'CIS Docker 4.1')")
    title: str = Field(description="Short human-readable summary of the violated rule")
    severity: Severity = Field(description="Assessed risk level for this specific finding")

    container_id: str = Field(description="Abbreviated 12-char container identifier")
    container_name: str = Field(description="Normalized container name")

    description: str = Field(description="Specific observation of what was detected at runtime")
    impact: str = Field(description="Technical explanation of the kernel and host security risk")
    remediation: str = Field(description="Actionable command, flag, or Compose snippet to fix")
    references: list[str] = Field(
        default_factory=list,
        description="External security references (CIS, CWE, MITRE ATT&CK)",
    )
