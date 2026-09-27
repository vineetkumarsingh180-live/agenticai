from typing import List, Optional
from pydantic import BaseModel, Field


class VulnerabilityDetail(BaseModel):
    cwe_id: str = Field(description="CWE Identifier, e.g. CWE-89, CWE-78")
    title: str = Field(description="Short descriptive title of the vulnerability")
    severity: str = Field(description="One of: CRITICAL, HIGH, MEDIUM, LOW")
    vulnerable_lines: List[int] = Field(
        description="Exact line numbers in the original code that are vulnerable"
    )
    risk_impact: str = Field(
        description="Concrete consequences and technical impact if exploited"
    )
    explanation: str = Field(
        description="Detailed technical explanation of the flaw and why it is dangerous"
    )


class VulnerabilityAnalysis(BaseModel):
    has_vulnerabilities: bool = Field(
        description="True if one or more vulnerabilities were found"
    )
    vulnerabilities: List[VulnerabilityDetail] = Field(
        default_factory=list,
        description="List of all identified vulnerabilities; empty if none found"
    )


class PatchResult(BaseModel):
    patched_code: str = Field(
        description="Complete, syntactically valid patched source code"
    )
    changes_made: List[str] = Field(
        description="Human-readable summary of each fix applied"
    )


class ValidationResult(BaseModel):
    is_valid_syntax: bool = Field(description="True if the patched code passes syntax check")
    error_message: Optional[str] = Field(
        default=None,
        description="Syntax error description if is_valid_syntax is False"
    )
    vulnerabilities_resolved: bool = Field(
        description="True if the patch appears to resolve the identified vulnerabilities"
    )