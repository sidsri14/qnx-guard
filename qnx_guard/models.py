"""Core data models and interfaces for QNX Sentinel (qnx-guard)."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Rule:
    rule_id: str
    name: str
    severity: Severity
    description: str
    category: str
    remediation: str


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    category: str
    file_path: str
    line_number: int
    matched_text: str
    message: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "category": self.category,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "matched_text": self.matched_text,
            "message": self.message,
            "remediation": self.remediation,
        }


@dataclass
class ScanSummary:
    total_files: int = 0
    scanned_files: int = 0
    total_findings: int = 0
    high_severity: int = 0
    medium_severity: int = 0
    low_severity: int = 0
    info_severity: int = 0
    findings: List[Finding] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.total_findings += 1
        if finding.severity == Severity.HIGH:
            self.high_severity += 1
        elif finding.severity == Severity.MEDIUM:
            self.medium_severity += 1
        elif finding.severity == Severity.LOW:
            self.low_severity += 1
        elif finding.severity == Severity.INFO:
            self.info_severity += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_files": self.total_files,
            "scanned_files": self.scanned_files,
            "total_findings": self.total_findings,
            "high_severity": self.high_severity,
            "medium_severity": self.medium_severity,
            "low_severity": self.low_severity,
            "info_severity": self.info_severity,
            "findings": [f.to_dict() for f in self.findings],
        }
