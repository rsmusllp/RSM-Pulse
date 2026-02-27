from dataclasses import dataclass, field
from typing import List, Dict, Any

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

@dataclass
class Finding:
    category:       str
    title:          str
    severity:       str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    description:    str
    details:        List[str] = field(default_factory=list)
    recommendation: str = ""
    risk_score:     int = 0      # points deducted from 100
    references:     List[str] = field(default_factory=list)

@dataclass
class ScanResult:
    domain:    str
    scan_time: str
    dc_ip:     str
    findings:  List[Finding]    = field(default_factory=list)
    stats:     Dict[str, Any]   = field(default_factory=dict)

    @property
    def total_score(self) -> int:
        return max(0, 100 - sum(f.risk_score for f in self.findings))

    @property
    def risk_level(self) -> str:
        s = self.total_score
        if s >= 80: return "LOW"
        if s >= 60: return "MEDIUM"
        if s >= 40: return "HIGH"
        return "CRITICAL"

    def findings_by_severity(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 5))

    def counts(self) -> Dict[str, int]:
        c: Dict[str, int] = {}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c