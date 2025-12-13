
from typing import Dict, Any, List

def format_risk(risk_score: int) -> str:
    if risk_score >= 8:
        return "CRITICAL"
    elif risk_score >= 5:
        return "HIGH"
    elif risk_score >= 2:
        return "MODERATE"
    else:
        return "LOW"

class AnalysisResult:
    def __init__(self, filename: str, file_type: str):
        self.filename = filename
        self.file_type = file_type
        self.is_malicious = False
        self.risk_level = "LOW"
        self.risk_score = 0
        self.findings: List[str] = []
        self.metadata: Dict[str, Any] = {}

    def add_finding(self, message: str, score_impact: int):
        self.findings.append(message)
        self.risk_score += score_impact
        if self.risk_score >= 5:
            self.is_malicious = True
        self.risk_level = format_risk(self.risk_score)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "type": self.file_type,
            "is_malicious": self.is_malicious,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "findings": self.findings,
            "metadata": self.metadata
        }
