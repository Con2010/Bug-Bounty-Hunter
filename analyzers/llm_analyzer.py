#!/usr/bin/env python3

import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger("bug_bounty_hunter.analyzers.llm")

class LLMAnalyzer:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.api_key = config.get("api_key")
        self.model = config.get("model", "gpt-4")
        self.provider = config.get("provider", "openai")
        logger.info(f"Initialized LLM Analyzer with provider: {self.provider}, model: {self.model}")
        if not self.api_key:
            logger.warning("No LLM API key provided. Functionality will be limited.")

    def analyze(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        logger.info(f"Analyzing scan results from {scan_results.get('scanner')} using LLM")
        issues = scan_results.get("issues", [])
        analysis_results = []
        for issue in issues:
            enhanced_issue = issue.copy()
            enhanced_issue.update({
                "llm_analysis": {
                    "risk_assessment": self._mock_risk_assessment(issue),
                    "remediation_steps": self._mock_remediation_steps(issue),
                    "exploit_potential": self._mock_exploit_potential(issue),
                    "false_positive_likelihood": "low" if issue["confidence"] == "certain" else "medium"
                },
                "source": "llm_analyzer"
            })
            analysis_results.append(enhanced_issue)
        logger.info(f"LLM analysis completed. Enhanced {len(analysis_results)} findings.")
        return analysis_results

    def deduplicate_and_prioritize(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        logger.info(f"Deduplicating and prioritizing {len(findings)} findings")
        deduplicated = {}
        for finding in findings:
            key = f"{finding.get('name')}:{finding.get('url')}"
            if key not in deduplicated or self._is_higher_priority(finding, deduplicated[key]):
                deduplicated[key] = finding
        result = list(deduplicated.values())
        result.sort(key=lambda x: self._severity_score(x.get("severity", "info")), reverse=True)
        logger.info(f"After deduplication: {len(result)} unique findings")
        return result

    def _severity_score(self, severity: str) -> int:
        return {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1
        }.get(severity.lower(), 0)

    def _is_higher_priority(self, finding1: Dict[str, Any], finding2: Dict[str, Any]) -> bool:
        score1 = self._severity_score(finding1.get("severity", "info"))
        score2 = self._severity_score(finding2.get("severity", "info"))
        if score1 != score2:
            return score1 > score2
        confidence_score = {
            "certain": 3,
            "high": 2,
            "medium": 1,
            "low": 0
        }
        conf1 = confidence_score.get(finding1.get("confidence", "low").lower(), 0)
        conf2 = confidence_score.get(finding2.get("confidence", "low").lower(), 0)
        return conf1 > conf2

    def _mock_risk_assessment(self, issue: Dict[str, Any]) -> str:
        severity = issue.get("severity", "medium").lower()
        if severity == "high":
            return "This vulnerability poses a significant risk to the application and could lead to unauthorized access, data theft, or service disruption. Immediate remediation is recommended."
        elif severity == "medium":
            return "This vulnerability represents a moderate risk to the application. While not immediately critical, it should be addressed in the near term to prevent potential exploitation."
        else:
            return "This issue represents a low risk to the application but should be addressed as part of routine security maintenance."

    def _mock_remediation_steps(self, issue: Dict[str, Any]) -> List[str]:
        issue_name = issue.get("name", "").lower()
        if "xss" in issue_name:
            return [
                "Implement proper output encoding for all user-controlled data displayed in the browser",
                "Use Content-Security-Policy headers to mitigate XSS attacks",
                "Validate and sanitize all user inputs on the server side",
                "Consider using modern frameworks that automatically escape output"
            ]
        elif "sql" in issue_name:
            return [
                "Use parameterized queries or prepared statements instead of string concatenation",
                "Implement proper input validation for all database queries",
                "Apply the principle of least privilege to database accounts",
                "Consider using an ORM framework to handle database interactions"
            ]
        elif "cookie" in issue_name:
            return [
                "Set the Secure flag on all cookies containing sensitive information",
                "Use HttpOnly flag to prevent JavaScript access to cookies",
                "Ensure cookies are not accessible via cross-site scripting vulnerabilities"
            ]
        else:
            return ["General remediation steps"]

    def _mock_exploit_potential(self, issue: Dict[str, Any]) -> str:
        return "Potential for exploitation depends on the specific context and implementation details."