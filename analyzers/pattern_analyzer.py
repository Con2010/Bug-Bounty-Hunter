#!/usr/bin/env python3
"""
Pattern-based Vulnerability Analyzer

This module uses pattern matching and rule-based techniques to analyze scan results
and identify vulnerabilities.
"""

import logging
import re
from typing import Dict, List, Any, Optional

logger = logging.getLogger("bug_bounty_hunter.analyzers.pattern")

class PatternAnalyzer:
    """Pattern-based analyzer for vulnerability detection and analysis."""
    
    def __init__(self):
        """
        Initialize the pattern analyzer with default rules.
        """
        logger.info("Initializing Pattern Analyzer with default ruleset")
        
        # Initialize vulnerability patterns
        self.patterns = {
            "sql_injection": [
                r"SQL syntax.*?error",
                r"MySQL.*?error",
                r"ORA-[0-9]{5}",
                r"PostgreSQL.*?ERROR",
                r"SQLite3::query"
            ],
            "xss": [
                r"<script>[^<]*?</script>",
                r"javascript:[^\s]+",
                r"onerror\s*=\s*['\"][^'\"]*?['\"]"  
            ],
            "path_traversal": [
                r"\.\.(/|\\)[^/\\]*?",
                r"(/|\\)etc(/|\\)passwd",
                r"(/|\\)windows(/|\\)win.ini"
            ],
            "sensitive_data": [
                r"password\s*=\s*['\"][^'\"]{3,}['\"]"  ,
                r"api[_-]?key\s*=\s*['\"][^'\"]{10,}['\"]"  ,
                r"secret\s*=\s*['\"][^'\"]{10,}['\"]"  
            ]
        }
    
    def analyze(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze scan results using pattern matching to identify vulnerabilities.
        
        Args:
            scan_results: Dictionary containing scan results from a scanner
            
        Returns:
            List of dictionaries containing identified vulnerabilities with analysis
        """
        logger.info(f"Analyzing scan results from {scan_results.get('scanner')} using pattern matching")
        
        # Extract issues from scan results
        scanner_issues = scan_results.get("issues", [])
        
        # Results from pattern analysis
        pattern_findings = []
        
        # Analyze each issue from the scanner
        for issue in scanner_issues:
            # Look for additional patterns in the request/response data
            request = issue.get("request", "")
            response = issue.get("response", "")
            url = issue.get("url", "")
            
            # Check for additional patterns in the request/response
            additional_findings = self._find_patterns_in_data(request, response, url)
            
            # Add the original issue with any additional pattern matches
            enhanced_issue = issue.copy()
            enhanced_issue.update({
                "pattern_matches": additional_findings,
                "source": "pattern_analyzer"
            })
            
            pattern_findings.append(enhanced_issue)
            
            # Add any new issues found through pattern matching
            for finding in additional_findings:
                if finding["type"] not in issue.get("name", "").lower():
                    # This is a new issue type not detected by the scanner
                    new_issue = {
                        "name": finding["type"].replace("_", " ").title(),
                        "severity": self._determine_severity(finding["type"]),
                        "confidence": "medium",
                        "description": f"Pattern-based detection of {finding['type'].replace('_', ' ')} vulnerability",
                        "url": url,
                        "request": request,
                        "response": response,
                        "pattern_matches": [finding],
                        "source": "pattern_analyzer"
                    }
                    pattern_findings.append(new_issue)
        
        logger.info(f"Pattern analysis completed. Found {len(pattern_findings)} findings.")
        return pattern_findings
    
    def _find_patterns_in_data(self, request: str, response: str, url: str) -> List[Dict[str, Any]]:
        """
        Find vulnerability patterns in request/response data.
        
        Args:
            request: HTTP request data
            response: HTTP response data
            url: The URL being analyzed
            
        Returns:
            List of pattern matches found
        """
        findings = []
        
        # Combine request and response for analysis
        data = f"{request}\n{response}"
        
        # Check each pattern type
        for vuln_type, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, data, re.IGNORECASE)
                
                if matches:
                    for match in matches:
                        findings.append({
                            "type": vuln_type,
                            "pattern": pattern,
                            "match": match,
                            "location": "request" if match in request else "response"
                        })
        
        # URL-specific patterns
        url_patterns = {
            "open_redirect": [r"(redirect|return|redir)=https?%3A%2F%2F"],
            "ssrf": [r"(url|endpoint|site|path)=https?%3A%2F%2F"],
            "idor": [r"(id|user_id|account)=[0-9]+"]
        }
        
        for vuln_type, patterns in url_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, url, re.IGNORECASE)
                
                if matches:
                    for match in matches:
                        findings.append({
                            "type": vuln_type,
                            "pattern": pattern,
                            "match": match,
                            "location": "url"
                        })
        
        return findings
    
    def _determine_severity(self, vuln_type: str) -> str:
        """
        Determine the severity of a vulnerability based on its type.
        
        Args:
            vuln_type: The type of vulnerability
            
        Returns:
            Severity level (high, medium, low, info)
        """
        severity_map = {
            "sql_injection": "high",
            "xss": "high",
            "path_traversal": "high",
            "open_redirect": "medium",
            "ssrf": "high",
            "idor": "medium",
            "sensitive_data": "medium"
        }
        
        return severity_map.get(vuln_type, "low")