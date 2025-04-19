#!/usr/bin/env python3

import logging
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger("bug_bounty_hunter.reporters.report")

class ReportGenerator:
    def __init__(self):
        logger.info("Initializing Report Generator")

    def generate(self, scan_results: List[Dict[str, Any]], analysis_results: List[Dict[str, Any]], 
                output_path: str, scan_type: str, timestamp: datetime) -> bool:
        logger.info(f"Generating report at {output_path}")
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            extension = os.path.splitext(output_path)[1].lower()
            if extension == ".html":
                return self._generate_html_report(scan_results, analysis_results, output_path, scan_type, timestamp)
            elif extension == ".pdf":
                return self._generate_pdf_report(scan_results, analysis_results, output_path, scan_type, timestamp)
            elif extension == ".json":
                return self._generate_json_report(scan_results, analysis_results, output_path, scan_type, timestamp)
            else:
                logger.warning(f"Unsupported report format: {extension}. Defaulting to HTML.")
                return self._generate_html_report(scan_results, analysis_results, output_path, scan_type, timestamp)
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return False

    def _generate_html_report(self, scan_results: List[Dict[str, Any]], analysis_results: List[Dict[str, Any]], 
                             output_path: str, scan_type: str, timestamp: datetime) -> bool:
        logger.info("Generating HTML report")
        try:
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Bug Bounty Hunter Report - {timestamp.strftime('%Y-%m-%d %H:%M:%S')}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1, h2, h3 {{ color: #2c3e50; }}
                    .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; }}
                    .vulnerability {{ margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                    .high {{ border-left: 5px solid #e74c3c; }}
                    .medium {{ border-left: 5px solid #f39c12; }}
                    .low {{ border-left: 5px solid #3498db; }}
                    .info {{ border-left: 5px solid #2ecc71; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                </style>
            </head>
            <body>
                <h1>Bug Bounty Hunter Report</h1>
                <div class="summary">
                    <h2>Scan Summary</h2>
                    <p><strong>Scan Type:</strong> {scan_type}</p>
                    <p><strong>Timestamp:</strong> {timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p><strong>Targets Scanned:</strong> {len(scan_results)}</p>
                    <p><strong>Total Vulnerabilities Found:</strong> {sum(len(result) for result in analysis_results)}</p>
                </div>
            """
            html_content += "<h2>Vulnerabilities</h2>"
            if not analysis_results or not isinstance(analysis_results, list):
                html_content += "<p>No vulnerabilities found</p>"
            else:
                all_findings = []
                for result_set in analysis_results:
                    if isinstance(result_set, list):
                        all_findings.extend(result_set)
                if not all_findings:
                    html_content += "<p>No vulnerabilities found</p>"
                else:
                    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                    all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5))
                    for finding in all_findings:
                        if not isinstance(finding, dict):
                            continue
                        severity = finding.get("severity", "info").lower()
                        html_content += f"""
                        <div class="vulnerability {severity}">
                            <h3>{finding.get('name', 'Unknown Vulnerability')}</h3>
                            <p><strong>Severity:</strong> {severity.title()}</p>
                            <p><strong>Confidence:</strong> {finding.get('confidence', 'Unknown').title()}</p>
                            <p><strong>URL:</strong> {finding.get('url', 'N/A')}</p>
                            <p><strong>Description:</strong> {finding.get('description', 'No description provided')}</p>
                        """
                        if "llm_analysis" in finding and isinstance(finding["llm_analysis"], dict):
                            llm_analysis = finding["llm_analysis"]
                            html_content += f"""
                            <h4>AI Analysis</h4>
                            <p><strong>Risk Assessment:</strong> {llm_analysis.get('risk_assessment', 'N/A')}</p>
                            <p><strong>Exploit Potential:</strong> {llm_analysis.get('exploit_potential', 'N/A')}</p>
                            <h4>Remediation Steps</h4>
                            <ul>
                            """
                            if isinstance(llm_analysis.get("remediation_steps"), list):
                                for step in llm_analysis["remediation_steps"]:
                                    if isinstance(step, str):
                                        html_content += f"<li>{step}</li>"
                            html_content += "</ul>"
                        html_content += f"""
                        <h4>Technical Details</h4>
                        <div class="request-response">
                            <h5>Request</h5>
                            <pre>{finding.get('request', 'N/A')}</pre>
                            <h5>Response</h5>
                            <pre>{finding.get('response', 'N/A')}</pre>
                        </div>
                        </div>
                        """
            html_content += "</body></html>"
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"HTML report successfully generated at {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            return False

    def _generate_pdf_report(self, scan_results: List[Dict[str, Any]], analysis_results: List[Dict[str, Any]], 
                            output_path: str, scan_type: str, timestamp: datetime) -> bool:
        pass

    def _generate_json_report(self, scan_results: List[Dict[str, Any]], analysis_results: List[Dict[str, Any]], 
                             output_path: str, scan_type: str, timestamp: datetime) -> bool:
        pass