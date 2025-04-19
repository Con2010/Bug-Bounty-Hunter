#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import yaml
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f"bug_bounty_hunter_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    ]
)
logger = logging.getLogger("bug_bounty_hunter")

try:
    from scanners.zap_scanner import ZAPScanner
    from analyzers.llm_analyzer import LLMAnalyzer
    from analyzers.pattern_analyzer import PatternAnalyzer
    from reporters.report_generator import ReportGenerator
    from utils.file_utils import load_config
except ImportError as e:
    logger.error(f"Failed to import required modules: {e}")
    logger.error("Please ensure you've installed all dependencies: pip install -r requirements.txt")
    sys.exit(1)


def parse_arguments():
    parser = argparse.ArgumentParser(description="AI-Powered Bug Bounty Hunter")
    parser.add_argument(
        "--target", "-t",
        help="Target URL to scan. Overrides targets in config file."
    )
    parser.add_argument(
        "--config", "-c",
        default="config/targets.yaml",
        help="Path to configuration file (default: config/targets.yaml)"
    )
    parser.add_argument(
        "--output", "-o",
        default=f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
        help="Path to output report file"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--scan-type",
        choices=["full", "quick", "passive"],
        default="full",
        help="Type of scan to perform"
    )
    parser.add_argument(
        "--scanner",
        choices=["zap"],
        default="zap",
        help="Scanner to use"
    )
    return parser.parse_args()


def setup_environment(args):
    os.makedirs("reports", exist_ok=True)
    os.makedirs("data", exist_ok=True)

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    output_path = Path(args.output)
    os.makedirs(output_path.parent, exist_ok=True)

    return args


def load_targets(args):
    if args.target:
        logger.info(f"Using target from command line: {args.target}")
        return [args.target]

    try:
        config = load_config(args.config)
        targets = config.get("targets", [])
        if not targets:
            logger.error(f"No targets found in configuration file: {args.config}")
            sys.exit(1)
        logger.info(f"Loaded {len(targets)} targets from configuration")
        return targets
    except Exception as e:
        logger.error(f"Error loading targets: {e}")
        sys.exit(1)


def run_scanners(targets, args):
    
    scan_results = []

    if args.scanner == "zap":
        try:
            logger.info("Initializing OWASP ZAP scanner...")
            zap_config = load_config("config/zap_config.yaml")
            zap_scanner = ZAPScanner(zap_config)

            for target in targets:
                logger.info(f"Scanning {target} with OWASP ZAP...")
                result = zap_scanner.scan(target, scan_type=args.scan_type)
                scan_results.append(result)
                logger.info(f"OWASP ZAP scan completed for {target}")
        except Exception as e:
            logger.error(f"Error during OWASP ZAP scanning: {e}")

    return scan_results


def analyze_results(scan_results, args):
    
    logger.info("Analyzing scan results...")

    try:
        llm_config = load_config("config/llm_config.yaml")
        llm_analyzer = LLMAnalyzer(llm_config)

        pattern_analyzer = PatternAnalyzer()

        analysis_results = []
        for result in scan_results:
            pattern_findings = pattern_analyzer.analyze(result)

            llm_findings = llm_analyzer.analyze(result)

            combined_findings = pattern_findings + llm_findings

            final_findings = llm_analyzer.deduplicate_and_prioritize(combined_findings)
            analysis_results.append(final_findings)

        logger.info(f"Analysis completed with {sum(len(r) for r in analysis_results)} total findings")
        return analysis_results

    except Exception as e:
        logger.error(f"Error during result analysis: {e}")
        return []


def generate_report(scan_results, analysis_results, args):
    
    logger.info(f"Generating report at {args.output}...")

    try:
        report_generator = ReportGenerator()
        report_generator.generate(
            scan_results=scan_results,
            analysis_results=analysis_results,
            output_path=args.output,
            scan_type=args.scan_type,
            timestamp=datetime.now()
        )
        logger.info(f"Report successfully generated at {args.output}")
        return True
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return False


def main():
    
    logger.info("Starting AI-Powered Bug Bounty Hunter")

    args = parse_arguments()
    args = setup_environment(args)

    targets = load_targets(args)
    logger.info(f"Preparing to scan {len(targets)} targets")

    scan_results = run_scanners(targets, args)
    if not scan_results:
        logger.error("No scan results obtained. Exiting.")
        return 1
    
    # Analyze results
    analysis_results = analyze_results(scan_results, args)
    
    # Generate report
    report_success = generate_report(scan_results, analysis_results, args)
    
    if report_success:
        logger.info("Bug bounty hunting process completed successfully")
        return 0
    else:
        logger.error("Bug bounty hunting process completed with errors")
        return 1


if __name__ == "__main__":
    sys.exit(main())