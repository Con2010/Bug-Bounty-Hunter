# AI-Powered Bug Bounty Hunter Tutorial

This tutorial will guide you through setting up and using the AI-Powered Bug Bounty Hunter tool to find security vulnerabilities in web applications.

## Table of Contents

1. [Project Overview](#project-overview)
2. [Installation and Setup](#installation-and-setup)
3. [Configuration](#configuration)
   - [Target Configuration](#target-configuration)
   - [Scanner Configuration](#scanner-configuration)
   - [LLM Configuration](#llm-configuration)
4. [Running Scans](#running-scans)
5. [Understanding Reports](#understanding-reports)
6. [Customization](#customization)
7. [Troubleshooting](#troubleshooting)

## Project Overview

The AI-Powered Bug Bounty Hunter is an automated tool that combines traditional security scanning with AI-powered analysis to identify vulnerabilities in web applications. The tool integrates with:

- **OWASP ZAP**: For comprehensive web application security testing
- **Large Language Models (LLMs)**: For intelligent analysis of scan results and code snippets

The workflow consists of three main phases:
1. **Scanning**: Using ZAP to scan target websites
2. **Analysis**: Using pattern matching and LLMs to analyze scan results
3. **Reporting**: Generating comprehensive vulnerability reports

## Installation and Setup

### Prerequisites

- Python 3.8 or higher
- OWASP ZAP
- API access to an LLM (OpenAI GPT, Anthropic Claude, etc.)

### Installation Steps

1. Clone or download the repository

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Ensure OWASP ZAP is installed and running with API access enabled

## Configuration

Before running the tool, you need to configure your targets and scanners.

### Target Configuration

Edit the `config/targets.yaml` file to specify the websites or applications you want to scan:

```yaml
# Example target configuration
targets:
  - url: "https://example.com"
    name: "Example Website"
    description: "Main company website"
    scope:
      - "https://example.com/*"
      - "https://api.example.com/*"
    exclude:
      - "https://example.com/admin/*"
      - "https://example.com/login"
```

Key fields:
- `url`: The base URL of the target (required)
- `name`: A descriptive name for the target (optional)
- `description`: Additional information about the target (optional)
- `scope`: List of URL patterns to include in the scan (optional)
- `exclude`: List of URL patterns to exclude from the scan (optional)

### OWASP ZAP Configuration

Edit the `config/zap_config.yaml` file:

```yaml
# API Connection Settings
api_key: "YOUR_ZAP_API_KEY_HERE"
api_url: "http://localhost:8080"

# Scan Configuration
scan_settings:
  scan_policy: "Default Policy"
  attack_mode: "Standard"
  use_ajax_spider: true
```

To get your ZAP API key:
1. Open ZAP
2. Go to Tools > Options > API
3. Enable the API
4. Set and copy the API key

### LLM Configuration

Edit the `config/llm_config.yaml` file:

```yaml
# API Connection Settings
provider: "openai"  # Options: openai, anthropic, etc.
api_key: "YOUR_LLM_API_KEY_HERE"
model: "gpt-4"  # For OpenAI: gpt-4, gpt-3.5-turbo, etc.

# Analysis Configuration
analysis_settings:
  temperature: 0.3
  max_tokens: 2048
  include_remediation: true
```

To get your LLM API key:
- For OpenAI: Visit https://platform.openai.com/api-keys
- For Anthropic: Visit https://console.anthropic.com/

## Running Scans

Once you've configured your targets and scanners, you can run the tool using the following command:

```
python main.py
```

### Command-Line Options

The tool supports several command-line options:

- `--target, -t`: Specify a single target URL (overrides targets in config file)
- `--config, -c`: Path to configuration file (default: config/targets.yaml)
- `--output, -o`: Path to output report file
- `--verbose, -v`: Enable verbose output
- `--scan-type`: Type of scan to perform (full, quick, passive)
- `--scanner`: Scanner to use (zap)

Examples:

```
# Scan a specific target using ZAP
python main.py -t https://example.com

# Perform a quick scan using only ZAP
python main.py --scan-type quick --scanner zap

# Specify a custom output file
python main.py -o reports/custom_report.html
```

## Understanding Reports

After a scan completes, the tool generates a comprehensive report in the specified output location (default: `reports/report_YYYYMMDD_HHMMSS.html`).

The report includes:

1. **Executive Summary**: Overview of the scan and key findings
2. **Vulnerability Details**: Detailed information about each vulnerability
   - Description
   - Severity rating
   - Affected URLs/components
   - Evidence
   - Remediation steps
3. **Technical Details**: Raw scan data and analysis results

Vulnerabilities are categorized by severity:
- **Critical**: Immediate action required
- **High**: Should be fixed as soon as possible
- **Medium**: Should be addressed in the near future
- **Low**: Should be fixed when time permits
- **Informational**: No immediate action required

## Viewing the Report

To view the generated HTML report:

1. Open a terminal in the project directory
2. Run the command: `python -m http.server 8000 --directory reports`
3. Open your web browser and navigate to: `http://localhost:8000/report_YYYYMMDD_HHMMSS.html` (replace with your actual report filename)

This will launch a local web server and allow you to view the report in your browser with full functionality.

## Customization

### Focusing on Specific Vulnerabilities

You can customize the LLM analyzer to focus on specific types of vulnerabilities by editing the `focus_categories` field in `config/llm_config.yaml`:

```yaml
focus_categories:
  - "sql_injection"
  - "xss"
  - "csrf"
```

### Customizing Prompts

You can customize the prompts used by the LLM analyzer by editing the `prompts` section in `config/llm_config.yaml`:

```yaml
prompts:
  vulnerability_analysis: |
    Analyze the following scan results for security vulnerabilities.
    Focus on identifying high-risk issues and provide detailed explanations.
```

### Adding Custom Pattern Rules

The pattern analyzer uses regular expressions to identify vulnerabilities. You can add custom patterns by modifying the `PatternAnalyzer` class in `analyzers/pattern_analyzer.py`.

## Troubleshooting

### Common Issues

1. **Scanner Connection Errors**
   - Ensure ZAP is running
   - Verify API keys are correct
   - Check that the API URL is correct (default: http://localhost:8080 for ZAP)

2. **LLM API Errors**
   - Verify your API key is correct
   - Check your API usage limits
   - Ensure you have specified a valid model

3. **No Vulnerabilities Found**
   - Try increasing scan coverage or duration
   - Check that your target is within scope
   - Verify that the scanners are properly configured

### Logs

The tool generates detailed logs that can help diagnose issues. By default, logs are written to both the console and a log file named `bug_bounty_hunter_YYYYMMDD_HHMMSS.log`.

Enable verbose logging with the `-v` flag for more detailed information:

```
python main.py -v
```

---

This tutorial covers the basics of using the AI-Powered Bug Bounty Hunter tool. For more advanced usage or to contribute to the project, please refer to the project's GitHub repository.