# Bug Bounty Hunter

A comprehensive web application security testing tool using OWASP ZAP for vulnerability scanning.

## Features

- Automated vulnerability scanning with OWASP ZAP
- Detailed HTML report generation
- AI-powered vulnerability analysis

## Setup

1. Clone this repository
2. Install dependencies: `pip install -r requirements.txt`
3. Configure targets in `config/targets.yaml`
4. Configure OWASP ZAP settings in `config/zap_config.yaml`

## Usage

Run the main script:

```bash
python main.py
```

Reports will be generated in the `reports` directory and can be viewed using the Python HTTP server.

## Viewing Reports

1. Start the local server:
```bash
python -m http.server 8000 --directory reports
```
2. Open `http://localhost:8000` in your browser

## Project Structure

```
.
├── analyzers/        # Vulnerability analysis modules
├── config/           # Configuration files
├── data/             # Scan data storage
├── reporters/        # Report generation modules
├── scanners/         # Vulnerability scanning modules
├── utils/            # Utility functions
├── main.py           # Main entry point
├── README.md         # This file
└── requirements.txt  # Python dependencies
```