# Syntryx

**Syntryx** is a modular web application vulnerability scanner focused on the **OWASP Top 10 (2025)**.

It helps you quickly identify common security issues in web applications and generates clean HTML and JSON reports.

## Features

- Security Misconfiguration
- Cryptographic Failures
- Injection (XSS + SQL Injection)
- CSRF Detection
- SSRF Detection
- Access Control Issues (IDOR + Forced Browsing)
- Authentication Checks
- Business Logic Flaws
- Insecure Design Indicators

## Installation

```bash
git clone https://github.com/Tende123/Syntryx.git
cd Syntryx

python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -e .
playwright install chromium

## Usage

```Bash
syntryx https://example.com

After the scan, reports will be saved in the results/ folder:

syntryx_report_XXXX.html → Visual report
syntryx_report_XXXX.json → Machine-readable report

Open the HTML report with:

```Bash
xdg-open results/syntryx_report_*.html
# or
firefox results/syntryx_report_*.html

## Configuration

You can enable or disable modules inside the config.yaml file.

##Disclaimer

Only scan websites that you own or have explicit permission to test.
Unauthorized scanning is illegal.
