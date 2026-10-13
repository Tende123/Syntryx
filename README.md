# Syntryx

**Syntryx** is a modular web application vulnerability scanner focused on the **OWASP Top 10 (2025)**.

It helps you quickly identify common security issues in web applications and generates clean HTML and JSON reports.

---

## About

Syntryx is designed to be simple, modular, and practical.  
It crawls a target website and runs multiple security checks based on the OWASP Top 10.

**Currently supports:**

- Security Misconfiguration
- Cryptographic Failures
- Injection (XSS + SQL Injection)
- CSRF Detection
- SSRF Detection
- Access Control Issues
- Authentication Checks
- Business Logic Flaws
- Insecure Design Indicators

---

## Installation

```bash
git clone https://github.com/Tende123/Syntryx.git
cd Syntryx

python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -e .
playwright install chromium

---

## Usage

```bash
syntryx https://example.com

After the scan finishes, reports will be saved in the results/ folder:

HTML Report → Visual report
JSON Report → Machine-readable report

To open the HTML report:

```bash
xdg-open results/syntryx_report_*.html
# or
firefox results/syntryx_report_*.html

## Configuration

You can enable/disable modules in config.yaml.

---

##Disclaimer

Only scan websites you own or have explicit permission to test.
Unauthorized scanning is illegal.
