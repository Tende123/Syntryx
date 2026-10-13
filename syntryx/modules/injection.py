import re
from rich.console import Console
from syntryx.core.reporter import Reporter
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

console = Console()

# Simple XSS payloads
XSS_PAYLOADS = [
    "<script>alert(1337)</script>",
    "\"><script>alert(1337)</script>",
    "'\"><img src=x onerror=alert(1337)>",
    "<svg/onload=alert(1337)>",
]

# Basic SQLi payloads
SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "1' ORDER BY 1--",
]

async def test_xss(requester, url: str, reporter: Reporter):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    if not query:
        return

    for param in query:
        for payload in XSS_PAYLOADS:
            new_query = query.copy()
            new_query[param] = [payload]
            new_query_string = urlencode(new_query, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query_string))

            response = await requester.get(test_url)
            if response and payload in response.text:
                reporter.add_finding(
                    module="Injection",
                    title="Possible Reflected XSS",
                    severity="high",
                    url=test_url,
                    description=f"Payload was reflected in the response. Parameter: {param}",
                    evidence=f"Payload: {payload}"
                )
                break  # one finding per parameter is enough for now

async def test_sqli(requester, url: str, reporter: Reporter):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    if not query:
        return

    error_patterns = [
        r"sql syntax",
        r"mysql_fetch",
        r"ORA-\d+",
        r"PostgreSQL.*ERROR",
        r"Microsoft OLE DB",
        r"ODBC Driver",
        r"SQLite/JDBCDriver",
        r"Warning.*mysql_",
        r"unclosed quotation mark",
    ]

    for param in query:
        for payload in SQLI_PAYLOADS:
            new_query = query.copy()
            new_query[param] = [payload]
            new_query_string = urlencode(new_query, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query_string))

            response = await requester.get(test_url)
            if not response:
                continue

            body = response.text.lower()
            for pattern in error_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    reporter.add_finding(
                        module="Injection",
                        title="Possible SQL Injection",
                        severity="high",
                        url=test_url,
                        description=f"SQL error pattern detected. Parameter: {param}",
                        evidence=f"Payload: {payload}\nPattern matched: {pattern}"
                    )
                    return  # stop after first strong indication

async def run(requester, urls: list, reporter: Reporter):
    console.print("\n[bold blue]Running Injection checks (XSS + SQLi)...[/bold blue]")

    for item in urls:
        url = item["url"]
        # Only test URLs that have parameters
        if "?" in url:
            await test_xss(requester, url, reporter)
            await test_sqli(requester, url, reporter)

    console.print("[green]Injection checks completed.[/green]")
