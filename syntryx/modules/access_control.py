from rich.console import Console
from syntryx.core.reporter import Reporter
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re

console = Console()

async def run(requester, urls: list, reporter: Reporter):
    console.print("\n[bold blue]Running Access Control checks...[/bold blue]")

    for item in urls:
        url = item["url"]
        parsed = urlparse(url)
        query = parse_qs(parsed.query)

        # 1. Basic IDOR detection (numeric IDs)
        if query:
            for param, values in query.items():
                value = values[0] if values else ""
                if value.isdigit():
                    # Try changing the ID
                    test_ids = [str(int(value) + 1), str(int(value) - 1), "1", "0", "99999"]
                    for test_id in test_ids:
                        new_query = query.copy()
                        new_query[param] = [test_id]
                        new_query_string = urlencode(new_query, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query_string))

                        response = await requester.get(test_url)
                        if response and response.status_code == 200:
                            # Very naive check - in real life we compare content similarity
                            if len(response.text) > 500:  # page has real content
                                reporter.add_finding(
                                    module="Access Control",
                                    title="Possible Insecure Direct Object Reference (IDOR)",
                                    severity="high",
                                    url=test_url,
                                    description=f"Parameter '{param}' accepts different IDs and returns content.",
                                    evidence=f"Original value: {value} → Tested: {test_id}"
                                )
                                break

        # 2. Forced browsing / sensitive path check
        sensitive_paths = [
            "/admin", "/administrator", "/dashboard", "/panel",
            "/user", "/profile", "/account", "/settings",
            "/config", "/backup", "/api", "/private"
        ]

        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in sensitive_paths:
            test_url = base + path
            response = await requester.get(test_url)
            if response and response.status_code == 200:
                reporter.add_finding(
                    module="Access Control",
                    title="Possibly Accessible Sensitive Path",
                    severity="medium",
                    url=test_url,
                    description="A potentially sensitive path returned HTTP 200.",
                    evidence=f"Path: {path} → Status: {response.status_code}"
                )

    console.print("[green]Access Control checks completed.[/green]")
