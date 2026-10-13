from rich.console import Console
from syntryx.core.reporter import Reporter
from urllib.parse import urlparse

console = Console()

async def run(requester, urls: list, reporter: Reporter):
    console.print("\n[bold blue]Running Cryptographic Failures checks...[/bold blue]")

    for item in urls:
        url = item["url"]
        parsed = urlparse(url)

        # 1. HTTP instead of HTTPS
        if parsed.scheme == "http":
            reporter.add_finding(
                module="Cryptographic Failures",
                title="Site is using HTTP (not HTTPS)",
                severity="high",
                url=url,
                description="The page is served over unencrypted HTTP. Sensitive data can be intercepted.",
                evidence="Scheme is http://"
            )
            continue

        response = await requester.get(url)
        if not response:
            continue

        # 2. Mixed Content (very basic check)
        if "http://" in response.text and url.startswith("https"):
            reporter.add_finding(
                module="Cryptographic Failures",
                title="Possible Mixed Content",
                severity="medium",
                url=url,
                description="HTTPS page contains references to HTTP resources (mixed content).",
                evidence="Found 'http://' inside an HTTPS response body."
            )

        # 3. Missing HSTS (already partially covered in misconfig, but we reinforce it here)
        headers = {k.lower(): v for k, v in response.headers.items()}
        if "strict-transport-security" not in headers:
            reporter.add_finding(
                module="Cryptographic Failures",
                title="Missing HSTS Header",
                severity="high",
                url=url,
                description="Strict-Transport-Security header is missing. Browsers are not forced to use HTTPS.",
                evidence="No Strict-Transport-Security header found."
            )

    console.print("[green]Cryptographic Failures checks completed.[/green]")
