from rich.console import Console
from syntryx.core.reporter import Reporter
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

console = Console()

# Common SSRF test payloads (internal & cloud metadata)
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",          # AWS
    "http://metadata.google.internal/computeMetadata/v1/", # GCP
    "http://[::1]",
]

async def run(requester, urls: list, reporter: Reporter):
    console.print("\n[bold blue]Running SSRF checks...[/bold blue]")

    for item in urls:
        url = item["url"]
        parsed = urlparse(url)
        query = parse_qs(parsed.query)

        if not query:
            continue

        for param in query:
            original_value = query[param][0] if query[param] else ""

            # Only test parameters that look like they might accept URLs
            if not any(x in param.lower() for x in ["url", "link", "src", "href", "uri", "path", "redirect", "next", "data", "file"]):
                continue

            for payload in SSRF_PAYLOADS:
                new_query = query.copy()
                new_query[param] = [payload]
                new_query_string = urlencode(new_query, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query_string))

                response = await requester.get(test_url)
                if not response:
                    continue

                body = response.text.lower()

                # Very basic detection heuristics
                indicators = [
                    "root:x:", "ami-id", "instance-id", "computeMetadata",
                    "meta-data", "localhost", "127.0.0.1"
                ]

                for indicator in indicators:
                    if indicator in body:
                        reporter.add_finding(
                            module="SSRF",
                            title="Possible Server-Side Request Forgery (SSRF)",
                            severity="high",
                            url=test_url,
                            description=f"Parameter '{param}' appears to be vulnerable to SSRF.",
                            evidence=f"Payload: {payload}\nIndicator found: {indicator}"
                        )
                        break

    console.print("[green]SSRF checks completed.[/green]")
