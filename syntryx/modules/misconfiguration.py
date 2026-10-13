from rich.console import Console
from syntryx.core.reporter import Reporter

console = Console()

# Common security headers we expect
SECURITY_HEADERS = {
    "Content-Security-Policy": "Missing Content-Security-Policy header",
    "X-Frame-Options": "Missing X-Frame-Options (Clickjacking protection)",
    "X-Content-Type-Options": "Missing X-Content-Type-Options (MIME sniffing protection)",
    "Strict-Transport-Security": "Missing Strict-Transport-Security (HSTS)",
    "Referrer-Policy": "Missing Referrer-Policy",
    "Permissions-Policy": "Missing Permissions-Policy",
    "X-XSS-Protection": "Missing X-XSS-Protection (legacy but still useful)"
}

async def run(requester, urls: list, reporter: Reporter):
    console.print("\n[bold blue]Running Security Misconfiguration checks...[/bold blue]")

    for item in urls:
        url = item["url"]
        response = await requester.get(url)
        if not response:
            continue

        headers = {k.lower(): v for k, v in response.headers.items()}

        # 1. Check missing security headers
        for header, message in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                severity = "medium"
                if header in ["Content-Security-Policy", "Strict-Transport-Security"]:
                    severity = "high"

                reporter.add_finding(
                    module="Security Misconfiguration",
                    title=message,
                    severity=severity,
                    url=url,
                    description=f"The response is missing the '{header}' security header.",
                    evidence=f"Checked headers: {list(headers.keys())}"
                )

        # 2. Server version disclosure
        server = headers.get("server", "")
        if server and any(x in server.lower() for x in ["apache", "nginx", "iis", "tomcat", "ubuntu", "debian"]):
            reporter.add_finding(
                module="Security Misconfiguration",
                title="Server Version Disclosure",
                severity="low",
                url=url,
                description="Server header reveals technology/version information.",
                evidence=f"Server: {server}"
            )

        # 3. Directory listing detection (very basic)
        if "index of /" in response.text.lower() or "directory listing" in response.text.lower():
            reporter.add_finding(
                module="Security Misconfiguration",
                title="Directory Listing Enabled",
                severity="medium",
                url=url,
                description="Possible directory listing detected on this page.",
                evidence="Found keywords related to directory listing in response body."
            )

        # 4. Insecure cookie flags (if Set-Cookie exists)
        set_cookie = response.headers.get("set-cookie", "")
        if set_cookie:
            if "httponly" not in set_cookie.lower():
                reporter.add_finding(
                    module="Security Misconfiguration",
                    title="Cookie without HttpOnly flag",
                    severity="medium",
                    url=url,
                    description="A cookie was set without the HttpOnly flag.",
                    evidence=set_cookie[:200]
                )
            if "secure" not in set_cookie.lower() and url.startswith("https"):
                reporter.add_finding(
                    module="Security Misconfiguration",
                    title="Cookie without Secure flag",
                    severity="medium",
                    url=url,
                    description="A cookie was set without the Secure flag on an HTTPS site.",
                    evidence=set_cookie[:200]
                )

    console.print("[green]Security Misconfiguration checks completed.[/green]")
