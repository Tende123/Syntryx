from rich.console import Console
from syntryx.core.reporter import Reporter
from bs4 import BeautifulSoup

console = Console()

async def run(requester, urls: list, forms: list, reporter: Reporter):
    console.print("\n[bold blue]Running CSRF checks...[/bold blue]")

    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = form.get("inputs", [])

        # We only care about state-changing forms
        if method != "post":
            continue

        has_token = False
        token_names = ["csrf", "csrf_token", "csrftoken", "_token", "authenticity_token", "nonce", "xsrf"]

        for inp in inputs:
            name = (inp.get("name") or "").lower()
            if any(t in name for t in token_names):
                has_token = True
                break

        if not has_token:
            reporter.add_finding(
                module="CSRF",
                title="Possible Missing CSRF Protection",
                severity="medium",
                url=action or "unknown",
                description="A POST form was found without a clear CSRF token field.",
                evidence=f"Form method: POST\nInputs: {[i.get('name') for i in inputs]}"
            )

    console.print("[green]CSRF checks completed.[/green]")
