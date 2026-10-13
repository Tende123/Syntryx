from rich.console import Console
from syntryx.core.reporter import Reporter
from bs4 import BeautifulSoup
from urllib.parse import urljoin

console = Console()

async def run(requester, urls: list, forms: list, reporter: Reporter):
    console.print("\n[bold blue]Running Authentication checks...[/bold blue]")

    login_forms = []

    # 1. Detect possible login forms
    for form in forms:
        inputs = form.get("inputs", [])
        input_names = [ (i.get("name") or "").lower() for i in inputs ]
        input_types = [ (i.get("type") or "").lower() for i in inputs ]

        has_password = "password" in input_types or any("pass" in n for n in input_names)
        has_user = any(n in input_names for n in ["username", "user", "email", "login", "phone"])

        if has_password and (has_user or len(inputs) >= 2):
            login_forms.append(form)

    if not login_forms:
        console.print("[yellow]No login forms detected.[/yellow]")
    else:
        console.print(f"[green]Found {len(login_forms)} possible login form(s)[/green]")

    for form in login_forms:
        action = form.get("action") or "unknown"
        method = form.get("method", "get").lower()
        inputs = form.get("inputs", [])

        # Check if form uses GET (bad for login)
        if method == "get":
            reporter.add_finding(
                module="Authentication",
                title="Login form uses GET method",
                severity="medium",
                url=action,
                description="Login forms should use POST. Using GET can leak credentials in logs and browser history.",
                evidence=f"Form method: {method}"
            )

        # Check for autocomplete on password field
        for inp in inputs:
            if (inp.get("type") or "").lower() == "password":
                # We can't perfectly detect autocomplete from HTML alone in all cases,
                # but we can note the presence of password field
                pass

        # Very basic weak password policy hint (if we later add login testing)
        reporter.add_finding(
            module="Authentication",
            title="Login form detected",
            severity="info",
            url=action,
            description="A potential login form was found. Manual testing recommended for weak password policy, rate limiting, and account lockout.",
            evidence=f"Method: {method} | Inputs: {[i.get('name') for i in inputs]}"
        )

    # 2. Check for common sensitive authentication-related paths
    sensitive_paths = [
        "/login", "/signin", "/sign-in", "/log-in",
        "/register", "/signup", "/sign-up",
        "/reset", "/forgot", "/password",
        "/admin/login", "/user/login", "/account/login"
    ]

    # Get unique base URLs from discovered pages
    bases = set()
    for item in urls:
        from urllib.parse import urlparse
        parsed = urlparse(item["url"])
        bases.add(f"{parsed.scheme}://{parsed.netloc}")

    for base in bases:
        for path in sensitive_paths:
            test_url = urljoin(base, path)
            response = await requester.get(test_url)
            if response and response.status_code == 200:
                reporter.add_finding(
                    module="Authentication",
                    title="Authentication-related page accessible",
                    severity="info",
                    url=test_url,
                    description="An authentication-related endpoint returned HTTP 200.",
                    evidence=f"Path: {path}"
                )

    console.print("[green]Authentication checks completed.[/green]")
