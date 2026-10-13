from rich.console import Console
from syntryx.core.reporter import Reporter
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

console = Console()

async def run(requester, urls: list, forms: list, reporter: Reporter):
    console.print("\n[bold blue]Running Business Logic checks...[/bold blue]")

    # 1. Look for price / quantity / amount parameters (common business logic targets)
    interesting_params = ["price", "amount", "qty", "quantity", "total", "cost", "discount", "coupon"]

    for item in urls:
        url = item["url"]
        parsed = urlparse(url)
        query = parse_qs(parsed.query)

        if not query:
            continue

        for param in query:
            if any(key in param.lower() for key in interesting_params):
                original = query[param][0]

                # Test negative values and zero
                test_values = ["-1", "0", "999999", "-999"]

                for val in test_values:
                    new_query = query.copy()
                    new_query[param] = [val]
                    new_qs = urlencode(new_query, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_qs))

                    response = await requester.get(test_url)
                    if response and response.status_code == 200:
                        reporter.add_finding(
                            module="Business Logic",
                            title="Possible Business Logic Issue (Parameter Tampering)",
                            severity="medium",
                            url=test_url,
                            description=f"Parameter '{param}' accepted unusual value '{val}'. Manual review recommended.",
                            evidence=f"Original: {original} → Tested: {val}"
                        )
                        break

    # 2. Detect multi-step forms / potential workflow issues (very basic)
    for form in forms:
        inputs = form.get("inputs", [])
        input_names = [ (i.get("name") or "").lower() for i in inputs ]

        # Look for common checkout / cart related fields
        if any(x in input_names for x in ["price", "quantity", "qty", "total", "payment", "card"]):
            reporter.add_finding(
                module="Business Logic",
                title="Potential Business Logic Form Detected",
                severity="info",
                url=form.get("action", "unknown"),
                description="A form related to pricing, quantity, or payment was found. Review for logic flaws (price tampering, negative quantities, step skipping, etc.).",
                evidence=f"Inputs: {input_names}"
            )

    console.print("[green]Business Logic checks completed.[/green]")
