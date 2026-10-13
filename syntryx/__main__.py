import asyncio
import yaml
from rich.console import Console
from rich.panel import Panel
import typer

from syntryx.core.requester import Requester
from syntryx.core.session import SessionManager
from syntryx.core.crawler import Crawler
from syntryx.core.reporter import Reporter

from syntryx.modules import (
    misconfiguration,
    crypto,
    injection,
    csrf,
    ssrf,
    access_control,
    authentication,
    business_logic,
    insecure_design
)

app = typer.Typer(help="Syntryx - OWASP Top 10 Vulnerability Scanner")
console = Console()

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

@app.command()
def scan(target: str = typer.Argument(..., help="Target URL (e.g. https://example.com)")):
    """Run a Syntryx security scan against a target."""
    
    BANNER = r"""
   _____             _                 
  / ____|           | |                
 | (___  _   _ _ __ | |_ _ __ _   ___  _
  \___ \| | | | '_ \| __| '__| | | \ \/ /
  ____) | |_| | | | | |_| |  | |_| |>  < 
 |_____/ \__, |_| |_|\__|_|   \__, /_/\_\
          __/ |                __/ |     
         |___/                |___/      
              v0.1.0  •  Web Vulnerability Scanner
"""
    console.print(BANNER)

    config = load_config()
    console.print(Panel.fit(
        f"[bold cyan]Syntryx v{config['scanner']['version']}[/bold cyan]\nTarget: {target}",
        title="Starting Scan"
    ))

    async def run():
        requester = Requester(
            timeout=config["scanner"]["timeout"],
            user_agent=config["scanner"]["user_agent"]
        )
        session = SessionManager()
        reporter = Reporter(output_folder=config["output"]["folder"])

        crawler = Crawler(
            requester=requester,
            session=session,
            max_depth=config["scanner"]["max_depth"],
            max_urls=config["scanner"]["max_urls"]
        )
        urls, forms = await crawler.crawl(target)

        # Modules
        if config["modules"].get("misconfiguration", True):
            await misconfiguration.run(requester, urls, reporter)

        if config["modules"].get("crypto", True):
            await crypto.run(requester, urls, reporter)

        if config["modules"].get("injection", True):
            await injection.run(requester, urls, reporter)

        if config["modules"].get("csrf", True):
            await csrf.run(requester, urls, forms, reporter)

        if config["modules"].get("ssrf", True):
            await ssrf.run(requester, urls, reporter)

        if config["modules"].get("access_control", True):
            await access_control.run(requester, urls, reporter)

        if config["modules"].get("authentication", True):
            await authentication.run(requester, urls, forms, reporter)

        if config["modules"].get("business_logic", True):
            await business_logic.run(requester, urls, forms, reporter)
            
        if config["modules"].get("insecure_design", True):
            await insecure_design.run(requester, urls, forms, reporter)

        report_path = reporter.generate_report(target, urls)

        await requester.close()
        console.print(f"\n[bold green]Scan finished![/bold green]")
        console.print(f"Report saved to: [cyan]{report_path}[/cyan]")

    asyncio.run(run())

if __name__ == "__main__":
    app()
