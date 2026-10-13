import asyncio
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from rich.console import Console
from syntryx.core.requester import Requester
from syntryx.core.session import SessionManager
console = Console()

class Crawler:
    def __init__(self, requester: Requester, session: SessionManager, max_depth: int = 3, max_urls: int = 150):
        self.requester = requester
        self.session = session
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.visited = set()
        self.to_visit = []
        self.found_urls = []
        self.forms = []

    def is_same_domain(self, base_url: str, new_url: str) -> bool:
        return urlparse(base_url).netloc == urlparse(new_url).netloc

    async def crawl(self, start_url: str):
        console.print(f"[bold cyan]Starting crawl on:[/bold cyan] {start_url}")
        self.to_visit.append((start_url, 0))

        while self.to_visit and len(self.visited) < self.max_urls:
            current_url, depth = self.to_visit.pop(0)

            if current_url in self.visited or depth > self.max_depth:
                continue

            self.visited.add(current_url)
            console.print(f"[green]Crawling:[/green] {current_url} (depth {depth})")

            response = await self.requester.get(current_url)
            if not response or response.status_code >= 400:
                continue

            self.found_urls.append({
                "url": current_url,
                "status": response.status_code,
                "content_type": response.headers.get("content-type", ""),
                "length": len(response.text)
            })

            # Update cookies if any
            self.session.set_cookies(response.cookies)

            soup = BeautifulSoup(response.text, "html.parser")

            # Collect links
            for link in soup.find_all("a", href=True):
                href = link["href"]
                full_url = urljoin(current_url, href)
                if self.is_same_domain(start_url, full_url) and full_url not in self.visited:
                    self.to_visit.append((full_url, depth + 1))

            # Collect forms
            for form in soup.find_all("form"):
                form_data = {
                    "action": urljoin(current_url, form.get("action", "")),
                    "method": form.get("method", "get").lower(),
                    "inputs": []
                }
                for inp in form.find_all(["input", "textarea", "select"]):
                    form_data["inputs"].append({
                        "name": inp.get("name"),
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", "")
                    })
                self.forms.append(form_data)

            await asyncio.sleep(0.3)  # small polite delay

        console.print(f"[bold green]Crawl finished.[/bold green] Found {len(self.found_urls)} URLs and {len(self.forms)} forms.")
        return self.found_urls, self.forms
