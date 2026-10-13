import httpx
from rich.console import Console

console = Console()

class Requester:
    def __init__(self, timeout: int = 15, user_agent: str = "Syntryx/0.1"):
        self.timeout = timeout
        self.headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        }
        self.client = httpx.AsyncClient(
            timeout=timeout,
            headers=self.headers,
            follow_redirects=True,
            verify=False  # for scanning purposes
        )

    async def get(self, url: str, **kwargs):
        try:
            response = await self.client.get(url, **kwargs)
            return response
        except Exception as e:
            console.print(f"[red]Request failed:[/red] {url} → {e}")
            return None

    async def post(self, url: str, data=None, json=None, **kwargs):
        try:
            response = await self.client.post(url, data=data, json=json, **kwargs)
            return response
        except Exception as e:
            console.print(f"[red]POST failed:[/red] {url} → {e}")
            return None

    async def close(self):
        await self.client.aclose()
