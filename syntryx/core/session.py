from typing import Optional, Dict
import httpx

class SessionManager:
    def __init__(self):
        self.cookies: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
        self.authenticated = False
        self.login_url: Optional[str] = None

    def set_cookies(self, cookies: httpx.Cookies):
        for name, value in cookies.items():
            self.cookies[name] = value

    def get_cookie_header(self) -> str:
        return "; ".join([f"{k}={v}" for k, v in self.cookies.items()])

    def mark_authenticated(self, login_url: str = None):
        self.authenticated = True
        self.login_url = login_url
