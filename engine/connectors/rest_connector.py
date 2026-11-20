from typing import Dict, Any, Optional
import json
import urllib.parse
import ipaddress
import re
from .base import BaseConnector

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

class RESTConnector(BaseConnector):
    def __init__(self, host: str, port: int = 443, use_https: bool = True, verify_ssl: bool = True, timeout: int = 10):
        if not use_https or not verify_ssl:
            raise ValueError("Live REST connections require HTTPS with certificate verification enabled")
        if not host or any(ch in host for ch in ("/", "\\", "@", "?", "#", "\r", "\n", " ")):
            raise ValueError("REST host must be a hostname or IP address, not a URL")
        raw_host = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        try:
            ipaddress.ip_address(raw_host)
        except ValueError:
            if not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?", raw_host):
                raise ValueError("REST host is not a valid hostname or IP address")
        if not 1 <= int(port) <= 65535:
            raise ValueError("REST port must be in range 1..65535")
        timeout = max(1, min(int(timeout), 30))
        super().__init__(host, port, timeout)
        self.use_https = True
        self.verify_ssl = True
        self.session: Optional[Any] = None
        host_for_url = f"[{host}]" if ":" in host and not host.startswith("[") else host
        self.base_url = f"https://{host_for_url}:{port}"
        self.headers: Dict[str, str] = {"Content-Type": "application/json"}
        self.allow_write = False

    def connect(self, credentials: Dict[str, Any]) -> bool:
        if not REQUESTS_AVAILABLE:
            raise RuntimeError("requests library is required for REST API connections.")
        
        self.session = requests.Session()
        self.session.verify = self.verify_ssl

        # Support Bearer Token, Basic Auth, or API Key
        if "token" in credentials:
            self.headers["Authorization"] = f"Bearer {credentials['token']}"
        elif "username" in credentials and "password" in credentials:
            self.session.auth = (credentials["username"], credentials["password"])
        elif "api_key" in credentials:
            header_name = credentials.get("api_key_header", "X-API-Key")
            if not isinstance(header_name, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,64}", header_name) or header_name.lower() in {"authorization", "host", "content-length"}:
                raise ValueError("Unsafe API-key header name in trusted credential configuration")
            self.headers[header_name] = credentials["api_key"]

        self.session.headers.update(self.headers)
        self.is_connected = True
        return True

    def disconnect(self):
        if self.session:
            self.session.close()
            self.session = None
        self.is_connected = False

    def request(self, method: str, endpoint: str, data: Optional[Any] = None, params: Optional[Dict[str, Any]] = None) -> Any:
        if not self.is_connected or not self.session:
            raise RuntimeError("REST Connector is not connected.")
        method = method.upper()
        if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("Unsupported REST HTTP method")
        if method not in {"GET", "HEAD"} and not self.allow_write:
            raise PermissionError("REST connector is read-only; mutation requires verified authorization")
        endpoint = str(endpoint).strip()
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme or parsed.netloc or endpoint.startswith("//"):
            raise ValueError("REST endpoint must be a relative path on the canonical host")
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        decoded_path = urllib.parse.unquote(parsed.path)
        if any(segment == ".." for segment in decoded_path.split("/")):
            raise ValueError("REST endpoint path traversal is not allowed")
        url = urllib.parse.urljoin(self.base_url + "/", endpoint.lstrip("/"))
        if urllib.parse.urlsplit(url).netloc != urllib.parse.urlsplit(self.base_url).netloc:
            raise ValueError("REST endpoint escaped canonical host")
        resp = self.session.request(
            method=method,
            url=url,
            json=data if isinstance(data, (dict, list)) else None,
            data=data if isinstance(data, str) else None,
            params=params,
            timeout=self.timeout
        )
        resp.raise_for_status()
        try:
            return resp.json()
        except Exception:
            return resp.text

    def execute_command(self, command: str) -> str:
        # Interpret command as "GET /api/v1/resource" or "POST /api/v1/..."
        parts = command.strip().split(" ", 1)
        method = "GET"
        endpoint = command
        if len(parts) == 2 and parts[0].upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
            method = parts[0].upper()
            endpoint = parts[1]
        res = self.request(method, endpoint)
        return json.dumps(res, indent=2) if isinstance(res, (dict, list)) else str(res)

    def ping_check(self) -> bool:
        return self.is_connected
