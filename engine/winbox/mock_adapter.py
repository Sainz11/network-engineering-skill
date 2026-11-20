from typing import Dict, Any, List, Optional
import time

class MockWinboxAdapter:
    """
    Simulated Winbox Adapter for automated testing, development, and offline environments.
    Simulates GUI lifecycle, menu navigation, screenshot capture, and error states.
    """
    def __init__(self, winbox_path: str = "C:\\Program Files\\MikroTik\\winbox64.exe"):
        self.winbox_path = winbox_path
        self.is_running = False
        self.active_session: Optional[Dict[str, Any]] = None
        self.current_menu: Optional[str] = None
        self.captured_screenshots: List[str] = []

    def is_available(self) -> bool:
        return True

    def get_status(self) -> Dict[str, Any]:
        return {
            "installed": True,
            "executable_path": self.winbox_path,
            "running_processes": [{"process_name": "winbox64.exe", "pid": 4812}] if self.is_running else [],
            "detected_windows": [{"hwnd": 65540, "title": "RouterOS v7.15.2 (admin@10.0.0.1) - WinBox v3.40"}] if self.active_session else [],
            "active_session": self.active_session
        }

    def launch(self) -> Dict[str, Any]:
        self.is_running = True
        return {
            "status": "LAUNCHED",
            "pid": 4812,
            "executable": self.winbox_path
        }

    def open_session(self, target: str, username: str, password: Optional[str] = None, port: int = 8291) -> Dict[str, Any]:
        if username == "invalid_user":
            raise PermissionError("Winbox connection failed: invalid username or password (mock).")
        self.is_running = True
        self.active_session = {
            "target": target,
            "port": port,
            "username": username,
            "password": "***REDACTED***",
            "pid": 4812,
            "connected_at": time.time()
        }
        return {
            "status": "SESSION_OPENED",
            "target": target,
            "username": username,
            "pid": 4812
        }

    def navigate_menu(self, menu_path: str) -> Dict[str, Any]:
        supported_menus = [
            "system -> resources",
            "system -> identity",
            "system -> routerboard",
            "interfaces",
            "ip -> addresses",
            "ip -> routes",
            "ip -> dhcp server",
            "ip -> firewall",
            "ip -> dns",
            "ppp",
            "bridge",
            "wireless / wifi",
            "queues",
            "log"
        ]
        norm = menu_path.strip().lower()
        if not any(norm in m or m in norm for m in supported_menus):
            return {
                "success": False,
                "menu": menu_path,
                "error": f"Menu '{menu_path}' not recognized in supported Winbox menu map.",
                "supported_menus": supported_menus
            }
        self.current_menu = menu_path
        return {
            "success": True,
            "menu": menu_path,
            "status": "NAVIGATED",
            "active_windows": 1,
            "evidence_note": f"Navigated to {menu_path} window in Winbox GUI."
        }

    def capture_evidence(self, output_path: str) -> Dict[str, Any]:
        self.captured_screenshots.append(output_path)
        return {
            "success": True,
            "output_path": output_path,
            "message": "Mock screenshot captured and verified."
        }

    def close_session(self) -> Dict[str, Any]:
        self.is_running = False
        self.active_session = None
        self.current_menu = None
        return {"status": "CLOSED"}
