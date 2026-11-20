import os
import subprocess
import time
from typing import Optional, Dict, Any, List
from .locator import WinboxLocator
from .ui_automation import WindowsUIAWrapper
from scripts.redact import redact_sensitive_data
from ..auth_provider import verify_issued_context
from ..inventory.inventory_manager import DeviceInventoryManager

class WinboxAdapter:
    """
    MikroTik Winbox Desktop GUI Automation Adapter.
    Security Hardened:
    - Never exposes passwords in command-line arguments (uses pre-saved sessions or safe GUI injection).
    - Session timeout handling.
    - Error dialog detection and classification.
    - Clean process termination.
    """
    def __init__(self, winbox_path: Optional[str] = None, connection_timeout: int = 15, max_retries: int = 2, user_ctx=None, inventory_manager=None, credential_provider=None, operations_engine=None):
        self.winbox_path = winbox_path or WinboxLocator.find_executable()
        self.ui = WindowsUIAWrapper()
        self.current_process = None
        self.active_session: Optional[Dict[str, Any]] = None
        self.connection_timeout = max(1, min(int(connection_timeout), 60))
        self.max_retries = max(0, min(int(max_retries), 3))
        self.user_ctx = user_ctx
        self.operations_engine = operations_engine
        if operations_engine is not None and inventory_manager is not None and inventory_manager is not operations_engine.inventory_manager:
            raise ValueError("Winbox inventory must be the canonical inventory owned by OperationsEngine.")
        self.inventory_manager = operations_engine.inventory_manager if operations_engine is not None else (inventory_manager or DeviceInventoryManager())
        self.credential_provider = credential_provider

    def _audit_session_event(self, event_type: str, device_id: str, details: Dict[str, Any], status: str) -> None:
        if self.operations_engine is None:
            raise PermissionError("Winbox requires the shared OperationsEngine audit lifecycle.")
        self.operations_engine.audit_logger.log_event(
            event_type=event_type,
            user=self.user_ctx.username,
            device_id=device_id,
            action="winbox_read_only_session",
            details=details,
            status=status,
        )

    def is_available(self) -> bool:
        """Checks if Winbox executable exists or a session is running."""
        return self.winbox_path is not None or len(WinboxLocator.get_running_processes()) > 0

    def get_status(self) -> Dict[str, Any]:
        """Inspects installation, running processes, and detected windows."""
        processes = WinboxLocator.get_running_processes()
        windows = self.ui.list_windows_by_title("winbox")
        return {
            "installed": self.winbox_path is not None,
            "executable_path": self.winbox_path,
            "running_processes": processes,
            "detected_windows": windows,
            "active_session": self.active_session
        }

    def launch(self) -> Dict[str, Any]:
        """Launches Winbox desktop application safely."""
        if not self.winbox_path or not os.path.isfile(self.winbox_path):
            raise FileNotFoundError("Winbox executable not found on Windows host.")
        
        proc = subprocess.Popen([self.winbox_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.current_process = proc
        time.sleep(1.5)
        return {
            "status": "LAUNCHED",
            "pid": proc.pid,
            "executable": self.winbox_path
        }

    def open_session(self, target: str, username: Optional[str] = None, password: Optional[str] = None, port: int = 8291) -> Dict[str, Any]:
        """Open a session only to a canonical inventory target with trusted credentials.

        Legacy caller-provided username/password arguments are rejected. The live
        Winbox integration remains unavailable until an external identity and
        credential provider are configured.
        """
        if username is not None or password is not None:
            raise PermissionError("Caller-supplied Winbox credentials are rejected; use a trusted credential provider.")
        if not self.user_ctx or not verify_issued_context(self.user_ctx):
            raise PermissionError("Winbox requires a verified authenticated UserContext.")
        if getattr(self.user_ctx, "is_dev_mode", False):
            raise PermissionError("Live Winbox sessions are not allowed with development identities.")
        if not self.user_ctx.has_scope("READ_ONLY") or self.user_ctx.has_scope("WRITE") or self.user_ctx.has_scope("CRITICAL"):
            raise PermissionError("Interactive Winbox is restricted to READ_ONLY identities without WRITE/CRITICAL scopes.")
        if self.operations_engine is None:
            raise PermissionError("Live Winbox is disabled until the shared OperationsEngine and audit lifecycle are configured.")
        canonical = self.operations_engine.inventory_manager.get_device(target)
        if canonical is None:
            raise PermissionError("Winbox target must resolve to a trusted inventory device.")
        if not self.user_ctx.can_access_device(canonical.device_id):
            raise PermissionError("User is not authorized for this inventory device.")
        if str(canonical.environment).upper() in {"SIMULATED", "LAB_MOCK"}:
            raise PermissionError("Simulated inventory devices cannot be opened through live Winbox.")
        if not canonical.credentials_ref or self.credential_provider is None:
            raise PermissionError("Trusted credential provider is not configured for this inventory device.")
        try:
            credentials = self.credential_provider.get_credentials(canonical.credentials_ref, canonical)
        except Exception:
            raise PermissionError("Trusted credential retrieval failed.") from None
        if not isinstance(credentials, dict) or not credentials.get("username") or not credentials.get("password"):
            raise PermissionError("Trusted credential provider returned incomplete Winbox credentials.")
        if credentials.get("device_enforced_read_only") is not True:
            raise PermissionError("Winbox credential provider must attest that the device account is enforced READ_ONLY.")
        target = canonical.ip_address
        username = str(credentials["username"])
        password = str(credentials["password"])
        if canonical.protocol == "winbox":
            port = int(canonical.port)
        else:
            if int(port) != 8291:
                raise PermissionError("Winbox port substitution is not allowed; use the canonical registered port.")
            port = 8291
        if not 1 <= port <= 65535:
            raise ValueError("Invalid canonical Winbox port.")
        if not self.winbox_path or not os.path.isfile(self.winbox_path):
            raise FileNotFoundError("Winbox executable not found.")

        # Password remains in memory and is never placed on the process command line.
        target_str = f"{target}:{port}" if port != 8291 else target
        safe_cmd = [self.winbox_path, target_str, username]

        device_id = canonical.device_id
        self._audit_session_event("WINBOX_SESSION_ATTEMPT", device_id, {"target": target, "port": port, "credential_profile": "DEVICE_ENFORCED_READ_ONLY"}, "PENDING")
        retries = 0
        while retries <= self.max_retries:
            try:
                proc = subprocess.Popen(safe_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as exc:
                self._audit_session_event("WINBOX_SESSION_FAILED", device_id, {"reason": type(exc).__name__}, "FAILED")
                raise
            self.current_process = proc
            
            # Wait for window
            start_time = time.time()
            session_hwnd = None
            while (time.time() - start_time) < self.connection_timeout:
                # Check for error dialogs first
                err = self.ui.detect_dialog_error(0)
                if err:
                    self._audit_session_event("WINBOX_SESSION_FAILED", device_id, {"reason": "WINBOX_ERROR_DIALOG"}, "FAILED")
                    self.close_session()
                    raise ConnectionError("Winbox connection failed with an error dialog.")

                # If password was provided and password dialog is displayed, inject via Windows Message
                if password:
                    winbox_windows = self.ui.list_windows_by_title("winbox")
                    for w in winbox_windows:
                        # Look for Edit controls
                        edits = [c for c in self.ui.enumerate_child_controls(w["hwnd"]) if c["class_name"].lower() == "edit"]
                        # The password field is typically the second edit or has ES_PASSWORD style
                        if edits:
                            # Send password directly into edit control safely
                            pwd_ctrl = edits[-1]
                            self.ui.set_control_text(pwd_ctrl["hwnd"], password)
                            # Find Connect button and click
                            btn = self.ui.find_control(w["hwnd"], class_name="Button", text="Connect")
                            if btn:
                                self.ui.send_click_to_control(btn["hwnd"])

                # Check if router window is open (Title contains RouterOS version)
                active_router_windows = self.ui.list_windows_by_title("RouterOS") + [
                    w for w in self.ui.list_windows_by_title("winbox") if "@" in str(w.get("title", ""))
                ]
                if active_router_windows:
                    session_hwnd = active_router_windows[0]["hwnd"]
                    break

                time.sleep(0.5)

            # A live process is only an application process, not proof of an
            # authenticated router session. Require a detected router window.
            if session_hwnd is not None and any(
                window.get("hwnd") == session_hwnd
                and ("routeros" in str(window.get("title", "")).casefold()
                     or "@" in str(window.get("title", "")))
                for window in (self.ui.list_windows_by_title("RouterOS") + self.ui.list_windows_by_title("winbox"))
            ):
                # Session opened only after UI-level evidence confirms a router window.
                session_info = {
                    "target": target,
                    "device_id": device_id,
                    "port": port,
                    "username": username,
                    "password": "***REDACTED***",
                    "device_enforced_read_only": True,
                    "pid": proc.pid,
                    "hwnd": session_hwnd,
                    "connected_at": time.time()
                }
                self.active_session = session_info
                try:
                    self._audit_session_event("WINBOX_SESSION_OPENED", device_id, {"target": target, "pid": proc.pid, "window_verified": True, "device_enforced_read_only": True}, "SUCCESS")
                except Exception:
                    self.close_session()
                    raise PermissionError("Winbox session could not be recorded in the shared audit log.")
                return {
                    "status": "SESSION_OPENED",
                    "target": target,
                    "username": username,
                    "pid": proc.pid,
                    "security_mode": "IN_MEMORY_WM_INJECTION (NO_CLI_PASSWORD)"
                }

            self.close_session()
            retries += 1
            if retries <= self.max_retries:
                time.sleep(1)

        self._audit_session_event("WINBOX_SESSION_FAILED", device_id, {"target": target, "reason": "SESSION_WINDOW_NOT_VERIFIED"}, "FAILED")
        raise TimeoutError(f"Winbox session connection to {target} timed out after {self.connection_timeout}s.")

    def navigate_menu(self, menu_path: str) -> Dict[str, Any]:
        """Navigates RouterOS submenus via accessible UI controls."""
        if not self.active_session or not self.user_ctx or not verify_issued_context(self.user_ctx):
            raise PermissionError("Winbox menu navigation requires an active authenticated session.")
        if self.operations_engine is None or self.active_session.get("device_enforced_read_only") is not True:
            raise PermissionError("Winbox navigation requires a shared-engine audited, device-enforced READ_ONLY session.")
        if self.user_ctx.has_scope("WRITE") or self.user_ctx.has_scope("CRITICAL") or not self.user_ctx.has_scope("READ_ONLY"):
            raise PermissionError("Winbox navigation is restricted to READ_ONLY identities.")
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

        normalized = " ".join(str(menu_path).strip().casefold().split())
        menu_map = {
            "system -> resources": "System -> Resources",
            "system -> identity": "System -> Identity",
            "system -> routerboard": "System -> Routerboard",
            "interfaces": "Interfaces",
            "ip -> addresses": "IP -> Addresses",
            "ip -> routes": "IP -> Routes",
            "ip -> dhcp server": "IP -> DHCP Server",
            "ip -> firewall": "IP -> Firewall",
            "ip -> dns": "IP -> DNS",
            "ppp": "PPP",
            "bridge": "Bridge",
            "wireless / wifi": "Wireless / WiFi",
            "queues": "Queues",
            "log": "Log",
        }
        canonical_menu = menu_map.get(normalized)
        if canonical_menu is None:
            return {
                "success": False,
                "menu": menu_path,
                "error": f"Menu '{menu_path}' is not an exact supported Winbox menu path.",
                "supported_menus": list(menu_map.values()),
            }

        if not self.current_process or self.current_process.poll() is not None:
            self.active_session = None
            raise ConnectionResetError("Winbox application process is not running.")
        hwnd = self.active_session.get("hwnd")
        if not hwnd:
            self.active_session = None
            return {"success": False, "menu": canonical_menu, "error": "No verified router window is bound to this session."}
        visible = self.ui.list_windows_by_title("RouterOS") + self.ui.list_windows_by_title("winbox")
        if not any(w.get("hwnd") == hwnd for w in visible):
            self.active_session = None
            return {"success": False, "menu": canonical_menu, "error": "Verified router window is no longer present."}

        # The UI wrapper must click the requested controls and verify the resulting
        # destination. Merely recognizing a menu label is never reported as success.
        navigator = getattr(self.ui, "navigate_menu_path", None)
        if not callable(navigator):
            return {"success": False, "menu": canonical_menu, "error": "UI automation cannot verify menu navigation."}
        try:
            navigated = bool(navigator(hwnd, canonical_menu, timeout=5.0))
        except Exception as exc:
            self._audit_session_event("WINBOX_NAVIGATION_FAILED", self.active_session["device_id"], {"menu": canonical_menu, "reason": type(exc).__name__}, "FAILED")
            return {"success": False, "menu": canonical_menu, "error": f"UI navigation failed: {type(exc).__name__}"}
        if not navigated:
            self._audit_session_event("WINBOX_NAVIGATION_FAILED", self.active_session["device_id"], {"menu": canonical_menu}, "FAILED")
            return {"success": False, "menu": canonical_menu, "error": "Winbox did not verify the requested destination."}
        self._audit_session_event("WINBOX_NAVIGATION_VERIFIED", self.active_session["device_id"], {"menu": canonical_menu}, "SUCCESS")
        return {
            "success": True,
            "menu": canonical_menu,
            "status": "NAVIGATED_VERIFIED",
            "active_windows": len(visible),
            "evidence_note": f"Winbox UI interaction and destination verified for {canonical_menu}.",
        }

    def capture_evidence(self, output_path: str) -> Dict[str, Any]:
        """Captures diagnostic screenshot evidence."""
        success = self.ui.capture_screenshot(output_path)
        return {
            "success": success,
            "output_path": output_path,
            "message": "Screenshot captured" if success else "Screenshot capture unavailable"
        }

    def close_session(self) -> Dict[str, Any]:
        """Closes active Winbox process and cleans up session state."""
        session = self.active_session
        if self.current_process:
            try:
                self.current_process.terminate()
                self.current_process.wait(timeout=2)
            except Exception:
                try:
                    self.current_process.kill()
                except Exception:
                    pass
            finally:
                self.current_process = None
        self.active_session = None
        if session and self.operations_engine is not None:
            try:
                self._audit_session_event("WINBOX_SESSION_CLOSED", session.get("device_id", "UNKNOWN"), {"target": session.get("target")}, "CLOSED")
            except Exception:
                return {"status": "CLOSED_AUDIT_FAILED"}
        return {"status": "CLOSED"}
