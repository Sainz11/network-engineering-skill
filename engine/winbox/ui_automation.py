import os
import subprocess
import time
from typing import Optional, Dict, Any, List

class WindowsUIAWrapper:
    """
    Windows UI Automation and Window Management Wrapper using native Win32/User32 ctypes.
    Discovers windows, controls, handles child elements, dialogs, error banners, and screenshots.
    """
    def __init__(self):
        self.is_windows = os.name == 'nt'
        if self.is_windows:
            import ctypes
            self.ctypes = ctypes
            self.user32 = ctypes.windll.user32
            self.kernel32 = ctypes.windll.kernel32
        else:
            self.ctypes = None
            self.user32 = None
            self.kernel32 = None

    def find_window(self, title_contains: str) -> Optional[int]:
        if not self.is_windows or not self.user32:
            return None
        
        hwnd_found = None

        @self.ctypes.WINFUNCTYPE(self.ctypes.c_bool, self.ctypes.c_int, self.ctypes.POINTER(self.ctypes.c_int))
        def enum_windows_proc(hwnd, lParam):
            nonlocal hwnd_found
            length = self.user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buffer = self.ctypes.create_unicode_buffer(length + 1)
                self.user32.GetWindowTextW(hwnd, buffer, length + 1)
                title = buffer.value
                if title_contains.lower() in title.lower():
                    if self.user32.IsWindowVisible(hwnd):
                        hwnd_found = hwnd
                        return False
            return True

        self.user32.EnumWindows(enum_windows_proc, 0)
        return hwnd_found

    def list_windows_by_title(self, pattern: str) -> List[Dict[str, Any]]:
        if not self.is_windows or not self.user32:
            return []
        
        matching = []

        @self.ctypes.WINFUNCTYPE(self.ctypes.c_bool, self.ctypes.c_int, self.ctypes.POINTER(self.ctypes.c_int))
        def enum_windows_proc(hwnd, lParam):
            length = self.user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buffer = self.ctypes.create_unicode_buffer(length + 1)
                self.user32.GetWindowTextW(hwnd, buffer, length + 1)
                title = buffer.value
                if pattern.lower() in title.lower() and self.user32.IsWindowVisible(hwnd):
                    matching.append({"hwnd": hwnd, "title": title})
            return True

        self.user32.EnumWindows(enum_windows_proc, 0)
        return matching

    def enumerate_child_controls(self, parent_hwnd: int) -> List[Dict[str, Any]]:
        """Enumerates child controls, buttons, edits, and list views within a window."""
        if not self.is_windows or not self.user32 or not parent_hwnd:
            return []

        children = []

        @self.ctypes.WINFUNCTYPE(self.ctypes.c_bool, self.ctypes.c_int, self.ctypes.POINTER(self.ctypes.c_int))
        def enum_child_proc(hwnd, lParam):
            # Class name
            class_buffer = self.ctypes.create_unicode_buffer(256)
            self.user32.GetClassNameW(hwnd, class_buffer, 256)
            c_name = class_buffer.value

            # Text / Value
            length = self.user32.GetWindowTextLengthW(hwnd)
            text = ""
            if length > 0:
                text_buffer = self.ctypes.create_unicode_buffer(length + 1)
                self.user32.GetWindowTextW(hwnd, text_buffer, length + 1)
                text = text_buffer.value

            is_visible = bool(self.user32.IsWindowVisible(hwnd))
            is_enabled = bool(self.user32.IsWindowEnabled(hwnd))

            children.append({
                "hwnd": hwnd,
                "class_name": c_name,
                "text": text,
                "is_visible": is_visible,
                "is_enabled": is_enabled
            })
            return True

        self.user32.EnumChildWindows(parent_hwnd, enum_child_proc, 0)
        return children

    def find_control(self, parent_hwnd: int, class_name: Optional[str] = None, text: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Finds a specific child control by class name or accessibility/window text."""
        children = self.enumerate_child_controls(parent_hwnd)
        for c in children:
            if class_name and c["class_name"].lower() != class_name.lower():
                continue
            if text and text.lower() not in c["text"].lower():
                continue
            return c
        return None

    def send_click_to_control(self, control_hwnd: int) -> bool:
        """Sends WM_LBUTTONDOWN and WM_LBUTTONUP messages to safely click a button control without coordinates."""
        if not self.is_windows or not self.user32 or not control_hwnd:
            return False
        BM_CLICK = 0x00F5
        self.user32.SendMessageW(control_hwnd, BM_CLICK, 0, 0)
        return True

    def set_control_text(self, control_hwnd: int, text: str) -> bool:
        """Sets text on Edit controls via WM_SETTEXT message without clipboard leakage."""
        if not self.is_windows or not self.user32 or not control_hwnd:
            return False
        WM_SETTEXT = 0x000C
        self.user32.SendMessageW(control_hwnd, WM_SETTEXT, 0, text)
        return True

    def detect_dialog_error(self, parent_hwnd: int) -> Optional[str]:
        """Detects modal dialogs or error banners (e.g. 'ERROR: could not connect', 'Login failed')."""
        if not self.is_windows or not self.user32:
            return None

        # Check for child dialogs or top-level message boxes
        dialogs = self.list_windows_by_title("error") + self.list_windows_by_title("winbox error")
        for d in dialogs:
            children = self.enumerate_child_controls(d["hwnd"])
            err_texts = [c["text"] for c in children if c["text"] and c["class_name"].lower() == "static"]
            if err_texts:
                return " ".join(err_texts)
            return d["title"]
        return None


    def navigate_menu_path(self, parent_hwnd: int, menu_path: str, timeout: float = 5.0) -> bool:
        """Click each accessible menu segment and verify the destination control.

        Winbox UI trees vary by release. This method deliberately fails closed when
        a menu control or the resulting destination cannot be identified.
        """
        if not self.is_windows or not self.user32 or not parent_hwnd:
            return False
        segments = [part.strip() for part in menu_path.split("->")]
        if not segments or any(not part for part in segments):
            return False
        for segment in segments:
            controls = self.enumerate_child_controls(parent_hwnd)
            match = next((
                control for control in controls
                if control.get("is_visible") and control.get("is_enabled")
                and str(control.get("text", "")).strip().casefold() == segment.casefold()
            ), None)
            if match is None or not self.send_click_to_control(match.get("hwnd")):
                return False
            time.sleep(min(max(timeout / max(len(segments), 1), 0.1), 1.0))
        if not self.is_window_visible(parent_hwnd):
            return False
        # A menu item remaining visible is not proof that its destination opened.
        # Require a distinct visible Winbox destination window whose title matches
        # the requested final menu segment. If the installed Winbox build exposes
        # no such evidence, fail closed rather than reporting a false success.
        final_label = segments[-1].casefold()
        destination_windows = self.list_windows_by_title(segments[-1])
        return any(
            window.get("hwnd") != parent_hwnd
            and final_label in str(window.get("title", "")).casefold()
            for window in destination_windows
        )

    def is_window_visible(self, hwnd: int) -> bool:
        if not self.is_windows or not self.user32 or not hwnd:
            return False
        return bool(self.user32.IsWindow(hwnd) and self.user32.IsWindowVisible(hwnd))

    def capture_screenshot(self, output_path: str) -> bool:
        """Captures desktop/window screenshot for diagnostic evidence using Pillow."""
        try:
            from PIL import ImageGrab
            screenshot = ImageGrab.grab()
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            screenshot.save(output_path)
            return True
        except Exception:
            return False
