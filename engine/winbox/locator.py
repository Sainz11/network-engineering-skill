import os
import shutil
import subprocess
from typing import Optional, List, Dict, Any

DEFAULT_WINBOX_NAMES = [
    "winbox64.exe",
    "winbox.exe",
    "WinBox.exe",
    "Winbox64.exe"
]

COMMON_SEARCH_PATHS = [
    os.environ.get("PROGRAMFILES", "C:\\Program Files"),
    os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)"),
    os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\Default"), "AppData", "Local", "Programs"),
    os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\Default"), "Downloads"),
    os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\Default"), "Desktop"),
    os.environ.get("SYSTEMDRIVE", "C:") + "\\MikroTik",
    os.environ.get("SYSTEMDRIVE", "C:") + "\\Tools"
]

class WinboxLocator:
    """Detects and locates MikroTik Winbox desktop executable on Windows systems."""
    
    @staticmethod
    def find_executable(custom_path: Optional[str] = None) -> Optional[str]:
        # 1. Check custom path if provided
        if custom_path and os.path.isfile(custom_path):
            return os.path.abspath(custom_path)

        # 2. Check system PATH
        for name in DEFAULT_WINBOX_NAMES:
            found = shutil.which(name)
            if found:
                return os.path.abspath(found)

        # 3. Check common installation directories
        for base in COMMON_SEARCH_PATHS:
            if not os.path.exists(base):
                continue
            for name in DEFAULT_WINBOX_NAMES:
                candidate = os.path.join(base, name)
                if os.path.isfile(candidate):
                    return os.path.abspath(candidate)
                # Check 1 level deep subdirectory (e.g. C:\Program Files\MikroTik\winbox64.exe)
                sub_dir = os.path.join(base, "MikroTik", name)
                if os.path.isfile(sub_dir):
                    return os.path.abspath(sub_dir)

        return None

    @staticmethod
    def get_running_processes() -> List[Dict[str, Any]]:
        """Returns list of running Winbox processes using tasklist or psutil."""
        processes = []
        try:
            # Query tasklist on Windows
            output = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                stderr=subprocess.DEVNULL,
                universal_newlines=True
            )
            for line in output.splitlines():
                if not line.strip():
                    continue
                parts = [p.strip('"\r') for p in line.split('","')]
                if len(parts) >= 2:
                    p_name, pid = parts[0], parts[1]
                    if any(w.lower() in p_name.lower() for w in ["winbox"]):
                        processes.append({
                            "process_name": p_name,
                            "pid": int(pid) if pid.isdigit() else pid
                        })
        except Exception:
            pass
        return processes

    @staticmethod
    def is_installed() -> bool:
        return WinboxLocator.find_executable() is not None
