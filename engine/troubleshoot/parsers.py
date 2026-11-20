"""Generic parsers for troubleshooting output.

Each parser returns a dictionary of structured data or ``None`` when parsing fails.
The confidence scoring logic lives in ``engine.troubleshoot.engine`` – a parser returning
non‑``None`` only contributes evidence; it does **not** set HIGH confidence on its own.
"""
from typing import Optional, Dict, Any
import re

def parse_interface_status(output: str) -> Optional[Dict[str, Any]]:
    """Parse a generic interface status block.

    Returns a dict like ``{"up": int, "down": int}`` or ``None`` if the pattern is not found.
    """
    # Very simple heuristic: look for lines like "\ninterface XYZ is up" or "down"
    up = len(re.findall(r"\bup\b", output, flags=re.IGNORECASE))
    down = len(re.findall(r"\bdown\b", output, flags=re.IGNORECASE))
    if up == 0 and down == 0:
        return None
    return {"up": up, "down": down}

def parse_ping_result(output: str) -> Optional[Dict[str, Any]]:
    """Parse ping output for packet loss.

    Matches formats like:
      - ``packet-loss=0%`` or ``packet_loss: 0%``
      - ``0% packet loss`` or ``100% packet loss``
      - ``0% loss``
    Returns ``{"packet_loss": "XX%"}``.
    """
    match = re.search(r"packet[-_ ]loss\s*[:=]\s*([0-9]+%?)", output, flags=re.IGNORECASE)
    if not match:
        match = re.search(r"([0-9]+%)\s*(?:packet\s*)?loss", output, flags=re.IGNORECASE)
    if not match:
        return None
    val = match.group(1)
    if not val.endswith("%"):
        val += "%"
    return {"packet_loss": val}

def parse_route_table(output: str) -> Optional[Dict[str, Any]]:
    """Parse a routing table to detect a missing default route.

    Returns ``{"has_default": bool}``.
    """
    has_default = bool(re.search(r"0\.0\.0\.0/0", output) or re.search(r"default", output, flags=re.IGNORECASE))
    return {"has_default": has_default}
