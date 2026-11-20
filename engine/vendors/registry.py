"""Vendor support registry with conservative, evidence-oriented statuses."""
from typing import Dict, Any
import re

IMPLEMENTED_MOCK_TESTED = "IMPLEMENTED, MOCK TESTED"
PARTIAL = "PARTIALLY IMPLEMENTED"
DOC_ONLY = "DOCUMENTED ONLY"
NOT_IMPLEMENTED = "NOT IMPLEMENTED"

VENDOR_CAPABILITIES: Dict[str, Dict[str, Any]] = {
    "mikrotik": {"adapter": "MikroTikAdapter", "status": IMPLEMENTED_MOCK_TESTED, "connectors": ["SSH"], "categories": ["router", "switch", "wireless", "ONT/ONU (not verified)"]},
    "cisco": {"adapter": "CiscoAdapter", "status": IMPLEMENTED_MOCK_TESTED, "connectors": ["SSH"], "categories": ["router", "switch"]},
    "huawei": {"adapter": "HuaweiAdapter", "status": IMPLEMENTED_MOCK_TESTED, "connectors": ["SSH"], "categories": ["router", "switch", "ONT/ONU (not verified)"]},
    "ruijie/reyee": {"adapter": "RuijieAdapter", "status": PARTIAL, "connectors": ["SSH"], "categories": ["router", "switch", "wireless"]},
    "cambium": {"adapter": "CambiumAdapter", "status": PARTIAL, "connectors": ["SSH"], "categories": ["wireless", "radio", "microwave"]},
    "ubiquiti": {"adapter": "UbiquitiAdapter", "status": PARTIAL, "connectors": ["SSH"], "categories": ["wireless", "router", "switch"]},
    "tp-link": {"adapter": "TPLinkAdapter", "status": PARTIAL, "connectors": ["SSH"], "categories": ["router", "switch", "wireless"]},
    "zte": {"adapter": None, "status": DOC_ONLY, "connectors": [], "categories": ["ONT/ONU"]},
    "vsol": {"adapter": None, "status": DOC_ONLY, "connectors": [], "categories": ["ONT/ONU"]},
    "fiberhome": {"adapter": None, "status": DOC_ONLY, "connectors": [], "categories": ["ONT/ONU"]},
    "nokia": {"adapter": None, "status": DOC_ONLY, "connectors": [], "categories": ["ONT/ONU"]},
    "snmp": {"adapter": None, "status": NOT_IMPLEMENTED, "connectors": ["SNMP interface; live transport disabled"], "categories": ["multi-vendor telemetry"]},
}

def vendor_capabilities() -> Dict[str, Dict[str, Any]]:
    """Return a defensive copy of registry data."""
    return {name: {**meta, "connectors": list(meta["connectors"]), "categories": list(meta["categories"])} for name, meta in VENDOR_CAPABILITIES.items()}

def capability_status(vendor: str) -> Dict[str, Any]:
    key = re.sub(r"[^a-z0-9]+", "-", (vendor or "").strip().casefold()).strip("-")
    aliases = {
        "reyee": "ruijie/reyee", "ruijie": "ruijie/reyee", "ruijie-reyee": "ruijie/reyee",
        "tplink": "tp-link", "tp-link": "tp-link", "tp-link-technologies": "tp-link",
        "cambium-networks": "cambium",
    }
    key = aliases.get(key, key)
    if key not in VENDOR_CAPABILITIES:
        return {"vendor": vendor, "adapter": None, "status": "NOT IMPLEMENTED", "connectors": [], "categories": []}
    return {"vendor": key, **vendor_capabilities()[key]}
