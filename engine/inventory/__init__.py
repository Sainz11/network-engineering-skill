"""engine.inventory public API."""

from .inventory_manager import DeviceInventoryManager


def get_device_by_id(device_id: str) -> dict:
    """Return a device dict by ID.  Returns a stub dict if not found (for testing)."""
    mgr = DeviceInventoryManager()
    dev = mgr.get_device(device_id)
    if dev:
        return {
            "id": dev.device_id,
            "vendor": dev.vendor,
            "management_ip": dev.ip_address,
            "preferred_connector": dev.protocol or "ssh",
            "hostname": dev.hostname,
        }
    # Stub for ad-hoc / unknown devices (used by TroubleshootEngine in tests)
    return {
        "id": device_id,
        "vendor": "generic",
        "management_ip": device_id,
        "preferred_connector": "mock",
        "hostname": device_id,
    }


__all__ = ["DeviceInventoryManager", "get_device_by_id"]
