import re
from typing import Dict, Type
from ..connectors.base import BaseConnector
from .base_adapter import BaseDeviceAdapter
from .mikrotik_adapter import MikroTikAdapter
from .cisco_adapter import CiscoAdapter
from .huawei_adapter import HuaweiAdapter
from .extended_adapters import RuijieAdapter, CambiumAdapter, UbiquitiAdapter, TPLinkAdapter

# Exact aliases only. Normalization is deterministic and never performs substring matching.
ADAPTER_REGISTRY: Dict[str, Type[BaseDeviceAdapter]] = {
    "mikrotik": MikroTikAdapter,
    "mikrotik-routeros": MikroTikAdapter,
    "cisco": CiscoAdapter,
    "cisco-systems": CiscoAdapter,
    "huawei": HuaweiAdapter,
    "huawei-technologies": HuaweiAdapter,
    "ruijie": RuijieAdapter,
    "reyee": RuijieAdapter,
    "ruijie-reyee": RuijieAdapter,
    "cambium": CambiumAdapter,
    "cambium-networks": CambiumAdapter,
    "ubiquiti": UbiquitiAdapter,
    "ubiquiti-networks": UbiquitiAdapter,
    "tp-link": TPLinkAdapter,
    "tplink": TPLinkAdapter,
    "tp-link-technologies": TPLinkAdapter,
}


def normalize_vendor_name(vendor: str) -> str:
    if not isinstance(vendor, str) or not vendor.strip():
        raise ValueError("Vendor must be a non-empty string.")
    normalized = vendor.casefold().strip()
    normalized = re.sub(r"[^a-z0-9]+", "-", normalized)
    normalized = normalized.strip("-")
    return normalized


class AdapterFactory:
    @staticmethod
    def get_adapter(vendor: str, connector: BaseConnector) -> BaseDeviceAdapter:
        normalized = normalize_vendor_name(vendor)
        adapter_cls = ADAPTER_REGISTRY.get(normalized)
        if adapter_cls is None:
            raise ValueError(f"No validated adapter registered for vendor {vendor!r}")
        return adapter_cls(connector)
