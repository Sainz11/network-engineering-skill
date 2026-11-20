# Vendor Support

Status is based on code presence and test evidence; no physical hardware certification is implied.

| Vendor | Adapter | Status | Connector | Notes |
|---|---|---|---|---|
| MikroTik | MikroTikAdapter | Implemented, mock tested | SSH | RouterOS command set; model/firmware differences remain |
| Cisco | CiscoAdapter | Implemented, mock tested | SSH | IOS-like commands; product variants not validated |
| Huawei | HuaweiAdapter | Implemented, mock tested | SSH | CLI compatibility varies |
| Ruijie/Reyee | RuijieAdapter | Partial | SSH | Limited command set |
| Cambium | CambiumAdapter | Partial | SSH | Command coverage varies by platform |
| Ubiquiti | UbiquitiAdapter | Partial | SSH | Platform/firmware differences; limited implementation |
| TP-Link | TPLinkAdapter | Partial | SSH | Model families vary |
| ZTE, VSOL, FiberHome, Nokia | None in adapter factory | Documented only | None | Provisioning/QC reference documentation only |
| SNMP | None | Not implemented live | Interface | Live SNMP transport disabled |

`engine/vendors/registry.py` provides machine-readable conservative capability statuses. Unsupported vendor resolution fails closed instead of using a default vendor adapter.
