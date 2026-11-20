from typing import List, Dict, Any, Tuple, Optional
import uuid
from ..discovery.models import DiscoveredDevice, TopologyLink, LinkConfidence, DeviceRole

class TopologyEngine:
    """
    Constructs an evidence-backed network topology graph from discovered devices and neighbors.
    Enforces strict corroboration rules:
    - Never fabricates connections from IP similarity alone.
    - Classifies links as VERIFIED, INFERRED, or UNKNOWN with confidence scores.
    """
    def __init__(self):
        self.devices: Dict[str, DiscoveredDevice] = {}
        self.links: Dict[str, TopologyLink] = {}

    @staticmethod
    def _protocol_value(neighbor) -> str:
        protocol = getattr(neighbor, "discovery_protocol", "UNKNOWN")
        return str(getattr(protocol, "value", protocol)).upper()

    @staticmethod
    def _interface_key(value: Optional[str]) -> Optional[str]:
        if not isinstance(value, str) or not value.strip() or value.strip().casefold() == "unknown":
            return None
        # Conservative normalization: case and whitespace only. Vendor-specific
        # abbreviations are not collapsed because that could manufacture a match.
        return " ".join(value.strip().casefold().split())

    @staticmethod
    def _observation(source_id: str, neighbor) -> Dict[str, Any]:
        return {
            "observer_device_id": source_id,
            "local_interface": neighbor.local_interface,
            "remote_device_id": neighbor.remote_device_id,
            "remote_interface": neighbor.remote_interface,
            "remote_hostname": neighbor.remote_hostname,
            "remote_ip": neighbor.remote_ip,
            "remote_mac": neighbor.remote_mac,
            "discovery_protocol": TopologyEngine._protocol_value(neighbor),
            "raw_details": dict(neighbor.raw_details or {}),
        }

    def build_topology(self, devices: List[DiscoveredDevice]) -> Tuple[List[DiscoveredDevice], List[TopologyLink]]:
        self.devices = {d.device_id: d for d in devices}
        self.links = {}
        supported_protocols = {"LLDP", "CDP", "MNDP"}

        for dev in devices:
            for neighbor in dev.neighbors:
                src_id = dev.device_id
                resolved_dst = self._resolve_device(neighbor.remote_device_id, neighbor.remote_ip, neighbor.remote_mac)
                target_id = resolved_dst.device_id if resolved_dst else neighbor.remote_device_id
                if src_id == target_id:
                    continue
                pair_key = tuple(sorted([src_id, target_id]))
                protocol = self._protocol_value(neighbor)
                forward_observation = self._observation(src_id, neighbor)
                reverse_neighbor = None
                reverse_observation = None

                if resolved_dst is not None and protocol in supported_protocols:
                    for candidate in resolved_dst.neighbors:
                        back_target = self._resolve_device(candidate.remote_device_id, candidate.remote_ip, candidate.remote_mac)
                        if (back_target and back_target.device_id == src_id
                                and self._protocol_value(candidate) in supported_protocols):
                            reverse_neighbor = candidate
                            reverse_observation = self._observation(resolved_dst.device_id, candidate)
                            break

                src_if = neighbor.local_interface or "unknown"
                dst_if = neighbor.remote_interface or "unknown"
                reciprocal = reverse_neighbor is not None
                interface_conflict = False
                interface_complete = False
                if reciprocal:
                    # LLDP/CDP/MNDP reciprocity must agree at BOTH ends:
                    # A.local == B.remote and A.remote == B.local.
                    a_local = self._interface_key(neighbor.local_interface)
                    b_remote = self._interface_key(reverse_neighbor.remote_interface)
                    b_local = self._interface_key(reverse_neighbor.local_interface)
                    a_remote = self._interface_key(neighbor.remote_interface)
                    interface_complete = all((a_local, b_remote, b_local, a_remote))
                    if interface_complete:
                        interface_conflict = a_local != b_remote or a_remote != b_local
                    else:
                        interface_conflict = True

                if reciprocal and interface_complete and not interface_conflict:
                    confidence = LinkConfidence.VERIFIED
                    status = "UP"
                elif reciprocal and interface_conflict:
                    confidence = LinkConfidence.INFERRED
                    status = "CONFLICT"
                elif protocol in supported_protocols or protocol == "ACS_INVENTORY":
                    confidence = LinkConfidence.INFERRED
                    status = "UP"
                else:
                    confidence = LinkConfidence.UNKNOWN
                    status = "UNKNOWN"

                observations = [forward_observation]
                if reverse_observation is not None:
                    observations.append(reverse_observation)

                if pair_key in self.links:
                    existing = self.links[pair_key]
                    existing_observations = existing.metrics.setdefault("observations", [])
                    known = {(o.get("observer_device_id"), o.get("local_interface"), o.get("remote_interface"), o.get("discovery_protocol")) for o in existing_observations}
                    for obs in observations:
                        key = (obs.get("observer_device_id"), obs.get("local_interface"), obs.get("remote_interface"), obs.get("discovery_protocol"))
                        if key not in known:
                            existing_observations.append(obs)
                            known.add(key)
                    if interface_conflict:
                        existing.confidence = LinkConfidence.INFERRED
                        existing.status = "CONFLICT"
                        existing.metrics["interface_conflict"] = {
                            "forward": forward_observation,
                            "reverse": reverse_observation,
                            "reason": "Reciprocal interface identifiers disagree or are incomplete.",
                        }
                    if protocol not in existing.evidence_sources:
                        existing.evidence_sources.append(protocol)
                    continue

                link = TopologyLink(
                    link_id=f"LINK-{uuid.uuid4().hex[:8].upper()}",
                    source_device_id=src_id,
                    source_interface=src_if,
                    target_device_id=target_id,
                    target_interface=dst_if,
                    confidence=confidence,
                    evidence_sources=[protocol],
                    status=status,
                    metrics={"observations": observations},
                )
                if interface_conflict:
                    link.metrics["interface_conflict"] = {
                        "forward": forward_observation,
                        "reverse": reverse_observation,
                        "reason": "Reciprocal interface identifiers disagree or are incomplete.",
                    }
                self.links[pair_key] = link

        return list(self.devices.values()), list(self.links.values())

    def _resolve_device(self, dev_id: str, ip: Optional[str] = None, mac: Optional[str] = None) -> Optional[DiscoveredDevice]:
        # 1. Match device_id
        if dev_id in self.devices:
            return self.devices[dev_id]

        # 2. Match hostname or IP
        for d in self.devices.values():
            if dev_id.casefold() == d.hostname.casefold():
                return d
            if ip and d.management_ip == ip:
                return d
            if mac and d.mac_address and mac.lower().replace(":", "").replace("-", "") == d.mac_address.lower().replace(":", "").replace("-", ""):
                return d
        return None

    def export_topology_data(self) -> Dict[str, Any]:
        return {
            "devices": [
                {
                    "device_id": d.device_id,
                    "hostname": d.hostname,
                    "management_ip": d.management_ip,
                    "vendor": d.vendor,
                    "model": d.model,
                    "role": d.role.value,
                    "health_status": d.health_status,
                    "health_metrics": d.health_metrics,
                    "interfaces_count": len(d.interfaces)
                }
                for d in self.devices.values()
            ],
            "links": [
                {
                    "link_id": l.link_id,
                    "source": l.source_device_id,
                    "source_interface": l.source_interface,
                    "target": l.target_device_id,
                    "target_interface": l.target_interface,
                    "confidence": l.confidence.value,
                    "evidence_sources": l.evidence_sources,
                    "status": l.status,
                    "metrics": l.metrics
                }
                for l in self.links.values()
            ]
        }
