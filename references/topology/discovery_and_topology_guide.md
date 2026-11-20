# Network Discovery & Topology Mapping Reference

This document details the architecture, discovery protocols, neighbor correlation algorithms, and confidence scoring rules implemented in the Network Discovery and Topology Mapping engine.

---

## 1. Multi-Source Discovery Hierarchy

```
+-----------------------------------------------------------------------------------+
|                           SCOPED DISCOVERY COLLECTOR                              |
|           (Authorized Subnets, Management Inventories, Seed Routers)              |
+-----------------------------------------------------------------------------------+
                                         |
         +-------------------------------+-------------------------------+
         |                               |                               |
         v                               v                               v
[L2 Adjacency Protocols]        [L3 & Forwarding State]          [Management Feeds]
  * IEEE 802.1AB LLDP             * ARP Table Interrogation        * TR-069 / CWMP ACS
  * Cisco CDP                     * Bridge Host (FDB) MACs         * Controller Inventories
  * MikroTik MNDP                 * DHCP Lease Tables              * Static Site Maps
```

---

## 2. Link Adjacency Corroboration & Confidence Scoring

> [!IMPORTANT]
> The Topology Engine never assumes physical connections based merely on shared IP subnets. Every link requires observable layer-2 or management corroboration.

| Link Confidence | Criteria / Evidence Required | Visualization Style |
| :--- | :--- | :--- |
| **`VERIFIED`** | **Bidirectional LLDP/CDP/MNDP**: Device A reports Device B on Port X, and Device B reports Device A on Port Y. Corroborated with matching chassis/port identifiers. | Solid Green line (`#10b981`), 2.5px width |
| **`INFERRED`** | **Unidirectional observation**: One device reports the neighbor, or bridge FDB table links a single MAC address to a known switch access port. | Dashed Orange line (`#f59e0b`), 5px dash |
| **`UNKNOWN`** | Weak correlation or conflicting bridge entries across multiple uplinks without LLDP/CDP confirmation. | Dotted Red line (`#ef4444`), flagged for operator review |

---

## 3. Discovered Role Classification

Devices are classified into roles according to verified hardware models, interface counts, and operational functions:
- **`ROUTER / GATEWAY`**: MikroTik CCR, Cisco ISR/Catalyst 8000, Huawei NE series terminating default routing and subscriber BNG.
- **`CORE_SWITCH / DISTRIBUTION_SWITCH`**: Multi-gigabit SFP+ aggregation switches and modular OLT chassis (e.g. Huawei MA5800, Cisco Catalyst 9300).
- **`ACCESS_SWITCH`**: Layer-2 edge switches providing 1G access ports (e.g. Huawei S5720, Ruijie Reyee).
- **`ACCESS_POINT`**: Wireless LAN access points (Ruijie RG-RAP, Ubiquiti UniFi, TP-Link Omada).
- **`ONT_ONU`**: Customer premises GPON/EPON terminals verified via ACS inventory or OLT OMCI registration.
- **`OUTDOOR_RADIO / MICROWAVE`**: Point-to-Point / PTMP wireless backhaul (Ubiquiti airMAX, Cambium ePMP/cnWave).

---

## 4. Telemetry Health Analysis Thresholds

The `NetworkHealthAnalyzer` flags potential incidents using model-aware tolerances:
- **CPU Utilization**: WARNING > 70%, CRITICAL > 85%.
- **Free Memory**: CRITICAL when < 32 MB remaining.
- **Optical Receiver Sensitivity**:
  - CRITICAL when RX < -27.0 dBm (GPON Class B+ attenuation limit).
  - WARNING when RX > -8.0 dBm (optical photodiode receiver overload risk).
- **Wireless RF Link**:
  - WARNING when RSSI < -78 dBm.
  - WARNING when SNR < 18 dB (causes modulation downshift and frame retransmissions).
- **Interface CRC / Dropped Frames**: WARNING when frame error count exceeds 50 drops during measurement window.
