# Quality Control Test Categories & Inspection Criteria

This reference document defines standard acceptance criteria and inspection steps across all device categories.

---

## 1. Physical Inspection & Housing Integrity
- **Chassis & Enclosure**: Housing must be free of cracks, structural fractures, melted casing, signs of water ingress, or internal loose rattling.
- **Ports & Terminals**: RJ45 jacks must have all 8 pins straight, gold-plated, uncorroded, and latch retention clips intact. Fiber SC/APC and LC ports must have dust caps in place and unchipped ceramic ferrules.
- **Labels & Identification**: Factory regulatory label, serial number, and primary MAC address barcode must be completely legible and match internal electronic identifiers.

---

## 2. Power & Boot Initialization
- **Cold Boot Stability**: Device must boot from cold start to operational ready state without infinite reboot loops, watchdog resets, or hardware fault buzzers.
- **LED Diagnostics**:
  - `Power LED`: Solid green / white (never solid red or blinking fault).
  - `Alarm / Warning LED`: Completely dark / off during normal operation.
  - `PON LED` (ONTs): Solid green after registration. Blinking indicates synchronization search; red indicates LOS (Loss of Signal).

---

## 3. Ethernet & Switch Port Performance
- **Speed & Duplex Negotiation**:
  - Test link negotiation with standard test partner switch at 10M, 100M, 1000M (where hardware PHY supports it).
  - Check device profiles: Never mark Fast Ethernet hardware (e.g. MikroTik hAP lite) as failed because it does not achieve 1 Gbps.
- **Port Error Counters**: Must maintain exactly `0 CRC errors`, `0 Frame Align errors`, `0 Buffer Overrun drops` during full rate bidirectional traffic test.

---

## 4. Optical Link & ONT Specifics
- **Registration**: Device registers into OLT State O5 within 30 seconds of fiber connection.
- **Optical Sensitivity Range**:
  - Minimum RX: Strictly greater than manufacturer minimum (typically -27.0 dBm for Class B+, -28.0 dBm for Class C+).
  - Overload limit: Must not exceed -8.0 dBm.
- **Laser Health**: Transmit (TX) optical power must fall within +0.5 dBm to +5.0 dBm.

---

## 5. Wireless Access Points & Outdoor Radios
- **Beaconing**: Unicast and broadcast SSIDs visible across both 2.4GHz and 5GHz (or 6GHz if Wi-Fi 6E/7).
- **Client Association**: Clean 4-way WPA2-PSK / WPA3-SAE handshake with test station under 2 seconds.
- **Outdoor Wireless / PTP**:
  - Verify RSSI is within +/- 3 dB of modeled path budget.
  - Signal-to-Noise Ratio (SNR) > 30 dB for maximum MCS rate.
  - Noise floor cleaner than -90 dBm.
  - Controlled throughput test shows zero dropped packets.

---

## 6. Microwave Backhaul Equipment
- **IDU / ODU Communication**: Digital interface between Indoor Unit (modem) and Outdoor Unit (transceiver) error-free.
- **RSL & Modulation**: Received Signal Level (RSL) matches licensed path profile; modem transitions cleanly to target QAM (e.g., 1024 QAM, 4096 QAM).
- **Protection Switching**: 1+1 HSB (Hot Standby) switchover test completes with sub-50ms traffic hit.
