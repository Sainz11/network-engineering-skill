# ISP Provisioning & Operational Playbooks

This document contains standardized operational playbooks for customer provisioning, device replacement, troubleshooting, and service lifecycle management.

---

## Playbook 1: New Customer Activation (GPON FTTH)

- **Preconditions**: Fiber drop cable installed, ODP port assigned, light level measured at field rosette between -15 dBm and -24 dBm.
- **Required Information**: Customer ID, Subscribed Speed Profile, ONT Serial Number / MAC, Service VLAN ID, PPPoE Credentials.
- **Safe Verification Steps**:
  1. Verify optical power at rosette before plugging into ONT (`power meter` check).
  2. Query OLT autofind to confirm ONT Serial Number visibility:
     `display ont autofind <frame/slot/port>`
- **Procedure**:
  1. Register ONT on OLT with designated line profile and service profile:
     `ont add <port> <ont-id> sn-auth "<SERIAL>" omci ont-lineprofile-name <PROFILE> ont-srvprofile-name <SRV_PROFILE>`
  2. Create service port mapping C-VLAN to GEM port and S-VLAN.
  3. Push PPPoE username and password to ONT via TR-069 or configure on WAN interface (redacted in logs).
  4. Verify ONT OMCI state reaches `O5 (Operation State)`.
  5. Verify BNG PPPoE active session binding.
- **Expected Results**: ONT PON LED solid green, WAN IP assigned via IPCP, DNS resolution active.
- **Failure Scenarios**:
  - Optical RX < -27 dBm: Clean fiber connector; check ODP splitter.
  - State O3 (Serial Number Mismatch): Verify typed SN against physical sticker.
- **Rollback**: Delete OLT service port and de-register ONT.

---

## Playbook 2: ONT Replacement (Faulty Hardware Swap)

- **Preconditions**: Existing customer ONT failed QC or hardware dead; replacement ONT tested and in PASS status.
- **Required Information**: Old ONT SN, New ONT SN, Customer account ID, OLT PON port & ONU ID.
- **Safe Verification Steps**:
  1. Ensure old ONT is unplugged or powered down.
  2. Confirm new ONT firmware is up to date and clean default config loaded.
- **Procedure**:
  1. Modify ONT registration on OLT:
     - Huawei: `ont modify <port> <ont-id> sn-auth "<NEW_SERIAL>"`
     - ZTE: Delete old ONU reference and re-bind new ONU on same ID.
  2. Connect drop fiber to new ONT.
  3. Verify PON registration and optical RX/TX levels.
  4. Push customer PPPoE credentials and Wi-Fi SSID settings via ACS or manual config.
  5. Test customer connectivity and speed test.
- **Expected Results**: Service restored without altering customer BNG billing profile or IP assignments.
- **Rollback**: Revert OLT SN to old ONT if replacement unit is defective.

---

## Playbook 3: PPPoE Troubleshooting Matrix

- **Preconditions**: Customer reports "No Internet / Authentication Failed".
- **Required Information**: Customer username, PPPoE server logs, ONT WAN status.
- **Troubleshooting Steps**:
  1. Inspect BNG log for disconnect reason:
     - `auth failed`: Password mismatch or account suspended in RADIUS.
     - `peer is not responding`: L2 broadcast issue; PADI not reaching BNG.
     - `user already online`: Stale session hung on BNG. Clear active session:
       `/ppp active remove [find name="cust_user101"]`
  2. Verify VLAN tagging across path (CPE -> OLT -> Agg Switch -> BNG).
  3. Verify MTU/MRU matching (ensure MTU 1492 on CPE, 1500+ on intermediate Ethernet trunks).

---

## Playbook 4: VLAN Mismatch Diagnosis

- **Preconditions**: ONT registered (State O5), but no PPPoE PADI or DHCP discover observed at BNG.
- **Procedure**:
  1. Run packet sniffer on BNG interface filtered for customer MAC:
     `/tool sniffer quick mac-address=XX:XX:XX:XX:XX:XX`
  2. Check VLAN ID inside Ethernet header:
     - If untagged: ONT WAN port not tagging customer VLAN.
     - If tagged with wrong VID: Check OLT `tag-transform translate` rule.
  3. Check S-VLAN QinQ outer tag on Aggregation switch uplink.

---

## Playbook 5: Customer Service Suspension & Restoration

- **Suspension Procedure**:
  1. Update RADIUS attribute to `Framed-Pool=ISOLATION-POOL` or change PPP profile to Walled Garden.
  2. Terminate active session via CoA (Disconnect-Request) or BNG CLI.
  3. CPE automatically reconnects, receives RFC 6598 CGNAT IP (100.64.x.x), and HTTP is redirected to payment reminder.
- **Restoration Procedure**:
  1. Verify payment cleared in billing system.
  2. Revert RADIUS profile to standard package.
  3. Terminate walled-garden session; customer reconnects to production pool.

---

## Playbook 6: Remote Diagnostics & Wi-Fi Configuration

- **Procedure**:
  1. Query ACS for connected Wi-Fi station list:
     `GetParameterValues("Device.WiFi.AccessPoint.1.AssociatedDeviceNumberOfEntries")`
  2. Query per-station RSSI, SNR, and Tx rate.
  3. Identify channel congestion via neighbor AP scan:
     `Device.WiFi.NeighboringWiFiDiagnostic.`
  4. Adjust 2.4GHz / 5GHz channels to non-overlapping spectrum (1, 6, 11 for 2.4GHz; 36, 44, 149 for 5GHz).
  5. Verify customer client throughput without requiring on-site dispatch.
