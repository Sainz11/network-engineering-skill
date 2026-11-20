# ONT / ONU Optical Provisioning Guide

This module details GPON, EPON, and XGS-PON provisioning procedures, optical parameters, profile hierarchies, and multi-vendor OLT command sets.

---

## 1. PON Architectures & Profile Hierarchy

In ITU-T GPON (G.984) and XGS-PON (G.9807), subscriber traffic mapping follows a structured hierarchy:

```
[Customer Ethernet / Wi-Fi Traffic]
             |
   [VLAN Mapping / 802.1Q]
             |
    [GEM Port (GEM 1..32)]
             |
       [T-CONT (1..8)]   <--- Alloc-ID & DBA Dynamic Bandwidth Allocation
             |
      [PON WDM Frame]   <--- Downstream 1490nm / Upstream 1310nm
```

### Key Provisioning Concepts:
- **T-CONT (Transmission Container)**: Manages upstream bandwidth allocation. Assigned a unique Alloc-ID by the OLT. Type 1 (Fixed) to Type 5 (Mixed).
- **GEM Port (G-PON Encapsulation Method)**: Virtual transport channel within a T-CONT. Multiple VLANs can map to one or distinct GEM ports.
- **Line Profile (dba-profile / lineprofile)**: Defines DBA profiles, T-CONT mappings, and GEM port bindings.
- **Service Profile (srvprofile)**: Defines hardware capabilities of the ONT: number of POTS (FXS) ports, Ethernet ports, Wi-Fi interfaces, and CATV RF ports.
- **Registration Identifiers**:
  - **Serial Number (SN)**: 8 or 12 character vendor string + hex (e.g., `HWTC4860ABCD`, `ZTEGC1234567`).
  - **LOID / Password**: Logical ONT Identifier used for registration when SN matching is not enforced.

---

## 2. Multi-Vendor OLT Provisioning Procedures

### 2.1 Huawei MA5600T / MA5800 GPON OLT

```text
! Step 1: Discover unconfigured ONT on PON port (e.g. 0/1/0)
MA5800-X7# display ont autofind 0/1/0

! Step 2: Configure DBA Profile (Upload rate limit e.g. 50Mbps)
MA5800-X7(config)# dba-profile add profile-name DBA-50M type4 max 51200

! Step 3: Configure ONT Line Profile
MA5800-X7(config)# ont-lineprofile gpon profile-name LINE-50M
MA5800-X7(config-gpon-lineprofile-LINE-50M)# tcont 1 dba-profile-name DBA-50M
MA5800-X7(config-gpon-lineprofile-LINE-50M)# gem add 1 tcont 1
MA5800-X7(config-gpon-lineprofile-LINE-50M)# gem mapping 1 0 vlan 100
MA5800-X7(config-gpon-lineprofile-LINE-50M)# commit
MA5800-X7(config-gpon-lineprofile-LINE-50M)# quit

! Step 4: Configure ONT Service Profile (4 GE + 1 Wi-Fi)
MA5800-X7(config)# ont-srvprofile gpon profile-name SRV-4GE-WIFI
MA5800-X7(config-gpon-srvprofile-SRV-4GE-WIFI)# ont-port eth 4 pots 0
MA5800-X7(config-gpon-srvprofile-SRV-4GE-WIFI)# commit
MA5800-X7(config-gpon-srvprofile-SRV-4GE-WIFI)# quit

! Step 5: Register ONT to PON Port
MA5800-X7(config)# interface gpon 0/1
MA5800-X7(config-if-gpon-0/1)# ont add 0 1 sn-auth "4857544312345678" omci ont-lineprofile-name LINE-50M ont-srvprofile-name SRV-4GE-WIFI desc "Cust-Cust101"

! Step 6: Create Service Port (VLAN Binding)
MA5800-X7(config)# service-port vlan 100 gpon 0/1/0 ont 1 gemport 1 multi-service user-vlan 100 tag-transform translate
```

---

### 2.2 ZTE C300 / C320 / C600 OLT

```text
! Step 1: Discover unassigned ONTs
ZX-C320# show gpon onu uncfg gpon-olt_1/1/1

! Step 2: Configure Traffic Profile
ZX-C320(config)# gpon
ZX-C320(config-gpon)# profile tcont TCONT-50M type 4 maximum 51200
ZX-C320(config-gpon)# profile traffic TRF-50M sir 51200 pir 51200

! Step 3: Register ONU on Port
ZX-C320(config)# interface gpon-olt_1/1/1
ZX-C320(config-if)# onu 1 type ZTE-F670L sn ZTEG12345678

! Step 4: Configure ONU Interface & T-CONT / GEM Binding
ZX-C320(config)# interface gpon-onu_1/1/1:1
ZX-C320(config-if)# name Cust-Cust101
ZX-C320(config-if)# tcont 1 name T1 profile TCONT-50M
ZX-C320(config-if)# gemport 1 name G1 tcont 1
ZX-C320(config-if)# switchport mode trunk vport 1

! Step 5: Pon-ONU Service Port
ZX-C320(config)# pon-onu-mng gpon-onu_1/1/1:1
ZX-C320(gpon-onu-mng)# service 1 gemport 1 vlan 100
ZX-C320(gpon-onu-mng)# vlan port eth_0/1 mode tag vlan 100
```

---

### 2.3 VSOL / CDATA / FiberHome / Nokia OLT Summary

- **VSOL (V1600G Series)**:
  - Supports automatic profile binding via WebGUI and CLI.
  - CLI: `ont add <port> <ont-id> sn-auth <SN> loid <LOID> loid-password <PASS>`.
  - Allows Native VLAN untagging directly on ONU LAN ports.
- **CDATA (FD1600 Series)**:
  - Configuration uses `epon/gpon onu-config` contexts.
  - Optical power verification via `show gpon optical-power port <pon-port> onu <onu-id>`.
- **FiberHome (AN5516 Series)**:
  - Managed via ANM2000 / UNM2000 NMS and Telnet CLI (`cd slot/port`, `set onu add ...`).
  - Strict LOID and LOID-password authorization is standard.
- **Nokia (ISAM 7360 FX)**:
  - Uses `configure equipment ont` and `interface pon` hierarchy.
  - Assigns `qos-profile` and `vlan bridge-port` definitions.

---

## 3. Bridge Mode vs. Router Mode on ONT

| Feature | Bridge Mode | Router Mode |
| :--- | :--- | :--- |
| **L3 Routing / NAT** | Performed on customer router (e.g. MikroTik/PC) | Performed directly by the ONT CPU |
| **PPPoE Termination** | Downstream Customer Router / Firewall | ONT WAN Interface |
| **Wi-Fi Handling** | Handled by downstream AP or disabled | Built-in ONT WLAN radio handles NAT/DHCP |
| **ISP Maintenance** | Transparent L2; low ONT CPU load | Requires TR-069/OMCI management of PPPoE & LAN |
| **Port Forwarding** | Direct control on customer router | Must be configured on ONT NAT table |

---

## 4. Optical Power Standards & Safety Thresholds

> [!IMPORTANT]
> Never guess optical thresholds. ITU-T Class B+ and Class C+ define exact operating budgets.

| Optical Class | OLT TX Range (1490nm) | ONT RX Sensitivity | ONT Overload Margin | Acceptable Operational RX |
| :--- | :--- | :--- | :--- | :--- |
| **Class B+** | +1.5 to +5.0 dBm | -27.0 dBm | -8.0 dBm | **-15.0 to -24.0 dBm** |
| **Class C+** | +3.0 to +7.0 dBm | -30.0 dBm | -8.0 dBm | **-16.0 to -26.0 dBm** |
| **XGS-PON (N1/N2)**| +4.0 to +9.0 dBm | -28.0 dBm | -9.0 dBm | **-14.0 to -25.0 dBm** |

### Optical Alarm Diagnostics:
- **RX < -27 dBm (Weak Optical Power)**: Check for dirty fiber connectors, excessive bend radius, splitters cascading (>1:64), or damaged drop cable.
- **RX > -8 dBm (Optical Overload)**: Risk of damaging optical receiver photodiode. Add optical attenuator (5dB / 10dB) immediately.
- **LOS (Loss of Signal)**: Fiber severed, disconnected at distribution point (ODP/ODC), or feeder cut.
- **LOF (Loss of Frame)**: Optical power detected but synchronization failed; potential dirty connector or wavelength mismatch.
