# ISP Network Provisioning Engineering Guide

This guide provides technical architectures, configuration workflows, and verification standards for provisioning residential and commercial broadband services.

---

## 1. Access Architecture Overview

Modern ISP access networks deliver broadband connectivity via **PPPoE** (Point-to-Point Protocol over Ethernet) or **IPoE** (IP over Ethernet / DHCP Option 82) over GPON/EPON/Metro-Ethernet infrastructures.

```
+-------------------+       +--------------------+       +----------------------+       +------------------+
| Customer Premise  |       | Optical Line Term  |       | Aggregation Switch   |       | Broadband Remote |
| (CPE / ONT Router)| ----> | (OLT GPON/XGS-PON) | ----> | (Metro Ethernet L2)  | ----> | Access Server    |
| PPPoE / IPoE      |       | QinQ / VLAN Map    |       | S-VLAN / C-VLAN      |       | (BNG / BRAS)     |
+-------------------+       +--------------------+       +----------------------+       +------------------+
```

---

## 2. PPPoE Provisioning Workflows

### 2.1 PPPoE Architecture & Protocol Stages
PPPoE operates across two distinct phases:
1. **PPPoE Discovery Stage (Ethertype 0x8863)**:
   - **PADI** (PPPoE Active Discovery Initiation): Broadcast sent by CPE to locate access concentrator.
   - **PADO** (PPPoE Active Discovery Offer): Unicast response from BNG with Service-Name and AC-Name.
   - **PADR** (PPPoE Active Discovery Request): CPE sends unicast session request to chosen AC.
   - **PADS** (PPPoE Active Discovery Session-confirmation): BNG assigns unique 16-bit `Session_ID`.
2. **PPP Session Stage (Ethertype 0x8864)**:
   - **LCP** (Link Control Protocol): Negotiates MTU/MRU (default 1492 bytes; or RFC 4638 1500 bytes with baby jumbo frames), authentication protocol (CHAP/PAP).
   - **Authentication**: CHAP challenge/response authenticated against RADIUS (RFC 2865).
   - **IPCP / IP6CP**: Negotiates IPv4 default gateway, DNS servers, and IPv6 Prefix Delegation (DHCPv6 PD via RFC 3633).

---

### 2.2 Vendor BNG & Concentrator Configurations

#### MikroTik RouterOS v7 PPPoE Server
```routeros
# 1. Create IP Pools
/ip pool add name=POOL-PPPOE-RESI ranges=100.64.10.2-100.64.10.254

# 2. Configure Profile with Rate-Limiting & Redacted Secrets
/ppp profile add name=PROFILE-50M \
    local-address=100.64.10.1 \
    remote-address=POOL-PPPOE-RESI \
    dns-server=1.1.1.1,8.8.8.8 \
    rate-limit="50M/50M" \
    only-one=yes \
    change-tcp-mss=yes

# 3. Enable PPPoE Server on Dedicated Service VLAN
/interface pppoe-server server add \
    service-name="ISP-INTERNET" \
    interface=vlan100-customers \
    max-mtu=1492 \
    max-mru=1492 \
    default-profile=PROFILE-50M \
    authentication=chap,mschap2 \
    disabled=no

# 4. PPPoE Secret Provisioning (Redacted for documentation)
/ppp secret add \
    name="cust_user101" \
    password="<REDACTED_PASSWORD>" \
    profile=PROFILE-50M \
    service=pppoe \
    comment="Ticket #9901 - Subscribed 50M Residential"
```

#### Cisco IOS-XE / BNG BBA-Group
```cisco
! 1. Define BBA Group
bba-group pppoe RESIDENTIAL-PPPOE
 virtual-template 1
 sessions per-mac limit 1
 sessions per-vlan limit 1000

! 2. Configure Virtual-Template
interface Virtual-Template1
 ip unnumbered Loopback0
 ip mtu 1492
 peer default ip address pool RESI-POOL-01
 ppp authentication chap
 ppp ipcp dns 1.1.1.1 8.8.8.8
 ppp ipcp mroute default

! 3. Apply PPPoE Enablement on Customer Service Sub-interface
interface GigabitEthernet0/0/1.100
 encapsulation dot1Q 100
 pppoe enable group RESIDENTIAL-PPPOE
```

#### Huawei SmartAX MA5800 / NE40E BRAS Provisioning
```text
# Domain & Radius AAA Configuration
aaa
 domain isp.net
  authentication-scheme auth_chap
  accounting-scheme acc_radius
  radius-server group RADIUS-SRV
  ip-pool RESI-POOL-1

# Interface Virtual-Template Binding
interface Virtual-Template 1
 ppp authentication-mode chap
 ppp ipcp dns 1.1.1.1 8.8.8.8
 mtu 1492
```

---

## 3. IPoE & DHCP Relay Provisioning

IPoE eliminates PPP encapsulation overhead and simplifies dual-stack deployment.

### 3.1 DHCP Option 82 (Relay Agent Information Option)
- **Sub-option 1 (Circuit-ID)**: Encodes physical port/chassis, slot, port, and ONT ID (e.g., `eth 0/1/2:1`).
- **Sub-option 2 (Remote-ID)**: Encodes customer account ID or subscriber identifier.

### 3.2 MikroTik DHCP Relay Configuration
```routeros
/ip dhcp-relay add \
    name=RELAY-OLT-PON1 \
    interface=vlan200-ipoe \
    dhcp-server=10.10.0.50 \
    local-address=10.200.0.1 \
    add-relay-info=yes \
    delay-threshold=none \
    disabled=no
```

---

## 4. VLAN Architecture: C-VLAN, S-VLAN & QinQ (802.1ad)

In carrier networks, VLAN exhaustion (4094 limits) is avoided using IEEE 802.1ad (QinQ / VLAN Stacking).

- **Customer VLAN (C-VLAN)**: Tag assigned at CPE/ONT (e.g., VLAN 10 for Internet, VLAN 20 for IPTV, VLAN 30 for VoIP). Ethertype `0x8100`.
- **Service VLAN (S-VLAN)**: Outer tag added by OLT/Agg switch representing PON port or distribution area. Ethertype `0x88A8` (or standard `0x8100`).

```
+-------------------------------------------------------------+
| Standard Ethernet Frame (Payload)                           |
+-------------------------------------------------------------+
| C-VLAN Tag: VID=10 (Internet), TPID=0x8100                  |
+-------------------------------------------------------------+
| Outer S-VLAN Tag: VID=100 (PON Slot 1), TPID=0x88A8 / 0x8100|
+-------------------------------------------------------------+
```

### QinQ Configuration Example (MikroTik RouterOS)
```routeros
# Outer Service VLAN
/interface vlan add name=s-vlan100 vlan-id=100 interface=sfp-sfpplus1

# Inner Customer VLAN riding on top of S-VLAN
/interface vlan add name=c-vlan10-cust01 vlan-id=10 interface=s-vlan100
```

---

## 5. Provisioning Verification & Health Check Commands

| Vendor | Command | Purpose |
| :--- | :--- | :--- |
| **MikroTik** | `/ppp active print detail where name="<username>"` | Verify active session, IP, uptime, bytes |
| **MikroTik** | `/interface print stats where name~"pppoe"` | Check interface RX/TX and dropped frames |
| **Cisco** | `show pppoe session [all \| interface]` | Display active PPPoE sessions and Virtual-Access bindings |
| **Cisco** | `show subscriber session username <user>` | Inspect BRAS subscriber policy and traffic policing |
| **Huawei** | `display access-user username <user>` | Check BRAS online status, assigned IP, and rate limit |
| **Huawei OLT** | `display ont info <frame> <slot> <port> <ont-id>` | Verify OMCI state, line profile, and serial match |

---

## 6. Deprovisioning & Suspension Procedures
1. **Administrative Disconnect**: Terminate active PPP session without removing customer profile (`/ppp active remove [find name="..."]`).
2. **Walled Garden / Payment Redirection**: Change PPP profile assignment to restricted IP pool with destination NAT redirecting TCP/80/443 traffic to the billing portal.
3. **Hard Port Deactivation**: Disable ONT service port or downstream switch port via NMS.
