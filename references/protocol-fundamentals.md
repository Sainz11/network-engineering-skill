# Protocol and Network Fundamentals

## Layer 2
Ethernet framing, MAC learning, access/trunk ports, 802.1Q VLAN tags, STP/RSTP/MSTP, LACP, LLDP, MTU, broadcast domains, loop prevention.

## Layer 3
IPv4/IPv6 addressing, subnetting, ARP/ND, static routing, OSPF/BGP concepts, default routes, route preference, VRF, ICMP, PMTUD.

## Services
DHCP scopes/relay, DNS resolution, NTP, PPPoE discovery/session, NAT/PAT, ACL/firewall state, QoS classification/queuing/shaping/policing.

## Operations
SNMPv3 preferred where supported, syslog, streaming telemetry, interface counters, CPU/memory, config backup, NMS, alert thresholds, time synchronization.

## Troubleshooting order
Physical/link -> L2/VLAN -> IP addressing/ARP -> routing -> DNS/services -> policy/NAT -> application. Validate each layer before moving upward.
