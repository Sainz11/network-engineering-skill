# Modems, ONT and ONU

## Technology families
- Fiber: GPON, EPON, XGS-PON
- DSL: ADSL, ADSL2+, VDSL
- Cellular: 4G LTE and 5G CPE
- Cable/broadband modem where deployed

## Functional checks
Power; optical/DSL/cellular state; registration; WAN mode; VLAN; PPPoE/IPoE; IP assignment; routing/bridge; DHCP; NAT; DNS; LAN ports; Wi-Fi; firmware; remote management.

## Optical/PON diagnosis
Check LOS/LOF, PON registration, serial/LOID, OMCI, optical readings, connector cleanliness records, and OLT-side status where authorized. Compare values to exact vendor/operator limits. Never diagnose solely from LED color.

## QC caution
Do not factory-reset a provisioned customer ONT/ONU. A reset may erase service credentials or operator provisioning.
