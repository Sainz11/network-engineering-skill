# MikroTik

## Families to recognize
- Routers: hEX RB750Gr3, hAP lite RB941-2nD, hAP ac², hAP ax², RB760iGS, RB4011 and other RB/hAP models.
- Switching: CRS/CSS families.
- Wireless: wAP, QRT 5/QRT 5 ac, LHG, SXTsq 5 ac, NetMetal, mANTBox.
- LTE/5G models where supported.

## Verify before giving commands
RouterOS version, architecture, exact model/revision, interface names, bridge/VLAN design, hardware offload, wireless package/driver generation, license level, and PoE input/output support.

## QC notes
- Read model datasheet: interface count/rate, wireless bands, antenna, PoE, power supply.
- hEX RB750Gr3 is a five-port Gigabit Ethernet router; hAP lite RB941-2nD has Fast Ethernet ports and 2.4 GHz wireless. Do not apply Gigabit pass criteria to Fast Ethernet hardware.
- Check link negotiation, interface errors, CPU/memory, temperature if exposed, reset-button condition, power stability, and configuration backup.
- Never assume RouterOS v6 and v7 CLI syntax or feature parity.
