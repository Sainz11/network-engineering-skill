# Microwave and Tower-to-Tower Backhaul

## Architecture vocabulary
IDU, ODU, RFU, antenna, feeder/waveguide (platform-dependent), branching, coupler, PoE/Ethernet, protection, synchronization, NMS.

## Planning inputs
Site coordinates and elevations; antenna heights; frequency pair/channel; channel bandwidth; polarization; antenna diameter/gain; cable/feeder losses; terrain and path profile; climate/rain region; target capacity and availability; licensed spectrum assignment.

## Engineering checks
- Confirm licensed vs unlicensed spectrum and local authorization.
- Verify LoS and Fresnel clearance; evaluate diffraction, reflections, and path obstruction.
- Calculate path loss, received signal level, fade margin, and availability using approved engineering methods.
- Validate modulation and ACM behavior, ATPC, XPIC, 1+1 protection, capacity, and synchronization only where supported.
- Validate Ethernet/IP/MPLS handoff, VLAN/QinQ, QoS, MTU, LAG/protection, and routing design.
- Check NMS reachability, alarms, event logs, performance counters, and configuration backup.

## Operational diagnosis
Compare both ends: RSL, modulation, errors, alarms, temperature, power, sync, Ethernet counters, and traffic. Correlate changes with weather, interference, maintenance, and configuration changes.

This file is a planning checklist, not a substitute for a licensed link design or vendor engineering software.
