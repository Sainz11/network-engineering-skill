# Release limitations and unverified capabilities

## Production providers

- Production authentication, credential retrieval, and external approval services are not bundled. `CredentialProvider` and `ApprovalProvider` are interfaces only. Live production operations fail closed without genuine external providers.
- `READ_ONLY` remains the default. Live `WRITE` and `CRITICAL` remain unavailable; CRITICAL approval requires two independent approvers and exact target/diff binding.
- Winbox live access is disabled unless a trusted provider attests a device-enforced READ_ONLY account and the shared identity, inventory and audit gates are satisfied. No Windows/Winbox real-world run was performed.

## Protocols and integrations

- SSH connector code enforces host-key rejection, but Paramiko is absent in the verification environment and no endpoint was tested.
- REST connector code enforces HTTPS/TLS validation; no vendor API endpoint was validated.
- Live SNMP transport is not implemented and fails closed.
- ACS connector is mock-only. No production TR-069/CWMP or TR-369/USP integration exists.
- PPPoE/IPoE, DHCP, VLAN/QinQ, GPON/EPON/XGS-PON and ONT/ONU workflows validate and record simulated requests; they do not apply provisioning.

## Module-specific boundaries

- Module 1 diagnostics/RCA are software-tested through simulated connectors; there is no authorized live device validation.
- Module 2 ACS and provisioning requests return explicitly simulated/not-applied results.
- Module 3 QC accepts validated artifact files or explicitly separate manual attestations. No physical router, optical power meter, RF instrument, or other hardware measurement was tested. XLSX generation uses optional `openpyxl`; it was tested with version 3.1.5 in this environment.
- Module 4 accepts authorized imported discovery evidence and supports mock data/parsers. No live LLDP/CDP/MNDP/SNMP/FDB collection was exercised. Reciprocal endpoint interface evidence is required for VERIFIED; conflicts are retained and downgraded.
- Vendor adapters are software/mock tested to differing degrees; no universal model or firmware compatibility is claimed. ZTE is documentation-only in the registry.

## Platform and environment limits

- Verification ran on Linux x86_64 with Python 3.13.5 and pytest 9.0.2. Windows junction, ACL, DPAPI, file-locking and Winbox UI behavior were not verified; three Windows-specific tests remain skipped.
- No physical lab router was configured; the real-router test remains skipped. No production device, ACS endpoint, or destructive command was contacted or executed.
- `requirements.txt` records the tested runtime dependency versions and `requirements-dev.txt` adds pytest. Optional live integrations such as Paramiko/SSH transport and Windows UI automation still require separately reviewed platform-specific dependencies; they are not certified by this Linux test run.
- Test and mock success proves software-path behavior only, not hardware/model/firmware compatibility or production readiness.

## Explicitly out of scope

Continuous monitoring, background polling, scheduled telemetry, and automatic alerting are excluded. Only on-demand diagnostics and explicitly requested workflows are in scope.
