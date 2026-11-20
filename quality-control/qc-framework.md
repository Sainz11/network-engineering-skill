# Device QC Framework

## Status
- PASS: every mandatory check passed with evidence.
- FAIL: one or more mandatory checks failed.
- NEEDS REVIEW: test unavailable, evidence incomplete, or engineering judgement required.

## Required record
Date/time; technician; device category; brand/model; hardware revision; serial (store securely); firmware; test environment; power supply/PoE; test steps; measured results; evidence; findings; final status.

## General inspection
1. Verify model/label/serial against work order.
2. Inspect enclosure, ports, connectors, antenna, mounting parts, and power supply.
3. Power on with approved supply; observe boot and alarms.
4. Verify management access using authorized credentials.
5. Check firmware and configuration without changing production state.
6. Test interfaces and negotiated rates against datasheet.
7. Run functional tests in an isolated/approved environment.
8. Save logs/evidence and complete report.

## Rules
No unauthorized reset, firmware upgrade, config wipe, stress test, or live customer interruption. Use model-specific acceptance criteria.
