# Changelog

## Audit/remediation release
- Added capability registry with conservative statuses and defensive-copy APIs.
- Changed unsupported vendor selection to fail closed.
- Added ping parameter validation and injection-oriented tests.
- Added required documentation set and repository audit/implementation matrix.
- Preserved existing code, tests, QC profiles, and historical QC records.

## Previous baseline
See existing README and project history; this ZIP contains no Git history for reconstruction.

## Release-candidate verification pass
- Re-ran the complete suite from a clean extraction: 202 passed, 5 skipped, 45 subtests passed.
- Re-ran Python compile check successfully.
- Added tested dependency manifests (`requirements.txt`, `requirements-dev.txt`).
- Replaced stale verification counts with exact current run data and explicit production blockers.
- Preserved fail-closed boundaries for unavailable production providers and live protocols.
- Fixed QC ETH-01 so measured Ethernet rates must parse and match the model profile; unsupported rates fail and ambiguous rates require review, even when a caller supplies a PASS status.
- Added regression coverage for out-of-profile and ambiguous Ethernet measurements, Skill mirror consistency, monitoring exclusion, and dependency manifests.
- Added a reproducible installation path using the tested runtime and development dependency manifests.
