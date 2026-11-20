# Connectors

| Connector | Code | Status | Operations / safeguards |
|---|---|---|---|
| SSH | `engine/connectors/ssh_connector.py` | Implemented; mock/security tested | RejectUnknown host-key policy; timeout; command syntax restrictions; WRITE/CRITICAL gates |
| REST | `rest_connector.py` | Implemented; tests | HTTPS, certificate validation, endpoint restrictions, write gate |
| SNMP | `snmp_connector.py` | Live transport not implemented | Fails closed; mock/simulation only |
| Mock | `mock_connector.py` | Implemented | Test/simulation only |
| Winbox | `engine/winbox` | Partial integration | Credential-safe wrappers and UI automation; Windows/live verification unavailable |
| ACS | `scripts/acs_integration` | Interface + mock | No real ACS implementation or endpoint verified |

Live operations additionally require inventory credentials, trusted auth, approval for changes, and device/environment verification. Retry is not assumed safe for writes.
