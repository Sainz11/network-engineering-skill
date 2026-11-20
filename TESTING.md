# Testing

Run from repository root:

```bash
python -m pytest -q -rs
python -m compileall -q engine scripts tests
```

Tests use mocks for connectors and simulated device behavior. Hardware tests are opt-in (e.g. `LAB_MIKROTIK_IP`) and must be reported separately. Windows-only junction and ACL tests are skipped on Linux and must be executed on Windows to verify those controls. Packaging checks run against an archive once a release ZIP exists.

Do not equate a mock test pass with live connector or physical device verification.
