# Installation

Python 3.10+ is required.

Install the tested runtime dependencies:

```bash
python -m pip install -r requirements.txt
```

For local development and regression testing:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q -rs
python -m compileall -q engine scripts tests
```

Optional live SSH support requires Paramiko and must be separately installed and validated. Windows users must validate Winbox/UI automation and ACL/DPAPI flows on a supported Windows host. No Windows verification is claimed by this release audit.

Do not store secrets in repository `.env` files or inventory fixtures. Configure production identity, credential, and approval integrations separately; until genuine providers are available, live operations requiring them remain disabled.
