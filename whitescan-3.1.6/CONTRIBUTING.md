# Contributing to WhiteScan

Thanks for your interest in improving WhiteScan.

## Ground rules

- Only propose features and tests that support **authorised** defensive assessment.
- Do not contribute code whose primary purpose is concealment from defenders or violation of law.
- Keep changes focused; open an issue first for large redesigns.

## Development setup

```bash
git clone https://github.com/Divaspathy/whitescan.git
cd whitescan
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python3 -m unittest discover -s tests -v
```

System tools for full end-to-end scans: `nmap`, `iproute2`. OpenVAS tests that talk to GVM need a live GVM instance and are not required for the pure-logic unit suite.

## Code style

- Python 3.10+, standard library preferred over new dependencies.
- Match existing module boundaries (`network`, `nmap_stage`, `openvas`, `report`, `process`, …).
- No passwords on the command line; keep credential handling in `--setup` / config file.
- Prefer explicit error messages and safe handling of partial scan results.

## Pull requests

1. Branch from `main` (or the default branch).
2. Add or update unit tests for pure logic you change.
3. Run `python3 -m unittest discover -s tests -v`.
4. Describe the problem, the approach, and any residual risk (especially around process lifecycle, resume, or GVM cleanup).

## Reporting bugs

Use GitHub Issues for functional bugs and docs gaps. For security issues in the tool itself, see [SECURITY.md](SECURITY.md).
