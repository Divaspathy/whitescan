# Changelog

All notable changes to this project are documented in this file.

## [3.1.6] - 2026-11-03

### Fixed
- Large-range + `--fullscan`/`--scriptscan` guard was a no-op under `--yes` because `confirm()` always returned true; forced prompts now ignore `--yes`, and non-interactive runs refuse that combination.
- Resume could crash when a report lacked `openvas_session` (`_load_openvas_section(None)` unpack).
- Abort only took effect before nmap started; discovery and port scans now notice `ABORT` while nmap is quiet (select-based IO).
- Help text showed the literal `{LARGE_RANGE}` instead of `4096`.

### Changed
- Codebase split into an installable package (`whitescan/`) with a thin launcher.
- `--setup` installs the package under `<prefix>/lib/whitescan` plus a bin launcher.
- Packaging metadata: `pyproject.toml`, CI workflow, unit tests for pure logic.

## [3.1.5] - prior

- Safer nmap / discovery error handling (`OSError`, partial XML warnings).
- KeepAwake tracks which settings it actually changed.
- Large-range constant and aggressive-profile warning path introduced.
- OpenVAS section load helper refinements.

## [3.1.4] - prior

- Baseline single-file release used for the modular split.
