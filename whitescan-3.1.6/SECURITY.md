# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 3.1.x   | Yes       |

## Authorised use only

WhiteScan is a network scanning and vulnerability assessment tool. Use it **only** on systems and networks you own or are explicitly authorised to test. Unauthorised scanning can violate criminal and civil law.

## Reporting a vulnerability

If you discover a security issue **in WhiteScan itself** (for example privilege mishandling, unsafe subprocess use, or credential leakage):

1. **Do not** open a public GitHub issue with exploit details.
2. Email the maintainers privately, or use GitHub’s private vulnerability reporting if enabled on the repository.
3. Include: affected version, reproduction steps, impact, and any suggested fix.

We aim to acknowledge reports within a reasonable time and to ship fixes for confirmed issues in a subsequent release.

## Operational risks

- **Privileges:** Live scans require root. Limit who can run the tool.
- **Credentials:** GVM passwords are stored in `~/.config/whitescan/openvas.json` (mode `0600`). Protect that file and prefer a least-privilege GVM account for automation.
- **Results:** Reports may contain hostnames, service versions, and vulnerability details. Treat output directories as sensitive.
- **Availability:** Aggressive scans (`--fullscan`, high `-T`, many workers) can stress networks and targets. Use the large-range guards and rate conservatively on production segments.
