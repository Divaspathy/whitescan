# WhiteScan

**ARP discovery → nmap port/service scan → optional OpenVAS (GVM) vulnerability scan.**

WhiteScan is a root-oriented network assessment toolkit for **networks you own or are explicitly authorised to test**. It discovers live hosts on a segment, runs nmap with configurable depth, and can hand targets to OpenVAS/GVM for vulnerability assessment. Results land in one timestamped folder (JSON + readable text + raw XML).

> **Legal / ethics:** Only scan systems and networks you are authorised to assess. Unauthorised scanning may be illegal. You are responsible for compliance with local law and your organisation’s policy.

## Features

- Adaptive host discovery (ARP on the local L2 segment; ICMP/TCP probes when routed)
- Merges nmap discovery with the kernel neighbour table
- Scan profiles: `--quick`, `--scan`, `--fullscan`, `--scriptscan` (overridable field-by-field)
- Parallel nmap workers (`-w 1..8`)
- Optional OpenVAS/GVM stage with stored credentials (no passwords on the command line)
- Resume interrupted nmap runs (`--resume`)
- OpenVAS-only mode against IPs or a previous results directory
- Abort-aware process handling; partial results are saved
- Sleep / screen / Wi‑Fi power-save inhibit while a scan runs
- Large-range + aggressive-profile guard (even with `--yes`)

## Requirements

| Component | Notes |
|-----------|--------|
| **Python** | 3.10+ recommended |
| **OS** | Linux (uses `ip`, nmap, optional `systemd-inhibit`, `xset`, `iw`) |
| **nmap** | Required for discovery and port scans |
| **root** | Required for live scanning (`sudo`); OpenVAS-only needs GVM socket access |
| **python-gvm** | Optional; only needed for OpenVAS integration |

```bash
# Debian / Ubuntu
sudo apt update
sudo apt install -y nmap python3 python3-pip
# Optional OpenVAS client library
pip3 install --user python-gvm
```

OpenVAS/GVM itself is separate (e.g. a local GVM install with `gvmd` and the default Unix socket).

## Install

### From a git clone (recommended for development)

```bash
git clone https://github.com/YOUR_USER/whitescan.git
cd whitescan

# Optional: library for OpenVAS
pip3 install -r requirements.txt

# One-time: install launcher onto sudo's PATH and store GVM credentials
sudo ./whitescan.py --setup
```

`sudo whitescan --setup` installs:

- the `whitescan` package under `<prefix>/lib/whitescan`
- a launcher at `<prefix>/bin/whitescan` (typically `/usr/bin/whitescan`)

Credentials are written to `~/.config/whitescan/openvas.json` (mode `0600`), resolved against `$SUDO_USER`'s home when run via sudo.

### Editable / venv install (pip)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[openvas]"   # or: pip install -e .
whitescan --version
```

Live network scanning still needs root (e.g. `sudo $(which whitescan) -i wlan0 --quick --yes`).

## Quick start

```bash
# Interactive
sudo whitescan

# Fast top-1000 ports, no OpenVAS
sudo whitescan -i wlan0 --quick --yes --no-openvas

# Top-1000 + service/OS detection, then OpenVAS on hosts with open ports
sudo whitescan -i wlan0 --scan --openvas open --yes

# Full TCP port space + service/OS detection
sudo whitescan -i wlan0 --fullscan --yes --no-openvas

# OpenVAS only (skip nmap)
sudo whitescan --openvas-only 192.168.2.1
sudo whitescan --openvas-only ./whitescan_results/<run_dir>
```

### Resuming

Ctrl-C during the nmap stage saves partial results:

```bash
sudo whitescan --resume ./whitescan_results/<run_dir>
```

Finished hosts are skipped. Orphaned OpenVAS tasks on the GVM server are **not** auto-resumed; WhiteScan prints the task id and `gvm-cli` commands to inspect or stop them.

## Output layout

```
./whitescan_results/<timestamp>_<iface>/
    scan_report.txt      # human-readable
    scan_report.json     # machine-readable
    raw/                 # nmap + GVM XML
    logs/whitescan.log
```

Override the root with `-o` / `--output-dir`.

## Configuration

OpenVAS credentials (created by `--setup` only):

```json
{
  "gvm_socket": "/run/gvmd/gvmd.sock",
  "username": "admin",
  "password": "..."
}
```

- No runtime password flags (they would leak via `ps`).
- Prefer a dedicated GVM user with scan-only privileges for automation.
- File mode `0600`; config directory mode `0700`.

## CLI overview

```text
whitescan [--quick|--scan|--fullscan|--scriptscan]
          [-i IFACE] [--cidr NET] [--targets IP[,IP...]]
          [--openvas open|all|IP[,IP...] | --no-openvas]
          [--openvas-only DIR_OR_IPS] [--resume DIR]
          [-T 0-5] [-w N] [--gvm-timeout SEC] [-y] ...
```

| Flag | Purpose |
|------|---------|
| `--quick` | Top 1000 ports only |
| `--scan` | Top 1000 + `-sV` + `-O` |
| `--fullscan` | All ports + `-sV` + `-O` |
| `--scriptscan` | All ports + `-sV` + `-O` + `-sC` |
| `--openvas open` | OpenVAS on hosts that had open ports |
| `--openvas all` | OpenVAS on every live host |
| `--no-openvas` | Never run OpenVAS |
| `-y` / `--yes` | Non-interactive defaults (large aggressive scans still require a TTY confirm) |

See `whitescan --help` for the full reference.

## Development

```bash
git clone https://github.com/YOUR_USER/whitescan.git
cd whitescan
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python3 -m unittest discover -s tests -v
```

Package layout:

```text
whitescan.py           # thin launcher for source checkouts
whitescan/             # installable package
  cli.py               # argparse + scan orchestration
  network.py           # interfaces, discovery, ARP
  nmap_stage.py        # nmap execution + XML parse
  openvas.py           # GVM integration
  report.py            # JSON/text reports
  process.py           # abort-aware subprocess IO
  keep_awake.py        # sleep / DPMS inhibit
  setup_cmd.py         # --setup
  util.py, paths.py, constants.py
tests/
```

## Security notes

- Runs privileged operations; treat the host and the results directory as sensitive.
- GVM password is stored **locally in plaintext** under `~/.config/whitescan/` (mode `0600`). Restrict filesystem access accordingly.
- Results may contain hostnames, service versions, and vulnerability details. Treat output directories as sensitive.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

This software is provided as-is for defensive security assessment and education. The authors are not responsible for misuse or damage arising from its use.
