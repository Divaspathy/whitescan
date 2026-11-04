# WhiteScan

**ARP discovery → Nmap port/service scan → optional OpenVAS (GVM) vulnerability scan.**

WhiteScan is a root-oriented network assessment toolkit for **networks you own or are explicitly authorised to test**. It discovers live hosts on a segment, runs Nmap with configurable scan depth, and can hand targets to OpenVAS/GVM for vulnerability assessment.

Results are saved in a timestamped directory containing JSON, readable text, and raw XML output.

> **Legal / ethics:** Only scan systems and networks you are authorised to assess. Unauthorised scanning may be illegal. You are responsible for complying with local laws and your organisation's policies.

## Features

- Adaptive host discovery (ARP on the local L2 segment; ICMP/TCP probes when routed)
- Merges Nmap discovery with the kernel neighbour table
- Scan profiles: `--quick`, `--scan`, `--fullscan`, `--scriptscan`
- Field-by-field scan profile overrides
- Parallel Nmap workers (`-w 1..8`)
- Optional OpenVAS/GVM integration with stored credentials
- Resume interrupted Nmap runs (`--resume`)
- OpenVAS-only mode against IPs or previous results directories
- Abort-aware process handling; partial results are saved
- Sleep, screen, and Wi-Fi power-save inhibition during scans
- Large-range and aggressive-profile safeguards

## Requirements

| Component | Notes |
|---|---|
| Python | 3.10+ recommended |
| OS | Linux |
| Nmap | Required for host discovery and port scanning |
| Root privileges | Required for live network scanning |
| python-gvm | Optional; required for OpenVAS integration |
| OpenVAS/GVM | Optional; must be installed and configured separately |

WhiteScan may use `ip`, `systemd-inhibit`, `xset`, and `iw` when available.

### Install system dependencies

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip nmap
```

OpenVAS/GVM itself is separate and requires a working GVM installation with `gvmd` and an accessible Unix socket.

## Installation

### From GitHub (Kali Linux / Debian)

#### 1. Clone the repository

```bash
git clone https://github.com/Divaspathy/whitescan.git
cd whitescan/whitescan-3.1.6
```

#### 2. Create a Python virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### 3. Install WhiteScan

For OpenVAS integration:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[openvas]"
```

Without OpenVAS integration:

```bash
python3 -m pip install -e .
```

#### 4. Configure WhiteScan

```bash
sudo "$(pwd)/.venv/bin/python3" whitescan.py --setup
```

Follow the prompts to configure the OpenVAS/GVM credentials.

The setup command installs:

- The WhiteScan package under the configured installation prefix
- The `whitescan` launcher
- OpenVAS/GVM credentials in the user's configuration directory

Credentials are stored in:

```text
~/.config/whitescan/openvas.json
```

The configuration file uses permissions `0600`, and the directory uses `0700`.

#### 5. Verify the installation

```bash
whitescan --help
whitescan --version
```

WhiteScan is now ready to use.

### OpenVAS/GVM

OpenVAS/GVM is optional and must be installed and configured separately.

The Python `openvas` extra installs the client library, not the GVM server.

### Updating

```bash
cd whitescan/whitescan-3.1.6
git pull

source .venv/bin/activate
python3 -m pip install -e ".[openvas]"
```

### Uninstalling

If installed using the default `/usr` prefix:

```bash
sudo rm -f /usr/bin/whitescan
sudo rm -rf /usr/lib/whitescan
```

Remove the local virtual environment from the project directory:

```bash
rm -rf .venv
```

If you used a custom installation prefix, remove the corresponding launcher and package from that prefix instead.

## Quick Start

### Interactive scan

```bash
sudo whitescan
```

### Quick scan (top 1000 ports, no OpenVAS)

```bash
sudo whitescan -i wlan0 --quick --yes --no-openvas
```

### Service and OS detection with OpenVAS

```bash
sudo whitescan -i wlan0 --scan --openvas open --yes
```

### Full TCP port scan

```bash
sudo whitescan -i wlan0 --fullscan --yes --no-openvas
```

### OpenVAS-only scan

```bash
sudo whitescan --openvas-only 192.168.2.1
```

Against a previous results directory:

```bash
sudo whitescan --openvas-only ./whitescan_results/<run_dir>
```

Replace `<run_dir>` with the actual directory name.

## Resuming Scans

Press `Ctrl+C` during the Nmap stage to save partial results.

Resume the scan using:

```bash
sudo whitescan --resume ./whitescan_results/<run_dir>
```

Finished hosts are skipped.

Orphaned OpenVAS tasks on the GVM server are **not automatically resumed**. WhiteScan prints the task ID and `gvm-cli` commands to inspect or stop them.

## Output Layout

```text
whitescan_results/
└── <timestamp>_<iface>/
    ├── scan_report.txt
    ├── scan_report.json
    ├── raw/
    │   └── Nmap and GVM XML files
    └── logs/
        └── whitescan.log
```

Override the output directory using `-o` or `--output-dir`.

## Configuration

OpenVAS credentials are created by `--setup`.

Example configuration:

```json
{
  "gvm_socket": "/run/gvmd/gvmd.sock",
  "username": "admin",
  "password": "..."
}
```

- No runtime password flags are used, avoiding exposure through process listings.
- Prefer a dedicated GVM user with scan-only privileges.
- Credentials are stored locally in plaintext with restrictive file permissions.
- Protect the configuration directory and scan results.

## CLI Overview

```text
whitescan [--quick|--scan|--fullscan|--scriptscan]
          [-i IFACE] [--cidr NET] [--targets IP[,IP...]]
          [--openvas open|all|IP[,IP...] | --no-openvas]
          [--openvas-only DIR_OR_IPS] [--resume DIR]
          [-T 0-5] [-w N] [--gvm-timeout SEC] [-y] ...
```

| Flag | Purpose |
|---|---|
| `--quick` | Top 1000 ports only |
| `--scan` | Top 1000 ports with service and OS detection |
| `--fullscan` | All TCP ports with service and OS detection |
| `--scriptscan` | All TCP ports with service detection, OS detection, and default scripts |
| `--openvas open` | OpenVAS on hosts with open ports |
| `--openvas all` | OpenVAS on every live host |
| `--no-openvas` | Disable OpenVAS |
| `-y`, `--yes` | Non-interactive defaults |

See `whitescan --help` for the complete command reference.

## Development

Clone the repository:

```bash
git clone https://github.com/Divaspathy/whitescan.git
cd whitescan/whitescan-3.1.6
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install development dependencies:

```bash
python3 -m pip install -e ".[dev]"
```

Run tests:

```bash
python3 -m unittest discover -s tests -v
```

### Package Layout

```text
whitescan-3.1.6/
├── whitescan.py
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── whitescan/
│   ├── cli.py
│   ├── network.py
│   ├── nmap_stage.py
│   ├── openvas.py
│   ├── report.py
│   ├── process.py
│   ├── keep_awake.py
│   ├── setup_cmd.py
│   ├── util.py
│   ├── paths.py
│   └── constants.py
└── tests/
```

## Security Notes

- WhiteScan performs privileged operations. Treat the host and results directory as sensitive.
- GVM passwords are stored locally in plaintext under `~/.config/whitescan/`, protected by restrictive permissions.
- Scan results may contain hostnames, service versions, and vulnerability details.
- Use a dedicated GVM account with minimal required privileges where possible.

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

This software is provided as-is for defensive security assessment and education. The authors are not responsible for misuse or damage arising from its use.
