# WhiteScan

**ARP Discovery → Nmap Scanning → Optional OpenVAS/GVM Vulnerability Assessment**

WhiteScan is a root-oriented network assessment toolkit for Linux. It discovers live hosts, scans ports and services using Nmap, and optionally performs vulnerability assessments through Greenbone Vulnerability Manager (GVM), formerly known as OpenVAS.

WhiteScan is designed for networks and systems you own or are explicitly authorized to test.

## Features

- **Adaptive host discovery:** ARP on the local network segment, with ICMP/TCP probes when routed.
- **Neighbour table integration:** Combines Nmap discovery results with the kernel neighbour table.
- **Multiple scan profiles:** Quick, standard, full TCP port, and script scanning.
- **Customizable scans:** Override individual scan settings.
- **Parallel scanning:** Run multiple Nmap workers (`-w 1..8`).
- **OpenVAS integration:** Send discovered hosts to GVM for vulnerability assessment.
- **Resume support:** Continue interrupted Nmap scans using `--resume`.
- **OpenVAS-only mode:** Scan IP addresses or hosts from previous result directories.
- **Partial result recovery:** Saves available results when a scan is interrupted.
- **Power management:** Inhibits sleep, screen blanking, and Wi-Fi power saving during scans when supported.
- **Safety checks:** Includes safeguards for large network ranges and aggressive scan profiles.
- **Detailed reports:** Saves JSON, readable text, raw XML, and logs.

## Requirements

| Component | Requirement |
|---|---|
| Operating system | Linux |
| Python | 3.10+ recommended |
| Nmap | Required |
| Root privileges | Required for live network scanning |
| python-gvm | Optional; required for GVM integration |
| OpenVAS/GVM | Optional; install separately |

WhiteScan may also use `ip`, `systemd-inhibit`, `xset`, and `iw` when available.

## Installation

### 1. Install system dependencies

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip nmap
```

### 2. Clone the repository

```bash
git clone https://github.com/Divaspathy/whitescan.git
cd whitescan/whitescan-3.1.6
```

### 3. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Install WhiteScan

For OpenVAS integration:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[openvas]"
```

Without OpenVAS integration:

```bash
python3 -m pip install -e .
```

### 5. Configure WhiteScan

```bash
sudo "$(pwd)/.venv/bin/python3" whitescan.py --setup
```

Follow the prompts to configure your GVM socket and credentials.

The setup command installs the WhiteScan package and launcher and configures the GVM credentials.

Credentials are stored in:

```text
~/.config/whitescan/openvas.json
```

The configuration directory uses `0700` permissions, and the credentials file uses `0600`.

### 6. Verify installation

```bash
whitescan --help
whitescan --version
```

## OpenVAS / GVM Installation (Kali Linux)

WhiteScan supports optional vulnerability scanning through Greenbone Vulnerability Manager.

### 1. Install GVM

```bash
sudo apt update
sudo apt install -y gvm
sudo gvm-setup
```

Save the administrator password generated during setup.

### 2. Verify the installation

```bash
sudo gvm-check-setup
```

Resolve any reported errors before proceeding.

### 3. Start GVM

```bash
sudo gvm-start
```

Open the web interface:

```text
https://127.0.0.1:9392
```

Log in using the `admin` account and the password generated during setup.

**Note:** Initial vulnerability feed synchronization may take considerable time. Wait until the feeds are imported and processed before scanning.

### 4. Configure WhiteScan

Check the GVM socket:

```bash
sudo ls -l /run/gvmd/gvmd.sock
```

Run the WhiteScan setup command:

```bash
sudo whitescan --setup
```

Enter your GVM credentials when prompted.

Default socket:

```text
/run/gvmd/gvmd.sock
```

### 5. Run a vulnerability scan

```bash
# OpenVAS against hosts with open ports
sudo whitescan -i wlan0 --scan --openvas open --yes

# OpenVAS against every discovered host
sudo whitescan -i wlan0 --scan --openvas all --yes

# OpenVAS-only scan
sudo whitescan --openvas-only 192.168.2.1
```

Replace `wlan0` with your network interface.

### 6. Troubleshooting

Restart GVM:

```bash
sudo gvm-stop
sudo gvm-start
```

Check service status:

```bash
sudo systemctl status gvmd ospd-openvas gsad
```

View GVM logs:

```bash
sudo journalctl -u gvmd -n 50 --no-pager
```

Reset the administrator password:

```bash
sudo runuser -u _gvm -- gvmd --user=admin --new-password='NEW_PASSWORD'
```

Official documentation:

- [Kali GVM Installation](https://www.kali.org/tools/gvm/)
- [Greenbone Documentation](https://greenbone.github.io/docs/)

## Quick Start

### Interactive scan

```bash
sudo whitescan
```

### Quick scan

Scans the top 1000 TCP ports without OpenVAS:

```bash
sudo whitescan -i wlan0 --quick --yes --no-openvas
```

### Standard scan

Performs service and OS detection and sends hosts with open ports to OpenVAS:

```bash
sudo whitescan -i wlan0 --scan --openvas open --yes
```

### Full TCP port scan

Scans all TCP ports without OpenVAS:

```bash
sudo whitescan -i wlan0 --fullscan --yes --no-openvas
```

### OpenVAS-only scan

```bash
sudo whitescan --openvas-only 192.168.2.1
```

You can also scan hosts from a previous results directory:

```bash
sudo whitescan --openvas-only ./whitescan_results/<run_dir>
```

Replace `<run_dir>` with the actual directory name.

## Resuming Interrupted Scans

If a scan is interrupted during the Nmap stage, WhiteScan saves partial results.

Resume using:

```bash
sudo whitescan --resume ./whitescan_results/<run_dir>
```

Previously completed hosts are skipped.

**Note:** Orphaned OpenVAS tasks on the GVM server are not automatically resumed. WhiteScan provides the task ID and `gvm-cli` commands to inspect or stop them.

## Output Structure

WhiteScan creates a timestamped results directory.

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

Use `-o` or `--output-dir` to specify a custom output directory.

## CLI Overview

```text
whitescan [--quick|--scan|--fullscan|--scriptscan]
          [-i IFACE] [--cidr NET] [--targets IP[,IP...]]
          [--openvas open|all|IP[,IP...] | --no-openvas]
          [--openvas-only DIR_OR_IPS] [--resume DIR]
          [-T 0-5] [-w N] [--gvm-timeout SEC] [-y] ...
```

| Option | Description |
|---|---|
| `--quick` | Scan the top 1000 TCP ports |
| `--scan` | Top 1000 ports with service and OS detection |
| `--fullscan` | All TCP ports with service and OS detection |
| `--scriptscan` | All TCP ports with service detection, OS detection, and default scripts |
| `--openvas open` | Run OpenVAS against hosts with open ports |
| `--openvas all` | Run OpenVAS against every discovered host |
| `--no-openvas` | Disable OpenVAS integration |
| `--openvas-only` | Run only the OpenVAS stage |
| `--resume` | Resume a previous Nmap scan |
| `-i` | Specify the network interface |
| `--cidr` | Specify a network range |
| `--targets` | Specify target IP addresses |
| `-T` | Set Nmap timing template |
| `-w` | Set the number of parallel Nmap workers |
| `-y`, `--yes` | Use non-interactive defaults |

For the complete list of options, run:

```bash
whitescan --help
```

## Updating WhiteScan

Navigate to the project directory:

```bash
cd whitescan/whitescan-3.1.6
```

Pull the latest changes:

```bash
git pull
```

Update the installation:

```bash
source .venv/bin/activate
python3 -m pip install -e ".[openvas]"
sudo python3 ./whitescan.py --setup
```

## Uninstalling

If installed using the default `/usr` prefix:

```bash
sudo rm -f /usr/bin/whitescan
sudo rm -rf /usr/lib/whitescan
```

Remove the local virtual environment:

```bash
rm -rf .venv
```

If you used a custom installation prefix, remove the corresponding launcher and package from that prefix instead.

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

Run the test suite:

```bash
python3 -m unittest discover -s tests -v
```

### Project Structure

```text
whitescan-3.1.6/
├── .github/
│   └── workflows/
├── tests/
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
├── whitescan.py
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── MANIFEST.in
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
└── README.md
```

## Security Notes

- WhiteScan performs privileged operations. Use it only on networks and systems you are authorized to assess.
- GVM credentials are stored locally in plaintext, protected by restrictive file permissions.
- Scan reports may contain sensitive information, including IP addresses, hostnames, service versions, and vulnerability details.
- Protect your configuration files and scan results.
- Use a dedicated GVM account with only the permissions required for scanning.

## License

WhiteScan is released under the **MIT License**. See [LICENSE](LICENSE) for details.

## Disclaimer

This project is intended for authorized security testing, defensive security assessment, and educational purposes. The author is not responsible for misuse, unauthorized scanning, or damage resulting from the use of this software.
