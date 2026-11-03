"""whitescan.network"""
import ipaddress
import logging
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

from .process import ABORT, _iter_proc_lines, _register, _unregister, terminate_active
from .util import C, err, info, log, log_exc, ok, warn

def list_interfaces():
    ifaces = []
    try:
        out = subprocess.check_output(["ip", "-o", "link", "show"], text=True)
    except FileNotFoundError:
        err("'ip' command not found.")
        sys.exit(1)

    for line in out.splitlines():
        m = re.match(r"\d+:\s+([^:]+):\s+<([^>]+)>", line)
        if not m:
            continue
        ifname = m.group(1).split("@")[0]
        flags = m.group(2).split(",")
        if "UP" not in flags or "LOOPBACK" in flags:
            continue
        if ifname.startswith(("docker", "veth", "br-", "virbr", "tun", "tap")):
            continue

        ip, prefix = get_iface_cidr(ifname)
        if not ip:
            continue
        mac = get_iface_mac(ifname)
        ifaces.append((ifname, ip, prefix, mac))
    return ifaces

def get_iface_cidr(ifname):
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-f", "inet", "addr", "show", ifname], text=True
        )
    except subprocess.CalledProcessError:
        return None, None
    m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out)
    if not m:
        return None, None
    return m.group(1), int(m.group(2))

def get_iface_mac(ifname):
    try:
        with open(f"/sys/class/net/{ifname}/address") as f:
            return f.read().strip()
    except OSError:
        return "?"

def cidr_from_iface(ip, prefixlen):
    try:
        return str(ipaddress.ip_network(f"{ip}/{prefixlen}", strict=False))
    except ValueError:
        return None

def choose_interface():
    ifaces = list_interfaces()
    if not ifaces:
        err("No usable network interfaces found.")
        sys.exit(1)

    print(f"\n{C.BOLD}===== Available Interfaces ====={C.RESET}")
    for idx, (ifname, ip, prefix, mac) in enumerate(ifaces, 1):
        cidr = cidr_from_iface(ip, prefix) or "?"
        print(f"  [{idx}] {C.GREEN}{ifname:<12}{C.RESET} "
              f"{ip}/{prefix:<3}  cidr={C.CYAN}{cidr:<20}{C.RESET} mac={mac}")

    while True:
        choice = input(f"\n{C.BOLD}Select interface number: {C.RESET}").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(ifaces):
            ifname, ip, prefix, mac = ifaces[int(choice) - 1]
            cidr = cidr_from_iface(ip, prefix)
            if not cidr:
                err("Could not derive CIDR.")
                sys.exit(1)
            ok(f"Using {ifname} -> CIDR {cidr}")
            return ifname, cidr
        warn("Invalid choice.")

def resolve_interface(args, interactive):
    if args.iface:
        ip, prefix = get_iface_cidr(args.iface)
        if not ip:
            err(f"Interface '{args.iface}' not found or has no IPv4 address.")
            sys.exit(1)
        cidr = args.cidr or cidr_from_iface(ip, prefix)
        ok(f"Using {args.iface} -> CIDR {cidr}")
        return args.iface, cidr

    if sys.stdin.isatty():
        iface, cidr = choose_interface()
        return iface, (args.cidr or cidr)

    ifaces = list_interfaces()
    if len(ifaces) == 1:
        ifname, ip, prefix, _ = ifaces[0]
        cidr = args.cidr or cidr_from_iface(ip, prefix)
        ok(f"Using the only usable interface {ifname} -> CIDR {cidr}")
        return ifname, cidr
    names = ", ".join(i[0] for i in ifaces) or "none found"
    err(f"Cannot choose an interface without a terminal. Pass --iface. Available: {names}")
    sys.exit(1)

def check_tool(tool):
    return shutil.which(tool) is not None

def cidr_on_local_segment(network, iface):
    ip, prefix = get_iface_cidr(iface)
    if not ip:
        return None
    iface_cidr = cidr_from_iface(ip, prefix)
    if not iface_cidr:
        return None
    try:
        iface_net = ipaddress.ip_network(iface_cidr, strict=False)
    except ValueError:
        return None
    try:
        return network.subnet_of(iface_net) or network == iface_net
    except (AttributeError, ValueError):
        return network == iface_net

def discover_hosts(network, iface, rawdir, on_segment=None):
    xml_path = os.path.join(rawdir, "discovery.xml")

    cmd = ["nmap", "-sn", "-n", "-T4", "--max-retries", "3"]
    if on_segment is False:
        cmd += ["-PE", "-PS22,80,443,445,3389", "-PA80,443"]
        mode = "ICMP+TCP (routed)"
    else:
        cmd += ["-PR"]
        mode = "ARP (local segment)"
    cmd += ["-e", iface, "-oX", xml_path, str(network)]

    info(f"Target range: {network} ({network.num_addresses} addresses)")
    info(f"Discovery mode: {mode}")
    info(f"$ {' '.join(cmd)}")
    log(f"discovery cmd ({mode}): {' '.join(cmd)}")

    proc = None
    count = 0
    aborted = False
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, bufsize=0,
                                start_new_session=True)
        _register(proc)
        for line in _iter_proc_lines(proc):
            line = line.strip()
            if line.startswith("Nmap scan report for"):
                count += 1
                host = line.replace("Nmap scan report for", "").strip()
                print(f"  {C.GREEN}ALIVE{C.RESET}  {C.BOLD}{host}{C.RESET}  "
                      f"{C.DIM}({count} so far){C.RESET}")
        aborted = ABORT.is_set() and proc.returncode not in (0,)
    except FileNotFoundError:
        err("nmap not installed. Install: sudo apt install nmap")
        return []
    except KeyboardInterrupt:
        terminate_active()
        raise
    except OSError as e:
        err(f"nmap discovery failed to start: {e}")
        log_exc("discovery Popen failed")
        return []
    finally:
        _unregister(proc)

    if aborted:
        warn("Discovery aborted; parsing whatever XML nmap managed to write.")
        log("discovery aborted", logging.WARNING)

    if proc is None or proc.returncode not in (0, None):
        rc = proc.returncode if proc is not None else -1
        warn(f"Discovery nmap exited with code {rc}; results may be partial.")
        log(f"discovery rc={rc}", logging.WARNING)

    alive = []
    parse_error = False
    try:
        root = ET.parse(xml_path).getroot()
        for h in root.findall("host"):
            st = h.find("status")
            if st is None or st.get("state") != "up":
                continue
            for a in h.findall("address"):
                if a.get("addrtype") == "ipv4":
                    alive.append(a.get("addr"))
    except ET.ParseError as e:
        parse_error = True
        err(f"Discovery XML is malformed (partial results): {e}")
        log_exc("discovery parse failure (partial results)")
    except OSError as e:
        parse_error = True
        err(f"Could not read discovery results: {e}")
        log_exc("discovery read failure")

    if parse_error:
        warn("Host discovery results are PARTIAL; some hosts may be missing.")
    ok(f"Discovery finished: {len(alive)} live host(s).")
    log(f"discovery alive hosts: {alive}")
    return alive

def get_arp_table(iface, network=None):
    info(f"Reading neighbour table for {iface}...")
    raw = {}
    try:
        result = subprocess.run(["ip", "neigh", "show", "dev", iface],
                                capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([0-9a-fA-F:]+)",
                             line)
                if m and m.group(2) != "00:00:00:00:00:00":
                    raw[m.group(1)] = m.group(2)
        else:
            result = subprocess.run(["arp", "-an", "-i", iface],
                                    capture_output=True, text=True)
            for line in result.stdout.splitlines():
                m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)",
                              line)
                if m:
                    raw[m.group(1)] = m.group(2)
    except FileNotFoundError:
        pass

    arp_ips = set()
    skipped = 0
    for ip, mac in raw.items():
        if network is not None:
            try:
                if ipaddress.ip_address(ip) not in network:
                    skipped += 1
                    continue
            except ValueError:
                skipped += 1
                continue
        arp_ips.add(ip)
        print(f"  {C.CYAN}ARP{C.RESET}    {ip} -> {mac}")

    if skipped:
        info(f"Ignored {skipped} neighbour entr"
             f"{'y' if skipped == 1 else 'ies'} outside {network}.")
    ok(f"Neighbour table: {len(arp_ips)} resolved host(s) "
       f"inside {network if network else iface}.")
    log(f"arp hosts inside {network}: {sorted(arp_ips)}")
    return arp_ips

