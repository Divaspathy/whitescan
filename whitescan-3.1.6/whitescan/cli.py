"""CLI entry points and argument parsing."""
import argparse
import ipaddress
import os
import re
import signal
import sys
from datetime import datetime

from .__version__ import __version__
from .constants import (DEFAULT_GVM_SOCKET, DEFAULT_GVM_TIMEOUT,
                        DEFAULT_RESULTS_ROOT, LARGE_RANGE)
from .paths import OPENVAS_JSON, CONFIG_DIR
from .keep_awake import KeepAwake, reexec_with_inhibitor
from .network import (
    check_tool, cidr_on_local_segment, discover_hosts, get_arp_table,
    list_interfaces, resolve_interface, cidr_from_iface,
)
from .nmap_stage import (
    get_scan_options, print_open_port_summary, run_nmap_stage,
)
from .openvas import HAVE_GVM, openvas_stage, require_openvas_config
from .process import ABORT, terminate_active
from .report import load_results, open_report, save_reports
from .setup_cmd import run_setup
from .util import (
    C, banner, confirm, default_options, disable_color, err, info, log,
    make_private_dir, next_step, ok, setup_logger, sorted_hosts, warn, _ip_key,
)

def finish(args, all_results, outdir, rawdir, interrupted):
    next_step("Save report")
    all_results["finished"] = datetime.now().isoformat()
    all_results["interrupted"] = interrupted
    jpath, tpath = save_reports(all_results, outdir)
    ok(f"Readable report : {tpath}")
    ok(f"JSON report     : {jpath}")
    ok(f"Raw nmap/GVM XML: {rawdir}")
    banner("Scan Complete", C.GREEN)
    if not args.no_open and sys.stdout.isatty():
        open_report(tpath)

def mode_openvas_only(args, interactive):
    banner("OpenVAS-only mode (nmap stage skipped)", C.CYAN)
    require_openvas_config()

    spec = args.openvas_only
    is_dir = os.path.isdir(spec) or (
        os.path.isfile(spec) and spec.endswith("scan_report.json"))

    if is_dir:
        all_results, outdir = load_results(spec)
        rawdir = os.path.join(outdir, "raw")
        make_private_dir(rawdir)
        setup_logger(outdir)
        info(f"Using results from {outdir} "
             f"({len(all_results.get('hosts', {}))} host(s))")
        if not all_results.get("hosts") and not args.openvas:
            err("The saved report has no hosts; pass --openvas IP[,IP...].")
            return 1
        if args.openvas is None and not args.openvas_file:
            args.openvas = "all"
            info("Using the saved target list for OpenVAS "
                 "(--openvas defaults to 'all' in --openvas-only mode).")
    else:
        ips = []
        for tok in re.split(r"[,\s]+", spec):
            tok = tok.strip()
            if not tok:
                continue
            try:
                ip = ipaddress.ip_address(tok)
            except ValueError:
                err(f"--openvas-only: '{tok}' is not a directory or an IP address.")
                info("Pass either a previous scan directory, or one or more "
                     "IPv4 addresses (comma-separated).")
                return 1
            if ip.version != 4:
                err(f"--openvas-only: '{tok}' is IPv6; WhiteScan is IPv4-only.")
                return 1
            ips.append(tok)
        ips = list(dict.fromkeys(ips))
        if not ips:
            err("--openvas-only: no IP addresses given.")
            return 1

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        root = os.path.abspath(args.output_dir or DEFAULT_RESULTS_ROOT)
        outdir = os.path.join(root, f"{ts}_openvas_only")
        rawdir = os.path.join(outdir, "raw")
        make_private_dir(outdir)
        make_private_dir(rawdir)
        setup_logger(outdir)
        log(f"whitescan v{__version__} openvas-only on {ips}")

        all_results = {
            "interface": None,
            "cidr": None,
            "started": datetime.now().isoformat(),
            "options": None,
            "hosts": {},
            "targets": ips,
        }
        info(f"OpenVAS-only on {len(ips)} IP(s) — no nmap data.")
        for ip in ips:
            print(f"     {C.GREEN}-{C.RESET} {ip}")

        if args.openvas is None and not args.openvas_file:
            args.openvas = ",".join(ips)

    if not HAVE_GVM:
        err("python-gvm is not installed (pip install python-gvm).")
        return 1

    if not args.no_keep_awake:
        awake = KeepAwake(all_results.get("interface") or "")
        awake.start()
        atexit.register(awake.stop)

    interrupted = False
    try:
        openvas_stage(args, all_results, rawdir, interactive)
    except KeyboardInterrupt:
        interrupted = True
        warn("Interrupted.")
    all_results.setdefault("finished", datetime.now().isoformat())
    next_step("Save report")
    jpath, tpath = save_reports(all_results, outdir)
    ok(f"Readable report : {tpath}")
    ok(f"JSON report     : {jpath}")
    ok(f"Raw GVM XML     : {rawdir}")
    if not args.no_open and sys.stdout.isatty():
        open_report(tpath)
    return 130 if interrupted else 0

def mode_scan(args, interactive):
    resumed = bool(args.resume)

    next_step("Dependency check")
    for tool in ("nmap", "ip"):
        if not check_tool(tool):
            err(f"Missing required tool: {tool}")
            return 1
        ok(f"{tool} found.")
    if os.geteuid() != 0:
        err("Run as root (sudo).")
        return 1
    ok("Running as root.")

    if resumed:
        all_results, outdir = load_results(args.resume)
        iface = args.iface or all_results.get("interface")
        cidr = args.cidr or all_results.get("cidr")
        if not iface or not cidr:
            err("The saved report has no interface/CIDR; pass --iface.")
            return 1
        opts = all_results.get("options") or default_options()
        for k, v in default_options().items():
            opts.setdefault(k, v)
        all_results["options"] = opts
        all_results.setdefault("resumes", []).append(datetime.now().isoformat())
        all_results.pop("finished", None)
        all_results["interrupted"] = False
        info(f"Resuming the scan stored in {outdir}")
    else:
        next_step("Interface selection & CIDR detection")
        iface, cidr = resolve_interface(args, interactive)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        root = os.path.abspath(args.output_dir or DEFAULT_RESULTS_ROOT)
        outdir = os.path.join(root, f"{ts}_{iface}")
        all_results = None

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        err(f"Invalid network '{cidr}': {e}")
        return 1
    if network.version != 4:
        err("WhiteScan currently supports IPv4 only (discovery/neighbour "
            "table are IPv4). Pass an IPv4 --cidr or --targets.")
        return 1
    info(f"Target network: {network} ({network.num_addresses} addrs)")

    large = (not resumed and not args.targets
             and network.num_addresses > LARGE_RANGE)
    aggressive = getattr(args, "profile", None) in ("fullscan", "scriptscan")
    if large and aggressive and args.yes:
        warn("Large range with --fullscan/--scriptscan is not skipped by --yes.")
        if not confirm(
            "Full/script scan on a large range — continue?",
            args, force=True,
        ):
            warn("Aborted. This combination is refused without a terminal. "
                 "Narrow --cidr or drop the aggressive profile.")
            return 0
    elif large and not confirm("Large range — continue?", args):
        warn("Large range: re-run with --yes to confirm.")
        return 0

    on_segment = cidr_on_local_segment(network, iface)
    if on_segment is False:
        warn(f"--cidr {network} is not on {iface}'s L2 segment.")
        info("Discovery will use ICMP/TCP host probes instead of ARP; "
             "ARP neighbour merges will be skipped.")

    rawdir = os.path.join(outdir, "raw")
    make_private_dir(outdir)
    make_private_dir(rawdir)
    logpath = setup_logger(outdir)
    log(f"whitescan v{__version__} starting run in {outdir}")
    log(f"interface={iface} cidr={cidr} on_local_segment={on_segment}")
    info(f"Output directory: {outdir}")
    info(f"Log file        : {logpath}")

    if not args.no_keep_awake:
        awake = KeepAwake(iface)
        awake.start()
        atexit.register(awake.stop)

    if args.targets:
        scan_targets = sorted(set(args.targets), key=_ip_key)
        ok(f"Using {len(scan_targets)} target(s) from --targets (discovery skipped).")
    elif resumed and all_results.get("targets"):
        scan_targets = sorted(all_results["targets"], key=_ip_key)
        ok(f"Using the saved target list ({len(scan_targets)} host(s)).")
    else:
        next_step("Host discovery")
        alive = discover_hosts(network, iface, rawdir,
                               on_segment=on_segment)
        next_step("Merge discovery results with neighbour table")
        arp_net = network if on_segment is not False else None
        arp_ips = get_arp_table(iface, arp_net)
        scan_targets = sorted(set(alive) | set(arp_ips), key=_ip_key)
        ok(f"discovery ∪ ARP = {len(scan_targets)} target(s)")
        for ip in scan_targets:
            tags = []
            if ip in alive:
                tags.append("nmap")
            if ip in arp_ips:
                tags.append("arp")
            print(f"     {C.GREEN}-{C.RESET} {ip}  "
                  f"{C.DIM}({', '.join(tags)}){C.RESET}")
    if not scan_targets:
        warn("No live hosts found. Exiting.")
        return 0

    if resumed:
        info("Using the scan options saved in the report.")
    else:
        next_step("Configure nmap options")
        opts = get_scan_options(args, interactive)
        all_results = {
            "interface": iface,
            "cidr": cidr,
            "started": datetime.now().isoformat(),
            "options": opts,
            "hosts": {},
        }
    all_results["targets"] = scan_targets

    done = {ip for ip, d in all_results["hosts"].items() if not d.get("error")}
    pending = [ip for ip in scan_targets if ip not in done]
    save_reports(all_results, outdir)

    interrupted = False
    if pending:
        extra = f" ({len(done)} already done)" if done else ""
        next_step(f"Scanning {len(pending)} host(s){extra}")
        interrupted = run_nmap_stage(pending, iface, opts, rawdir, outdir,
                                     all_results)
    else:
        info("Every host is already scanned; nothing to resume.")

    print_open_port_summary(all_results)

    if interrupted:
        info("Skipping OpenVAS because the nmap stage was interrupted.")
        info(f"Resume nmap:            sudo whitescan --resume {outdir}")
        info(f"OpenVAS on finished:    sudo whitescan --openvas-only {outdir}")
    else:
        try:
            openvas_stage(args, all_results, rawdir, interactive)
        except KeyboardInterrupt:
            interrupted = True
            warn("OpenVAS stage interrupted.")

    finish(args, all_results, outdir, rawdir, interrupted)
    return 130 if interrupted else 0

def main(args):
    if args.setup:
        return run_setup(sys.stdin.isatty(), args.setup_socket)

    interactive = sys.stdin.isatty() and not args.yes
    banner(f"WhiteScan v{__version__}: ARP discovery + nmap (+ OpenVAS)",
           C.CYAN)
    if args.openvas_only:
        return mode_openvas_only(args, interactive)
    return mode_scan(args, interactive)


DESCRIPTION = """\
WhiteScan: ARP host discovery -> nmap port/service scan -> optional
OpenVAS (GVM) vulnerability scan.

All output from a run lives in one folder:

    ./whitescan_results/<timestamp>_<iface>/
        scan_report.txt          readable report
        scan_report.json         machine-readable report
        raw/                     raw nmap + GVM XML
        logs/                    run logs (whitescan.log)

Override the root with -o/--output-dir.

OpenVAS credentials are configured once via `sudo whitescan --setup` and
stored in ~/.config/whitescan/openvas.json (mode 0600) — the file is
resolved against $SUDO_USER's home even when invoked via sudo.

`--openvas` accepts only: open | all | <IP[,IP...]>.

`--openvas-only` accepts either a previous scan directory or bare IPs.

Discovery adapts to the target: ARP (-PR) is used when --cidr is on
the interface's own L2 segment; ICMP/TCP host probes are used when the
target is routed.

On SUCCESSFUL OpenVAS runs, the GVM task and target are deleted (the
report is preserved server-side). On timeout, poll failure, or user
interrupt, the GVM task is LEFT RUNNING server-side; the task id is
printed in red so you can inspect or stop it manually.

Failed OpenVAS attempts are recorded separately in the report
(openvas_session.failed_runs) so they do not masquerade as completed
assessments.
"""

EPILOG = """\
scan presets (mutually exclusive; other flags still apply):

  --quick         top 1000 ports, no -sV / -O / -sC
  --scan          top 1000 ports, -sV + -O
  --fullscan      all 65535 ports, -sV + -O
  --scriptscan    all 65535 ports, -sV + -O + -sC

  Each preset is a starting point. Any explicit flag overrides that one
  field:

      --fullscan --no-os-detection        full ports + -sV only
      --fullscan --no-service-detection --no-os-detection
                                          = full ports only (fast)
      --scan --no-os-detection            top 1000 + -sV only
      --scriptscan --ports top1000        NSE but only top 1000 ports

quick start:

  sudo ./whitescan.py --setup
      one-time: install onto sudo's PATH and store GVM socket, username
      and password in ~/.config/whitescan/openvas.json (mode 0600).

  sudo whitescan -i wlan0 --quick --yes
      fast top-1000 scan, no OpenVAS.

  sudo whitescan -i wlan0 --scan --openvas open --yes
      top-1000 + -sV + -O, then OpenVAS on hosts with open ports.

  sudo whitescan -i wlan0 --fullscan --yes
      all 65535 ports + -sV + -O, no OpenVAS.

  sudo whitescan -i wlan0 --scriptscan --yes
      all 65535 ports + -sV + -O + default NSE.

  sudo whitescan --openvas-only 192.168.2.1
      skip nmap; run OpenVAS on that IP only (uses stored creds).

  sudo whitescan --openvas-only ./whitescan_results/20261103_030000_wlan0
      skip nmap; run OpenVAS on a previous run's hosts.

resuming:

  Ctrl-C during the nmap stage leaves partial results. Resume with:

      sudo whitescan --resume ./whitescan_results/<run>

  Finished hosts are skipped.

  An OpenVAS timeout, poll failure, or Ctrl-C during polling does NOT
  get resumed automatically. The GVM task keeps running server-side;
  WhiteScan prints the task id and gvm-cli commands to inspect or stop
  it. --resume starts a fresh OpenVAS task on the same hosts if needed.

examples:
  whitescan
      fully interactive (asks for interface and options)

  sudo whitescan -i wlan0 --quick --yes --no-openvas
      quick, unattended

  sudo whitescan -i wlan0 --fullscan -T5 -w 4 --yes --no-openvas
      full ports + -sV + -O, aggressive timing, 4 workers

  cron (weekly, Sunday 03:00):
      0 3 * * 0  root  /usr/bin/whitescan -i wlan0 --scan --yes --no-open --no-openvas

configuration:
  ~/.config/whitescan/openvas.json        (mode 0600)
      {
        "gvm_socket": "/run/gvmd/gvmd.sock",
        "username":   "admin",
        "password":   "..."
      }

  Written and updated only by `sudo whitescan --setup`.
  There is no runtime credential flag and no interactive login prompt.
  For automation, use a dedicated GVM user with scan-only privileges
  rather than the built-in admin account.

notes:
  * Passwords are never taken from the command line (would leak via ps).
  * Run as root for scanning. --openvas-only needs only gvmd socket access.
  * WhiteScan is IPv4-only.
  * Ctrl-C saves partial results; continue with --resume.
  * --gvm-timeout defaults to 3600s. On timeout/poll-failure/user-
    interrupt the GVM task is left running server-side; the task id is
    printed (red) and logged.
  * Successful OpenVAS runs delete their GVM task and target; the report
    is preserved on the server.
  * Failed OpenVAS attempts are recorded under
    openvas_session.failed_runs in the report, not as completed sessions.
  * Large ranges (>4096 addresses) combined with --fullscan or
    --scriptscan always ask, even with --yes. Non-interactive runs
    refuse that combination.
  * Only scan networks you own or are authorised to test.
"""

def _timing_arg(v):
    t = v.strip().upper()
    if t in ("0", "1", "2", "3", "4", "5"):
        t = "T" + t
    if t not in ("T0", "T1", "T2", "T3", "T4", "T5"):
        raise argparse.ArgumentTypeError("use 0-5 or T0-T5")
    return t

def _workers_arg(v):
    try:
        n = int(v)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number from 1 to 8")
    if not 1 <= n <= 8:
        raise argparse.ArgumentTypeError("must be from 1 to 8")
    return n

def _cidr_arg(v):
    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"'{v}' is not a valid network, e.g. 192.168.1.0/24")
    if net.version != 4:
        raise argparse.ArgumentTypeError("WhiteScan supports IPv4 networks only")
    return str(net)

def _ip_list_arg(v):
    out = []
    for tok in v.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            ip = ipaddress.ip_address(tok)
        except ValueError:
            raise argparse.ArgumentTypeError(f"'{tok}' is not an IP address")
        if ip.version != 4:
            raise argparse.ArgumentTypeError(f"'{tok}' is IPv6; WhiteScan is IPv4-only")
        out.append(tok)
    if not out:
        raise argparse.ArgumentTypeError("no IP addresses given")
    return out

def _pos_int(v):
    try:
        n = int(v)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number")
    if n < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return n

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="whitescan",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    g = p.add_argument_group("setup")
    g.add_argument("--setup", action="store_true",
                   help="install onto sudo's PATH and prompt once for GVM "
                        "socket / username / password, stored in "
                        f"{OPENVAS_JSON} (mode 0600). Re-run any time to change.")
    g.add_argument("--setup-socket", metavar="PATH",
                   help="with --setup: pre-fill the GVM socket path "
                        f"(default {DEFAULT_GVM_SOCKET})")

    g = p.add_argument_group("modes (default: full scan)")
    mx = g.add_mutually_exclusive_group()
    mx.add_argument("--resume", metavar="DIR",
                    help="continue an interrupted nmap scan stored in DIR "
                         "(or its scan_report.json); finished hosts are skipped. "
                         "Does NOT resume an orphaned OpenVAS task.")
    mx.add_argument("--openvas-only", metavar="DIR_OR_IPS",
                    help="skip nmap and run OpenVAS. Accepts a previous scan "
                         "directory (its hosts are used; --openvas defaults to "
                         "'all') or a comma-separated IP list. Uses stored creds.")

    g = p.add_argument_group("network")
    g.add_argument("-i", "--iface", metavar="IFACE",
                   help="interface to scan from, e.g. wlan0")
    g.add_argument("--cidr", metavar="NET", type=_cidr_arg,
                   help="IPv4 network to scan (default: the interface's own subnet)")
    g.add_argument("--targets", metavar="IP[,IP...]", type=_ip_list_arg,
                   help="scan exactly these hosts and skip discovery "
                        "(overrides saved targets when combined with --resume)")
    g.add_argument("--list-interfaces", action="store_true",
                   help="show usable interfaces and exit")

    g = p.add_argument_group("scan presets (mutually exclusive)")
    pp = g.add_mutually_exclusive_group()
    pp.add_argument("--quick", dest="profile", action="store_const",
                    const="quick",
                    help="top 1000 ports, no -sV / -O / -sC")
    pp.add_argument("--scan", dest="profile", action="store_const",
                    const="scan",
                    help="top 1000 ports, -sV + -O")
    pp.add_argument("--fullscan", dest="profile", action="store_const",
                    const="fullscan",
                    help="all 65535 ports, -sV + -O")
    pp.add_argument("--scriptscan", dest="profile", action="store_const",
                    const="scriptscan",
                    help="all 65535 ports, -sV + -O + -sC")

    g = p.add_argument_group("nmap options (override profile fields)")
    g.add_argument("--ports", choices=["top1000", "all"],
                   help="port scope: top1000 or all 65535")
    g.add_argument("--service-detection", action=argparse.BooleanOptionalAction,
                   default=None, help="service/version detection (-sV)")
    g.add_argument("--os-detection", action=argparse.BooleanOptionalAction,
                   default=None, help="OS detection (-O)")
    g.add_argument("--nse-scripts", action=argparse.BooleanOptionalAction,
                   default=None, help="default NSE scripts (-sC)")
    g.add_argument("-T", "--timing", metavar="0-5", type=_timing_arg,
                   help="timing template, 4 or T4 (default T4)")
    g.add_argument("-w", "--workers", metavar="N", type=_workers_arg,
                   help="hosts scanned in parallel, 1-8 (default 1)")

    g = p.add_argument_group(
        "OpenVAS / GVM",
        "Credentials are configured once with `sudo whitescan --setup` and "
        "then used automatically. No login prompts at scan time.",
    )
    mo = g.add_mutually_exclusive_group()
    mo.add_argument("--openvas", metavar="[TARGETS]", nargs="?", const="open",
                    help="run OpenVAS. TARGETS is one of: "
                         "'open' (hosts with open ports) or 'all' (every live "
                         "host) or a comma-separated IP list. Bare `--openvas` "
                         "== `--openvas open`. Anything else is rejected.")
    mo.add_argument("--no-openvas", action="store_true",
                    help="never run OpenVAS (and do not ask)")
    g.add_argument("--openvas-file", metavar="FILE",
                   help="read OpenVAS targets from FILE (one IP per line, "
                        "# comments allowed)")
    g.add_argument("--gvm-poll", metavar="SEC", type=_pos_int, default=15,
                   help="seconds between status checks (default 15)")
    g.add_argument("--gvm-timeout", metavar="SEC", type=_pos_int, default=None,
                   help="stop waiting for the OpenVAS task after SEC seconds "
                        f"(default {DEFAULT_GVM_TIMEOUT}); the task keeps "
                        "running on GVM — its id is printed in red so you "
                        "can stop it manually")

    g = p.add_argument_group("output and behaviour")
    g.add_argument("-o", "--output-dir", metavar="DIR",
                   help="root folder for all run outputs "
                        f"(default ./{DEFAULT_RESULTS_ROOT}); each run creates "
                        "a <timestamp>_<iface>/ subfolder inside it")
    g.add_argument("--no-open", action="store_true",
                   help="do not open the report in mousepad when finished")
    g.add_argument("--no-keep-awake", action="store_true",
                   help="do not block sleep/screen blanking or change Wi-Fi power saving")
    g.add_argument("--no-color", action="store_true",
                   help="plain output (automatic when not on a terminal)")
    g.add_argument("-y", "--yes", action="store_true",
                   help="never prompt: answer yes to confirmations and use "
                        "defaults for options not given (interface prompt and "
                        "large-range aggressive-scan guard are still shown if "
                        "applicable)")
    g.add_argument("-V", "--version", action="version",
                   version=f"%(prog)s {__version__}")
    return p.parse_args(argv)

