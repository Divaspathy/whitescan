"""whitescan.nmap_stage"""
import os
import subprocess
import re
import time
import xml.etree.ElementTree as ET
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

from .constants import SCAN_PROFILES
from .process import ABORT, _iter_proc_lines, _register, _unregister, terminate_active
from .report import save_reports
from .util import (
    C, banner, default_options, err, fix_perms, info, log, log_exc, next_step, nse_lines,
    ok, os_note, sorted_hosts, warn,
)

def get_scan_options(args, interactive):
    opts = default_options()
    if interactive:
        banner("Scan Options", C.YELLOW)

    profile = getattr(args, "profile", None)
    if profile:
        top, svc, osm, nse = SCAN_PROFILES[profile]
        opts["top_1000"] = top
        opts["service_detection"] = svc
        opts["os_detection"] = osm
        opts["nse_scripts"] = nse
        ok(f"Profile '{profile}': top_1000={top} "
           f"service={svc} os={osm} nse={nse}")

    if args.ports is not None:
        opts["top_1000"] = (args.ports == "top1000")
    elif profile:
        pass
    elif interactive:
        while True:
            pc = input("Port scope: [1] Top 1000  [2] Full 65535: ").strip()
            if pc in ("1", "2"):
                break
        opts["top_1000"] = (pc == "1")

    for key, flag, question in (
        ("service_detection", args.service_detection, "Detect service/version? [y/N]: "),
        ("os_detection", args.os_detection, "Detect OS? [y/N]: "),
        ("nse_scripts", args.nse_scripts, "Run default NSE scripts? [y/N]: "),
    ):
        if flag is not None:
            opts[key] = flag
        elif profile:
            pass
        elif interactive:
            opts[key] = input(question).strip().lower() == "y"

    if args.timing:
        opts["timing"] = args.timing
    elif interactive:
        while True:
            raw = input("Timing template [2/3/4 or T2/T3/T4] (default 4): ").strip()
            if not raw:
                break
            t = raw.upper()
            if t in ("T0", "T1", "T2", "T3", "T4", "T5"):
                opts["timing"] = t
                break
            if raw in ("0", "1", "2", "3", "4", "5"):
                opts["timing"] = "T" + raw
                break
            warn("Invalid timing. Enter 2, 3, 4 or T2/T3/T4.")

    if args.workers:
        opts["workers"] = args.workers
    elif interactive:
        while True:
            raw = input("Parallel nmap workers [1-8] (default 1): ").strip()
            if not raw:
                break
            if raw.isdigit() and 1 <= int(raw) <= 8:
                opts["workers"] = int(raw)
                break
            warn("Enter a number from 1 to 8.")

    if not interactive:
        info("Scan options: " + ", ".join(f"{k}={v}" for k, v in opts.items()))
    return opts

def build_nmap_cmd(ip, iface, opts, xml_path, verbose=True):
    cmd = ["nmap", "-sS", "-Pn", "-e", iface, f"-{opts['timing']}"]
    if verbose:
        cmd.append("-v")
    if opts["top_1000"]:
        cmd += ["--top-ports", "1000"]
    else:
        cmd += ["-p-"]
    if opts["service_detection"]:
        cmd.append("-sV")
    if opts["os_detection"]:
        cmd.append("-O")
    if opts["nse_scripts"]:
        cmd.append("-sC")
    cmd += ["-oX", xml_path, ip]
    return cmd

def colorize_nmap_line(line):
    if re.search(r"\bopen\b", line):
        return f"    {C.GREEN}{line}{C.RESET}"
    if re.search(r"\b(filtered|closed)\b", line):
        return f"    {C.DIM}{line}{C.RESET}"
    if "Nmap scan report" in line:
        return f"    {C.BOLD}{C.CYAN}{line}{C.RESET}"
    if "Nmap done" in line:
        return f"    {C.BOLD}{C.GREEN}{line}{C.RESET}"
    return f"    {line}"

def run_nmap(ip, iface, opts, rawdir, stream=True):
    xml_path = os.path.join(rawdir, f"nmap_{ip.replace('.', '_')}.xml")
    cmd = build_nmap_cmd(ip, iface, opts, xml_path, verbose=stream)
    if stream:
        info(f"$ {' '.join(cmd)}")
    log(f"nmap cmd {ip}: {' '.join(cmd)}")
    if ABORT.is_set():
        return "", -1, ["aborted"]

    tail = deque(maxlen=5)
    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, bufsize=0,
                                start_new_session=True)
        _register(proc)
        for line in _iter_proc_lines(proc):
            line = line.rstrip()
            if not line:
                continue
            tail.append(line)
            if stream:
                print(colorize_nmap_line(line))
    except FileNotFoundError:
        return "", 127, ["nmap not found"]
    except KeyboardInterrupt:
        terminate_active()
        raise
    except OSError as e:
        err(f"nmap failed to start for {ip}: {e}")
        log_exc(f"nmap Popen failed {ip}")
        return "", -1, [f"nmap start failed: {e}"]
    finally:
        _unregister(proc)

    # A finished scan (rc 0) is kept even if abort raced with exit.
    # Anything else under ABORT is incomplete and must be retried.
    if ABORT.is_set() and not (proc is not None and proc.returncode == 0):
        return "", -1, ["aborted"]

    xml = ""
    if os.path.exists(xml_path):
        with open(xml_path) as f:
            xml = f.read()
        fix_perms(xml_path, 0o600, fatal=False)

    rc = proc.returncode if proc is not None else -1
    return xml, rc, list(tail)

def parse_nmap_xml(xml_data):
    result = {
        "hostname": "",
        "state": "unknown",
        "mac": "",
        "vendor": "",
        "os": None,
        "ports": [],
        "host_scripts": [],
        "error": "",
    }
    if not xml_data:
        return result

    try:
        host = ET.fromstring(xml_data).find("host")
    except ET.ParseError as e:
        result["error"] = f"could not parse nmap XML: {e}"
        return result
    if host is None:
        return result

    st = host.find("status")
    if st is not None:
        result["state"] = st.get("state", "unknown")

    for a in host.findall("address"):
        if a.get("addrtype") == "mac":
            result["mac"] = a.get("addr", "")
            result["vendor"] = a.get("vendor", "")

    hn = host.find("hostnames/hostname")
    if hn is not None:
        result["hostname"] = hn.get("name", "")

    om = host.find("os/osmatch")
    if om is not None:
        result["os"] = f"{om.get('name', '?')} ({om.get('accuracy', '?')}%)"

    for p in host.findall("ports/port"):
        state_el = p.find("state")
        svc_el = p.find("service")
        s = svc_el.attrib if svc_el is not None else {}
        result["ports"].append({
            "proto": p.get("protocol", "tcp"),
            "port": p.get("portid", ""),
            "state": state_el.get("state") if state_el is not None else "unknown",
            "reason": state_el.get("reason", "") if state_el is not None else "",
            "service": s.get("name", ""),
            "product": s.get("product", ""),
            "version": s.get("version", ""),
            "extrainfo": s.get("extrainfo", ""),
            "ostype": s.get("ostype", ""),
            "devicetype": s.get("devicetype", ""),
            "tunnel": s.get("tunnel", ""),
            "cpe": [c.text for c in p.findall("service/cpe") if c.text],
            "scripts": [{"id": sc.get("id", ""), "output": sc.get("output", "")}
                        for sc in p.findall("script")],
        })

    for sc in host.findall("hostscript/script"):
        result["host_scripts"].append({
            "id": sc.get("id", ""),
            "output": sc.get("output", ""),
        })

    return result

def print_host_details(ip, parsed, duration):
    banner(f"{ip}  ({duration:.1f}s)", C.CYAN)

    if parsed.get("error"):
        err(f"  {parsed['error']}")
    if parsed.get("hostname"):
        print(f"  {C.BOLD}Hostname :{C.RESET} {parsed['hostname']}")
    print(f"  {C.BOLD}State    :{C.RESET} {parsed.get('state', '?')}")
    if parsed.get("mac"):
        vendor = f"  ({parsed['vendor']})" if parsed.get("vendor") else ""
        print(f"  {C.BOLD}MAC      :{C.RESET} {parsed['mac']}{vendor}")
    if parsed.get("os"):
        print(f"  {C.BOLD}OS guess :{C.RESET} {parsed['os']}{os_note(parsed)}")

    ports = parsed.get("ports", [])
    open_ports = [p for p in ports if p["state"] == "open"]

    if not open_ports:
        warn("  No open ports found.")
        return

    print(f"\n  {C.BOLD}{C.GREEN}Open ports ({len(open_ports)}):{C.RESET}")
    print(f"  {C.DIM}{'-' * 68}{C.RESET}")

    for p in open_ports:
        port_str = f"{p['port']}/{p['proto']}"
        svc_str = p["service"] or "unknown"
        print(f"  {C.GREEN}{C.BOLD}{port_str:<10}{C.RESET} "
              f"{C.GREEN}{p['state']:<8}{C.RESET} "
              f"{C.CYAN}{svc_str}{C.RESET}")

        pv = " ".join(x for x in [p["product"], p["version"]] if x).strip()
        if pv:
            print(f"      {C.BOLD}└─ Version :{C.RESET} {pv}")

        if p["extrainfo"]:
            print(f"      {C.BOLD}└─ Extra   :{C.RESET} {p['extrainfo']}")

        if p["ostype"] or p["devicetype"]:
            osdt = " ".join(x for x in [p["ostype"], p["devicetype"]] if x)
            print(f"      {C.BOLD}└─ Device  :{C.RESET} {osdt}")

        if p["tunnel"]:
            print(f"      {C.BOLD}└─ Tunnel  :{C.RESET} {p['tunnel']}")

        if p["reason"]:
            print(f"      {C.BOLD}└─ Reason  :{C.RESET} {p['reason']}")

        for cpe in p["cpe"]:
            print(f"      {C.BOLD}└─ CPE     :{C.RESET} {cpe}")

        for s in p["scripts"]:
            print(f"      {C.BOLD}└─ NSE {s['id']}:{C.RESET}")
            for ln in nse_lines(s["id"], s["output"]):
                print(f"           {ln}")

        print(f"  {C.DIM}{'-' * 68}{C.RESET}")

    if parsed.get("host_scripts"):
        print(f"\n  {C.BOLD}Host scripts:{C.RESET}")
        for s in parsed["host_scripts"]:
            print(f"    {C.CYAN}{s['id']}{C.RESET}")
            for ln in nse_lines(s["id"], s["output"]):
                print(f"      {ln}")

def print_open_port_summary(all_results):
    next_step("Summary of all open ports")
    total_open = 0
    print(f"\n  {C.BOLD}{'HOST':<18}{'PORT':<12}{'SERVICE':<14}"
          f"{'VERSION':<40}{C.RESET}")
    print(f"  {'-' * 84}")
    for ip, data in sorted_hosts(all_results["hosts"]):
        opens = [p for p in data.get("ports", []) if p["state"] == "open"]
        if not opens:
            print(f"  {ip:<18}{C.DIM}(no open ports){C.RESET}")
            continue
        for p in opens:
            total_open += 1
            service = p["service"] or "?"
            ver = " ".join(x for x in [p["product"], p["version"]] if x).strip()
            if len(ver) > 38:
                ver = ver[:37] + "…"
            print(f"  {C.CYAN}{ip:<18}{C.RESET}"
                  f"{C.GREEN}{p['port'] + '/' + p['proto']:<12}{C.RESET}"
                  f"{service:<14}{ver:<40}")
    ok(f"Total open ports discovered: {total_open}")

def run_nmap_stage(pending, iface, opts, rawdir, outdir, all_results):
    interrupted = False

    def record(ip, xml, rc, tail, dur):
        if rc == -1 and list(tail) == ["aborted"] and not xml:
            log(f"nmap skipped {ip}: aborted before a finished result")
            return False
        parsed = parse_nmap_xml(xml)
        if not parsed["error"]:
            if rc not in (0, None):
                parsed["error"] = f"nmap exited with code {rc}: " + " | ".join(tail)
            elif not xml:
                parsed["error"] = "nmap produced no XML output"
        parsed["duration_s"] = round(dur, 1)
        all_results["hosts"][ip] = parsed
        save_reports(all_results, outdir)
        log(f"nmap done {ip} rc={rc} dur={dur:.1f}s "
            f"open={sum(1 for p in parsed['ports'] if p['state'] == 'open')}")
        print_host_details(ip, parsed, dur)
        return True

    try:
        if opts["workers"] == 1:
            for i, ip in enumerate(pending, 1):
                if ABORT.is_set():
                    interrupted = True
                    warn("Aborted — remaining hosts were not scanned.")
                    break
                info(f"[{i}/{len(pending)}] Scanning {ip} "
                     "(results are shown when this host finishes)...")
                t0 = time.time()
                xml, rc, tail = run_nmap(ip, iface, opts, rawdir, stream=False)
                if not record(ip, xml, rc, tail, time.time() - t0):
                    interrupted = True
                    warn("Aborted — remaining hosts were not scanned.")
                    break
        else:
            info(f"Running {opts['workers']} nmap workers "
                 "(details are printed as each host finishes).")

            def job(ip):
                t0 = time.time()
                xml, rc, tail = run_nmap(ip, iface, opts, rawdir, stream=False)
                return ip, xml, rc, tail, time.time() - t0

            ex = ThreadPoolExecutor(max_workers=opts["workers"])
            futs = [ex.submit(job, ip) for ip in pending]
            try:
                for n, fut in enumerate(as_completed(futs), 1):
                    if ABORT.is_set():
                        interrupted = True
                    ip, xml, rc, tail, dur = fut.result()
                    if not record(ip, xml, rc, tail, dur):
                        warn(f"[{n}/{len(pending)}] aborted {ip}")
                        interrupted = True
                        continue
                    ok(f"[{n}/{len(pending)}] finished {ip}")
            except KeyboardInterrupt:
                ABORT.set()
                ex.shutdown(wait=False, cancel_futures=True)
                terminate_active()
                raise
            finally:
                ex.shutdown(wait=True)
    except KeyboardInterrupt:
        interrupted = True
        ABORT.set()
        terminate_active()
        warn("Interrupted (Ctrl-C or SIGINT) — saving partial results.")
        info(f"Resume nmap:            sudo whitescan --resume {outdir}")
        info(f"OpenVAS on finished:    sudo whitescan --openvas-only {outdir}")
    return interrupted

