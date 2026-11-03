"""whitescan.openvas"""
import importlib
import ipaddress
import logging
import os
import re
import sys
import time
from datetime import datetime

try:
    from gvm.connections import UnixSocketConnection, TLSConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeCheckCommandTransform
    from gvm.errors import GvmResponseError
    HAVE_GVM = True
except ImportError:
    HAVE_GVM = False
    GvmResponseError = Exception  # noqa: A001 — placeholder when gvm missing

from .constants import (
    DEFAULT_GVM_TIMEOUT, GVM_CONFIG_NAME, GVM_DEFAULT_PORTLIST,
    GVM_DEFAULT_SCAN_CONFIG, GVM_DEFAULT_SCANNER, GVM_PORTLIST_NAME,
    GVM_REPORT_FILTER, GVM_SCANNER_NAME, GVM_XML_REPORT_FORMAT,
)
from .paths import CONFIG_DIR, OPENVAS_JSON
from .util import (
    C, alert, banner, err, fix_perms, info, log, log_exc, make_private_dir,
    next_step, ok, sorted_hosts, warn, _ip_key,
)

def _load_alive_test():
    for mod in ("gvm.protocols.gmp.requests.v224",
                "gvm.protocols.gmpv224",
                "gvm.protocols.gmpv208",
                "gvm.protocols.gmpv208.entities.hosts"):
        try:
            return importlib.import_module(mod).AliveTest
        except (ImportError, AttributeError):
            continue
    return None

def load_openvas_config():
    try:
        with open(OPENVAS_JSON) as f:
            data = json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        err(f"Cannot read {OPENVAS_JSON}: {e}")
        return None
    if not isinstance(data, dict):
        err(f"{OPENVAS_JSON}: expected a JSON object.")
        return None
    return data

def save_openvas_config(cfg):
    make_private_dir(CONFIG_DIR)
    tmp = OPENVAS_JSON + ".tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps(cfg, indent=2).encode("utf-8"))
        finally:
            os.close(fd)
        try:
            fix_perms(tmp, 0o600, fatal=True)
        except RuntimeError as e:
            err(str(e))
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return False
        os.replace(tmp, OPENVAS_JSON)
        try:
            fix_perms(OPENVAS_JSON, 0o600, fatal=True)
        except RuntimeError as e:
            err(str(e))
            return False
        return True
    except OSError as e:
        err(f"Cannot write {OPENVAS_JSON}: {e}")
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False

def require_openvas_config():
    cfg = load_openvas_config()
    if cfg is None:
        err(f"OpenVAS credentials not configured ({OPENVAS_JSON} not found).")
        info("Run once:  sudo whitescan --setup")
        sys.exit(2)
    missing = [k for k in ("username", "password", "gvm_socket") if not cfg.get(k)]
    if missing:
        err(f"OpenVAS config is incomplete ({OPENVAS_JSON}): "
            f"missing {', '.join(missing)}.")
        info("Run:  sudo whitescan --setup")
        sys.exit(2)
    return cfg


GVM_DEFAULT_SCAN_CONFIG = "daba56c8-73ec-11df-a475-002264764cea"
GVM_DEFAULT_SCANNER     = "08b69003-5fc2-4037-a479-93b440211c73"
GVM_DEFAULT_PORTLIST    = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
GVM_XML_REPORT_FORMAT   = "a994b278-1f62-11e1-96ac-406186ea4fc5"
GVM_REPORT_FILTER       = "levels=chmlg min_qod=0 rows=-1 first=1"

GVM_CONFIG_NAME   = "Full and fast"
GVM_SCANNER_NAME  = "OpenVAS Default"
GVM_PORTLIST_NAME = "All IANA assigned TCP"

def prompt_openvas_targets(candidate_ips):
    banner("OpenVAS / GVM Scan", C.YELLOW)

    if not HAVE_GVM:
        warn("python-gvm not installed — skipping OpenVAS.")
        info("Install with: pip install python-gvm")
        return None

    if not candidate_ips:
        warn("No candidate IPs to scan with OpenVAS.")
        return None

    print(f"{C.BOLD}Hosts Nmap found to be up:{C.RESET}")
    for idx, ip in enumerate(candidate_ips, 1):
        print(f"  [{idx}] {C.GREEN}{ip}{C.RESET}")
    print()

    while True:
        choice = input(
            f"{C.BOLD}Select hosts to scan with OpenVAS "
            f"(space-separated numbers), or 'n' for no: {C.RESET}"
        ).strip()

        if choice.lower() == "n":
            info("Skipping OpenVAS scan.")
            return None
        if not choice:
            warn("Empty input. Enter numbers or 'n'.")
            continue

        picked = []
        bad = []
        for token in choice.split():
            if token.isdigit():
                idx = int(token)
                if 1 <= idx <= len(candidate_ips):
                    picked.append(candidate_ips[idx - 1])
                else:
                    bad.append(f"#{token} (out of range 1..{len(candidate_ips)})")
                continue
            try:
                ipaddress.ip_address(token)
                picked.append(token)
            except ValueError:
                bad.append(token)

        if bad:
            warn(f"Invalid selection: {', '.join(bad)}")
            continue

        seen = set()
        uniq = []
        for ip in picked:
            if ip not in seen:
                seen.add(ip)
                uniq.append(ip)
        picked = uniq

        if not picked:
            warn("No valid selection.")
            continue

        unknown = [ip for ip in picked if ip not in candidate_ips]
        if unknown:
            warn(f"Not in Nmap results: {', '.join(unknown)}")
            retry = input(
                f"{C.YELLOW}Continue with these anyway? [y/N]: {C.RESET}"
            ).strip().lower()
            if retry != "y":
                continue

        ok(f"Selected {len(picked)} OpenVAS target(s): {', '.join(picked)}")
        return picked

def _gvm_connect(gmp_host):
    if gmp_host and gmp_host.startswith("/"):
        connection = UnixSocketConnection(path=gmp_host)
    else:
        connection = TLSConnection(hostname=gmp_host, port=9390)
    return Gmp(connection=connection, transform=EtreeCheckCommandTransform())

def _read_target_file(path):
    ips = []
    try:
        with open(path) as f:
            for ln in f:
                ln = ln.split("#", 1)[0].strip()
                if not ln:
                    continue
                try:
                    ip = ipaddress.ip_address(ln)
                except ValueError:
                    err(f"{path}: '{ln}' is not an IP address; skipping.")
                    continue
                if ip.version != 4:
                    err(f"{path}: '{ln}' is IPv6; WhiteScan is IPv4-only; skipping.")
                    continue
                ips.append(ln)
    except OSError as e:
        err(f"Cannot read {path}: {e}")
        return None
    if not ips:
        err(f"{path}: no IP addresses found.")
        return None
    ok(f"Read {len(ips)} target(s) from {path}.")
    return ips

def resolve_openvas_targets(args, candidates, all_ips, interactive):
    if args.no_openvas:
        info("OpenVAS skipped (--no-openvas).")
        return None
    if not HAVE_GVM:
        warn("python-gvm not installed — skipping OpenVAS.")
        info("Install with: pip install python-gvm")
        return None

    if args.openvas_file:
        if args.openvas:
            err("Use --openvas or --openvas-file, not both.")
            return None
        picked = _read_target_file(args.openvas_file)
        if not picked:
            return None
        picked = list(dict.fromkeys(picked))
        ok(f"OpenVAS targets ({len(picked)}): {', '.join(picked)}")
        return picked

    if args.openvas is not None:
        spec = args.openvas.strip().lower()

        if spec == "open" or spec == "":
            picked = list(candidates)
            label = "hosts with open ports"
            if not picked:
                warn(f"--openvas: no {label} to scan.")
                return None
            ok(f"OpenVAS targets ({len(picked)}, {label}): {', '.join(picked)}")
            return picked

        if spec == "all":
            picked = list(all_ips)
            if not picked:
                warn("--openvas all: no live hosts.")
                return None
            ok(f"OpenVAS targets ({len(picked)}, all live hosts): {', '.join(picked)}")
            return picked

        picked = []
        for tok in re.split(r"[,\s]+", spec):
            if not tok:
                continue
            try:
                ip = ipaddress.ip_address(tok)
            except ValueError:
                err(f"--openvas: '{tok}' is not an IP address.")
                err(f"--openvas accepts only: open | all | <IP[,IP...]>")
                return None
            if ip.version != 4:
                err(f"--openvas: '{tok}' is IPv6; WhiteScan is IPv4-only.")
                return None
            picked.append(tok)
        if not picked:
            warn("--openvas: no IP addresses given.")
            return None
        picked = list(dict.fromkeys(picked))
        unknown = [ip for ip in picked if ip not in all_ips]
        if unknown:
            warn(f"Not in the scan results (scanning anyway): {', '.join(unknown)}")
        ok(f"OpenVAS targets ({len(picked)}): {', '.join(picked)}")
        return picked

    if interactive:
        return prompt_openvas_targets(candidates)
    info("OpenVAS skipped (no terminal and no --openvas given).")
    return None

def _extract_task_status(task_xml):
    status_el = task_xml.find(".//status")
    progress_el = task_xml.find(".//progress")
    status = status_el.text if status_el is not None else "unknown"
    progress = progress_el.text if progress_el is not None else "?"
    return status, progress

def poll_task_until_done(gmp, task_id, poll_interval=15,
                         max_errors=5, timeout=None):
    info(f"Polling task {task_id} every {poll_interval}s until completion...")
    log(f"openvas poll start task={task_id} interval={poll_interval}s timeout={timeout}")
    last_status = None
    last_progress = None
    errors = 0
    deadline = time.time() + timeout if timeout else None

    while True:
        if deadline and time.time() > deadline:
            warn("Polling timeout reached. Task may still be running on GVM.")
            log(f"openvas poll timeout task={task_id}")
            return "timeout"
        try:
            task_xml = gmp.get_task(task_id)
            status, progress = _extract_task_status(task_xml)
            errors = 0

            if status != last_status or progress != last_progress:
                print(f"  {C.DIM}[{datetime.now().strftime('%H:%M:%S')}]{C.RESET} "
                      f"status={C.YELLOW}{status}{C.RESET} "
                      f"progress={C.CYAN}{progress}%{C.RESET}")
                log(f"openvas poll task={task_id} status={status} progress={progress}")
                last_status, last_progress = status, progress

            if status.lower() in ("done", "stopped", "interrupted"):
                log(f"openvas poll finished task={task_id} status={status}")
                return status

        except KeyboardInterrupt:
            warn("Polling interrupted by user. Task continues on GVM side.")
            log(f"openvas poll user-interrupted task={task_id}")
            return "user_interrupted"
        except Exception as e:
            errors += 1
            err(f"Poll error ({errors}/{max_errors}): {e}")
            log_exc(f"openvas poll error ({errors}/{max_errors}) task={task_id}")
            if errors >= max_errors:
                err("Too many consecutive poll errors; giving up.")
                return "poll_failed"

        try:
            time.sleep(poll_interval)
        except KeyboardInterrupt:
            warn("Polling interrupted by user. Task continues on GVM side.")
            log(f"openvas poll user-interrupted task={task_id}")
            return "user_interrupted"

def parse_openvas_results(report_xml):
    results = []
    for res_el in report_xml.findall(".//result"):
        def txt(tag):
            el = res_el.find(tag)
            return el.text if el is not None and el.text else ""

        name = txt("name")
        host = txt("host")
        port = txt("port")
        severity = txt("severity")
        threat = txt("threat")
        description = txt("description")

        nvt_el = res_el.find("nvt")
        nvt_oid = nvt_el.get("oid") if nvt_el is not None else ""

        cves = []
        refs_el = res_el.find("nvt/refs")
        if refs_el is not None:
            for ref in refs_el.findall("ref"):
                if ref.get("type") == "cve":
                    cves.append(ref.get("id", ""))

        cvss = ""
        sev_el = res_el.find("nvt/severity")
        if sev_el is not None and sev_el.text:
            cvss = sev_el.text

        results.append({
            "name": name,
            "host": host,
            "port": port,
            "severity": severity,
            "cvss": cvss,
            "threat": threat,
            "cve": cves,
            "nvt_oid": nvt_oid,
            "description": description,
        })

    def sort_key(r):
        try:
            return float(r["severity"] or r["cvss"] or 0)
        except ValueError:
            return 0.0

    results.sort(key=sort_key, reverse=True)
    return results

def print_openvas_results(results):
    if not results:
        warn("OpenVAS returned zero vulnerability results.")
        return

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Log": 0, "Unknown": 0}
    for r in results:
        threat = (r["threat"] or "").strip()
        if threat in counts:
            counts[threat] += 1
        else:
            counts["Unknown"] += 1

    banner(f"OpenVAS Results: {len(results)} finding(s)", C.RED)
    print(f"  {C.BOLD}Severity breakdown:{C.RESET}")
    for label, color in [("Critical", C.RED), ("High", C.RED),
                          ("Medium", C.YELLOW), ("Low", C.CYAN),
                          ("Log", C.DIM), ("Unknown", C.DIM)]:
        if counts[label]:
            print(f"    {color}{label:<10}{C.RESET} {counts[label]}")

    print(f"\n  {C.DIM}{'-' * 72}{C.RESET}")

    for i, r in enumerate(results, 1):
        sev = r["severity"] or r["cvss"] or "?"
        threat = r["threat"] or "?"
        color = C.RED if threat in ("Critical", "High") else (
            C.YELLOW if threat == "Medium" else C.CYAN)

        print(f"\n  {C.BOLD}[{i}/{len(results)}]{C.RESET} "
              f"{color}{C.BOLD}{r['name']}{C.RESET}")
        print(f"      {C.BOLD}Severity :{C.RESET} {color}{sev}{C.RESET} ({threat})")
        print(f"      {C.BOLD}Host     :{C.RESET} {r['host']}")
        if r["port"] and r["port"] != "general/tcp":
            print(f"      {C.BOLD}Port     :{C.RESET} {r['port']}")
        if r["cve"]:
            print(f"      {C.BOLD}CVE      :{C.RESET} {', '.join(r['cve'])}")
        if r["nvt_oid"]:
            print(f"      {C.BOLD}NVT OID  :{C.RESET} {r['nvt_oid']}")

        if r["description"]:
            desc_lines = r["description"].splitlines()
            for ln in desc_lines[:6]:
                print(f"      {C.DIM}{ln}{C.RESET}")
            if len(desc_lines) > 6:
                print(f"      {C.DIM}... ({len(desc_lines) - 6} more lines){C.RESET}")

        print(f"  {C.DIM}{'-' * 72}{C.RESET}")

def _xml_bytes(el):
    try:
        from lxml import etree as LET
        return LET.tostring(el, pretty_print=True)
    except ImportError:
        return ET.tostring(el, encoding="utf-8")

def fetch_report_with_fallback(gmp, report_id, rawdir=None):
    attempts = [
        ("custom_filter", dict(filter_string=GVM_REPORT_FILTER)),
        ("default_filter", {}),
        ("explicit_xml_format", dict(report_format_id=GVM_XML_REPORT_FORMAT,
                                     filter_string=GVM_REPORT_FILTER)),
    ]
    best = None
    for label, extra in attempts:
        try:
            report_xml = gmp.get_report(
                report_id=report_id,
                ignore_pagination=True,
                details=True,
                **extra,
            )
        except Exception as e:
            warn(f"Report request '{label}' failed: {e}")
            log_exc(f"openvas get_report '{label}' failed report={report_id}")
            continue

        n = len(report_xml.findall(".//result"))
        info(f"Report request '{label}': {n} result element(s) returned.")
        log(f"openvas get_report '{label}' report={report_id} results={n}")

        if rawdir:
            path = os.path.join(rawdir, f"openvas_report_{label}.xml")
            try:
                with open(path, "wb") as f:
                    f.write(_xml_bytes(report_xml))
                fix_perms(path, 0o600, fatal=False)
                info(f"Raw GVM response saved: {path}")
            except OSError as e:
                warn(f"Could not save raw report: {e}")

        if best is None or n > len(best.findall(".//result")):
            best = report_xml
        if n > 0:
            return report_xml
    return best

def _resolve_gvm_by_name(gmp, kind, name, fallback_id):
    try:
        if kind == "config":
            xml = gmp.get_scan_configs()
            nodes = xml.findall(".//config")
        elif kind == "scanner":
            xml = gmp.get_scanners()
            nodes = xml.findall(".//scanner")
        elif kind == "portlist":
            xml = gmp.get_port_lists()
            nodes = xml.findall(".//port_list")
        else:
            return fallback_id
        for n in nodes:
            if (n.findtext("name") or "").strip() == name:
                gid = n.get("id")
                if gid:
                    log(f"gvm resolved {kind} '{name}' -> {gid}")
                    return gid
    except Exception:
        log_exc(f"gvm resolve {kind} '{name}' failed; using fallback {fallback_id}")
    return fallback_id

def _latest_report_for_task(gmp, task_id, task_xml):
    try:
        flt = f"task_id={task_id} sort=created desc"
        res = gmp.get_reports(filter_string=flt, ignore_pagination=True)
        report_els = res.findall(".//report")
        if report_els:
            rid = report_els[0].get("id")
            if rid:
                log(f"openvas report by task_id={task_id} -> {rid}")
                return rid
    except Exception:
        log_exc(f"openvas get_reports by task_id={task_id} failed; "
                f"falling back to task XML")

    task_el = task_xml.find(".//task")
    if task_el is not None:
        last = task_el.find("last_report/report")
        if last is not None and last.get("id"):
            log(f"openvas report from task last_report -> {last.get('id')}")
            return last.get("id")

    report_els = task_xml.findall(".//report")
    if report_els:
        rid = report_els[-1].get("id")
        log(f"openvas report from task .//report[-1] -> {rid}")
        return rid
    return None

def _delete_gvm_object(gmp, kind, oid):
    try:
        if kind == "task":
            gmp.delete_task(oid, ultimate=True)
        elif kind == "target":
            gmp.delete_target(oid, ultimate=True)
        log(f"gvm deleted {kind} {oid}")
        return True
    except Exception:
        log_exc(f"gvm delete {kind} {oid} failed")
        return False

def _print_orphan_warning(reason, task_id, target_id,
                          gmp_host, username):
    alert("=" * 66)
    alert(f"OpenVAS {reason.upper()}: task {task_id} is STILL RUNNING")
    alert("on the GVM server. WhiteScan has stopped waiting.")
    alert("The scan continues server-side.")
    alert("=" * 66)
    alert(f"Inspect:")
    alert(f"  gvm-cli --gmp-username {username} --gmp-password '<pw>' \\")
    alert(f"    socket --socketpath {gmp_host} \\")
    alert(f"    --xml \"<get_tasks task_id='{task_id}'/>\"")
    alert(f"Stop:")
    alert(f"  gvm-cli ... --xml \"<stop_task task_id='{task_id}'/>\"")
    alert(f"Task ID    : {task_id}")
    alert(f"Target ID  : {target_id}")
    alert("=" * 66)
    log(f"openvas orphaned task={task_id} target={target_id} reason={reason}",
        logging.WARNING)

def run_openvas_scan(target_ips, gmp_host, username, password,
                     poll_interval=15, rawdir=None, timeout=None,
                     cleanup_on_success=True):
    banner(f"Launching OpenVAS scan on {len(target_ips)} host(s)", C.MAGENTA)
    log(f"openvas start targets={target_ips} host={gmp_host} user={username}")

    meta = {
        "success": False,
        "targets": target_ips,
        "vulnerabilities": [],
    }

    try:
        with _gvm_connect(gmp_host) as gmp:
            gmp.authenticate(username, password)
            ok(f"Authenticated with GVM as '{username}'.")
            log(f"openvas authenticated user={username}")

            config_id = _resolve_gvm_by_name(
                gmp, "config", GVM_CONFIG_NAME, GVM_DEFAULT_SCAN_CONFIG)
            scanner_id = _resolve_gvm_by_name(
                gmp, "scanner", GVM_SCANNER_NAME, GVM_DEFAULT_SCANNER)
            portlist_id = _resolve_gvm_by_name(
                gmp, "portlist", GVM_PORTLIST_NAME, GVM_DEFAULT_PORTLIST)

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_name = f"nmap_targets_{ts}"
            info(f"Creating target '{target_name}'...")
            log(f"openvas create_target name={target_name} portlist={portlist_id}")

            target_kwargs = dict(
                name=target_name,
                hosts=target_ips,
                port_list_id=portlist_id,
            )
            alive_test_cls = _load_alive_test()
            if alive_test_cls is not None:
                target_kwargs["alive_test"] = alive_test_cls.CONSIDER_ALIVE
            else:
                warn("Could not import AliveTest from python-gvm; hosts that "
                     "block ping may be skipped by OpenVAS.")

            target_resp = gmp.create_target(**target_kwargs)
            target_id = target_resp.get("id")
            ok(f"Target created: {target_id}")
            log(f"openvas target_id={target_id}")

            task_name = f"nmap_scan_{ts}"
            info(f"Creating task '{task_name}'...")
            log(f"openvas create_task name={task_name} config={config_id} "
                f"scanner={scanner_id}")
            task_resp = gmp.create_task(
                name=task_name,
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id,
            )
            task_id = task_resp.get("id")
            ok(f"Task created: {task_id}")
            log(f"openvas task_id={task_id}")

            meta.update({
                "task_id": task_id,
                "target_id": target_id,
                "target_name": target_name,
                "task_name": task_name,
            })

            info(f"Starting task {task_id}...")
            gmp.start_task(task_id)
            meta["started"] = datetime.now().isoformat()
            ok("OpenVAS scan started.")
            log(f"openvas start_task task={task_id}")

            final_status = poll_task_until_done(gmp, task_id, poll_interval,
                                                timeout=timeout)
            meta["final_status"] = final_status
            meta["finished"] = datetime.now().isoformat()
            log(f"openvas task={task_id} final_status={final_status}")

            if final_status in ("timeout", "poll_failed", "user_interrupted"):
                reason = {
                    "timeout": "timeout",
                    "poll_failed": "poll_failed",
                    "user_interrupted": "user-interrupted",
                }[final_status]
                _print_orphan_warning(reason, task_id, target_id,
                                      gmp_host, username)
                meta["orphaned"] = (
                    f"task {task_id} is still running on GVM; "
                    f"check or stop it manually")
                meta["error"] = f"openvas poll ended with {final_status}"
                return meta

            if final_status.lower() != "done":
                warn(f"Task ended with status: {final_status}")
                meta["error"] = f"task ended with status {final_status}"
                if cleanup_on_success:
                    _delete_gvm_object(gmp, "task", task_id)
                    _delete_gvm_object(gmp, "target", target_id)
                return meta

            info("Fetching report...")
            task_xml = gmp.get_task(task_id)
            report_id = _latest_report_for_task(gmp, task_id, task_xml)
            if not report_id:
                err("No report attached to task.")
                meta["error"] = "no report attached to task"
                log(f"openvas task={task_id} no report attached")
                if cleanup_on_success:
                    _delete_gvm_object(gmp, "task", task_id)
                    _delete_gvm_object(gmp, "target", target_id)
                return meta

            info(f"Report ID: {report_id}")
            log(f"openvas report_id={report_id}")
            meta["report_id"] = report_id

            report_xml = fetch_report_with_fallback(gmp, report_id, rawdir)
            if report_xml is None:
                err("Could not fetch the report from GVM.")
                meta["error"] = "could not fetch report from GVM"
                if cleanup_on_success:
                    _delete_gvm_object(gmp, "task", task_id)
                    _delete_gvm_object(gmp, "target", target_id)
                return meta

            vulns = parse_openvas_results(report_xml)
            print_openvas_results(vulns)
            meta["vulnerabilities"] = vulns
            log(f"openvas parsed {len(vulns)} findings")

            meta["success"] = True

            if cleanup_on_success:
                info("Cleaning up GVM task/target (report is preserved)...")
                _delete_gvm_object(gmp, "task", task_id)
                _delete_gvm_object(gmp, "target", target_id)

            return meta

    except Exception as e:
        err(f"OpenVAS error: {e}")
        info("Hint: verify GVM is running, credentials, and socket path.")
        log_exc("openvas fatal error")
        meta["error"] = str(e)
        if meta.get("task_id"):
            _print_orphan_warning("error", meta["task_id"],
                                  meta.get("target_id", "?"),
                                  gmp_host, username)
            meta["orphaned"] = (
                f"task {meta['task_id']} may still be running on GVM")
        return meta

def openvas_stage(args, all_results, rawdir, interactive):
    next_step("OpenVAS vulnerability scan (optional)")
    hosts = all_results.get("hosts", {})
    all_ips = sorted(set(hosts) | set(all_results.get("targets") or []),
                     key=_ip_key)
    candidates = [ip for ip, d in sorted_hosts(hosts)
                  if any(p["state"] == "open" for p in d.get("ports", []))]
    if not candidates:
        candidates = list(all_ips)

    selected = resolve_openvas_targets(args, candidates, all_ips, interactive)
    if not selected:
        return False

    cfg = require_openvas_config()

    timeout = args.gvm_timeout if args.gvm_timeout is not None else DEFAULT_GVM_TIMEOUT
    if args.gvm_timeout is None:
        info(f"--gvm-timeout not set; defaulting to {DEFAULT_GVM_TIMEOUT}s.")

    meta = run_openvas_scan(selected,
                            gmp_host=cfg["gvm_socket"],
                            username=cfg["username"],
                            password=cfg["password"],
                            poll_interval=args.gvm_poll,
                            rawdir=rawdir,
                            timeout=timeout)

    if not meta:
        return False

    if meta.get("success"):
        old = all_results.get("openvas")
        if old:
            all_results.setdefault("openvas_history", []).append(old)
        all_results["openvas"] = meta
        return True

    all_results.setdefault("openvas_failures", []).append(meta)
    log(f"openvas attempt recorded as failure: "
        f"{meta.get('error') or meta.get('final_status') or 'unknown'}")
    return False

