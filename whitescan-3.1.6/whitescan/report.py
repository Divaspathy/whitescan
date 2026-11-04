"""whitescan.report"""
import json
import logging
import os
import pwd
import shutil
import shlex
import subprocess
import sys
from datetime import datetime

from .constants import MAX_LINE, NSE_CAPS, NSE_DEFAULT_CAP, TXT_W
from .util import (
    C, clean_lines, err, fix_perms, info, log, log_exc, nse_lines, ok,
    os_note, sorted_hosts, warn, _ip_key,
)

def _load_openvas_section(ov):
    if not isinstance(ov, dict):
        return None, [], []
    ov = dict(ov)
    history = ov.pop("previous_runs", []) or []
    failures = ov.pop("failed_runs", []) or []
    if ov.get("ran") is False:
        success = None
    elif ov.get("success") is False:
        success = None
        if not any(f.get("task_id") == ov.get("task_id") for f in failures):
            failures = failures + [ov]
    else:
        success = ov
    return success, history, failures

def load_results(path):
    jpath = os.path.join(path, "scan_report.json") if os.path.isdir(path) else path
    try:
        with open(jpath) as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        err(f"Cannot read {jpath}: {e}")
        sys.exit(1)

    outdir = os.path.dirname(os.path.abspath(jpath))
    if "nmap_session" in data:
        sc = data.get("scan", {})
        ns = data.get("nmap_session", {})
        r = {
            "interface": sc.get("interface"),
            "cidr": sc.get("cidr"),
            "started": sc.get("started"),
            "finished": sc.get("finished"),
            "targets": sc.get("targets"),
            "resumes": sc.get("resumes", []),
            "options": ns.get("options"),
            "hosts": ns.get("hosts", {}),
        }
        success, history, failures = _load_openvas_section(
            data.get("openvas_session"))
        r["openvas"] = success
        if history:
            r["openvas_history"] = history
        if failures:
            r["openvas_failures"] = failures
    else:
        r = data
        r.setdefault("hosts", {})
    return r, outdir

def structure_report(r):
    ov = r.get("openvas")
    ov_sess = dict(ov) if ov else {"ran": False}
    if r.get("openvas_history"):
        ov_sess["previous_runs"] = r["openvas_history"]
    if r.get("openvas_failures"):
        ov_sess["failed_runs"] = r["openvas_failures"]
    return {
        "scan": {
            "interface": r.get("interface"),
            "cidr": r.get("cidr"),
            "started": r.get("started"),
            "finished": r.get("finished"),
            "interrupted": r.get("interrupted", False),
            "resumes": r.get("resumes", []),
            "targets": r.get("targets"),
        },
        "nmap_session": {
            "options": r.get("options"),
            "hosts": dict(sorted_hosts(r.get("hosts", {}))),
        },
        "openvas_session": ov_sess,
    }

def write_report(data, path):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(structure_report(data), f, indent=2)
    fix_perms(tmp, 0o600, fatal=False)
    os.replace(tmp, path)


TXT_W = 80

def _hash_banner(title):
    line = "#" * TXT_W
    blank = "#" + " " * (TXT_W - 2) + "#"
    inner = title.center(TXT_W - 4)[:TXT_W - 4]
    return "\n".join([line, blank, f"# {inner} #", blank, line]) + "\n"

def _indent(text, n=6, max_lines=None):
    lines = clean_lines(text) or ["(no output)"]
    extra = 0
    if max_lines and len(lines) > max_lines:
        extra = len(lines) - max_lines
        lines = lines[:max_lines]
    out = [" " * n + ln if ln else "" for ln in lines]
    if extra:
        out.append(" " * n + f"... ({extra} more lines, see scan_report.json)")
    return "\n".join(out)

def render_text_report(r):
    L = []
    hosts = sorted_hosts(r.get("hosts", {}))

    L.append(_hash_banner("WHITESCAN REPORT"))
    L.append(f"Interface : {r.get('interface')}")
    L.append(f"Network   : {r.get('cidr')}")
    L.append(f"Started   : {r.get('started')}")
    L.append(f"Finished  : {r.get('finished', '(still running)')}")
    for t in r.get("resumes", []):
        L.append(f"Resumed   : {t}")
    if r.get("interrupted"):
        L.append("NOTE      : scan was interrupted, results are partial")
    L.append("")
    L.append("Contents  : [1] NMAP SESSION     [2] OPENVAS SESSION")
    L.append("")
    L.append("")

    L.append(_hash_banner("SECTION 1 of 2  :  NMAP SESSION"))
    o = r.get("options") or {}
    L.append("[NMAP] Options")
    L.append(f"       port scope        : "
             f"{'top 1000' if o.get('top_1000') else 'all 65535'}")
    L.append(f"       service detection : {o.get('service_detection')}")
    L.append(f"       OS detection      : {o.get('os_detection')}")
    L.append(f"       default NSE       : {o.get('nse_scripts')}")
    L.append(f"       timing            : {o.get('timing')}")
    L.append(f"       workers           : {o.get('workers')}")
    L.append("")

    for ip, d in hosts:
        L.append("=" * TXT_W)
        dur = d.get("duration_s")
        dur_txt = f"   ({dur}s)" if dur is not None else ""
        L.append(f"[NMAP] HOST {ip}   state={d.get('state', '?')}{dur_txt}")
        L.append("=" * TXT_W)
        if d.get("error"):
            L.append(f"  ERROR    : {d['error']}")
        if d.get("hostname"):
            L.append(f"  Hostname : {d['hostname']}")
        if d.get("mac"):
            v = f" ({d['vendor']})" if d.get("vendor") else ""
            L.append(f"  MAC      : {d['mac']}{v}")
        if d.get("os"):
            L.append(f"  OS guess : {d['os']}{os_note(d)}")

        ports = d.get("ports", [])
        opens = [p for p in ports if p["state"] == "open"]
        other = len(ports) - len(opens)
        if not opens:
            L.append("  Open ports: none")
        else:
            L.append(f"  Open ports ({len(opens)}):")
            for p in opens:
                pv = " ".join(x for x in [p["product"], p["version"]] if x)
                line = f"    {p['port'] + '/' + p['proto']:<11}{p['service'] or '?':<16}{pv}"
                L.append(line.rstrip())
                if p.get("extrainfo"):
                    L.append(f"        extra : {p['extrainfo']}")
                for c in p.get("cpe", []):
                    L.append(f"        cpe   : {c}")
                for sc in p.get("scripts", []):
                    L.append(f"        NSE {sc['id']}:")
                    for ln in nse_lines(sc["id"], sc["output"]):
                        L.append(" " * 12 + ln if ln else "")
        if other:
            L.append(f"  (+{other} closed/filtered port(s) listed in the JSON)")
        for sc in d.get("host_scripts", []):
            L.append(f"  Host script {sc['id']}:")
            for ln in nse_lines(sc["id"], sc["output"]):
                L.append(" " * 6 + ln if ln else "")
        L.append("")

    L.append("[NMAP] Summary of open ports")
    L.append(f"       {'HOST':<18}{'PORT':<12}{'SERVICE':<16}VERSION")
    total = 0
    for ip, d in hosts:
        opens = [p for p in d.get("ports", []) if p["state"] == "open"]
        if not opens:
            L.append(f"       {ip:<18}(no open ports)")
        for p in opens:
            total += 1
            pv = " ".join(x for x in [p["product"], p["version"]] if x)
            L.append(f"       {ip:<18}{p['port'] + '/' + p['proto']:<12}"
                     f"{p['service'] or '?':<16}{pv}".rstrip())
    L.append(f"       Total open ports: {total}")
    L.append("")
    L.append("")

    L.append(_hash_banner("SECTION 2 of 2  :  OPENVAS SESSION"))
    ov = r.get("openvas")
    hist = r.get("openvas_history") or []
    failures = r.get("openvas_failures") or []
    if hist:
        L.append(f"[OPENVAS] {len(hist)} earlier successful run(s) are stored "
                 "in scan_report.json under openvas_session.previous_runs")
        L.append("")
    if failures:
        L.append(f"[OPENVAS] {len(failures)} failed attempt(s) are stored "
                 "in scan_report.json under openvas_session.failed_runs")
        for f in failures:
            tgt = ", ".join(f.get("targets", [])) or "?"
            why = f.get("error") or f.get("final_status") or "unknown"
            tid = f.get("task_id") or "-"
            L.append(f"          targets={tgt}  status={why}  task={tid}")
            if f.get("orphaned"):
                L.append(f"          NOTE: {f['orphaned']}")
        L.append("")
    if not ov:
        L.append("[OPENVAS] OpenVAS was not successfully completed in this session.")
        return "\n".join(L) + "\n"

    if ov.get("error"):
        L.append(f"[OPENVAS] ERROR: {ov['error']}")
        L.append("")

    L.append(f"[OPENVAS] Targets     : {', '.join(ov.get('targets', []))}")
    L.append(f"[OPENVAS] Task        : {ov.get('task_name', '?')}  ({ov.get('task_id', '?')})")
    L.append(f"[OPENVAS] Started     : {ov.get('started', '?')}")
    L.append(f"[OPENVAS] Finished    : {ov.get('finished', '?')}")
    L.append(f"[OPENVAS] Status      : {ov.get('final_status', '?')}")
    L.append(f"[OPENVAS] Report ID   : {ov.get('report_id', '?')}")
    L.append("")

    vulns = list(ov.get("vulnerabilities", []))

    def sev(v):
        try:
            return float(v.get("severity") or v.get("cvss") or 0)
        except ValueError:
            return 0.0

    vulns.sort(key=lambda v: (_ip_key(v.get("host", "")), -sev(v)))

    counts = {}
    for v in vulns:
        t = (v.get("threat") or "Unknown").strip() or "Unknown"
        counts[t] = counts.get(t, 0) + 1
    L.append(f"[OPENVAS] Findings: {len(vulns)}")
    for label in ("Critical", "High", "Medium", "Low", "Log", "Unknown"):
        if counts.get(label):
            L.append(f"          {label:<10}{counts[label]}")
    L.append("")

    for i, v in enumerate(vulns, 1):
        L.append("~" * TXT_W)
        L.append(f"[OPENVAS] FINDING {i}/{len(vulns)}: {v['name']}")
        L.append("~" * TXT_W)
        L.append(f"  Severity : {v.get('severity') or v.get('cvss') or '?'} "
                 f"({v.get('threat') or '?'})")
        L.append(f"  Host     : {v['host']}")
        if v.get("port"):
            L.append(f"  Port     : {v['port']}")
        if v.get("cve"):
            L.append(f"  CVE      : {', '.join(v['cve'])}")
        if v.get("nvt_oid"):
            L.append(f"  NVT OID  : {v['nvt_oid']}")
        L.append("  Details  :")
        L.append(_indent(v.get("description", ""), 4, max_lines=40))
        L.append("")
    return "\n".join(L) + "\n"

def save_reports(r, outdir):
    jpath = os.path.join(outdir, "scan_report.json")
    tpath = os.path.join(outdir, "scan_report.txt")
    write_report(r, jpath)
    try:
        tmp = tpath + ".tmp"
        with open(tmp, "w") as f:
            f.write(render_text_report(r))
        fix_perms(tmp, 0o600, fatal=False)
        os.replace(tmp, tpath)
    except Exception as e:
        warn(f"Could not write text report: {e}")
        log_exc("write text report failed")
    return jpath, tpath

def open_report(path):
    info(f"Report: {path}")

    editor = shutil.which("mousepad")
    if editor:
        env = os.environ.copy()
        env.setdefault("DISPLAY", ":0")
        cmd = [editor, path]
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user and sudo_user != "root":
            try:
                pw = pwd.getpwnam(sudo_user)
                assigns = [f"DISPLAY={env['DISPLAY']}"]
                xa = os.path.join(pw.pw_dir, ".Xauthority")
                if os.path.exists(xa):
                    assigns.append(f"XAUTHORITY={xa}")
                bus = f"/run/user/{pw.pw_uid}/bus"
                if os.path.exists(bus):
                    assigns.append(f"DBUS_SESSION_BUS_ADDRESS=unix:path={bus}")
                cmd = ["sudo", "-u", sudo_user, "env", *assigns, editor, path]
            except KeyError:
                pass
        try:
            proc = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL,
                                    start_new_session=True)
            try:
                rc = proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                rc = None
            if rc in (None, 0):
                ok("Opened in mousepad.")
                return
            warn(f"mousepad exited with code {rc}.")
        except OSError as e:
            warn(f"Could not start mousepad: {e}")
    else:
        warn("mousepad not found (sudo apt install mousepad).")

    if not sys.stdout.isatty():
        return
    pager = os.environ.get("PAGER") or "less"
    try:
        subprocess.run(shlex.split(pager) + [path])
    except Exception as e:
        warn(f"Could not run pager '{pager}': {e}")

