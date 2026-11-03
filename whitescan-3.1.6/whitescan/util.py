"""whitescan.util"""
import ipaddress
import logging
import os
import sys

from .constants import MAX_LINE, NSE_CAPS, NSE_DEFAULT_CAP
from .paths import real_home

_STEP = [0]
_LOG = logging.getLogger("whitescan")
_LOG.addHandler(logging.NullHandler())

# Back-compat alias used across the codebase
_real_home = real_home

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

def banner(text, color=None):
    color = C.CYAN if color is None else color
    line = "=" * 72
    print(f"\n{color}{C.BOLD}{line}\n {text}\n{line}{C.RESET}")

def next_step(text):
    _STEP[0] += 1
    step(_STEP[0], text)

def step(n, text):
    print(f"\n{C.MAGENTA}{C.BOLD}[STEP {n}]{C.RESET} {C.BOLD}{text}{C.RESET}")

def info(text):  print(f"{C.CYAN}[*]{C.RESET} {text}")

def ok(text):    print(f"{C.GREEN}[+]{C.RESET} {text}")

def warn(text):  print(f"{C.YELLOW}[!]{C.RESET} {text}")

def err(text):   print(f"{C.RED}[-]{C.RESET} {text}")

def alert(text):
    print(f"{C.RED}{C.BOLD}[!] {text}{C.RESET}")


def disable_color():
    for k in list(vars(C)):
        if k.isupper():
            setattr(C, k, "")

def confirm(question, args, default=False, force=False):
    # force=True is the large-range aggressive guard: --yes must not skip it.
    if getattr(args, "yes", False) and not force:
        return True
    if not sys.stdin.isatty():
        return default
    return input(f"{C.YELLOW}[!] {question} [y/N]: {C.RESET}").strip().lower() == "y"

def _ip_key(ip):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, str(ip))

def sorted_hosts(hosts):
    return sorted(hosts.items(), key=lambda kv: _ip_key(kv[0]))

def clean_lines(text):
    out = []
    for ln in (text or "").splitlines():
        ln = ln.rstrip()
        if not ln:
            if out and out[-1] != "":
                out.append("")
            continue
        out.append(ln)
    while out and out[-1] == "":
        out.pop()
    return out

def nse_lines(script_id, output, max_lines=None, max_width=MAX_LINE):
    lines = clean_lines(output) or ["(no output)"]
    cap = max_lines or NSE_CAPS.get(script_id, NSE_DEFAULT_CAP)
    extra = 0
    if len(lines) > cap:
        extra = len(lines) - cap
        lines = lines[:cap]
    if max_width:
        lines = [ln if len(ln) <= max_width else ln[:max_width - 1] + "…"
                 for ln in lines]
    if extra:
        lines.append(f"... ({extra} more line(s); full output is in scan_report.json)")
    return lines

def os_note(parsed):
    if not parsed.get("os"):
        return ""
    ports = parsed.get("ports", [])
    opens = [p for p in ports if p["state"] == "open"]
    if not opens:
        if ports and all(p["state"] == "filtered" for p in ports):
            return "  [unreliable: all probed ports are filtered]"
        return "  [unreliable: host has no open ports]"
    if not any(p["state"] == "closed" for p in ports):
        return "  [unreliable: no closed port seen]"
    return ""

def default_options():
    return {
        "top_1000": True,
        "service_detection": False,
        "os_detection": False,
        "nse_scripts": False,
        "timing": "T4",
        "workers": 1,
    }

def fix_perms(path, mode, fatal=False):
    try:
        os.chmod(path, mode)
    except OSError as e:
        log(f"chmod {path} -> {oct(mode)} failed: {e}", logging.WARNING)
        if fatal:
            raise RuntimeError(f"Could not set permissions on {path}: {e}")
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid:
        try:
            os.chown(path, int(uid), int(gid))
        except OSError as e:
            log(f"chown {path} -> {uid}:{gid} failed: {e}", logging.WARNING)
            if fatal:
                raise RuntimeError(f"Could not set ownership on {path}: {e}")

def make_private_dir(path):
    os.makedirs(path, exist_ok=True)
    fix_perms(path, 0o700, fatal=False)

def setup_logger(outdir):
    logdir = os.path.join(outdir, "logs")
    make_private_dir(logdir)
    path = os.path.join(logdir, "whitescan.log")
    _LOG.setLevel(logging.INFO)
    for h in list(_LOG.handlers):
        if isinstance(h, logging.FileHandler):
            _LOG.removeHandler(h)
            try:
                h.close()
            except Exception:
                pass
    fh = logging.FileHandler(path, encoding="utf-8")
    fh.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s %(message)s"))
    _LOG.addHandler(fh)
    return path

def log(msg, level=logging.INFO):
    _LOG.log(level, msg)

def log_exc(msg):
    _LOG.exception(msg)

