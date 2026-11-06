"""whitescan.setup_cmd"""
import getpass
import os
import shutil
import subprocess
import sys

from .__version__ import __version__
from .constants import DEFAULT_GVM_SOCKET, _SETUP_PREFERRED_BINDIRS
from .openvas import HAVE_GVM, _gvm_connect, load_openvas_config, save_openvas_config
from .paths import CONFIG_DIR, OPENVAS_JSON
from .util import C, banner, err, info, next_step, ok, warn

try:
    from gvm.errors import GvmResponseError
except ImportError:
    GvmResponseError = Exception

def _sudo_secure_path():
    try:
        out = subprocess.run(["sudo", "-n", "sh", "-c", "echo $PATH"],
                             capture_output=True, text=True, timeout=5)
        if out.returncode == 0 and out.stdout.strip():
            return [d for d in out.stdout.strip().split(":") if d]
    except (OSError, subprocess.TimeoutExpired):
        pass

    try:
        out = subprocess.run(["sudo", "-V"], capture_output=True,
                             text=True, timeout=5)
        if out.returncode == 0:
            for line in out.stdout.splitlines():
                line = line.strip()
                low = line.lower()
                if low.startswith("value to override secure_path with"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        return [d for d in parts[1].strip().split(":") if d]
    except (OSError, subprocess.TimeoutExpired):
        pass

    return None

def _pick_install_bindir():
    sudo_path = _sudo_secure_path()
    if sudo_path:
        for d in _SETUP_PREFERRED_BINDIRS:
            if d in sudo_path:
                return d, sudo_path
        for d in sudo_path:
            if os.path.isdir(d):
                return d, sudo_path
    return "/usr/bin", sudo_path

def _install_script_on_path():
    """Install the whitescan package + a small /usr/bin launcher.

    Layout:
        <libdir>/whitescan/     the Python package
        <bindir>/whitescan      launcher that puts <libdir> on sys.path
    """
    src = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else None
    if not src or not os.path.exists(src):
        err("Cannot locate the running script to install.")
        return None

    # Package lives next to the launcher in a source checkout.
    # When already installed, argv[0] is /usr/bin/whitescan — fall back to
    # the installed package under <prefix>/lib/whitescan and only refresh it
    # if we can still see a source tree.
    src_dir = os.path.dirname(src)
    pkg_src = os.path.join(src_dir, "whitescan")
    bindir, sudo_path = _pick_install_bindir()
    parent = os.path.dirname(bindir.rstrip(os.sep)) or "/"
    libdir = os.path.join(parent, "lib")
    pkg_dst = os.path.join(libdir, "whitescan")
    target = os.path.join(bindir, "whitescan")

    have_src = os.path.isdir(pkg_src) and os.path.isfile(
        os.path.join(pkg_src, "__main__.py"))
    have_dst = os.path.isdir(pkg_dst) and os.path.isfile(
        os.path.join(pkg_dst, "__main__.py"))

    if not have_src and have_dst:
        # Re-running: sudo whitescan --setup  (credentials only / already installed)
        ok(f"Already installed at {pkg_dst}")
        info(f"launcher        : {target}")
        return target

    if not have_src:
        err(f"Cannot find the whitescan package next to {src}")
        info("Expected: ./whitescan.py  and  ./whitescan/")
        info("Run from the source tree:  sudo python3 ./whitescan.py --setup")
        return None

    info(f"sudo PATH       : {':'.join(sudo_path) if sudo_path else '(unknown)'}")
    info(f"package install : {pkg_dst}")
    info(f"launcher        : {target}")

    try:
        os.makedirs(bindir, exist_ok=True)
        os.makedirs(libdir, exist_ok=True)
    except OSError as e:
        err(f"Cannot create install dirs: {e}")
        return None

    try:
        if os.path.isdir(pkg_dst):
            shutil.rmtree(pkg_dst)
        shutil.copytree(pkg_src, pkg_dst)
        ok(f"Installed package: {pkg_dst}")
    except OSError as e:
        err(f"Cannot install package to {pkg_dst}: {e}")
        info("If this is a permission error, run: sudo ./whitescan.py --setup")
        return None

    launcher = (
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"sys.path.insert(0, {libdir!r})\n"
        "from whitescan.__main__ import entry\n"
        "entry()\n"
    )
    try:
        with open(target, "w") as f:
            f.write(launcher)
        os.chmod(target, 0o755)
        ok(f"Installed launcher: {target}")
    except OSError as e:
        err(f"Cannot install launcher to {target}: {e}")
        return None

    stale = "/usr/local/bin/whitescan"
    if os.path.abspath(target) != os.path.abspath(stale) and os.path.exists(stale):
        try:
            os.unlink(stale)
            ok(f"Removed stale copy at {stale}.")
        except OSError as e:
            warn(f"Could not remove stale {stale}: {e}")

    return target
    
def _ensure_path_has(bindir):
    paths = os.environ.get("PATH", "").split(os.pathsep)
    if bindir not in paths:
        warn(f"{bindir} is not in your $PATH; you may need to log out/in "
             "or add it manually to use 'whitescan'.")

def _prompt_retry(default_user, existing):
    print()
    print(f"{C.BOLD}Authentication failed.{C.RESET}")
    choice = input(
        f"{C.YELLOW}[?]{C.RESET} [r]etry with a different password, "
        f"[u]se a different username, or [q]uit? (default: r): "
    ).strip().lower()
    if choice == "q":
        return None
    if choice == "u":
        raw = input(f"GVM username [{default_user or 'admin'}]: ").strip()
        return (raw or default_user or "admin", None)
    return (None, True)

def run_setup(interactive, socket_override=None):
    banner("WhiteScan setup", C.CYAN)

    next_step("Install the script where sudo can find it")
    installed = _install_script_on_path()
    if not installed:
        err("Installation failed.")
        info("As a last resort:  sudo cp ./whitescan.py /usr/bin/whitescan")
        return 1
    _ensure_path_has(os.path.dirname(installed))

    next_step("Configure OpenVAS credentials")
    existing = load_openvas_config() or {}
    default_socket = (socket_override
                      or existing.get("gvm_socket")
                      or DEFAULT_GVM_SOCKET)
    default_user = existing.get("username") or ""

    print(f"\nStored in: {C.BOLD}{OPENVAS_JSON}{C.RESET}")
    print(f"{C.DIM}Press Enter to keep the value shown in [brackets].{C.RESET}\n")

    if interactive:
        raw = input(f"GVM socket path [{default_socket}]: ").strip()
        gvm_socket = raw or default_socket
    else:
        gvm_socket = default_socket

    if interactive:
        raw = input(f"GVM username [{default_user or 'admin'}]: ").strip()
        username = raw or default_user or "admin"
    else:
        username = default_user or "admin"

    if interactive:
        print()
        if existing.get("password"):
            print(f"{C.DIM}A password is already stored. "
                  f"Leave blank to keep it.{C.RESET}")
        pw1 = getpass.getpass("GVM password: ")
        if not pw1 and existing.get("password"):
            password = existing["password"]
        else:
            pw2 = getpass.getpass("Repeat password: ")
            if pw1 != pw2:
                err("Passwords did not match.")
                return 1
            if not pw1:
                err("Empty password not allowed.")
                return 1
            password = pw1
    else:
        if not existing.get("password"):
            err("Non-interactive setup cannot prompt for a password.")
            info("Re-run from a terminal:  sudo whitescan --setup")
            return 1
        password = existing["password"]

    if interactive and HAVE_GVM:
        info("Verifying credentials against GVM...")
        while True:
            try:
                with _gvm_connect(gvm_socket) as gmp:
                    gmp.authenticate(username, password)
                ok(f"GVM accepted credentials for '{username}'.")
                break
            except GvmResponseError:
                err("GVM rejected the username/password.")
            except Exception as e:
                err(f"Cannot reach GVM at {gvm_socket}: {e}")
                info("Saving without verifying.")
                break

            result = _prompt_retry(default_user, existing)
            if result is None:
                warn("Setup cancelled; existing config left unchanged.")
                return 1
            new_user, retry_pw = result
            if new_user:
                username = new_user
            if retry_pw:
                pw1 = getpass.getpass("GVM password: ")
                pw2 = getpass.getpass("Repeat password: ")
                if pw1 != pw2:
                    err("Passwords did not match.")
                    continue
                if not pw1:
                    err("Empty password not allowed.")
                    continue
                password = pw1

    cfg = {
        "gvm_socket": gvm_socket,
        "username": username,
        "password": password,
    }
    if not save_openvas_config(cfg):
        return 1
    ok(f"OpenVAS credentials saved to {OPENVAS_JSON} (mode 0600).")

    banner("Setup complete", C.GREEN)
    print(f"  Installed binary : {installed}")
    print(f"  Config dir       : {CONFIG_DIR}   (mode 0700)")
    print(f"  OpenVAS config   : {OPENVAS_JSON}   (mode 0600)")
    print()
    print(f"  Try: {C.BOLD}{C.GREEN}sudo whitescan -i wlan0 --yes{C.RESET}")
    print(f"       {C.BOLD}{C.GREEN}sudo whitescan -i wlan0 --openvas open --yes{C.RESET}")
    print(f"       {C.BOLD}{C.GREEN}sudo whitescan --openvas-only 192.168.2.1{C.RESET}")
    print()
    print("  For automation, use a dedicated GVM user with scan-only")
    print("  privileges rather than 'admin'.")
    print()
    print("  Re-run `sudo whitescan --setup` any time to change these.")
    print()
    return 0

