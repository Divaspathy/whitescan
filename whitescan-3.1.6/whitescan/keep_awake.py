"""whitescan.keep_awake"""
import os
import pwd
import re
import shutil
import subprocess

from .util import info, log, ok, warn

def reexec_with_inhibitor():
    if os.environ.get("WHITESCAN_INHIBITED") == "1":
        return
    if os.geteuid() != 0 or not shutil.which("systemd-inhibit"):
        return
    base = ["systemd-inhibit", "--what=sleep:idle:handle-lid-switch",
            "--who=whitescan", "--why=Network scan in progress",
            "--mode=block"]
    try:
        t = subprocess.run(base + ["--list"], capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return
    if t.returncode != 0:
        return
    os.environ["WHITESCAN_INHIBITED"] = "1"
    try:
        os.execvp(base[0], base + [sys.executable] + sys.argv)
    except OSError:
        pass

class KeepAwake:
    def __init__(self, iface):
        self.iface = iface or ""
        self.active = False
        self.saved_x = None
        self.saved_wifi = None
        self.changed = []
        self.x_warnings = []

    def _xenv(self):
        env = os.environ.copy()
        env.setdefault("DISPLAY", ":0")
        user = os.environ.get("SUDO_USER")
        if "XAUTHORITY" not in env and user:
            try:
                xa = os.path.join(pwd.getpwnam(user).pw_dir, ".Xauthority")
                if os.path.exists(xa):
                    env["XAUTHORITY"] = xa
            except KeyError:
                pass
        return env

    def _xset(self, *args):
        try:
            r = subprocess.run(["xset", *args], env=self._xenv(),
                               capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                self.x_warnings.append(
                    f"xset {' '.join(args)} exited {r.returncode}")
                return None
            return r
        except (OSError, subprocess.TimeoutExpired) as e:
            self.x_warnings.append(f"xset {' '.join(args)} failed: {e}")
            return None

    def start(self):
        if self.active:
            return
        self.active = True

        if os.environ.get("WHITESCAN_INHIBITED") == "1":
            ok("Sleep / suspend / lid-close blocked while the scan runs.")
        else:
            warn("systemd-inhibit unavailable; system sleep is NOT blocked.")

        if shutil.which("xset"):
            q = self._xset("q")
            if q and q.returncode == 0:
                t = re.search(r"timeout:\s+(\d+)\s+cycle:\s+(\d+)", q.stdout)
                b = re.search(r"prefer blanking:\s+(yes|no)", q.stdout)
                dpms_on = "DPMS is Enabled" in q.stdout
                self.saved_x = {
                    "dpms": dpms_on,
                    "timeout": t.groups() if t else None,
                    "blank": b.group(1) if b else None,
                }
                log(f"KeepAwake saved xstate: {self.saved_x}")
                if self._xset("s", "off"):
                    self.changed.append("s_off")
                if self._xset("s", "noblank"):
                    self.changed.append("s_noblank")
                if self._xset("-dpms"):
                    self.changed.append("dpms_off")
                ok("Screen blanking and DPMS disabled for the scan.")
            else:
                warn("Could not reach the X display; screen blanking unchanged.")
        else:
            warn("xset not found; screen blanking unchanged.")

        if (self.iface and shutil.which("iw")
                and os.path.isdir(f"/sys/class/net/{self.iface}/wireless")):
            try:
                r = subprocess.run(["iw", "dev", self.iface, "get", "power_save"],
                                   capture_output=True, text=True, timeout=5)
                m = re.search(r"Power save:\s*(on|off)", r.stdout)
                if m:
                    self.saved_wifi = m.group(1)
                    if m.group(1) == "on":
                        subprocess.run(["iw", "dev", self.iface, "set",
                                        "power_save", "off"],
                                       capture_output=True, timeout=5)
                        self.changed.append("wifi_off")
                        ok(f"Wi-Fi power saving turned off on {self.iface}.")
            except (OSError, subprocess.TimeoutExpired) as e:
                log(f"KeepAwake iw failed: {e}")

    def stop(self):
        if not self.active:
            return
        self.active = False

        if "dpms_off" in self.changed:
            if self.saved_x and self.saved_x.get("dpms"):
                self._xset("+dpms")
            else:
                self._xset("-dpms")

        if self.saved_x:
            x = self.saved_x
            if x["timeout"]:
                self._xset("s", x["timeout"][0], x["timeout"][1])
            else:
                self._xset("s", "on")
            if x["blank"]:
                self._xset("s", "blank" if x["blank"] == "yes" else "noblank")
            else:
                self._xset("s", "blank")

        if "wifi_off" in self.changed and self.iface:
            try:
                subprocess.run(["iw", "dev", self.iface, "set", "power_save", "on"],
                               capture_output=True, timeout=5)
            except (OSError, subprocess.TimeoutExpired) as e:
                self.x_warnings.append(f"iw restore failed: {e}")

        if self.x_warnings:
            warn(f"KeepAwake had {len(self.x_warnings)} warning(s) during restore:")
            for w in self.x_warnings:
                warn(f"  - {w}")
                log(f"KeepAwake warning: {w}")
            info("Some display/wifi settings may not be fully restored.")

