"""Config paths resolved against the real user home (even under sudo)."""
import os
import pwd


def real_home():
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            return pwd.getpwnam(sudo_user).pw_dir
        except KeyError:
            pass
    return os.path.expanduser("~")


CONFIG_DIR = os.path.join(real_home(), ".config", "whitescan")
OPENVAS_JSON = os.path.join(CONFIG_DIR, "openvas.json")
