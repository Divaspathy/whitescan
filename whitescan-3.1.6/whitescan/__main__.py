"""python -m whitescan / console_scripts entry point."""
import os
import signal
import sys

from .cli import main, parse_args
from .keep_awake import reexec_with_inhibitor
from .network import list_interfaces, cidr_from_iface
from .process import terminate_active
from .util import C, disable_color


def entry():
    args = parse_args()

    if args.no_color or not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        disable_color()

    if args.list_interfaces:
        rows = list_interfaces()
        if not rows:
            print("No usable interfaces found.")
        for ifname, ip, prefix, mac in rows:
            print(f"{ifname:<12} {ip}/{prefix:<3} "
                  f"{cidr_from_iface(ip, prefix) or '?':<20} {mac}")
        sys.exit(0)

    if not args.setup and not args.no_keep_awake:
        reexec_with_inhibitor()

    signal.signal(signal.SIGTERM, lambda *a: sys.exit(143))
    try:
        sys.exit(main(args) or 0)
    except KeyboardInterrupt:
        terminate_active()
        print(f"\n{C.YELLOW}[!] Interrupted by user.{C.RESET}")
        sys.exit(130)


if __name__ == "__main__":
    entry()
