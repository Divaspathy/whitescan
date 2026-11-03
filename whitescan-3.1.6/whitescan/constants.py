"""Shared constants for WhiteScan."""
import os
from .paths import CONFIG_DIR, OPENVAS_JSON

DEFAULT_GVM_SOCKET = "/run/gvmd/gvmd.sock"
DEFAULT_RESULTS_ROOT = "whitescan_results"
DEFAULT_GVM_TIMEOUT = 3600
NSE_CAPS = {"fingerprint-strings": 10}
NSE_DEFAULT_CAP = 40
MAX_LINE = 160
_OPENVAS_SCOPES = {"open", "all"}
_SETUP_PREFERRED_BINDIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")
LARGE_RANGE = 4096
SCAN_PROFILES = {
    "quick":      (True,  False, False, False),
    "scan":       (True,  True,  True,  False),
    "fullscan":   (False, True,  True,  False),
    "scriptscan": (False, True,  True,  True),
}
TXT_W = 80
GVM_DEFAULT_SCAN_CONFIG = "daba56c8-73ec-11df-a475-002264764cea"
GVM_DEFAULT_SCANNER     = "08b69003-5fc2-4037-a479-93b440211c73"
GVM_DEFAULT_PORTLIST    = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
GVM_XML_REPORT_FORMAT   = "a994b278-1f62-11e1-96ac-406186ea4fc5"
GVM_REPORT_FILTER       = "levels=chmlg min_qod=0 rows=-1 first=1"
GVM_CONFIG_NAME   = "Full and fast"
GVM_SCANNER_NAME  = "OpenVAS Default"
GVM_PORTLIST_NAME = "All IANA assigned TCP"
