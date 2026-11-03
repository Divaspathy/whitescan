#!/usr/bin/env python3
"""Pure-logic tests for whitescan. No root, nmap, or GVM required."""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import whitescan as ws
from whitescan import process, util, report, network, nmap_stage, openvas, constants
from whitescan.util import confirm, nse_lines, os_note, default_options, sorted_hosts
from whitescan.report import (
    _load_openvas_section, load_results, write_report, render_text_report,
)
from whitescan.nmap_stage import parse_nmap_xml, build_nmap_cmd
from whitescan.openvas import resolve_openvas_targets
from whitescan.process import ABORT, _iter_proc_lines


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.5" addrtype="ipv4"/>
    <address addr="aa:bb:cc:dd:ee:ff" addrtype="mac" vendor="TestCo"/>
    <hostnames><hostname name="box.local"/></hostnames>
    <os><osmatch name="Linux 5.x" accuracy="95"/></os>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.6">
          <cpe>cpe:/a:openbsd:openssh:9.6</cpe>
        </service>
        <script id="banner" output="SSH-2.0-OpenSSH_9.6"/>
      </port>
      <port protocol="tcp" portid="1">
        <state state="closed" reason="reset"/>
      </port>
    </ports>
    <hostscript>
      <script id="nbstat" output="netbios ok"/>
    </hostscript>
  </host>
</nmaprun>
"""


class Args:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class ParseTests(unittest.TestCase):
    def test_empty_and_malformed(self):
        empty = parse_nmap_xml("")
        self.assertEqual(empty["ports"], [])
        self.assertEqual(empty["state"], "unknown")
        bad = parse_nmap_xml("<not-xml")
        self.assertIn("could not parse", bad["error"])

    def test_sample_host(self):
        host = parse_nmap_xml(SAMPLE_XML)
        self.assertEqual(host["state"], "up")
        self.assertEqual(host["hostname"], "box.local")
        self.assertEqual(host["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(host["vendor"], "TestCo")
        self.assertIn("Linux 5.x", host["os"])
        opens = [p for p in host["ports"] if p["state"] == "open"]
        self.assertEqual(len(opens), 1)
        self.assertEqual(opens[0]["port"], "22")
        self.assertEqual(opens[0]["product"], "OpenSSH")
        self.assertEqual(opens[0]["cpe"], ["cpe:/a:openbsd:openssh:9.6"])
        self.assertEqual(opens[0]["scripts"][0]["id"], "banner")
        self.assertEqual(host["host_scripts"][0]["id"], "nbstat")
        self.assertEqual(os_note(host), "")

    def test_os_note(self):
        self.assertEqual(os_note({}), "")
        filtered = {"os": "Guess", "ports": [{"state": "filtered"}]}
        self.assertIn("filtered", os_note(filtered))
        no_open = {"os": "Guess", "ports": [{"state": "closed"}]}
        self.assertIn("no open ports", os_note(no_open))
        no_closed = {"os": "Guess", "ports": [{"state": "open"}]}
        self.assertIn("no closed port", os_note(no_closed))


class ReportTests(unittest.TestCase):
    def test_missing_openvas_section_does_not_crash(self):
        self.assertEqual(_load_openvas_section(None), (None, [], []))
        self.assertEqual(_load_openvas_section("nope"), (None, [], []))

    def test_failed_attempt_is_not_a_success(self):
        success, _hist, fails = _load_openvas_section({
            "success": False,
            "task_id": "t2",
            "error": "boom",
            "targets": ["192.168.0.2"],
        })
        self.assertIsNone(success)
        self.assertEqual([f["task_id"] for f in fails], ["t2"])

        success, _hist, fails = _load_openvas_section({
            "success": False,
            "task_id": "t2",
            "failed_runs": [{"task_id": "t2", "error": "old"}],
        })
        self.assertIsNone(success)
        self.assertEqual(len(fails), 1)

    def test_round_trip(self):
        original = {
            "interface": "wlan0",
            "cidr": "192.168.1.0/24",
            "started": "t0",
            "finished": "t1",
            "interrupted": False,
            "resumes": [],
            "targets": ["192.168.1.5", "10.0.0.2", "10.0.0.10"],
            "options": default_options(),
            "hosts": {
                "10.0.0.10": {"state": "up", "ports": []},
                "10.0.0.2": {"state": "up", "ports": [{
                    "state": "open", "port": "80", "proto": "tcp",
                    "service": "http", "product": "nginx", "version": "1.25",
                    "scripts": [],
                }]},
            },
            "openvas": {
                "success": True,
                "task_id": "ok",
                "targets": ["10.0.0.2"],
                "vulnerabilities": [],
            },
            "openvas_failures": [{
                "success": False,
                "task_id": "bad",
                "error": "nope",
                "targets": [],
            }],
        }
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "scan_report.json")
            write_report(original, path)
            loaded, _outdir = load_results(td)
        self.assertEqual(list(loaded["hosts"]), ["10.0.0.2", "10.0.0.10"])
        self.assertEqual(loaded["openvas"]["task_id"], "ok")
        self.assertEqual(loaded["openvas_failures"][0]["task_id"], "bad")
        self.assertEqual(loaded["interface"], "wlan0")
        text = render_text_report(loaded)
        self.assertIn("OPENVAS", text)
        self.assertIn("ok", text)
        self.assertIn("bad", text)

    def test_report_without_openvas_session(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "scan_report.json")
            with open(path, "w") as f:
                json.dump({
                    "scan": {"interface": "eth0", "cidr": "10.0.0.0/24",
                             "targets": ["10.0.0.1"]},
                    "nmap_session": {"options": default_options(),
                                     "hosts": {}},
                }, f)
            loaded, _ = load_results(path)
        self.assertIsNone(loaded["openvas"])
        self.assertNotIn("openvas_failures", loaded)


class TargetAndCmdTests(unittest.TestCase):
    def setUp(self):
        self._gvm = openvas.HAVE_GVM
        openvas.HAVE_GVM = True

    def tearDown(self):
        openvas.HAVE_GVM = self._gvm

    def test_openvas_target_resolution(self):
        args = Args(no_openvas=False, openvas_file=None, openvas="open")
        picked = resolve_openvas_targets(
            args, ["192.168.0.2", "192.168.0.1"], ["192.168.0.1"], False)
        self.assertEqual(picked, ["192.168.0.2", "192.168.0.1"])

        args.openvas = "all"
        picked = resolve_openvas_targets(
            args, [], ["10.0.0.2", "10.1.0.1"], False)
        self.assertEqual(picked, ["10.0.0.2", "10.1.0.1"])

        args.openvas = "192.168.5.5,192.168.5.5"
        picked = resolve_openvas_targets(args, [], [], False)
        self.assertEqual(picked, ["192.168.5.5"])

        args.openvas = "fe80::1"
        self.assertIsNone(resolve_openvas_targets(args, [], [], False))
        args.openvas = "not-an-ip"
        self.assertIsNone(resolve_openvas_targets(args, [], [], False))

        args.no_openvas = True
        self.assertIsNone(resolve_openvas_targets(
            args, ["1.1.1.1"], ["1.1.1.1"], False))

    def test_build_nmap_cmd(self):
        opts = default_options()
        cmd = build_nmap_cmd("10.0.0.1", "wlan0", opts, "/tmp/x.xml",
                             verbose=False)
        self.assertIn("--top-ports", cmd)
        self.assertNotIn("-sV", cmd)
        opts = dict(opts, top_1000=False, service_detection=True,
                    os_detection=True, nse_scripts=True, timing="T2")
        cmd = build_nmap_cmd("10.0.0.1", "wlan0", opts, "/tmp/x.xml")
        self.assertIn("-p-", cmd)
        self.assertIn("-sV", cmd)
        self.assertIn("-O", cmd)
        self.assertIn("-sC", cmd)
        self.assertIn("-T2", cmd)

    def test_sorted_hosts(self):
        hosts = {"10.0.0.10": {}, "name": {}, "10.0.0.2": {}}
        self.assertEqual(
            [ip for ip, _ in sorted_hosts(hosts)],
            ["10.0.0.2", "10.0.0.10", "name"],
        )


class GuardTests(unittest.TestCase):
    def test_yes_does_not_bypass_forced_confirm(self):
        args = Args(yes=True)
        with patch.object(sys.stdin, "isatty", return_value=False):
            self.assertTrue(confirm("continue?", args))
            self.assertFalse(confirm("continue?", args, force=True))
        with patch.object(sys.stdin, "isatty", return_value=True), \
                patch("builtins.input", return_value="n"):
            self.assertFalse(confirm("continue?", args, force=True))
            self.assertTrue(confirm("continue?", args))

    def test_nse_line_cap(self):
        lines = nse_lines("banner", "\n".join(f"line {i}" for i in range(5)),
                          max_lines=2, max_width=80)
        self.assertEqual(len(lines), 3)
        self.assertIn("3 more", lines[-1])

    def test_help_has_concrete_range(self):
        from whitescan.cli import EPILOG
        self.assertIn(">4096", EPILOG)
        self.assertNotIn("{LARGE_RANGE}", EPILOG)
        self.assertEqual(ws.__version__, "3.1.6")


class ProcTests(unittest.TestCase):
    def tearDown(self):
        ABORT.clear()

    def test_lines_are_read(self):
        ABORT.clear()
        proc = subprocess.Popen(
            [sys.executable, "-c", "print('hello'); print('world')"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0,
        )
        try:
            lines = [ln.strip() for ln in _iter_proc_lines(proc, poll_s=0.05)]
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2)
            proc.stdout.close()
        self.assertEqual(lines, ["hello", "world"])
        self.assertEqual(proc.returncode, 0)

    def test_abort_stops_a_quiet_process(self):
        ABORT.set()
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0,
            start_new_session=True,
        )
        t0 = time.time()
        try:
            lines = list(_iter_proc_lines(proc, poll_s=0.05))
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2)
            proc.stdout.close()
        self.assertLess(time.time() - t0, 5)
        self.assertEqual(lines, [])
        self.assertIsNotNone(proc.poll())


if __name__ == "__main__":
    unittest.main()
