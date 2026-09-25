#!/usr/bin/env python3
"""
tools/demo_screenshots.py - company-free demo network and README screenshots.

Runs the REAL application: main window, discovery engine, controller, progress
and log panels, live topology preview, map viewer, jump-host dialog and the
Draw.io / yEd exporters. Only per-device discovery is simulated, against a
synthetic two-datacenter network (7 levels deep) with realistic platforms,
a few failures, excluded servers and neighbors beyond max depth.

Nothing touches your real data: the vault, settings and jump-host file live
in a throwaway SECCART2_HOME under the output directory.

    python tools/demo_screenshots.py                    # both themes -> ./screenshots
    python tools/demo_screenshots.py --theme dark --out shots
    QT_QPA_PLATFORM=offscreen python tools/demo_screenshots.py   # headless

Output (per theme): main_crawling, main_complete, not_dialed, map_viewer,
device_card, jump_hosts (.png), plus demo_topology.drawio / .graphml.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ----------------------------------------------------------------- arguments

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--out", default="screenshots", help="output directory (default: ./screenshots)")
ap.add_argument("--theme", choices=["dark", "light", "both"], default="both")
ap.add_argument("--size", default="1600x1000", help="main window size WxH (default 1600x1000)")
ap.add_argument("--speed", type=float, default=1.0, help="crawl pacing multiplier (lower = faster)")
args = ap.parse_args()
OUT = Path(args.out).resolve()
OUT.mkdir(parents=True, exist_ok=True)

if args.theme == "both":
    # The live preview is a process-wide singleton, so each theme gets its own run
    for theme in ("dark", "light"):
        subprocess.run([sys.executable, __file__, "--theme", theme, "--out", str(OUT),
                        "--size", args.size, "--speed", str(args.speed)], check=True)
    sys.exit(0)

THEME = args.theme
W, H = (int(v) for v in args.size.lower().split("x"))

# Isolated app home BEFORE importing sc2 (sc2.paths reads it at import)
# Fixed, readable path (it is visible in the screenshots); recreated each run
DEMO_HOME = (Path("/tmp") if os.name != "nt" else Path(tempfile.gettempdir())) / "seccart2-demo"
import shutil  # noqa: E402
shutil.rmtree(DEMO_HOME, ignore_errors=True)
DEMO_HOME.mkdir(parents=True)
os.environ["SECCART2_HOME"] = str(DEMO_HOME)
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from PyQt6.QtCore import QPoint, Qt, QTimer                       # noqa: E402
from PyQt6.QtGui import QPainter, QPixmap                          # noqa: E402
from PyQt6.QtWidgets import QApplication, QWidget                  # noqa: E402

QApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts, True)
app = QApplication(sys.argv)
app.setStyle("Fusion")

from PyQt6.QtWebEngineWidgets import QWebEngineView                # noqa: E402
from sc2.scng.creds.models import SNMPv3AuthProtocol, SNMPv3PrivProtocol   # noqa: E402
from sc2.scng.creds.vault import CredentialVault                   # noqa: E402
from sc2.scng.discovery.engine import DiscoveryEngine              # noqa: E402
from sc2.scng.discovery.models import (                            # noqa: E402
    Device, DeviceVendor, DiscoveryProtocol, Interface, InterfaceStatus, Neighbor,
)
from sc2.ui.main_window import MainWindow                          # noqa: E402
from sc2.ui.settings import get_settings                           # noqa: E402
from sc2.ui.themes import ThemeManager, ThemeName                  # noqa: E402

random.seed(7)  # same network and timings every run

# ======================================================================
# Synthetic network
# ======================================================================

DOMAIN = "example.net"

KINDS = {
    #  kind      vendor        platform string                                model              os           ifname pattern         via
    "core":   ("juniper", "Juniper MX10003 JUNOS 23.4R2-S3",              "MX10003",         "23.4R2-S3", "et-0/0/{n}",             "snmp"),
    "wan":    ("juniper", "Juniper MX204 JUNOS 22.4R3-S2",                "MX204",           "22.4R3-S2", "et-0/0/{n}",             "snmp"),
    "fw":     ("paloalto", "Palo Alto PA-3220 PAN-OS 11.1.2",             "PA-3220",         "11.1.2",    "ethernet1/{n}",          "snmp"),
    "spine":  ("arista",  "Arista DCS-7280SR3-48YC8 EOS 4.31.2F",         "DCS-7280SR3-48YC8", "4.31.2F", "Ethernet{n}/1",          "snmp"),
    "leaf":   ("arista",  "Arista DCS-7050SX3-48YC8 EOS 4.30.4M",         "DCS-7050SX3-48YC8", "4.30.4M", "Ethernet{n}",            "snmp"),
    "access": ("cisco",   "Cisco C9300-48P IOS-XE 17.9.4",                "C9300-48P",       "17.9.4",    "TenGigabitEthernet1/1/{n}", "snmp"),
    "oob":    ("cisco",   "Cisco C9200L-24T IOS-XE 17.9.4",               "C9200L-24T",      "17.9.4",    "GigabitEthernet1/0/{n}", "snmp"),
    "nxcore": ("cisco",   "Cisco N9K-C9364C NX-OS 10.3(4a)",              "N9K-C9364C",      "10.3(4a)",  "Ethernet1/{n}",          "ssh"),
    "nxleaf": ("cisco",   "Cisco N9K-C93180YC-FX NX-OS 10.3(4a)",         "N9K-C93180YC-FX", "10.3(4a)",  "Ethernet1/{n}",          "ssh"),
    "iosacc": ("cisco",   "Cisco C9200L-48P IOS-XE 17.9.4",               "C9200L-48P",      "17.9.4",    "GigabitEthernet1/0/{n}", "ssh"),
    # never discovered - they only appear as neighbors
    "server": ("linux",   "Ubuntu 22.04.4 LTS Linux 5.15.0-105-generic x86_64", "", "",      "eno{n}",                 None),
    "ap":     ("cisco",   "Cisco C9120AXI-B AP IOS-XE 17.9.4",            "C9120AXI-B",      "17.9.4",    "GigabitEthernet{n}",     None),
}

DEVICES: dict = {}      # name -> dict
LINKS: list = []        # (a, b)
_port = {}              # per-device port counter


def add(name, kind, ip, site, fail=None):
    DEVICES[name] = dict(name=name, kind=kind, ip=ip, site=site, fail=fail)


def link(a, b):
    LINKS.append((a, b))


def build_network():
    # ---- DC1: core / WAN / firewall / 4 spines / 16 leaves / 16 access / OOB
    for i in (1, 2):
        add(f"core{i}.dc1", "core", f"10.1.0.{i}", "DC1 Hall A")
    link("core1.dc1", "core2.dc1")
    add("wan1.dc1", "wan", "10.1.0.10", "DC1 Meet-Me Room")
    add("fw1.dc1", "fw", "10.1.0.20", "DC1 Hall A")
    for c in ("core1.dc1", "core2.dc1"):
        link(c, "wan1.dc1")
        link(c, "fw1.dc1")
    for s in range(1, 5):
        add(f"spine{s}.dc1", "spine", f"10.1.1.{s}", "DC1 Row 2")
        link("core1.dc1", f"spine{s}.dc1")
        link("core2.dc1", f"spine{s}.dc1")
    for l in range(1, 17):
        add(f"leaf{l}.dc1", "leaf", f"10.1.2.{l}", f"DC1 Row {3 + (l - 1) // 4}",
            fail="SNMP timeout; SSH authentication failed" if l == 11 else None)
        link(f"spine{1 + (l - 1) % 2}.dc1", f"leaf{l}.dc1")
        link(f"spine{3 + (l - 1) % 2}.dc1", f"leaf{l}.dc1")
        for srv in (1, 2):                               # excluded before dialing
            name = f"app{l:02d}{srv}.dc1"
            add(name, "server", f"10.1.20.{l * 2 + srv}", "DC1")
            link(f"leaf{l}.dc1", name)
    for a in range(1, 17):
        add(f"access{a}.dc1", "access", f"10.1.3.{a}", f"DC1 Office Floor {1 + (a - 1) // 8}",
            fail="No working SNMP or SSH credential found" if a == 14 else None)
        link(f"leaf{a}.dc1", f"access{a}.dc1")
        add(f"ap{a}.dc1", "ap", f"10.1.30.{a}", "DC1 Office")   # beyond max depth
        link(f"access{a}.dc1", f"ap{a}.dc1")
    for o in (1, 2):
        add(f"oob{o}.dc1", "oob", f"10.1.9.{o}", "DC1 Row 1")
        link(f"core{o}.dc1", f"oob{o}.dc1")

    # ---- DC2 over the WAN: WAN edge / NX-OS core / 8 leaves / access
    add("wan1.dc2", "wan", "10.2.0.10", "DC2 Meet-Me Room")
    link("wan1.dc1", "wan1.dc2")
    for i in (1, 2):
        add(f"core{i}.dc2", "nxcore", f"10.2.0.{i}", "DC2 Hall B")
        link("wan1.dc2", f"core{i}.dc2")
    link("core1.dc2", "core2.dc2")
    for l in range(1, 9):
        add(f"leaf{l}.dc2", "nxleaf", f"10.2.2.{l}", f"DC2 Row {1 + (l - 1) // 4}",
            fail="jump host bastion.dc2 could not reach 10.2.2.6:22" if l == 6 else None)
        link("core1.dc2", f"leaf{l}.dc2")
        link("core2.dc2", f"leaf{l}.dc2")
        add(f"db{l}.dc2", "server", f"10.2.20.{l}", "DC2")
        link(f"leaf{l}.dc2", f"db{l}.dc2")
    for a in range(1, 9):
        add(f"access{a}.dc2", "iosacc", f"10.2.3.{a}", "DC2 Office")
        link(f"leaf{a}.dc2", f"access{a}.dc2")
        add(f"ap{a}.dc2", "ap", f"10.2.30.{a}", "DC2 Office")    # beyond max depth
        link(f"access{a}.dc2", f"ap{a}.dc2")


def port(dev):
    _port[dev] = _port.get(dev, 0) + 1
    return KINDS[DEVICES[dev]["kind"]][4].format(n=_port[dev])


NEIGHBORS: dict = {}    # name -> [Neighbor]
IFACES: dict = {}       # name -> [Interface]


def wire():
    for a, b in LINKS:
        pa, pb = port(a), port(b)
        for me, my_if, peer, peer_if in ((a, pa, b, pb), (b, pb, a, pa)):
            pk = KINDS[DEVICES[peer]["kind"]]
            NEIGHBORS.setdefault(me, []).append(Neighbor(
                local_interface=my_if, remote_device=peer, remote_ip=DEVICES[peer]["ip"],
                remote_interface=peer_if, remote_platform=pk[2] or None,
                remote_description=pk[1],
            ))
            IFACES.setdefault(me, []).append(Interface(
                name=my_if, if_index=len(IFACES.get(me, [])) + 1,
                alias=f"to {peer}", speed_mbps=100000 if "et-" in my_if or "Ethernet" in my_if else 10000,
                mtu=9216, status=InterfaceStatus.UP,
            ))


BY_IP = {}


async def fake_discover_device(self, target, *a, **k):
    """Stands in for SNMP/SSH collection; everything downstream is real."""
    d = DEVICES[BY_IP.get(target, target)]
    kind = KINDS[d["kind"]]
    await asyncio.sleep(random.uniform(0.35, 1.1) * args.speed)
    dev = Device(hostname=d["name"], ip_address=d["ip"], sys_name=d["name"], depth=k.get("depth", 0))
    if d["fail"]:
        dev.discovery_success = False
        dev.discovery_errors = [d["fail"]]
        return dev
    dev.fqdn = f"{d['name']}.{DOMAIN}"
    dev.vendor = DeviceVendor(kind[0]) if kind[0] in {v.value for v in DeviceVendor} else DeviceVendor.UNKNOWN
    dev.sys_descr = kind[1]
    dev.model, dev.os_version = kind[2], kind[3]
    dev.serial = f"FX{abs(hash(d['name'])) % 10**8:08d}"
    dev.sys_location = d["site"]
    dev.sys_contact = f"noc@{DOMAIN}"
    dev.uptime_ticks = random.randint(30, 400) * 8640000
    dev.discovered_via = DiscoveryProtocol.SSH if kind[5] == "ssh" else DiscoveryProtocol.SNMP
    dev.credential_used = "dc2-ssh" if kind[5] == "ssh" else "dc-snmpv3"
    dev.discovery_duration_ms = random.randint(400, 2600)
    dev.neighbors = list(NEIGHBORS.get(d["name"], []))
    dev.interfaces = list(IFACES.get(d["name"], []))
    if kind[5] == "snmp" and d["kind"] in ("core", "leaf", "access"):
        dev.arp_table = {f"10.{d['ip'].split('.')[1]}.50.{i}": f"52:54:00:{i:02x}:1a:2b" for i in range(1, 40)}
    return dev


# ======================================================================
# Capture helpers
# ======================================================================

def capture(widget: QWidget) -> QPixmap:
    """Grab a window, then paint each web view's own grab over it (web views
    do not appear in a parent-window grab when rendering offscreen)."""
    pix = widget.grab()
    painter = QPainter(pix)
    for view in widget.findChildren(QWebEngineView):
        if view.isVisible() and view.width() > 10:
            painter.drawPixmap(view.mapTo(widget, QPoint(0, 0)), view.grab())
    painter.end()
    return pix


def save(widget, name):
    path = OUT / f"{name}_{THEME}.png"
    capture(widget).save(str(path))
    print(f"  saved {path.name}")


def wait(ms):
    t = time.time() + ms / 1000
    while time.time() < t:
        app.processEvents()
        time.sleep(0.02)


def run_js(view, script):
    result = {}
    view.page().runJavaScript(script, lambda r: result.setdefault("r", r))
    for _ in range(200):
        if "r" in result:
            break
        wait(25)
    return result.get("r")


# ======================================================================
# Main
# ======================================================================

def main():
    build_network()
    wire()
    BY_IP.update({d["ip"]: n for n, d in DEVICES.items()})
    DiscoveryEngine.discover_device = fake_discover_device

    # Demo vault with plausible credentials (fake secrets, throwaway home)
    vault = CredentialVault()
    vault.initialize("demo-vault-password")
    vault.add_snmpv3_credential("dc-snmpv3", "netmon", auth_protocol=SNMPv3AuthProtocol.SHA256,
                                auth_password="demo-auth-secret", priv_protocol=SNMPv3PrivProtocol.AES,
                                priv_password="demo-priv-secret", is_default=True)
    vault.add_ssh_credential("dc2-ssh", "netops", password="demo-ssh-secret")
    vault.add_ssh_credential("bastion-dc2", "netops", password="demo-bastion-secret")

    # Jump-host config shown in the panel and the dialog shot
    (DEMO_HOME / "jump_hosts.yaml").write_text(
        "jump_hosts:\n"
        "  bastion-dc2:\n    host: 10.2.0.250\n    credential: bastion-dc2\n"
        "proxy_rules:\n"
        "  - match: {devices: ['bastion*']}\n    jump: direct\n"
        "  - match: {devices: ['*.dc2*']}\n    jump: bastion-dc2\n")

    tm = ThemeManager(ThemeName.from_str(THEME))
    app.setStyleSheet(tm.stylesheet)
    w = MainWindow(vault=vault, theme_name=tm.theme_name, settings=get_settings())
    w.resize(W, H)
    w.show()
    wait(4000)  # web view + bundled JS libraries load

    cp, op = w.connection_panel, w.options_panel
    cp.set_seeds(["core1.dc1"])
    cp.set_domains([DOMAIN])
    cp.set_exclude_patterns(["linux", "ubuntu", "vmware"])
    op.set_max_depth(5)   # DC2 access-layer APs land just past it: "beyond max depth"
    op.set_concurrency(8)
    op.set_timeout(5)
    w.output_panel.set_output_directory(str(DEMO_HOME / "maps"))
    wait(300)

    print(f"[{THEME}] crawling synthetic network ({sum(1 for d in DEVICES.values() if KINDS[d['kind']][5])} "
          f"dialable devices, {len(LINKS)} links)")
    w._on_start_crawl()

    # Mid-crawl frame: once depth 3 is under way and the map has grown
    pp = w.progress_panel
    deadline = time.time() + 120
    while time.time() < deadline and pp._current_depth < 3:
        wait(100)
    wait(int(1600 * args.speed))
    save(w, "main_crawling")

    while time.time() < deadline and w.discovery_controller.is_running:
        wait(200)
    wait(3500)  # final layout settles
    save(w, "main_complete")

    # Not dialed dialog (modal: grab it from a timer while it is open)
    def grab_modal():
        dlg = QApplication.activeModalWidget()
        if dlg:
            dlg.resize(760, 520)
            wait(300)
            save(dlg, "not_dialed")
            dlg.reject()
    QTimer.singleShot(900, grab_modal)
    w.log_panel._show_not_dialed()

    # Map viewer: hierarchical, discovered edge devices on, placeholders off
    w._on_enhance_map()
    mv = w._map_viewer_dialog
    mv.resize(1500, 950)
    wait(1500)
    mv._show_leaves_checkbox.setChecked(True)
    mv._show_undiscovered_checkbox.setChecked(False)
    wait(4000)
    view = mv.findChild(QWebEngineView)
    run_js(view, "TopologyViewer.fitView(); void 0")
    wait(800)
    save(mv, "map_viewer")

    # Device card over the map
    run_js(view, "(function(){var n=TopologyViewer.cy.getElementById('spine1.dc1');"
                 "if(n.length){TopologyViewer.showNodeInfo(n.data());} })(); void 0")
    wait(1200)
    save(mv, "device_card")
    run_js(view, "TopologyViewer.hideNodeInfo && TopologyViewer.hideNodeInfo(); void 0")

    # Exports (open these in draw.io / yEd for the remaining shots)
    try:
        from sc2.export.drawio_exporter import DrawioExporter
        from sc2.export.graphml_exporter import GraphMLExporter
        topo = mv._get_display_topology()
        DrawioExporter().export(topo, OUT / "demo_topology.drawio")
        GraphMLExporter().export(topo, OUT / "demo_topology.graphml")
        print("  saved demo_topology.drawio / .graphml")
    except Exception as e:  # exporters are optional for the screenshots
        print(f"  (exports skipped: {e})")
    mv.close()

    # Jump Hosts dialog with a route test
    from sc2.ui.widgets.jump_hosts_dialog import JumpHostsDialog
    dlg = JumpHostsDialog(path=DEMO_HOME / "jump_hosts.yaml", vault=vault, parent=w)
    dlg.show()
    wait(600)
    dlg.test_name.setText("leaf3.dc2")
    dlg._run_test()
    wait(500)
    save(dlg, "jump_hosts")
    dlg.close()

    w.close()
    app.quit()


if __name__ == "__main__":
    main()
