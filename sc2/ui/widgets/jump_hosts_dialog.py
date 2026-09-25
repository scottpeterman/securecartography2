"""
Secure Cartography - Jump Hosts dialog

Edits the jump-host YAML (default ~/.seccart2/jump_hosts.yaml) that the
discovery engine and the seccart2-discover CLI already read. The file stays the
single source of truth; this dialog is a structured editor for it.

    jump_hosts:  name -> {host, port, credential}
    proxy_rules: ordered list, FIRST MATCH WINS, keys within a rule are ANDed

Bastion secrets never appear here: a jump host names a vault SSH credential,
which the resolver fetches at connect time.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox, QPushButton,
    QSpinBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from ...paths import JUMP_HOSTS_FILE
from ...scng.discovery.jump import device_context
from ...scng.discovery.models import DeviceVendor
from ...scng.reachssh.proxy import build_proxy_resolver

DIRECT = "direct"
_PRESERVED_KEYS = ("site", "role")  # valid in the file, never match in SC2


def _csv(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(v) for v in value)
    return str(value)


def _split(text: str) -> List[str]:
    return [p.strip() for p in (text or "").split(",") if p.strip()]


def summarize_jump_config(path: Optional[Path]) -> str:
    """One-line description of a jump-host file for the connection panel."""
    if not path:
        return "Direct connections - no bastion"
    path = Path(path)
    if not path.exists():
        return "File not found - discovery will fail to start"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        hosts = data.get("jump_hosts") or {}
        rules = data.get("proxy_rules") or []
        build_proxy_resolver(
            {"jump_hosts": hosts, "proxy_rules": rules}, lambda _n: ("", "")
        )
    except Exception as e:
        return f"Config error: {e}"
    if not hosts and not rules:
        return "No jump hosts defined - direct connections"
    h = f"{len(hosts)} jump host{'s' if len(hosts) != 1 else ''}"
    r = f"{len(rules)} rule{'s' if len(rules) != 1 else ''}"
    return f"{h} · {r} - SSH via bastion (SNMP does not tunnel)"


class JumpHostsDialog(QDialog):
    """Structured editor for the jump-host YAML file."""

    # Rules table columns
    R_DEVICES, R_REGEX, R_PLATFORM, R_VIA = range(4)
    # Hosts table columns
    H_NAME, H_HOST, H_PORT, H_CRED = range(4)

    def __init__(self, path: Optional[Path] = None, vault=None, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Jump Hosts")
        self.resize(940, 820)
        # Stylesheet padding on QGroupBox is not counted in its size hint, so
        # boxes come up short and contents overlap. Keep the frame, move the
        # spacing into layout margins (which Qt does count).
        self.setStyleSheet("QGroupBox { padding: 0px; margin-top: 18px; }")
        self.path = Path(path) if path else JUMP_HOSTS_FILE
        self.vault = vault
        self._ssh_creds = self._vault_ssh_credentials()
        self._build_ui()
        self._load()

    # ------------------------------------------------------------------ data

    def _vault_ssh_credentials(self) -> List[str]:
        if not self.vault:
            return []
        try:
            from ...scng.creds.models import CredentialType
            return [c.name for c in self.vault.list_credentials(credential_type=CredentialType.SSH)]
        except Exception:
            return []

    def _load(self):
        data: Dict[str, Any] = {}
        if self.path.exists():
            try:
                data = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
            except Exception as e:
                QMessageBox.warning(self, "Jump Hosts", f"Could not read {self.path}:\n{e}")
        for name, body in (data.get("jump_hosts") or {}).items():
            body = body or {}
            self._add_host_row(str(name), str(body.get("host", "")),
                               int(body.get("port") or 22), body.get("credential") or "")
        for rule in data.get("proxy_rules") or []:
            self._add_rule_row(rule or {})
        self._refresh_via_choices()
        self._update_order_warning()

    def config(self) -> Dict[str, Any]:
        """Current dialog contents in the YAML schema."""
        hosts: Dict[str, Dict[str, Any]] = {}
        for r in range(self.hosts.rowCount()):
            name = self._text(self.hosts, r, self.H_NAME)
            if not name:
                continue
            body: Dict[str, Any] = {"host": self._text(self.hosts, r, self.H_HOST)}
            port = self.hosts.cellWidget(r, self.H_PORT).value()
            if port != 22:
                body["port"] = port
            cred = self.hosts.cellWidget(r, self.H_CRED).currentText().strip()
            if cred:
                body["credential"] = cred
            hosts[name] = body

        rules: List[Dict[str, Any]] = []
        for r in range(self.rules.rowCount()):
            match: Dict[str, Any] = dict(self.rules.item(r, self.R_DEVICES).data(Qt.ItemDataRole.UserRole) or {})
            devices = _split(self._text(self.rules, r, self.R_DEVICES))
            regex = self._text(self.rules, r, self.R_REGEX)
            platforms = _split(self._text(self.rules, r, self.R_PLATFORM))
            if devices:
                match["devices"] = devices
            if regex:
                match["name_regex"] = regex
            if platforms:
                match["platform"] = [p.lower() for p in platforms]
            via = self.rules.cellWidget(r, self.R_VIA).currentText().strip() or DIRECT
            hops = _split(via)
            jump: Any = DIRECT if via == DIRECT else (hops[0] if len(hops) == 1 else hops)
            rules.append({"match": match, "jump": jump})
        return {"jump_hosts": hosts, "proxy_rules": rules}

    # -------------------------------------------------------------------- UI

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        path_label = QLabel(f"File: {self.path}")
        path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(path_label)

        # ---- Jump hosts
        hosts_box = QGroupBox("Jump hosts")
        hl = QVBoxLayout(hosts_box)
        hl.setContentsMargins(14, 22, 14, 14)
        self.hosts = QTableWidget(0, 4)
        self.hosts.setHorizontalHeaderLabels(["Name", "Host", "Port", "Vault SSH credential"])
        self._table_common(self.hosts)
        hh = self.hosts.horizontalHeader()
        hh.setSectionResizeMode(self.H_NAME, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(self.H_HOST, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(self.H_PORT, QHeaderView.ResizeMode.Fixed)
        self.hosts.setColumnWidth(self.H_PORT, 90)
        hh.setSectionResizeMode(self.H_CRED, QHeaderView.ResizeMode.Stretch)
        self.hosts.itemChanged.connect(lambda *_: self._refresh_via_choices())
        self.hosts.setMinimumHeight(40 + 38 * 2)
        hl.addWidget(self.hosts)
        hb = QHBoxLayout()
        add_h = QPushButton("Add host")
        add_h.clicked.connect(lambda: self._add_host_row("", "", 22, ""))
        rm_h = QPushButton("Remove")
        rm_h.clicked.connect(lambda: self._remove_selected(self.hosts))
        hb.addWidget(add_h)
        hb.addWidget(rm_h)
        hb.addStretch()
        if not self._ssh_creds:
            hb.addWidget(QLabel("No SSH credentials in the vault - type a name or add one first"))
        hl.addLayout(hb)
        layout.addWidget(hosts_box, 2)

        # ---- Rules
        rules_box = QGroupBox("Routing rules - first match wins; fields in a rule must all match")
        rl = QVBoxLayout(rules_box)
        rl.setContentsMargins(14, 22, 14, 14)
        self.rules = QTableWidget(0, 4)
        self.rules.setHorizontalHeaderLabels(
            ["Device names / globs", "Name regex", "Platform", "Route via"])
        self._table_common(self.rules)
        rh = self.rules.horizontalHeader()
        for c in (self.R_DEVICES, self.R_REGEX):
            rh.setSectionResizeMode(c, QHeaderView.ResizeMode.Stretch)
        rh.setSectionResizeMode(self.R_PLATFORM, QHeaderView.ResizeMode.Fixed)
        self.rules.setColumnWidth(self.R_PLATFORM, 150)
        rh.setSectionResizeMode(self.R_VIA, QHeaderView.ResizeMode.Fixed)
        self.rules.setColumnWidth(self.R_VIA, 190)
        self.rules.itemChanged.connect(lambda *_: self._update_order_warning())
        self.rules.setMinimumHeight(40 + 38 * 4)
        rl.addWidget(self.rules)
        rb = QHBoxLayout()
        for label, fn in (("Add rule", lambda: self._add_rule_row({"match": {}, "jump": DIRECT})),
                          ("Remove", lambda: self._remove_selected(self.rules)),
                          ("Move up", lambda: self._move_rule(-1)),
                          ("Move down", lambda: self._move_rule(1))):
            b = QPushButton(label)
            b.clicked.connect(fn)
            rb.addWidget(b)
        rb.addStretch()
        rl.addLayout(rb)
        self.order_warning = QLabel("")
        self.order_warning.setWordWrap(True)
        self.order_warning.setVisible(False)
        rl.addWidget(self.order_warning)
        hint = QLabel(
            "Empty row = any device (catch-all), so keep it last. Globs use * and ?; "
            "platform is the discovered vendor (cisco, juniper, arista, ...). "
            "One jump host per rule (chains are not supported yet). "
            "No matching rule means a direct connection. Full guide: Help > Crawl Scope & Jump Hosts.")
        hint.setWordWrap(True)
        hint.setObjectName("formHint")
        rl.addWidget(hint)
        layout.addWidget(rules_box, 3)

        # ---- Test
        test_box = QGroupBox("Test a device")
        tl = QHBoxLayout(test_box)
        tl.setContentsMargins(14, 22, 14, 14)
        self.test_name = QLineEdit()
        self.test_name.setPlaceholderText("hostname, e.g. core-rtr-01.dc1")
        self.test_ip = QLineEdit()
        self.test_ip.setPlaceholderText("IP (optional)")
        self.test_ip.setMaximumWidth(140)
        self.test_platform = QComboBox()
        self.test_platform.setEditable(True)
        self.test_platform.addItems([""] + [v.value for v in DeviceVendor if v.value != "unknown"])
        self.test_platform.setMaximumWidth(130)
        test_btn = QPushButton("Test")
        test_btn.clicked.connect(self._run_test)
        self.test_name.returnPressed.connect(self._run_test)
        tl.addWidget(self.test_name, 2)
        tl.addWidget(self.test_ip, 1)
        tl.addWidget(self.test_platform)
        tl.addWidget(test_btn)
        layout.addWidget(test_box)
        self.test_result = QLabel("")
        self.test_result.setWordWrap(True)
        self.test_result.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.test_result)

        note = QLabel(
            "A jump host carries SSH (TCP) only. SNMP does not tunnel, so devices "
            "reached through a bastion come back with neighbors and platform, "
            "without SNMP inventory, interfaces or ARP.")
        note.setWordWrap(True)
        note.setObjectName("formHint")
        layout.addWidget(note)

        # QSS margin-top (room for the title) is also left out of the size
        # hint; add it back so no box is squeezed below its contents.
        for box in (hosts_box, rules_box, test_box):
            box.setMinimumHeight(box.minimumSizeHint().height() + 20)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    # Cell editors need far less padding than the app-wide form controls
    _CELL_STYLE = "QComboBox, QSpinBox { padding: 2px 8px; margin: 2px; min-height: 0px; }"

    @staticmethod
    def _table_common(t: QTableWidget):
        t.verticalHeader().setVisible(True)
        t.verticalHeader().setDefaultSectionSize(38)
        t.setStyleSheet(JumpHostsDialog._CELL_STYLE)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        t.setAlternatingRowColors(True)

    @staticmethod
    def _text(t: QTableWidget, r: int, c: int) -> str:
        item = t.item(r, c)
        return item.text().strip() if item else ""

    def _add_host_row(self, name: str, host: str, port: int, cred: str):
        self.hosts.blockSignals(True)
        r = self.hosts.rowCount()
        self.hosts.insertRow(r)
        self.hosts.setItem(r, self.H_NAME, QTableWidgetItem(name))
        self.hosts.setItem(r, self.H_HOST, QTableWidgetItem(host))
        spin = QSpinBox()
        spin.setRange(1, 65535)
        spin.setValue(port)
        self.hosts.setCellWidget(r, self.H_PORT, spin)
        combo = QComboBox()
        combo.setEditable(True)
        combo.addItems([""] + self._ssh_creds)
        combo.setCurrentText(cred)
        self.hosts.setCellWidget(r, self.H_CRED, combo)
        self.hosts.blockSignals(False)
        self._refresh_via_choices()

    def _add_rule_row(self, rule: Dict[str, Any], row: Optional[int] = None):
        match = dict(rule.get("match") or {})
        preserved = {k: match[k] for k in _PRESERVED_KEYS if k in match}
        jump = rule.get("jump", DIRECT)
        via = DIRECT if jump in (None, "", DIRECT) else _csv(jump)

        self.rules.blockSignals(True)
        r = self.rules.rowCount() if row is None else row
        self.rules.insertRow(r)
        dev_item = QTableWidgetItem(_csv(match.get("devices")))
        dev_item.setData(Qt.ItemDataRole.UserRole, preserved)
        if preserved:
            dev_item.setToolTip(
                "Also matches " + ", ".join(f"{k}={_csv(v)}" for k, v in preserved.items())
                + " (kept from the file; SC2 has no site/role data, so this rule never matches)")
        self.rules.setItem(r, self.R_DEVICES, dev_item)
        self.rules.setItem(r, self.R_REGEX, QTableWidgetItem(str(match.get("name_regex") or "")))
        self.rules.setItem(r, self.R_PLATFORM, QTableWidgetItem(_csv(match.get("platform"))))
        combo = QComboBox()
        combo.setEditable(True)
        combo.currentTextChanged.connect(lambda *_: self._update_order_warning())
        self.rules.setCellWidget(r, self.R_VIA, combo)
        self._fill_via(combo, via)
        self.rules.blockSignals(False)
        self._update_order_warning()

    def _host_names(self) -> List[str]:
        return [n for n in (self._text(self.hosts, r, self.H_NAME) for r in range(self.hosts.rowCount())) if n]

    def _fill_via(self, combo: QComboBox, current: str):
        combo.blockSignals(True)
        combo.clear()
        combo.addItems([DIRECT] + self._host_names())
        combo.setCurrentText(current or DIRECT)
        combo.blockSignals(False)

    def _refresh_via_choices(self):
        if not hasattr(self, "rules"):
            return
        for r in range(self.rules.rowCount()):
            combo = self.rules.cellWidget(r, self.R_VIA)
            if combo:
                self._fill_via(combo, combo.currentText())

    def _remove_selected(self, table: QTableWidget):
        row = table.currentRow()
        if row >= 0:
            table.removeRow(row)
        self._refresh_via_choices()
        self._update_order_warning()

    def _move_rule(self, delta: int):
        r = self.rules.currentRow()
        dest = r + delta
        if r < 0 or not (0 <= dest < self.rules.rowCount()):
            return
        rule = self.config()["proxy_rules"][r]
        preserved = self.rules.item(r, self.R_DEVICES).data(Qt.ItemDataRole.UserRole) or {}
        rule["match"].update(preserved)
        self.rules.removeRow(r)
        self._add_rule_row(rule, row=dest)
        self.rules.selectRow(dest)

    def _update_order_warning(self):
        if not hasattr(self, "order_warning"):
            return
        rules = self.config()["proxy_rules"]
        catch_alls = [i for i, rule in enumerate(rules) if not rule["match"]]
        if catch_alls and catch_alls[0] < len(rules) - 1:
            self.order_warning.setText(
                f"Rule {catch_alls[0] + 1} matches every device, so the rules below it "
                f"never apply. Move it to the bottom.")
            self.order_warning.setVisible(True)
        else:
            self.order_warning.setText("")
            self.order_warning.setVisible(False)

    # ------------------------------------------------------------ test / save

    def _validate(self) -> Optional[str]:
        cfg = self.config()
        for name, body in cfg["jump_hosts"].items():
            if not body.get("host"):
                return f"Jump host '{name}' has no host address."
        for i, rule in enumerate(cfg["proxy_rules"], 1):
            if isinstance(rule["jump"], list):
                return (f"Rule {i} routes through a chain ({', '.join(rule['jump'])}). "
                        f"Only one jump host per rule is supported.")
            regex = rule["match"].get("name_regex", "")
            if regex.startswith(("*", "?")):
                return (f"Rule {i}: Name regex '{regex}' looks like a glob. Put it in "
                        f"'Device names / globs' instead, or write it as a regex (e.g. \\.dc2\\b).")
        try:
            build_proxy_resolver(cfg, lambda _n: ("", ""))
        except Exception as e:
            return str(e)
        return None

    def _run_test(self):
        error = self._validate()
        if error:
            self.test_result.setText(f"Config error: {error}")
            return
        name = self.test_name.text().strip()
        ip = self.test_ip.text().strip()
        if not name and not ip:
            self.test_result.setText("Enter a hostname or IP to test.")
            return
        cfg = self.config()
        resolver = build_proxy_resolver(cfg, lambda _n: ("", ""))
        if resolver is None:
            self.test_result.setText("No rules - every device connects directly.")
            return
        device = device_context(hostname=name or None, ip=ip or None,
                                vendor=self.test_platform.currentText().strip() or None)
        for index, rule in enumerate(resolver._rules):  # same objects resolve() walks
            if rule.matches(device):
                self.rules.selectRow(index)
                if rule.is_direct:
                    self.test_result.setText(f"Rule {index + 1} matches: direct connection.")
                    return
                hops = []
                for hop in rule.jump_names:
                    body = cfg["jump_hosts"][hop]
                    hops.append(f"{hop} ({body['host']}:{body.get('port', 22)}, "
                                f"credential {body.get('credential') or 'not set'})")
                self.test_result.setText(f"Rule {index + 1} matches: via " + " -> ".join(hops))
                return
        self.test_result.setText("No rule matches: direct connection.")

    def _save(self):
        error = self._validate()
        if error:
            QMessageBox.warning(self, "Jump Hosts", f"Not saved:\n{error}")
            return
        cfg = self.config()
        missing = [h for h, b in cfg["jump_hosts"].items() if not b.get("credential")]
        if missing and QMessageBox.question(
                self, "Jump Hosts",
                "No vault credential set for: " + ", ".join(missing)
                + "\nConnections through these hosts will fail. Save anyway?"
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists():
                # Saving rewrites the file, which drops hand-written comments
                shutil.copy2(self.path, self.path.with_suffix(self.path.suffix + ".bak"))
            header = ("# Secure Cartography 2 jump hosts - edited in the app (Jump Hosts dialog).\n"
                      "# Rules: first match wins; keys in one rule are ANDed.\n")
            body = yaml.safe_dump(cfg, sort_keys=False, default_flow_style=False)
            self.path.write_text(header + body, encoding="utf-8")
        except Exception as e:
            QMessageBox.warning(self, "Jump Hosts", f"Could not write {self.path}:\n{e}")
            return
        self.accept()
