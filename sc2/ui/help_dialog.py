"""
SecureCartography v2 - Help Dialog

Comprehensive help system covering:
- GUI workflow overview
- CLI usage for remote/jump host scenarios
- Keyboard shortcuts
"""

from typing import Optional
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QTextBrowser,
    QPushButton, QWidget, QScrollArea, QLabel
)
from PyQt6.QtGui import QFont

from .themes import ThemeManager, ThemeColors


class HelpDialog(QDialog):
    """
    Help dialog with tabbed sections for different topics.

    Sections:
    - Overview: What Secure Cartography does
    - GUI Guide: Using the desktop application
    - CLI Guide: Command-line tools for jump hosts
    - Shortcuts: Keyboard shortcuts reference
    """

    def __init__(
            self,
            theme_manager: Optional[ThemeManager] = None,
            parent: Optional[QWidget] = None
    ):
        super().__init__(parent)
        self.theme_manager = theme_manager

        self.setWindowTitle("Secure Cartography - Help")
        self.setMinimumSize(800, 600)
        self.resize(900, 700)

        self._setup_ui()

        if theme_manager:
            self.apply_theme(theme_manager.theme)

    def _setup_ui(self):
        """Build the help dialog UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Tab widget for different help sections
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        # Help sections - single source of truth for tab order and content
        self._pages = [
            ("Overview", self._get_overview_html),
            ("GUI Guide", self._get_gui_html),
            ("Crawl Scope && Jump Hosts", self._get_scope_html),
            ("CLI Guide", self._get_cli_html),
            ("Shortcuts", self._get_shortcuts_html),
        ]
        for title, getter in self._pages:
            self.tabs.addTab(self._create_text_browser(getter()), title)

        layout.addWidget(self.tabs)

        # Close button
        button_layout = QHBoxLayout()
        button_layout.setContentsMargins(16, 12, 16, 12)
        button_layout.addStretch()

        self.close_btn = QPushButton("Close")
        self.close_btn.setFixedWidth(100)
        self.close_btn.clicked.connect(self.accept)
        button_layout.addWidget(self.close_btn)

        layout.addLayout(button_layout)

    def _create_text_browser(self, html: str) -> QTextBrowser:
        """Create a styled text browser with HTML content."""
        browser = QTextBrowser()
        browser.setOpenExternalLinks(True)
        browser.setHtml(html)
        return browser

    def apply_theme(self, theme: ThemeColors):
        """Apply theme colors to the dialog."""
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {theme.bg_primary};
                color: {theme.text_primary};
            }}

            QTabWidget::pane {{
                background-color: {theme.bg_secondary};
                border: 1px solid {theme.border_dim};
                border-top: none;
            }}

            QTabBar::tab {{
                background-color: {theme.bg_tertiary};
                border: 1px solid {theme.border_dim};
                border-bottom: none;
                padding: 10px 20px;
                color: {theme.text_secondary};
                margin-right: 2px;
            }}

            QTabBar::tab:selected {{
                background-color: {theme.bg_secondary};
                color: {theme.accent};
                border-bottom: 2px solid {theme.accent};
            }}

            QTabBar::tab:hover:!selected {{
                color: {theme.text_primary};
            }}

            QTextBrowser {{
                background-color: {theme.bg_secondary};
                border: none;
                padding: 20px;
                color: {theme.text_primary};
            }}

            QPushButton {{
                background-color: {theme.bg_tertiary};
                border: 1px solid {theme.border_dim};
                border-radius: 6px;
                padding: 10px 20px;
                color: {theme.text_primary};
                font-weight: 500;
            }}

            QPushButton:hover {{
                border-color: {theme.accent};
                color: {theme.accent};
            }}
        """)

        # Style the HTML content in text browsers
        html_style = f"""
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    font-size: 14px;
                    line-height: 1.6;
                    color: {theme.text_primary};
                }}
                h1 {{
                    color: {theme.accent};
                    font-size: 24px;
                    margin-bottom: 16px;
                    border-bottom: 1px solid {theme.border_dim};
                    padding-bottom: 8px;
                }}
                h2 {{
                    color: {theme.text_primary};
                    font-size: 18px;
                    margin-top: 24px;
                    margin-bottom: 12px;
                }}
                h3 {{
                    color: {theme.text_secondary};
                    font-size: 15px;
                    margin-top: 16px;
                    margin-bottom: 8px;
                }}
                code {{
                    background-color: {theme.bg_tertiary};
                    padding: 2px 6px;
                    border-radius: 4px;
                    font-family: 'Consolas', 'Monaco', monospace;
                    font-size: 13px;
                }}
                pre {{
                    background-color: {theme.bg_tertiary};
                    padding: 12px 16px;
                    border-radius: 6px;
                    border-left: 3px solid {theme.accent};
                    overflow-x: auto;
                    font-family: 'Consolas', 'Monaco', monospace;
                    font-size: 13px;
                    line-height: 1.5;
                }}
                table {{
                    border-collapse: collapse;
                    margin: 12px 0;
                }}
                td {{
                    vertical-align: top;
                    padding: 6px 12px;
                }}
                ul, ol {{
                    margin: 8px 0;
                    padding-left: 24px;
                }}
                li {{
                    margin: 4px 0;
                }}
                a {{
                    color: {theme.accent};
                }}
                hr {{
                    border: none;
                    border-top: 1px solid {theme.border_dim};
                    margin: 24px 0;
                }}
            </style>
        """

        # Re-render every page with the themed style block
        for i, (_title, getter) in enumerate(self._pages):
            browser = self.tabs.widget(i)
            if isinstance(browser, QTextBrowser):
                browser.setHtml(html_style + getter())

    # HTML content methods for re-theming
    def _get_overview_html(self) -> str:
        return """
        <h1>Secure Cartography</h1>
        <p><b>Network Discovery &amp; Topology Mapping</b></p>

        <h2>What It Does</h2>
        <p>Secure Cartography automatically discovers your network infrastructure using 
        SNMP, CDP, and LLDP protocols. It builds topology maps showing how devices connect, 
        and extracts hardware inventory.</p>

        <h2>Key Capabilities</h2>
        <table cellpadding="8">
            <tr>
                <td><b>Discovery</b></td>
                <td>Recursive network crawling from seed devices using CDP/LLDP neighbor data</td>
            </tr>
            <tr>
                <td><b>Topology</b></td>
                <td>Interactive network maps with device relationships and connection details</td>
            </tr>
            <tr>
                <td><b>Inventory</b></td>
                <td>Hardware components, serial numbers, software versions across all discovered devices</td>
            </tr>
            <tr>
                <td><b>Credentials</b></td>
                <td>Encrypted vault for SNMP credentials with automatic discovery of working creds</td>
            </tr>
        </table>

        <h2>Typical Workflow</h2>
        <ol>
            <li>Configure SNMP credentials in the vault</li>
            <li>Enter seed IP(s) - core routers or switches that see the network</li>
            <li>Set domain filters to constrain discovery scope</li>
            <li>Run discovery - watch the topology build in real-time</li>
            <li>Export maps and reports for documentation</li>
        </ol>

        <h2>Supported Platforms</h2>
        <p>Secure Cartography works with any SNMP-enabled device. Enhanced parsing for:</p>
        <ul>
            <li>Cisco IOS, IOS-XE, IOS-XR, NX-OS</li>
            <li>Arista EOS</li>
            <li>Juniper JUNOS</li>
            <li>Palo Alto PAN-OS</li>
            <li>Fortinet FortiOS</li>
            <li>Aruba/HPE, Dell, Extreme, MikroTik, Ubiquiti</li>
        </ul>
        """

    def _get_gui_html(self) -> str:
        return """
        <h1>GUI Guide</h1>

        <h2>Main Window Layout</h2>
        <p>The interface is organized into three columns:</p>

        <h3>Left Column - Connection Setup</h3>
        <ul>
            <li><b>Seed IPs:</b> Starting points for discovery (usually core routers/switches)</li>
            <li><b>Domain Suffixes:</b> Appended to names that don't resolve, and stripped from names in the map (see <i>Crawl Scope &amp; Jump Hosts</i>)</li>
            <li><b>Exclude Patterns:</b> Neighbors matching these are not dialed</li>
            <li><b>Jump Host Config:</b> Route SSH to some devices through a bastion - <b>Edit</b> opens the editor</li>
            <li><b>Credentials:</b> SNMP and SSH credentials from your encrypted vault</li>
        </ul>

        <h3>Middle Column - Options &amp; Actions</h3>
        <ul>
            <li><b>Max Depth:</b> How many hops from seed devices to crawl</li>
            <li><b>Concurrency:</b> Parallel device queries (higher = faster, more load)</li>
            <li><b>Timeout:</b> Per-device SNMP timeout in seconds</li>
            <li><b>No DNS:</b> Use raw IPs from CDP/LLDP (useful for lab environments)</li>
            <li><b>Output Directory:</b> Where to save discovery results</li>
        </ul>

        <h3>Right Column - Results</h3>
        <ul>
            <li><b>Progress:</b> Discovery status and statistics</li>
            <li><b>Topology Preview:</b> Real-time network map as devices are discovered</li>
            <li><b>Discovery Log:</b> Detailed event log with timestamps</li>
        </ul>

        <h2>Header Bar</h2>
        <table cellpadding="8">
            <tr>
                <td><b>Help</b></td>
                <td>Opens this help dialog</td>
            </tr>
            <tr>
                <td><b>Theme Selector</b></td>
                <td>Switch between Dark and Light themes</td>
            </tr>
        </table>

        <h2>Discovery Process</h2>
        <ol>
            <li>Click <b>START CRAWL</b> to begin discovery</li>
            <li>Watch the topology build in the preview panel</li>
            <li>Click <b>STOP CRAWL</b> to halt discovery early if needed</li>
            <li>Use <b>ENHANCE MAP</b> to open the full interactive map viewer</li>
            <li>Results are automatically saved to the output directory</li>
        </ol>

        <h2>Output Files</h2>
        <p>Discovery creates several files in your output directory:</p>
        <ul>
            <li><code>map.json</code> - Topology data for map viewer</li>
            <li><code>devices.csv</code> - Device inventory spreadsheet</li>
            <li><code>devices.json</code> - Full device data in JSON format</li>
            <li><code>topology.graphml</code> - Network graph for external tools</li>
        </ul>
        """

    def _get_scope_html(self) -> str:
        return """
        <h1>Crawl Scope &amp; Jump Hosts</h1>

        <h2>How a Crawl Proceeds</h2>
        <p>Discovery is breadth-first. Depth 0 is your seeds; every CDP/LLDP neighbor they report
        becomes a target at the next depth, up to <b>Max Depth</b>. Each target is tried with SNMP
        first, then SSH. The <b>Progress</b> panel shows one row per depth, and every neighbor that
        was seen but not dialed is listed, with the reason, under <b>Not dialed</b> in the Discovery Log.</p>
        <p>Every device also has an absolute deadline of 5 minutes covering all of its attempts
        (credentials, SNMP, SSH, DNS fallback). A device that has not finished by then is marked
        failed with <code>per-device deadline</code> and the crawl moves on
        (CLI: <code>--device-deadline SECONDS</code>, 0 disables it).</p>

        <h2>Exclude Patterns</h2>
        <p>Comma-separated, case-insensitive <b>substrings</b> - not globs or regex.
        <code>linux</code> matches <code>Ubuntu 22.04 LTS Linux 5.15</code>; <code>*phone*</code> matches nothing.</p>
        <table cellpadding="6" border="0">
            <tr><td><b>Before dialing</b></td>
                <td>Checked against what the neighbor entry says about itself: its name, CDP platform,
                and LLDP system description. A match is never dialed - no SNMP or SSH attempt, no
                timeout - and is listed as <code>matches exclude '&lt;pattern&gt;'</code>.</td></tr>
            <tr><td><b>After dialing</b></td>
                <td>For neighbors that advertise nothing useful, the check runs again once the device
                answers: sysDescr, hostname, sysName and detected vendor. A match is kept on the map
                but not expanded; its own neighbors are listed as <code>behind excluded device</code>.</td></tr>
        </table>
        <p>Good patterns are the words servers and appliances put in their LLDP description
        (<code>linux</code>, <code>debian</code>, <code>ubuntu</code>, <code>vmware</code>), a NIC vendor
        (<code>broadcom</code>, <code>mellanox</code>), or a hostname prefix you use for hosts.
        Interface and port descriptions are never used for matching.</p>

        <h2>Not Dialed - Reasons</h2>
        <table cellpadding="6" border="0">
            <tr><td><code>matches exclude '...'</code></td><td>Excluded before dialing</td></tr>
            <tr><td><code>behind excluded device</code></td><td>Neighbor of a device excluded after dialing</td></tr>
            <tr><td><code>beyond max depth</code></td><td>Seen at the last depth; raise Max Depth to include it</td></tr>
            <tr><td><code>MAC address, no IP</code></td><td>Neighbor advertised only a MAC and no address</td></tr>
        </table>

        <h2>Domain Suffixes &amp; DNS Fallback</h2>
        <p>Neighbors are dialed at the management address they advertise. When that fails - or the
        address can never work from here (link-local, loopback) - the neighbor's <b>name</b> is looked
        up in DNS and the device is retried at the address DNS returns. Names are tried in this order:</p>
        <ul>
            <li>the name as advertised, if it has a dot (<code>agg1.dc2</code>, <code>agg1.dc2.example.net</code>)</li>
            <li>for short or <code>host.site</code> names, the name plus each suffix (<code>agg1.dc2.example.com</code>)</li>
            <li>the short host name plus each suffix (<code>agg1.example.com</code>)</li>
            <li>the bare short name, so your resolver's own search list is used too</li>
        </ul>
        <p>This recovers sites whose advertised management addresses are not routable from where the
        crawl runs. The log shows each retry, e.g. <code>agg1: 10.9.0.1 failed; retrying via DNS -&gt; 172.16.4.1</code>.
        <b>No DNS Mode</b> turns the fallback off.</p>

        <hr>

        <h2>Jump Hosts (Bastion Routing)</h2>
        <p>Routes the <b>SSH</b> connection to selected devices through a bastion. SNMP is UDP and
        does not tunnel, so devices reached this way come back with neighbors and platform only -
        no SNMP inventory, interfaces or ARP. Click <b>Edit</b> next to Jump Host Config.</p>

        <h3>1. Jump hosts</h3>
        <p>Each bastion needs a <b>name</b> (any label, used by the rules), its <b>host</b> address,
        port, and a <b>vault SSH credential</b> used to log in to the bastion. The file stores only
        the credential's name; the secret stays in the vault.</p>

        <h3>2. Routing rules</h3>
        <p>Rules decide, per device, whether to connect <b>direct</b> or <b>via</b> a jump host.</p>
        <ul>
            <li>Evaluated top to bottom - <b>the first matching rule wins</b></li>
            <li>Fields filled in on one rule must <b>all</b> match; empty fields are ignored</li>
            <li>A row with every field empty matches every device - keep it last</li>
            <li>No rule matches: the device connects <b>direct</b></li>
        </ul>
        <table cellpadding="6" border="0">
            <tr><td><b>Device names / globs</b></td><td><code>*</code> and <code>?</code> wildcards, comma-separated: <code>*.dc2*, fw?-dmz</code></td></tr>
            <tr><td><b>Name regex</b></td><td>Python regex searched in the name: <code>^(agg|tor)\\d+\\.dc2</code></td></tr>
            <tr><td><b>Platform</b></td><td>Discovered vendor: <code>cisco</code>, <code>juniper</code>, <code>arista</code>, ...</td></tr>
            <tr><td><b>Route via</b></td><td><code>direct</code> or one jump host name (chains of jump hosts are not supported)</td></tr>
        </table>
        <p>Rules match the device's <b>name</b> as its neighbors advertise it (or as DNS returns it),
        so name-based rules work for devices dialed by IP.</p>
        <p>A device routed through a jump host is <b>SSH only</b>: SNMP is not attempted for it
        (it cannot cross the bastion), and the credential check runs through the bastion too.
        If its name does not resolve from where you run the crawl, the name is passed to the
        bastion to resolve on its side.</p>

        <h3>Example</h3>
        <p>Reach everything in one datacenter through its bastion, connect directly to the rest:</p>
        <table cellpadding="6" border="1" cellspacing="0">
            <tr><th>#</th><th>Device names / globs</th><th>Route via</th></tr>
            <tr><td>1</td><td><code>bastion01*</code></td><td><code>direct</code></td></tr>
            <tr><td>2</td><td><code>*.dc2*</code></td><td><code>bastion-dc2</code></td></tr>
        </table>
        <p>Rule 1 keeps the bastion itself from being routed through itself if the crawl finds it as a
        neighbor. Nothing matches a device outside dc2, so it connects direct - no catch-all needed.
        A rule whose Route via is <code>direct</code> and that has nothing below it has no effect.</p>

        <h3>3. Test a device</h3>
        <p>Enter a hostname (and optionally an IP and platform) and click <b>Test</b>. It runs the
        same matching the crawl uses, highlights the winning rule, and shows the hop with its host,
        port and credential.</p>

        <p>The configuration is saved to <code>~/.seccart2/jump_hosts.yaml</code> - the same file the
        <code>seccart2-discover --jump-config</code> CLI reads. Saving keeps the previous version as
        <code>jump_hosts.yaml.bak</code>.</p>
        """

    def _get_cli_html(self) -> str:
        return """
        <h1>CLI Guide</h1>
        <p>Command-line tools for running discovery from jump hosts, automation scripts, 
        or environments without GUI access.</p>

        <h2>Credential Manager</h2>
        <pre>python -m sc2.scng.creds [command] [options]</pre>

        <h3>Commands</h3>
        <table cellpadding="6" border="0">
            <tr><td><code>init</code></td><td>Initialize a new credential vault</td></tr>
            <tr><td><code>unlock</code></td><td>Validate vault password</td></tr>
            <tr><td><code>add</code></td><td>Add a new SNMP credential</td></tr>
            <tr><td><code>list</code></td><td>List all stored credentials</td></tr>
            <tr><td><code>show</code></td><td>Show credential details</td></tr>
            <tr><td><code>remove</code></td><td>Remove a credential</td></tr>
            <tr><td><code>set-default</code></td><td>Set credential as default</td></tr>
            <tr><td><code>test</code></td><td>Test credential against a device</td></tr>
            <tr><td><code>discover</code></td><td>Discover working credentials for a device</td></tr>
            <tr><td><code>change-password</code></td><td>Change vault master password</td></tr>
            <tr><td><code>deps</code></td><td>Check SNMP dependencies</td></tr>
        </table>

        <h3>Options</h3>
        <pre>
--vault-path, -v    Path to vault database 
                    (default: ~/.seccart2/credentials.db)
--password, -p      Vault password 
                    (or set SCNG_VAULT_PASSWORD env var)
        </pre>

        <h3>Examples</h3>
        <pre>
# Initialize vault on a jump host
python -m sc2.scng.creds init

# Add SNMPv2 credential
python -m sc2.scng.creds add --name "network-ro" \\
    --version 2c --community "readonlystring"

# Add SNMPv3 credential
python -m sc2.scng.creds add --name "secure-snmp" \\
    --version 3 --user "snmpuser" \\
    --auth-proto SHA --auth-pass "authpass123" \\
    --priv-proto AES --priv-pass "privpass123"

# Test credential against device
python -m sc2.scng.creds test 192.168.1.1 --name "network-ro"
        </pre>

        <hr>

        <h2>Network Discovery</h2>
        <pre>python -m sc2.scng.discovery [command] [options]</pre>

        <h3>Commands</h3>
        <table cellpadding="6" border="0">
            <tr><td><code>test</code></td><td>Quick test with inline community string</td></tr>
            <tr><td><code>device</code></td><td>Discover single device using vault credentials</td></tr>
            <tr><td><code>crawl</code></td><td>Recursive network discovery</td></tr>
        </table>

        <h3>Crawl Options</h3>
        <pre>
-d, --depth         Max hops from seed (default: 3)
--domain            Domain filter (can specify multiple)
--exclude           Exclude pattern (can specify multiple)
-o, --output        Output directory
--concurrency       Parallel queries (default: 10)
--timeout           Per-device timeout seconds (default: 5)
--no-dns            Use raw IPs from CDP/LLDP
-v, --verbose       Verbose output
--timestamps        Show timestamps in output
        </pre>

        <h3>Examples</h3>
        <pre>
# Quick SNMP test with community string
python -m sc2.scng.discovery test 192.168.1.1 --community public

# Single device discovery using vault
python -m sc2.scng.discovery device 192.168.1.1

# Recursive crawl with domain filter
python -m sc2.scng.discovery crawl 192.168.1.1 \\
    -d 3 --domain example.com -o ./output

# Home lab (no DNS, use IPs from LLDP/CDP)
python -m sc2.scng.discovery crawl 192.168.1.1 \\
    -d 3 --no-dns

# Large network with high concurrency
python -m sc2.scng.discovery crawl 10.0.0.1 \\
    -d 5 --concurrency 30 -o ./datacenter

# Verbose with timestamps for debugging
python -m sc2.scng.discovery crawl 192.168.1.1 \\
    -v --timestamps
        </pre>

        <hr>

        <h2>Running Discovery on a Remote Host</h2>
        <p>When your desktop has no SNMP reachability but another host does, run the whole
        crawl there (this is different from the GUI's jump-host routing, which only carries SSH):</p>
        <ol>
            <li>SSH to the jump host</li>
            <li>Install Secure Cartography: <code>pip install seccart2</code></li>
            <li>Initialize vault: <code>python -m sc2.scng.creds init</code></li>
            <li>Add credentials: <code>python -m sc2.scng.creds add ...</code></li>
            <li>Run discovery: <code>python -m sc2.scng.discovery crawl ...</code></li>
            <li>Copy output files back to desktop for analysis</li>
            <li>Open in the GUI map viewer</li>
        </ol>

        <h2>Environment Variables</h2>
        <table cellpadding="6" border="0">
            <tr><td><code>SCNG_VAULT_PASSWORD</code></td><td>Vault password (avoids -p flag)</td></tr>
            <tr><td><code>SCNG_VAULT_PATH</code></td><td>Custom vault location</td></tr>
        </table>
        """

    def _get_shortcuts_html(self) -> str:
        return """
        <h1>Keyboard Shortcuts</h1>

        <h2>Main Window</h2>
        <table cellpadding="8" border="0">
            <tr><td><code>Ctrl+Enter</code></td><td>Start/Stop discovery</td></tr>
            <tr><td><code>Ctrl+M</code></td><td>Open map viewer</td></tr>
            <tr><td><code>F1</code></td><td>Open help</td></tr>
            <tr><td><code>Ctrl+Q</code></td><td>Quit application</td></tr>
        </table>

        <h2>Map Viewer</h2>
        <table cellpadding="8" border="0">
            <tr><td><code>Ctrl+O</code></td><td>Open map file</td></tr>
            <tr><td><code>Ctrl+S</code></td><td>Save map</td></tr>
            <tr><td><code>Ctrl+E</code></td><td>Export image</td></tr>
            <tr><td><code>Ctrl+F</code></td><td>Find device</td></tr>
            <tr><td><code>+</code> / <code>-</code></td><td>Zoom in/out</td></tr>
            <tr><td><code>0</code></td><td>Reset zoom</td></tr>
            <tr><td><code>F</code></td><td>Fit to window</td></tr>
            <tr><td><code>Escape</code></td><td>Clear selection</td></tr>
        </table>

        <h2>Tables</h2>
        <table cellpadding="8" border="0">
            <tr><td><code>Ctrl+C</code></td><td>Copy selected cells</td></tr>
            <tr><td><code>Double-click</code></td><td>Edit cell (where supported)</td></tr>
            <tr><td><code>Click header</code></td><td>Sort by column</td></tr>
        </table>
        """