"""
reachssh SSH client — Paramiko wrapper for network-device SSH.

Invoke-shell only — no exec mode. Required for most network devices.

Features:
- Legacy algorithm support (DH group1, 3DES, etc.)
- ANSI sequence filtering
- Prompt detection and counting
- Key or password authentication
- Optional emulation support via reachssh.emulation

"""

import os
import re
import time
import logging
from io import StringIO
from dataclasses import dataclass
from typing import Optional

import paramiko

from . import emulation
from .proxy import JumpSpec


# ═══════════════════════════════════════════════════════════════════════════
# Non-interactive authentication
# ═══════════════════════════════════════════════════════════════════════════

class TargetUnreachable(paramiko.SSHException):
    """The target (or the bastion's path to it) could not be reached."""


def _no_retry(err: Exception) -> bool:
    """
    Failures where the second connect pass cannot help. That pass exists to
    retry pubkey-algorithm negotiation (ssh-rsa vs rsa-sha2). Reachability
    failures and second-factor prompts would only repeat the same wait or the
    same prompt. Connection resets and EOF are NOT listed: some devices drop
    the session when they reject ssh-rsa, which is exactly what pass 2 fixes.
    """
    import socket as _socket
    if isinstance(err, SecondFactorRequired):
        return True
    return isinstance(err, (
        TargetUnreachable,                          # bastion could not reach target
        paramiko.ChannelException,                  # direct-tcpip refused by bastion
        paramiko.ssh_exception.NoValidConnectionsError,  # refused / no route (direct)
        _socket.timeout, TimeoutError,              # nothing answered
    ))


class SecondFactorRequired(paramiko.AuthenticationException):
    """The server asked for something other than a password (OTP, YubiKey, Duo...)."""

    def __init__(self, prompts):
        self.prompts = [p.strip() for p in prompts if p and p.strip()] or ["keyboard-interactive"]
        super().__init__(
            "server requires a second factor (" + "; ".join(self.prompts) + ") - skipped"
        )


_PASSWORD_PROMPT = re.compile(r"password\s*:?\s*$", re.IGNORECASE)
_NOT_A_PASSWORD = re.compile(
    r"yubi|otp|one[- ]time|token|passcode|verification|duo|2fa|mfa|pin\b", re.IGNORECASE)


def _is_password_prompt(prompt: str) -> bool:
    return bool(_PASSWORD_PROMPT.search(prompt or "")) and not _NOT_A_PASSWORD.search(prompt or "")


class _NonInteractiveTransport(paramiko.Transport):
    """
    Transport that never reads the terminal and never hands a password to a
    prompt that is not asking for one.

    Stock Paramiko has two paths that are wrong for an unattended crawler:
      - key auth succeeds but the server wants a second factor and no password
        is configured -> SSHClient calls auth_interactive_dumb(), which prints
        the prompt and blocks on input() in a worker thread
      - a password is configured -> auth_password() falls back to
        keyboard-interactive and answers EVERY prompt with the password,
        e.g. sends it as the YubiKey OTP
    Here a plain "Password:" prompt still gets the password (Junos, IOS and
    friends use keyboard-interactive for that); anything else is answered
    with an empty string and the login fails as SecondFactorRequired.
    """

    def auth_interactive_dumb(self, username, handler=None, submethods=""):
        prompts = []

        def refuse(title, instructions, prompt_list):
            prompts.extend(p for p, _echo in prompt_list)
            return ["" for _ in prompt_list]

        try:
            return self.auth_interactive(username, refuse, submethods)
        except paramiko.SSHException:
            raise SecondFactorRequired(prompts)

    def auth_password(self, username, password, event=None, fallback=True):
        try:
            return super().auth_password(username, password, event, fallback=False)
        except paramiko.BadAuthenticationType as e:
            if not fallback or "keyboard-interactive" not in e.allowed_types:
                raise
            refused = []

            def strict(title, instructions, prompt_list):
                answers = []
                for prompt, _echo in prompt_list:
                    if _is_password_prompt(prompt):
                        answers.append(password)
                    else:
                        refused.append(prompt)
                        answers.append("")
                return answers

            try:
                return self.auth_interactive(username, strict)
            except paramiko.SSHException:
                if refused:
                    raise SecondFactorRequired(refused)
                raise

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# ANSI filtering
# ═══════════════════════════════════════════════════════════════════════════

def filter_ansi_sequences(text: str) -> str:
    """
    Remove ANSI escape sequences and control characters.

    Args:
        text: Input text with potential ANSI sequences.

    Returns:
        Cleaned text.
    """
    if not text:
        return text

    ansi_pattern = (
        r'\x1b\[[0-9;?]*[a-zA-Z]'   # CSI sequences
        r'|\x1b[()][AB012]'          # Character set selection
        r'|\x07'                      # Bell
        r'|[\x00-\x08\x0B\x0C\x0E-\x1F]'  # Control chars (preserve \n \r \t)
    )
    return re.sub(ansi_pattern, '', text)


def _load_private_key_from(
    key_content: Optional[str] = None,
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
) -> paramiko.PKey:
    """
    Load a private key from a PEM string or a file, trying RSA/Ed25519/ECDSA.

    Shared by device and bastion connections so jump-host key auth behaves
    identically to device key auth.
    """
    if key_content:
        key_source = StringIO(key_content)
        load_method = 'from_private_key'
        logger.debug("Loading key from memory")
    elif key_file:
        path = os.path.expanduser(key_file)
        if not os.path.exists(path):
            raise ValueError(f"Key file not found: {path}")
        key_source = path
        load_method = 'from_private_key_file'
        logger.debug(f"Loading key from file: {path}")
    else:
        raise ValueError("No key source specified")

    key_types = [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey]

    last_error = None
    for key_class in key_types:
        try:
            loader = getattr(key_class, load_method)
            if passphrase:
                return loader(key_source, password=passphrase)
            return loader(key_source)
        except Exception as e:
            last_error = e
            if isinstance(key_source, StringIO):
                key_source.seek(0)

    raise ValueError(f"Unable to load key: {last_error}")


# ═══════════════════════════════════════════════════════════════════════════
# Pagination disable — shotgun approach
# Fire all of these; wrong ones just error harmlessly.
# ═══════════════════════════════════════════════════════════════════════════

PAGINATION_DISABLE_SHOTGUN = [
    'terminal length 0',           # Cisco IOS/IOS-XE/NX-OS, Arista, Dell, Ubiquiti
    'terminal pager 0',            # Cisco ASA
    'set cli screen-length 0',     # Juniper Junos
    'screen-length 0 temporary',   # Huawei VRP
    'disable clipaging',           # Extreme EXOS
    'terminal more disable',       # Extreme VOSS
    'no page',                     # HP ProCurve
    'set cli pager off',           # Palo Alto
]


@dataclass
class SSHClientConfig:
    """SSH connection configuration."""
    host: str
    username: str
    password: Optional[str] = None
    key_content: Optional[str] = None   # PEM string (in-memory)
    key_file: Optional[str] = None      # Path to key file
    key_passphrase: Optional[str] = None
    port: int = 22
    timeout: int = 30
    shell_timeout: float = 5.0
    inter_command_time: float = 1.0
    expect_prompt_timeout: int = 3000   # ms
    prompt_count: int = 3
    legacy_mode: bool = False
    debug: bool = False

    # ── Optional platform hints ───────────────────────────────────────
    # When populated (e.g. from an external device inventory), these
    # override the shotgun approach with a single known-good command
    # for the target platform.
    paging_disable_command: Optional[str] = None
    prompt_regex: Optional[str] = None
    enable_command: Optional[str] = None
    legacy_ssh: Optional[bool] = None

    # Jump host / bastion (ProxyJump). When set, the device is reached
    # through the bastion(s) in this spec instead of a direct connection.
    # Resolved per-device by reachssh.proxy.ProxyResolver. Bypassed in
    # emulation mode (mock devices are local; there is nothing to proxy to).
    jump: Optional[JumpSpec] = None

    def __post_init__(self):
        if not self.password and not self.key_content and not self.key_file:
            raise ValueError("Either password, key_content, or key_file required")
        # explicit legacy_ssh overrides legacy_mode when set
        if self.legacy_ssh is not None:
            self.legacy_mode = self.legacy_ssh


class LegacySSHSupport:
    """
    Fix Paramiko's algorithm handler dictionaries for mixed-fleet SSH.

    Paramiko 3.x+ on Python 3.14 has gutted Transport._kex_info and
    Transport._key_info — algorithm names are offered during negotiation
    but their handler classes aren't registered, causing KeyErrors when
    the peer accepts them. This affects BOTH legacy (group1, ssh-dss)
    AND modern (curve25519-sha256, ssh-rsa) algorithms.

    This class discovers every handler class Paramiko ships and registers
    them all, then sets preference lists that include ONLY algorithms
    with registered handlers.

    Call once at process startup, before any SSH connections.
    """

    _configured = False

    # Every kex algorithm name → module path and class name that has
    # ever existed in Paramiko 2.x/3.x/4.x.  We try them all.
    _KEX_REGISTRY = {
        'diffie-hellman-group1-sha1':           ('paramiko.kex_group1', 'KexGroup1'),
        'diffie-hellman-group14-sha1':          ('paramiko.kex_group14', 'KexGroup14'),
        'diffie-hellman-group14-sha256':        ('paramiko.kex_group14', 'KexGroup14SHA256'),
        'diffie-hellman-group16-sha512':        ('paramiko.kex_group16', 'KexGroup16SHA512'),
        'diffie-hellman-group-exchange-sha1':   ('paramiko.kex_gex', 'KexGex'),
        'diffie-hellman-group-exchange-sha256':  ('paramiko.kex_gex', 'KexGexSHA256'),
        'ecdh-sha2-nistp256':                   ('paramiko.kex_ecdh_nist', 'KexNistp256'),
        'ecdh-sha2-nistp384':                   ('paramiko.kex_ecdh_nist', 'KexNistp384'),
        'ecdh-sha2-nistp521':                   ('paramiko.kex_ecdh_nist', 'KexNistp521'),
        'curve25519-sha256':                    ('paramiko.kex_curve25519', 'KexCurve25519'),
        'curve25519-sha256@libssh.org':         ('paramiko.kex_curve25519', 'KexCurve25519'),
    }

    # Host key type → Paramiko key class
    _KEY_REGISTRY = {
        'ssh-rsa':               ('paramiko.rsakey', 'RSAKey'),
        'rsa-sha2-256':          ('paramiko.rsakey', 'RSAKey'),
        'rsa-sha2-512':          ('paramiko.rsakey', 'RSAKey'),
        'ssh-dss':               ('paramiko.dsskey', 'DSSKey'),
        'ssh-ed25519':           ('paramiko.ed25519key', 'Ed25519Key'),
        'ecdsa-sha2-nistp256':   ('paramiko.ecdsakey', 'ECDSAKey'),
        'ecdsa-sha2-nistp384':   ('paramiko.ecdsakey', 'ECDSAKey'),
        'ecdsa-sha2-nistp521':   ('paramiko.ecdsakey', 'ECDSAKey'),
    }

    # Kex preference order (modern first, legacy last)
    _KEX_PREFERENCE = (
        "curve25519-sha256@libssh.org",
        "curve25519-sha256",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group1-sha1",
    )

    # Host key preference order
    _KEY_PREFERENCE = (
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ssh-rsa",
        "ssh-dss",
    )

    _CIPHER_PREFERENCE = (
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
        "chacha20-poly1305@openssh.com",
        "aes128-cbc",
        "aes256-cbc",
        "3des-cbc",
        "aes192-cbc",
    )

    @classmethod
    def configure_legacy_algorithms(cls):
        """
        Discover and register all available kex/key handlers.

        Safe to call multiple times — only runs once per process.
        """
        if cls._configured:
            return

        import importlib

        kex_registered = []
        key_registered = []

        # ── Register kex handlers ─────────────────────────────────────
        for algo_name, (module_path, class_name) in cls._KEX_REGISTRY.items():
            if algo_name in paramiko.Transport._kex_info:
                continue  # Already registered
            try:
                mod = importlib.import_module(module_path)
                handler_class = getattr(mod, class_name)
                paramiko.Transport._kex_info[algo_name] = handler_class
                kex_registered.append(algo_name)
            except (ImportError, AttributeError):
                pass  # Module/class doesn't exist in this version

        # ── Register host key handlers ────────────────────────────────
        for algo_name, (module_path, class_name) in cls._KEY_REGISTRY.items():
            if algo_name in paramiko.Transport._key_info:
                continue  # Already registered
            try:
                mod = importlib.import_module(module_path)
                handler_class = getattr(mod, class_name)
                paramiko.Transport._key_info[algo_name] = handler_class
                key_registered.append(algo_name)
            except (ImportError, AttributeError):
                pass

        # ── Set preference lists (only include registered algos) ──────
        paramiko.Transport._preferred_kex = tuple(
            a for a in cls._KEX_PREFERENCE
            if a in paramiko.Transport._kex_info
        )
        paramiko.Transport._preferred_keys = tuple(
            a for a in cls._KEY_PREFERENCE
            if a in paramiko.Transport._key_info
        )
        # Filter like kex/keys above: Paramiko does not filter _preferred_ciphers
        # against _cipher_info, so advertising one it can't run (it has never
        # implemented chacha20-poly1305) turns a server that picks it into a
        # KeyError mid-negotiation instead of a clean no-match.
        paramiko.Transport._preferred_ciphers = tuple(
            c for c in cls._CIPHER_PREFERENCE
            if c in paramiko.Transport._cipher_info
        )

        cls._configured = True
        logger.info(
            f"SSH algorithm support configured: "
            f"{len(paramiko.Transport._kex_info)} kex, "
            f"{len(paramiko.Transport._key_info)} host key types "
            f"(registered: {len(kex_registered)} kex, {len(key_registered)} keys)"
        )
        if kex_registered:
            logger.debug(f"  kex added: {', '.join(kex_registered)}")
        if key_registered:
            logger.debug(f"  keys added: {', '.join(key_registered)}")


class SSHClient:
    """
    SSH client for network device interaction.

    Uses invoke_shell for interactive session — required for most
    network devices that don't support direct exec.

    Supports emulation mode for testing against NetEmulate mock devices.
    When emulation is enabled (via reachssh.emulation), connections
    are transparently redirected to localhost:<port> based on ip_lookup.json.

    Example:
        config = SSHClientConfig(
            host="192.168.1.1",
            username="admin",
            password="secret",
            legacy_mode=True,
        )

        with SSHClient(config) as client:
            client.find_prompt()
            output = client.execute_command("show version")

    Emulation example:
        from sc2.scng.reachssh.emulation import enable_emulation
        enable_emulation("ip_lookup.json")
        # Same code — 192.168.1.1 → 127.0.0.1:10248 transparently
    """

    def __init__(self, config: SSHClientConfig):
        self.config = config
        self._client: Optional[paramiko.SSHClient] = None
        self._jump_client: Optional[paramiko.SSHClient] = None
        self._shell: Optional[paramiko.Channel] = None
        self._output_buffer = StringIO()
        self._detected_prompt: Optional[str] = None
        self._expect_prompt: Optional[str] = None
        self._emulated: bool = False
        self._emulated_device: Optional[str] = None

    # ═══════════════════════════════════════════════════════════════════
    # Connection lifecycle
    # ═══════════════════════════════════════════════════════════════════

    def connect(self) -> None:
        """
        Establish SSH connection and open interactive shell.

        In emulation mode, target host/port are transparently redirected
        to the mock device server based on ip_lookup.json. Credentials
        are overridden to match the mock server.
        """
        # ── Emulation redirect ──────────────────────────────────────
        if emulation.is_enabled():
            host = self.config.host
            is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host))
            logger.info(
                f"[EMULATION] Resolving {host!r}  "
                f"({'IP' if is_ip else 'hostname — will try FQDN-strip + reverse-scan'})"
            )

        emu = emulation.lookup(self.config.host)
        if emu:
            original_host = self.config.host
            original_port = self.config.port
            creds = emulation.get_credentials()
            self.config.host = emulation.get_bind_host()
            self.config.port = emu["port"]
            self.config.username = creds[0]
            self.config.password = creds[1]
            self.config.legacy_mode = False  # Mock server doesn't need legacy
            self._emulated = True
            self._emulated_device = emu["hostname"]
            logger.info(
                f"[EMULATION] {original_host}:{original_port} → "
                f"{self.config.host}:{emu['port']} ({emu['hostname']})"
            )
        elif emulation.is_enabled():
            logger.warning(
                f"[EMULATION] UNRESOLVED {self.config.host!r} — "
                f"no IP, DNS, FQDN-strip, or hostname match found. "
                f"This device will fail to connect. "
                f"Check ip_lookup.json contains an entry for this device."
            )
        # ────────────────────────────────────────────────────────────

        logger.debug(f"Connecting to {self.config.host}:{self.config.port}")

        # Ensure all kex/key handlers are registered before ANY connection.
        # Idempotent — runs once per process. Required because Paramiko 3.x+
        # on Python 3.14 ships with incomplete _kex_info/_key_info dicts.
        LegacySSHSupport.configure_legacy_algorithms()

        # Build base connection params. Pubkey signature algorithms are
        # NOT disabled here — that is handled per-attempt in the two-pass
        # connect below.
        base_params = {
            'hostname': self.config.host,
            'port': self.config.port,
            'username': self.config.username,
            'timeout': self.config.timeout,
            'allow_agent': False,
            'look_for_keys': False,
        }

        # Add authentication
        if self.config.key_content or self.config.key_file:
            pkey = self._load_private_key()
            base_params['pkey'] = pkey
            if self.config.password:
                base_params['password'] = self.config.password
        else:
            base_params['password'] = self.config.password

        # ── Two-pass connect (the SC2-proven strategy) ──────────────────
        # PASS 1: disable RFC 8332 rsa-sha2-512/256 so only ssh-rsa (SHA-1)
        #   is offered for host-key and pubkey auth. This is required for
        #   the large population of network devices (older IOS/IOS-XE,
        #   NX-OS, Junos <15.1, ASA, and many vendor stacks) that ADVERTISE
        #   rsa-sha2 support in their KEXINIT but cannot actually produce a
        #   valid SHA-2 signature. Paramiko, trusting the advertisement,
        #   selects rsa-sha2-512 and the signature check fails — surfacing
        #   as a vague negotiation/cipher error or an auth failure rather
        #   than an honest "unsupported signature algorithm" message.
        #
        # PASS 2: if pass 1 fails for ANY reason, retry with rsa-sha2-*
        #   re-enabled, covering modern hardened devices that REQUIRE SHA-2
        #   and refuse ssh-rsa entirely.
        #
        # NOTE: registering the kex/key handlers above fixes the separate
        #   "modern algo KeyErrors on Python 3.14" problem. It does NOT fix
        #   this negotiation problem, which is why the two-pass fallback is
        #   still required. legacy_mode is intentionally NOT consulted here:
        #   forcing ssh-rsa first + fallback is safe for ALL devices, so we
        #   do not depend on DCIM having the legacy flag set correctly.
        legacy_first = {'pubkeys': ['rsa-sha2-512', 'rsa-sha2-256']}

        # ── Jump host / bastion ─────────────────────────────────────────
        # When a JumpSpec is present (and we are not emulating, since mock
        # devices are local), reach the device through the bastion: open a
        # 'direct-tcpip' channel on the bastion transport and feed it to the
        # target connect as `sock`. The channel is single-use — if the target
        # two-pass retry fires, it needs a FRESH channel, so the bastion
        # transport is held open and `sock_factory` re-opens per attempt.
        if self.config.jump and not self._emulated:
            spec = self.config.jump
            if len(spec) != 1:
                # Data model accepts a chain; client implements single-hop.
                raise NotImplementedError(
                    f"Multi-hop jump chains are not yet supported "
                    f"({len(spec)} hops requested: {spec.describe()}). "
                    f"Use a single jump host per rule for now."
                )
            hop = spec.hops[0]
            logger.debug(
                "Connecting via jump host %s (%s:%d) to %s:%d",
                hop.name, hop.host, hop.port,
                self.config.host, self.config.port,
            )
            self._jump_client = self._two_pass_connect(
                self._build_jump_params(hop),
                sock_factory=lambda: None,
            )
            jump_transport = self._jump_client.get_transport()
            target_addr = (self.config.host, self.config.port)

            # Paramiko's default wait here is channel_timeout = 1 hour. The
            # bastion answers only when ITS connect to the target succeeds or
            # gives up (~2 min on Linux for an unreachable host), so bound it.
            channel_wait = max(float(self.config.timeout or 0), 10.0)

            def _open_channel():
                # Fresh channel each call — survives the target retry.
                try:
                    return jump_transport.open_channel(
                        "direct-tcpip", target_addr, ("", 0), timeout=channel_wait
                    )
                except Exception as e:
                    raise TargetUnreachable(
                        f"jump host {hop.name} could not reach "
                        f"{target_addr[0]}:{target_addr[1]} ({e or type(e).__name__})"
                    ) from e

            self._client = self._two_pass_connect(base_params, sock_factory=_open_channel)
        else:
            self._client = self._two_pass_connect(base_params, sock_factory=lambda: None)

        logger.debug(f"Connected to {self.config.host}")

        # Open interactive shell
        self._create_shell()

    def _two_pass_connect(self, base_params: dict, sock_factory) -> paramiko.SSHClient:
        """
        Run the SC2-proven two-pass paramiko connect and return the client.

        PASS 1 forces ssh-rsa (SHA-1) by disabling RFC 8332 rsa-sha2-512/256,
        covering the large population of network devices that advertise
        rsa-sha2 in KEXINIT but cannot actually produce a SHA-2 signature.
        PASS 2 re-enables rsa-sha2-* for modern hardened devices that require
        it. See connect() history for the full rationale.

        `sock_factory` returns the transport to tunnel over (a bastion
        'direct-tcpip' channel) or None for a direct connection. It is called
        once per attempt so the retry gets a fresh, unconsumed channel.
        """
        legacy_first = {'pubkeys': ['rsa-sha2-512', 'rsa-sha2-256']}

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            logger.debug("Connect attempt 1: forcing ssh-rsa (SHA-1)")
            params = dict(base_params)
            sock = sock_factory()
            if sock is not None:
                params['sock'] = sock
            client.connect(**params, disabled_algorithms=legacy_first,
                           transport_factory=_NonInteractiveTransport)
            return client
        except Exception as first_err:
            if _no_retry(first_err):
                # Unreachable target / bastion path, or a second-factor prompt:
                # a second pass would repeat the same wait or the same prompt.
                try:
                    client.close()
                except Exception:
                    pass
                raise
            logger.debug(
                f"Attempt 1 failed ({type(first_err).__name__}: {first_err}); "
                f"retrying with rsa-sha2-512/256 enabled"
            )
            # The failed transport/socket is unusable — start with a fresh
            # client (and a fresh tunnel channel) rather than reconnecting
            # on the dead one.
            try:
                client.close()
            except Exception:
                pass
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            params = dict(base_params)
            sock = sock_factory()
            if sock is not None:
                params['sock'] = sock
            client.connect(**params, transport_factory=_NonInteractiveTransport)
            return client

    def _build_jump_params(self, hop) -> dict:
        """Build paramiko.connect params for a bastion hop (its own creds)."""
        params = {
            'hostname': hop.host,
            'port': hop.port,
            'username': hop.username,
            'timeout': self.config.timeout,
            'allow_agent': False,
            'look_for_keys': False,
        }
        if hop.key_content:
            params['pkey'] = _load_private_key_from(
                key_content=hop.key_content,
                passphrase=self.config.key_passphrase,
            )
            if hop.password:
                params['password'] = hop.password
        else:
            params['password'] = hop.password
        return params

    def disconnect(self) -> None:
        """Close SSH connection."""
        if self._emulated:
            logger.debug(
                f"[EMULATION] Disconnecting from mock device {self._emulated_device}"
            )

        if self._shell:
            try:
                self._shell.close()
            except Exception as e:
                logger.debug(f"Shell close error: {e}")
            self._shell = None

        if self._client:
            try:
                self._client.close()
            except Exception as e:
                logger.debug(f"Client close error: {e}")
            self._client = None

        if self._jump_client:
            try:
                self._jump_client.close()
            except Exception as e:
                logger.debug(f"Jump client close error: {e}")
            self._jump_client = None

        logger.debug(f"Disconnected from {self.config.host}")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False

    # ═══════════════════════════════════════════════════════════════════
    # Shell setup
    # ═══════════════════════════════════════════════════════════════════

    def _create_shell(self) -> None:
        """Create interactive shell stream."""
        logger.debug("Creating shell stream")

        # height=24 required — some older IOS SSH implementations
        # (e.g. Cisco-1.25) reject or silently fail on height=0 PTY requests.
        # Pagination is handled by 'terminal length 0', not PTY size.
        self._shell = self._client.invoke_shell(
            term='xterm',
            width=200,
            height=24,
        )
        self._shell.settimeout(self.config.timeout)

        # Wait for shell initialization
        if self._emulated:
            time.sleep(0.3)  # Mock devices are instant
        else:
            time.sleep(2)

        # Read and discard banner/MOTD
        self._drain_output()

    def _load_private_key(self) -> paramiko.PKey:
        """Load private key from this connection's PEM string or file."""
        return _load_private_key_from(
            key_content=self.config.key_content,
            key_file=self.config.key_file,
            passphrase=self.config.key_passphrase,
        )

    # ═══════════════════════════════════════════════════════════════════
    # Prompt detection
    # ═══════════════════════════════════════════════════════════════════

    def find_prompt(
        self,
        attempt_count: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> str:
        """
        Detect the device prompt by sending newlines and observing output.

        Each probe polls the channel and returns as soon as a prompt is
        parseable rather than always sleeping the full `timeout` — a device
        that answers instantly costs ~one poll interval, not the whole
        window. `timeout` is the *upper bound* per probe (for a silent
        device the total stays attempt_count × timeout, unchanged), not a
        fixed wait. With attempt_count >= 2, the loop exits early once two
        consecutive probes agree on the prompt.

        Faster timeouts in emulation mode since mock devices respond instantly.
        """
        attempt_count = attempt_count or self.config.prompt_count
        timeout = timeout or self.config.shell_timeout

        # Mock devices respond instantly
        if self._emulated:
            attempt_count = min(attempt_count, 2)
            timeout = min(timeout, 1.0)

        poll = 0.05  # channel poll interval — never blocks on recv

        prompts_seen = []

        for _i in range(attempt_count):
            self._drain_output()
            self._shell.send('\n')

            # Accumulate output until a prompt is parseable or `timeout`
            # elapses. recv_ready() keeps us off the blocking socket path.
            buffer = ""
            prompt = None
            deadline = time.time() + timeout
            while time.time() < deadline:
                if self._shell.recv_ready():
                    buffer += self._recv_filtered()
                    prompt = self._extract_prompt(buffer)
                    if prompt:
                        break
                time.sleep(poll)

            if prompt:
                prompts_seen.append(prompt)
                # Two consecutive agreeing probes is enough to trust it —
                # stop instead of burning the remaining attempts.
                if len(prompts_seen) >= 2 and prompts_seen[-1] == prompts_seen[-2]:
                    break

        if prompts_seen:
            # Use most common prompt seen
            prompt = max(set(prompts_seen), key=prompts_seen.count)
            self._detected_prompt = prompt
            logger.debug(f"Detected prompt: {prompt!r}")
            return prompt

        logger.warning("Could not detect prompt, using '#' fallback")
        self._detected_prompt = "#"
        return "#"

    def _extract_prompt(self, buffer: str) -> Optional[str]:
        """Extract prompt from buffer content."""
        if not buffer or not buffer.strip():
            return None

        lines = [line.strip() for line in buffer.split('\n') if line.strip()]
        if not lines:
            return None

        # Prompt patterns — ordered by specificity
        patterns = [
            r'([A-Za-z0-9\-_.@()]+[#>$%])\s*$',   # Standard prompts
            r'([^\r\n]+[#>$%])\s*$',                 # Anything ending with prompt char
        ]

        common_endings = ['#', '>', '$', '%', ':', ']', ')']

        # Check last lines for prompt
        for line in reversed(lines[-5:]):
            if len(line) > 60:
                continue

            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    prompt = match.group(1).strip()
                    base = self._extract_base_prompt(prompt)
                    return base if base else prompt

            if any(line.endswith(char) for char in common_endings) and len(line) < 40:
                return line

        return None

    def _extract_base_prompt(self, text: str) -> Optional[str]:
        """Extract base prompt from potentially repeated text."""
        for ending in ['#', '>', '$', '%']:
            if ending in text:
                parts = text.split(ending)
                if len(parts) > 2:
                    base = parts[0].strip() + ending
                    if len(base) < 40:
                        return base
        return None

    def extract_hostname_from_prompt(self, prompt: Optional[str] = None) -> Optional[str]:
        """
        Extract hostname from detected prompt.

        Handles common formats:
        - Cisco/Arista/Juniper: "hostname#" or "hostname>"
        - Linux: "user@hostname:~$" or "user@hostname $"
        - Juniper: "user@hostname>"
        """
        prompt = prompt or self._detected_prompt
        if not prompt:
            return None

        # Linux style: user@hostname:path$
        match = re.match(r'^[^@]+@([A-Za-z0-9\-_.]+)', prompt)
        if match:
            return match.group(1)

        # Network device style: hostname# or hostname(config)#
        clean_prompt = re.sub(r'\([^)]+\)', '', prompt)
        match = re.match(r'^([A-Za-z0-9\-_.]+)[#>$%:\]]', clean_prompt)
        if match:
            return match.group(1)

        return None

    # ═══════════════════════════════════════════════════════════════════
    # Command execution
    # ═══════════════════════════════════════════════════════════════════

    def set_expect_prompt(self, prompt: str) -> None:
        """Set the prompt string to expect after commands."""
        self._expect_prompt = prompt
        logger.debug(f"Expect prompt set to: {prompt!r}")

    def disable_pagination(self, command: Optional[str] = None) -> None:
        """
        Disable pagination.

        If a specific command is provided (from config.paging_disable_command),
        sends only that command. Otherwise fires the shotgun list — wrong ones
        just produce errors that are drained and discarded.

        Skipped entirely in emulation mode — mock devices don't paginate.
        """
        if self._emulated:
            logger.debug("[EMULATION] Skipping pagination disable (mock device)")
            return

        # ── Platform-specific command (from DCIM) ────────────────────
        if command or self.config.paging_disable_command:
            cmd = command or self.config.paging_disable_command
            logger.debug(f"Disabling pagination with platform command: {cmd}")
            try:
                self._shell.send(cmd + '\n')
                self.find_prompt(attempt_count=1, timeout=3.0)
            except Exception as e:
                logger.debug(f"Platform pagination command failed: {cmd} — {e}")
            return

        # ── Shotgun approach (vendor-agnostic) ───────────────────────
        logger.debug("Disabling pagination (shotgun approach)")

        for cmd in PAGINATION_DISABLE_SHOTGUN:
            try:
                self._shell.send(cmd + '\n')
                self.find_prompt(attempt_count=1, timeout=3.0)
            except Exception as e:
                logger.debug(f"Pagination cmd failed (expected): {cmd} — {e}")

        # Final prompt check — confirm clean shell state
        prompt = self.find_prompt(attempt_count=2, timeout=3.0)
        logger.debug(f"Pagination disable complete, prompt={prompt!r}")

    def send_enable(self, enable_command: Optional[str] = None) -> None:
        """
        Enter enable/privileged mode if needed.

        Uses the configured enable_command if available,
        otherwise sends 'enable' and the config password.

        Skipped in emulation mode.
        """
        if self._emulated:
            logger.debug("[EMULATION] Skipping enable (mock device)")
            return

        cmd = enable_command or self.config.enable_command
        if not cmd:
            return

        logger.debug(f"Sending enable command: {cmd}")
        self._shell.send(cmd + '\n')
        time.sleep(1.0)

        # Check if password prompt appeared
        output = self._drain_output()
        if 'assword' in output:
            if self.config.password:
                self._shell.send(self.config.password + '\n')
                time.sleep(1.0)
                self._drain_output()

        # Re-detect prompt (may have changed from > to #)
        self.find_prompt()

    def execute_command(
        self,
        command: str,
        timeout: Optional[float] = None,
    ) -> str:
        """
        Execute command and return output.

        Args:
            command: Command string. Can be comma-separated for multiple commands.
            timeout: Override default timeout.

        Returns:
            Command output with ANSI sequences filtered.
        """
        if not self._shell:
            raise RuntimeError("Not connected")

        timeout = timeout or self.config.expect_prompt_timeout / 1000

        # Split comma-separated commands
        commands = [cmd.strip() for cmd in command.split(',') if cmd.strip()]

        output_buffer = StringIO()

        for cmd in commands:
            if cmd in ('\\n', '\n'):
                self._shell.send('\n')
                time.sleep(0.1)
                continue

            # ── Drain stale data before sending ──────────────────────
            # Between poll cycles, the channel may accumulate trailing
            # bytes from the previous command (post-prompt newlines,
            # late-arriving output fragments). Without draining, the
            # next _wait_for_prompt() reads stale data first, finds
            # the *previous* command's prompt, and returns immediately
            # with garbage — causing a one-command offset desync where
            # every collection parses the previous collection's output.
            stale = self._drain_output()
            if stale:
                logger.debug(
                    f"Drained {len(stale)} bytes of stale data before '{cmd}'"
                )

            logger.debug(f"Sending: {cmd}")
            self._shell.send(cmd + '\n')

            cmd_output = self._wait_for_prompt(timeout, sent=cmd)
            # Remove the echoed command and trailing prompt so stored output is
            # deterministic (otherwise the head/tail drift run-to-run and show
            # as phantom diffs). Done per-command before concatenation.
            cmd_output = self._strip_echo_and_prompt(
                cmd_output, cmd, self._expect_prompt or self._detected_prompt
            )
            if cmd_output:
                if output_buffer.tell() > 0:
                    output_buffer.write('\n')   # one separator between commands
                output_buffer.write(cmd_output)

            time.sleep(
                self.config.inter_command_time if not self._emulated else 0.05
            )

        return output_buffer.getvalue()

    # ═══════════════════════════════════════════════════════════════════
    # I/O helpers
    # ═══════════════════════════════════════════════════════════════════

    def _wait_for_prompt(self, timeout: float, sent: Optional[str] = None) -> str:
        """Wait for the prompt to appear after a command.

        Two safeguards beyond a bare ``prompt in output`` substring test:

        1. Echo-anchored matching. A stale ready-prompt can already be sitting
           in the channel when this starts — Junos prints ``{master:0}`` +
           prompt the moment it's ready, and IOS prints its prompt then echoes
           the command on the *same* line (``host#show run``), so the stale
           prompt and the echo arrive together. The pre-send drain races that
           and can miss it. The terminating prompt always comes *after* the
           command echo, the stale one *before* it — so once the echo is
           located, the prompt is only searched for in the region *after* it.
           Searching the whole buffer would match the stale prompt and return
           the truncated head. No-echo devices (rare for network CLI) release
           the anchor after a short grace window and match anywhere.

        2. Inactivity timeout. ``timeout`` is treated as a cap on *silence*,
           not total elapsed time — it resets on every received chunk. This
           lets a large config stream for as long as bytes keep flowing
           (e.g. Cisco ``show run`` after its ``Building configuration...``
           pause) while a hard ceiling still bounds a genuinely wborderd
           session. The idle window must exceed the longest mid-command quiet
           stretch, so size ``expect_prompt_timeout`` accordingly.
        """
        prompt = self._expect_prompt or self._detected_prompt

        if not prompt:
            time.sleep(self.config.shell_timeout)
            return self._drain_output()

        output = ""
        idle_deadline = time.time() + timeout              # resets on every recv
        hard_deadline = time.time() + max(timeout * 20, 60)  # absolute safety cap
        # Index just past the command echo; the prompt is only matched beyond
        # it. None = not located yet, 0 = match anywhere (no echo expected).
        echo_end = 0 if (sent is None or not sent.strip()) else None
        echo_grace = time.time() + min(1.5, timeout / 2)
        needle = sent.strip() if sent else ""

        while time.time() < idle_deadline and time.time() < hard_deadline:
            if self._shell.recv_ready():
                output += self._recv_filtered()
                idle_deadline = time.time() + timeout      # got bytes — extend the window

                if echo_end is None:
                    pos = output.find(needle)
                    if pos != -1:
                        echo_end = pos + len(needle)
                    elif time.time() < echo_grace:
                        time.sleep(0.01)
                        continue
                    else:
                        echo_end = 0  # grace expired, echo never seen — match anywhere

                if prompt in output[echo_end:]:
                    logger.debug("Prompt detected in output")
                    # Brief settle: some devices send trailing bytes
                    # (newlines, control chars) after the prompt.
                    time.sleep(0.05)
                    if self._shell.recv_ready():
                        output += self._recv_filtered()
                    return output

            time.sleep(0.01)

        logger.warning(
            "Prompt wait ended without match (idle cap %.1fs / hard cap reached)",
            timeout,
        )
        return output

    def _strip_echo_and_prompt(
        self, output: str, command: str, prompt: Optional[str]
    ) -> str:
        """
        Make a single command's output deterministic for storage.

        Devices echo the command back — sometimes bare ("show run"), sometimes
        prompt-prefixed on the same line ("host#show run") depending on prompt-
        detection timing — and terminate with the prompt line. Left in, those
        head/tail lines drift run-to-run and register as phantom config changes
        on the first and last lines of every snapshot. This removes:

          - leading/trailing blank lines
          - the command echo (first non-blank line)
          - the trailing prompt (last non-blank line)

        Anchored to the first and last non-blank lines ONLY. Interior lines are
        never inspected, so a config line that legitimately contains the command
        text or ends in a prompt character is safe. Echo removal additionally
        requires any prefix before the command to be empty or prompt-like;
        prompt removal requires an exact (or prompt-plus-whitespace) match
        against the detected base prompt, falling back to a conservative
        heuristic only when no base prompt is known.
        """
        if not output:
            return output

        lines = output.split("\n")

        def _trim_blank_edges(seq):
            while seq and seq[0].strip() == "":
                seq.pop(0)
            while seq and seq[-1].strip() == "":
                seq.pop()

        cmd = (command or "").strip()
        base = (prompt or "").strip()

        _trim_blank_edges(lines)

        # ── Command echo: first non-blank line ───────────────────────
        if cmd and lines:
            head = lines[0].rstrip("\r").strip()
            if head == cmd or head.endswith(cmd):
                prefix = head[: len(head) - len(cmd)].rstrip()
                # bare echo, or prompt-prefixed echo (prefix ends in a prompt
                # char). A real config line ending in the command text — e.g.
                # "description show run" — has a non-prompt prefix and is kept.
                if prefix == "" or re.search(r"[#>$%]\s*$", prefix):
                    lines.pop(0)

        # ── Trailing prompt: last non-blank line ─────────────────────
        if lines:
            tail = lines[-1].rstrip("\r").strip()
            is_prompt = (
                (base and tail == base)
                or (base and tail.startswith(base) and tail[len(base):].strip() == "")
                # No base prompt known: short line ending in a prompt char and
                # not a config terminator ('!' and '}' are excluded by the set).
                or (not base and len(tail) <= 60 and bool(re.search(r"[#>$%]$", tail)))
            )
            if is_prompt:
                lines.pop()

        _trim_blank_edges(lines)
        return "\n".join(lines)

    def _drain_output(self) -> str:
        """Read all pending output from the shell."""
        output = ""
        while self._shell.recv_ready():
            chunk = self._shell.recv(65535).decode('utf-8', errors='replace')
            output += filter_ansi_sequences(chunk)
            time.sleep(0.05)
        return output

    def _recv_filtered(self) -> str:
        """Receive and filter data from shell."""
        data = self._shell.recv(65535).decode('utf-8', errors='replace')
        return filter_ansi_sequences(data)

    # ═══════════════════════════════════════════════════════════════════
    # Properties
    # ═══════════════════════════════════════════════════════════════════

    @property
    def hostname(self) -> Optional[str]:
        """Get hostname extracted from prompt."""
        return self.extract_hostname_from_prompt()

    @property
    def is_emulated(self) -> bool:
        """True if this connection is using emulation mode."""
        return self._emulated

    @property
    def emulated_device(self) -> Optional[str]:
        """Hostname of the mock device (if emulated)."""
        return self._emulated_device

    @property
    def detected_prompt(self) -> Optional[str]:
        """The prompt string detected by find_prompt()."""
        return self._detected_prompt