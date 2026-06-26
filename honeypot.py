#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Windows SSH Honeypot — fakes an SSH service and bans every connecting IP into a
# SINGLE Windows Firewall rule (per direction). Updates are DEBOUNCED (flushed
# periodically, not per-hit) and the ban list is a bounded FIFO ring: once the
# configured cap is reached the oldest-inserted IP is evicted (unbanned) to make
# room for the new one, keeping the rule small and avoiding size/perf problems.
# Bans are reported to Telegram in batches.
#
# Copyright (C) 2026  https://github.com/Leproide
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Author: https://github.com/Leproide

import os
import sys
import html
import json
import time
import socket
import ctypes
import logging
import ipaddress
import threading
import subprocess
import http.server
import urllib.parse
import urllib.error
import urllib.request
from collections import OrderedDict
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# CONFIGURATION  (all parameters overridable via environment variables)
# ---------------------------------------------------------------------------

def _env_bool(name, default):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")

# Ports to expose. Each will pretend to be SSH. Port < 1024 is fine on Windows.
PORTS = [int(p) for p in os.environ.get("HP_PORTS", "22").split(",")]

# Fake SSH server banner sent on connect (must look believable to scanners).
SSH_BANNER = os.environ.get(
    "HP_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
).encode()

# Telegram bot credentials. Leave empty to disable Telegram reporting.
TELEGRAM_TOKEN = os.environ.get("HP_TG_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("HP_TG_CHAT", "")

# Also block OUTBOUND traffic to banned IPs (second rule). Inbound is always
# blocked. Set HP_BLOCK_OUT=0 to keep a single inbound-only rule.
BLOCK_OUTBOUND = _env_bool("HP_BLOCK_OUT", True)

# Collapse contiguous addresses into CIDR ranges to keep the rule small/fast.
AGGREGATE = _env_bool("HP_AGGREGATE", True)

# Cap on the number of tracked IPs (and therefore an upper bound on rule
# entries, since aggregation only shrinks). 0 = unlimited. When the cap is hit,
# the OLDEST-inserted IP is evicted (i.e. unbanned) to admit the new one.
MAX_BANNED = int(os.environ.get("HP_MAX", "2000"))

# Debounce: seconds between firewall rewrites. Hits accumulate in memory and the
# rule is rebuilt at most once per interval (plus a final flush on shutdown).
FLUSH_INTERVAL = float(os.environ.get("HP_FLUSH", "5"))

# If True, re-seeing an already-banned IP moves it to the newest slot so active
# attackers are not evicted before idle ones. If False (default), pure FIFO on
# first-insertion order, as requested.
REFRESH_ON_HIT = _env_bool("HP_REFRESH_ON_HIT", False)

# Rebuild the rule from the persisted set once at startup. Disable to avoid a
# full rewrite on boot when the rule is already maintained/intact.
SYNC_ON_START = _env_bool("HP_SYNC_ON_START", True)

# Local admin HTTP endpoint (loopback only) for listing/unbanning at runtime.
ADMIN_ENABLED = _env_bool("HP_ADMIN", True)
ADMIN_HOST = "127.0.0.1"                       # never bind to anything but loopback
ADMIN_PORT = int(os.environ.get("HP_ADMIN_PORT", "65432"))

# IPThreat.net reporting. The API key is read from the environment ONLY — never
# hardcode it (this file is GPL/public). Reporting auto-enables when a key is set.
#   PowerShell:  $env:HP_IPTHREAT_KEY = "your-key"
#   cmd:         set "HP_IPTHREAT_KEY=your-key"
IPTHREAT_KEY = os.environ.get("HP_IPTHREAT_KEY", "").strip()
IPTHREAT_ENABLED = _env_bool("HP_IPTHREAT", bool(IPTHREAT_KEY))
IPTHREAT_URL = "https://api.ipthreat.net/api/report"
# Flags: comma-separated names or a bitwise-OR integer. BruteForce(8)+PortScan(4096).
IPTHREAT_FLAGS = os.environ.get("HP_IPTHREAT_FLAGS", "BruteForce,PortScan")
IPTHREAT_SYSTEM = os.environ.get("HP_IPTHREAT_SYSTEM", "SSH")   # 32 char max
# Aggregated attack count reported per IP. IPThreat accepts 1-10 (clamped).
IPTHREAT_COUNT = max(1, min(10, int(os.environ.get("HP_IPTHREAT_COUNT", "3"))))
# Notes must not contain usernames/PII/timestamps per IPThreat guidelines.
IPTHREAT_NOTES = os.environ.get(
    "HP_IPTHREAT_NOTES",
    "Unsolicited connection to an SSH honeypot port (no real service exposed).")

# Never ban these (CIDR allowed). Loopback is always whitelisted.
WHITELIST = [
    "127.0.0.0/8",
    "::1/128",
    # "192.168.0.0/16",   # uncomment to never ban your LAN
    # "10.0.0.0/8",
]

# Persistence + logging paths (next to the script).
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BAN_DB = os.path.join(BASE_DIR, "banned_ips.json")   # ordered source of truth
IP_FILE = os.path.join(BASE_DIR, "banned_ips.txt")   # fed to PowerShell
LOG_FILE = os.path.join(BASE_DIR, "honeypot.log")

# Firewall rule display names (one per direction — the ONLY rules created).
RULE_IN = "HONEYPOT_BAN_IN"
RULE_OUT = "HONEYPOT_BAN_OUT"

# ---------------------------------------------------------------------------
# INTERNAL STATE
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_fw_lock = threading.Lock()            # serializes firewall (file+PowerShell) writes
_banned = OrderedDict()                # ip -> first_seen_epoch (insertion order)
_dirty = False                         # set when the firewall needs rewriting
_pending_new = []                      # new bans since last flush (for Telegram)
_pending_evicted = []                  # IPs evicted by the cap since last flush
_stop = threading.Event()
_whitelist_nets = [ipaddress.ip_network(c, strict=False) for c in WHITELIST]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    force=True,                       # win even if the root logger was pre-configured
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
try:
    sys.stdout.reconfigure(line_buffering=True)   # flush each line to the console
except Exception:
    pass
log = logging.getLogger("honeypot")

# ---------------------------------------------------------------------------
# PRIVILEGE HANDLING
# ---------------------------------------------------------------------------

def is_admin():
    """True if the process holds administrator rights (needed for firewall)."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def ensure_admin():
    """Re-launch the script elevated via UAC if not already admin."""
    if is_admin():
        return
    log.warning("Not elevated — requesting administrator privileges (UAC)...")
    params = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    sys.exit(0)

# ---------------------------------------------------------------------------
# PERSISTENCE
# ---------------------------------------------------------------------------

def load_banned():
    """Reload previously banned IPs preserving insertion order."""
    global _banned
    try:
        with open(BAN_DB, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Supports both the new [[ip, ts], ...] format and a plain [ip, ...] list.
        items = OrderedDict()
        for entry in data:
            if isinstance(entry, (list, tuple)):
                items[entry[0]] = float(entry[1])
            else:
                items[entry] = time.time()
        _banned = items
        log.info("Loaded %d previously banned IP(s).", len(_banned))
    except (FileNotFoundError, json.JSONDecodeError):
        _banned = OrderedDict()


def _save_db(snapshot):
    """Persist the ordered ban list atomically (snapshot = list of (ip, ts))."""
    tmp = BAN_DB + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump([[ip, ts] for ip, ts in snapshot], f, indent=2)
    os.replace(tmp, BAN_DB)

# ---------------------------------------------------------------------------
# ADDRESS LIST / AGGREGATION
# ---------------------------------------------------------------------------

def _aggregate(ips):
    """
    Build the address list written to the rule. With AGGREGATE on, contiguous
    addresses are collapsed into CIDR ranges (v4 and v6 separately), which keeps
    the rule small when whole scanner ranges get banned.
    """
    if not AGGREGATE:
        return list(ips)
    v4, v6 = [], []
    for ip in ips:
        try:
            net = ipaddress.ip_network(ip, strict=False)
        except ValueError:
            continue
        (v4 if net.version == 4 else v6).append(net)
    out = [str(n) for n in ipaddress.collapse_addresses(v4)]
    out += [str(n) for n in ipaddress.collapse_addresses(v6)]
    return out


def _write_ip_file(lines):
    """Write the (aggregated) address list, one entry per line, atomically."""
    tmp = IP_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    os.replace(tmp, IP_FILE)

# ---------------------------------------------------------------------------
# WHITELIST
# ---------------------------------------------------------------------------

def is_whitelisted(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _whitelist_nets)

# ---------------------------------------------------------------------------
# WINDOWS FIREWALL (single rule per direction, rebuilt from IP_FILE)
# ---------------------------------------------------------------------------

# PowerShell template: reads addresses from the file (avoids command-line length
# limits), then creates or updates ONE rule. If the list is empty it removes the
# rule — crucial, because an empty RemoteAddress would mean "Any" (block all).
_PS_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
$ips = @(Get-Content -LiteralPath '{file}' -ErrorAction SilentlyContinue |
         ForEach-Object {{ $_.Trim() }} | Where-Object {{ $_ -ne '' }})
$name = '{name}'
if ($ips.Count -eq 0) {{
    Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    return
}}
if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) {{
    Set-NetFirewallRule -DisplayName $name -RemoteAddress $ips | Out-Null
}} else {{
    New-NetFirewallRule -DisplayName $name -Direction {direction} -Action Block `
        -Profile Any -RemoteAddress $ips -Enabled True | Out-Null
}}
"""


def _run_ps(name, direction):
    """Create/update one firewall rule from IP_FILE via PowerShell."""
    script = _PS_TEMPLATE.format(file=IP_FILE, name=name, direction=direction)
    res = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        log.error("Firewall update failed (%s): %s", name,
                  (res.stderr or res.stdout).strip())
        return False
    return True


def sync_firewall(lines):
    """Write IP_FILE and (re)build the firewall rule(s) from `lines`."""
    _write_ip_file(lines)
    ok = _run_ps(RULE_IN, "Inbound")
    if BLOCK_OUTBOUND:
        ok = _run_ps(RULE_OUT, "Outbound") and ok
    return ok

# ---------------------------------------------------------------------------
# TELEGRAM
# ---------------------------------------------------------------------------

def notify_telegram(text):
    if not (TELEGRAM_TOKEN and TELEGRAM_CHAT_ID):
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }).encode()
    try:
        with urllib.request.urlopen(url, data=data, timeout=10) as r:
            r.read()
    except Exception as e:
        log.error("Telegram error: %s", e)


def _fmt_list(items, limit=15):
    """Compact, HTML-escaped preview of an IP list for Telegram."""
    shown = ", ".join(html.escape(x) for x in items[:limit])
    extra = len(items) - limit
    return shown + (f" (+{extra})" if extra > 0 else "")

# ---------------------------------------------------------------------------
# IPTHREAT.NET REPORTING
# ---------------------------------------------------------------------------

def report_ipthreat(ip):
    """Submit one offending IP to IPThreat.net. Returns True on success (2xx)."""
    if not (IPTHREAT_ENABLED and IPTHREAT_KEY):
        return False
    body = json.dumps({
        "ip": ip,
        "flags": IPTHREAT_FLAGS,                # e.g. "BruteForce,PortScan"
        "system": IPTHREAT_SYSTEM[:32],         # e.g. "SSH"
        "notes": IPTHREAT_NOTES[:1000],         # no PII / usernames / timestamps
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": IPTHREAT_COUNT,
    }).encode()
    req = urllib.request.Request(
        IPTHREAT_URL, data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            # Default urllib UA ("Python-urllib/x") is often WAF-blocked (403).
            "User-Agent": "WindowsSSHHoneypot/1.0 (+https://github.com/Leproide)",
            "X-API-KEY": IPTHREAT_KEY,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
            return 200 <= r.status < 300
    except urllib.error.HTTPError as e:
        # The response body carries IPThreat's reason (e.g. allowlisted IP, quota).
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace").strip()[:300]
        except Exception:
            pass
        log.error("IPThreat report %s rejected: HTTP %s %s%s", ip, e.code, e.reason,
                  f" - {detail}" if detail else "")
    except Exception as e:
        log.error("IPThreat report %s failed: %s", ip, e)
    return False


def _report_batch(ips):
    """Report a batch of new IPs sequentially (runs in its own daemon thread)."""
    ok = sum(1 for ip in ips if report_ipthreat(ip))
    log.info("IPThreat: reported %d/%d new IP(s).", ok, len(ips))

# ---------------------------------------------------------------------------
# BAN RECORDING (in-memory; firewall is touched only by the flush loop)
# ---------------------------------------------------------------------------

def record_ban(ip):
    """
    Register a hit. Returns 'already' if the IP was already banned.
    Applies the FIFO cap (evicting the oldest IP when full) and marks state
    dirty so the next flush rewrites the firewall rule.
    """
    global _dirty
    with _lock:
        if ip in _banned:
            if REFRESH_ON_HIT:
                _banned.move_to_end(ip)         # keep active attackers fresh
                _banned[ip] = time.time()
            return True
        # Enforce the cap with FIFO eviction (oldest inserted -> unbanned).
        if MAX_BANNED > 0:
            while len(_banned) >= MAX_BANNED:
                old_ip, _ = _banned.popitem(last=False)
                _pending_evicted.append(old_ip)
        _banned[ip] = time.time()
        _pending_new.append(ip)
        _dirty = True
        return False


def flush():
    """
    Debounced flush: ONLY when state is dirty, rebuild the firewall rule(s) once
    and send a single batched Telegram summary. If nothing changed it is a no-op
    and the firewall is not touched — so exiting while idle never rewrites a
    large rule. Heavy work runs OUTSIDE the lock so connections aren't blocked.
    """
    global _dirty
    with _lock:
        if not _dirty:
            return
        snapshot = list(_banned.items())
        new = _pending_new[:]
        evicted = _pending_evicted[:]
        _pending_new.clear()
        _pending_evicted.clear()
        _dirty = False
    lines = _aggregate(ip for ip, _ in snapshot)
    with _fw_lock:                     # avoid concurrent rule rewrites
        _save_db(snapshot)
        ok = sync_firewall(lines)
    log.info("Flush: +%d new, -%d evicted, %d IPs, %d rule entries, fw=%s",
             len(new), len(evicted), len(snapshot), len(lines),
             "OK" if ok else "FAIL")
    # Report only the genuinely new (non-aggregated) offending IPs, off-thread.
    if new and IPTHREAT_ENABLED and IPTHREAT_KEY:
        threading.Thread(target=_report_batch, args=(new,), daemon=True).start()
    if new or evicted:
        parts = ["🚫 <b>Honeypot</b> — flush"]
        if new:
            parts.append(f"New bans ({len(new)}): <code>{_fmt_list(new)}</code>")
        if evicted:
            parts.append(f"Evicted by cap ({len(evicted)}): "
                         f"<code>{_fmt_list(evicted)}</code>")
        cap = MAX_BANNED if MAX_BANNED > 0 else "∞"
        parts.append(f"IPs: {len(snapshot)}/{cap} | rule entries: {len(lines)}")
        parts.append(f"Firewall: {'OK' if ok else 'FAILED'}")
        parts.append(f"Time: {datetime.now().isoformat(timespec='seconds')}")
        notify_telegram("\n".join(parts))


def flush_loop():
    """Background debounce timer: flush at most once per FLUSH_INTERVAL."""
    while not _stop.wait(FLUSH_INTERVAL):
        try:
            flush()
        except Exception as e:
            log.error("Flush error: %s", e)

# ---------------------------------------------------------------------------
# UNBAN
# ---------------------------------------------------------------------------

def unban(value):
    """
    Remove a single IP or every banned IP within a CIDR from the set and mark
    state dirty (the rule is rewritten on the next/forced flush).
    Returns the list of removed IPs, or None if `value` is not a valid IP/CIDR.
    """
    global _dirty
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    removed = []
    with _lock:
        for ip in list(_banned.keys()):
            try:
                hit = ipaddress.ip_address(ip) in net
            except ValueError:
                hit = (ip == value)
            if hit:
                del _banned[ip]
                removed.append(ip)
        if removed:
            _dirty = True
    return removed

# ---------------------------------------------------------------------------
# LOCAL ADMIN HTTP ENDPOINT (loopback only)
# ---------------------------------------------------------------------------

class _AdminHandler(http.server.BaseHTTPRequestHandler):
    """
    Minimal JSON control API, bound to 127.0.0.1 only.
      GET /list                      -> {count, ips}
      GET /stats                     -> runtime configuration/counters
      GET /unban?ip=<ip|cidr>[&now=0] -> {unbanned, count, applied}
    `now=0` defers the rule rewrite to the next debounce flush (default applies now).
    """

    server_version = "Honeypot-Admin/1.0"

    def _send(self, code, obj):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):       # route access logs to our logger
        log.info("admin %s %s", self.address_string(), fmt % args)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = (parsed.path.rstrip("/") or "/")
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/list":
            with _lock:
                ips = list(_banned.keys())
            self._send(200, {"count": len(ips), "ips": ips})

        elif path == "/stats":
            with _lock:
                n = len(_banned)
            self._send(200, {
                "banned": n,
                "cap": MAX_BANNED or None,
                "flush_interval": FLUSH_INTERVAL,
                "aggregate": AGGREGATE,
                "block_outbound": BLOCK_OUTBOUND,
                "refresh_on_hit": REFRESH_ON_HIT,
                "ipthreat": IPTHREAT_ENABLED and bool(IPTHREAT_KEY),
                "ports": PORTS,
            })

        elif path == "/unban":
            val = (qs.get("ip") or [""])[0].strip()
            if not val:
                self._send(400, {"error": "missing 'ip' parameter"})
                return
            removed = unban(val)
            if removed is None:
                self._send(400, {"error": f"invalid ip/cidr: {val}"})
                return
            apply_now = (qs.get("now") or ["1"])[0] != "0"
            if removed and apply_now:
                flush()                       # apply immediately (PS runs here)
            log.info("Admin unban %s -> %d removed (applied=%s)",
                     val, len(removed), bool(removed and apply_now))
            self._send(200, {"unbanned": removed, "count": len(removed),
                             "applied": bool(removed and apply_now)})

        else:
            self._send(404, {"error": "not found", "endpoints": [
                "/list", "/stats", "/unban?ip=<ip|cidr>[&now=0]"]})

    # Allow POST as an alias so mutating calls can use POST if preferred.
    do_POST = do_GET


def start_admin():
    """Start the loopback-only admin HTTP server in a daemon thread."""
    if not ADMIN_ENABLED:
        return
    try:
        srv = http.server.ThreadingHTTPServer((ADMIN_HOST, ADMIN_PORT), _AdminHandler)
    except OSError as e:
        log.error("Admin HTTP bind failed on %s:%s: %s", ADMIN_HOST, ADMIN_PORT, e)
        return
    log.info("Admin HTTP on http://%s:%s (loopback only)", ADMIN_HOST, ADMIN_PORT)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

# ---------------------------------------------------------------------------
# CONNECTION HANDLING
# ---------------------------------------------------------------------------

def handle_client(conn, addr, port):
    """Greet the connection like SSH, grab its banner, then record the ban."""
    ip = addr[0]
    client_data = b""
    try:
        conn.settimeout(5)
        try:
            conn.sendall(SSH_BANNER + b"\r\n")   # look like a real SSH daemon
            client_data = conn.recv(1024)        # capture client's first bytes
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

    if is_whitelisted(ip):
        log.info("Whitelisted %s:%s — ignored.", ip, port)
        return

    already = record_ban(ip)
    payload = client_data.decode("latin-1", "replace").strip()
    log.info("HIT %s (port %s) %s client=%r", ip, port,
             "(known)" if already else "-> queued ban", payload[:200])


def serve(port):
    """Bind a port and dispatch each inbound connection to a handler thread."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
    except OSError as e:
        log.error("Cannot bind port %s: %s "
                  "(another service may own it — e.g. OpenSSH on 22).", port, e)
        return
    s.listen(128)
    log.info("Listening on 0.0.0.0:%s (fake SSH).", port)
    while not _stop.is_set():
        try:
            conn, addr = s.accept()
        except OSError:
            break
        threading.Thread(
            target=handle_client, args=(conn, addr, port), daemon=True
        ).start()

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    if os.name != "nt":
        log.error("This honeypot targets Windows (uses the Windows Firewall).")
        sys.exit(1)

    ensure_admin()          # firewall changes require elevation
    load_banned()
    # Optional one-time rebuild of the rule(s) from the persisted set on start.
    if SYNC_ON_START:
        sync_firewall(_aggregate(_banned.keys()))

    cap = MAX_BANNED if MAX_BANNED > 0 else "unlimited"
    log.info("Honeypot starting — ports=%s, cap=%s, flush=%ss, outbound=%s, "
             "aggregate=%s, refresh_on_hit=%s, admin=%s, ipthreat=%s, telegram=%s",
             PORTS, cap, FLUSH_INTERVAL, BLOCK_OUTBOUND, AGGREGATE, REFRESH_ON_HIT,
             f"{ADMIN_HOST}:{ADMIN_PORT}" if ADMIN_ENABLED else "off",
             "on" if (IPTHREAT_ENABLED and IPTHREAT_KEY) else "off",
             "on" if (TELEGRAM_TOKEN and TELEGRAM_CHAT_ID) else "off")
    if IPTHREAT_ENABLED and IPTHREAT_KEY:
        # Masked fingerprint: confirms the key reached Python intact (no shell mangling).
        log.info("IPThreat key loaded: length=%d, starts=%s..., ends=...%s",
                 len(IPTHREAT_KEY), IPTHREAT_KEY[:4], IPTHREAT_KEY[-4:])

    threading.Thread(target=flush_loop, daemon=True).start()
    start_admin()

    threads = []
    for port in PORTS:
        t = threading.Thread(target=serve, args=(port,), daemon=True)
        t.start()
        threads.append(t)

    try:
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=1)
    except KeyboardInterrupt:
        log.info("Shutting down — flushing only pending bans (no full rewrite).")
    finally:
        _stop.set()
        flush()   # writes ONLY if there are unflushed bans; no-op otherwise


if __name__ == "__main__":
    main()
