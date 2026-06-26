# Windows SSH Honeypot

![License](https://img.shields.io/badge/license-GPL--3.0-blue)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6)
![Python](https://img.shields.io/badge/python-3.8%2B-3776AB)

A single-file Windows honeypot that exposes a port (default **22**) impersonating an SSH
service. Every connecting IP is banned into a **single Windows Firewall rule per direction**,
with **debounced** updates, a **bounded FIFO cap** to keep the rule small, optional reporting
to **[IPThreat.net](https://ipthreat.net)** and **Telegram**, and a **loopback admin API**
for unbanning at runtime.

Any connection to the honeypot port is by definition unsolicited (no real service runs there),
so each source is treated as a port-scan / brute-force attempt and blocked system-wide.

## Features

- Fake SSH banner on one or more ports.
- Permanent, system-wide ban via Windows Firewall (inbound + optional outbound), surviving reboots.
- **Single rule per direction**, fed from a file via PowerShell — no per-IP rule explosion and no command-line length limits.
- **Debounced** firewall updates: bursts of scanner hits collapse into one rewrite per interval.
- **Bounded FIFO cap**: once the cap is reached, the oldest-inserted IP is evicted (unbanned) to admit the new one, keeping the rule within a safe size.
- **CIDR aggregation**: contiguous addresses collapse into ranges to shrink the rule further.
- **IPThreat.net reporting** of newly banned IPs (cause: `BruteForce,PortScan`).
- **Telegram** batch alerts (new bans + evictions per flush).
- **Local admin HTTP API** (127.0.0.1 only) to list/unban, plus a prompt-based `unban.bat`.
- Standard library only — no third-party Python packages.

## How it works

1. Listens on the configured port(s) and sends a believable `SSH-2.0-OpenSSH_...` banner.
2. Each connection records the source IP in memory (FIFO cap applied) and marks state dirty.
3. A background timer flushes at most once per `HP_FLUSH` seconds: it rewrites the rule(s) from
   the current set, reports new IPs to IPThreat, and sends one batched Telegram summary.
4. `banned_ips.json` (ordered) is the source of truth; the rule is rebuilt from it on start.

The single rule is maintained by writing all addresses to `banned_ips.txt` and pushing them in
via PowerShell (`Set-NetFirewallRule -RemoteAddress (Get-Content ...)`), which avoids the
command-line length limit. An empty list removes the rule (an empty `RemoteAddress` would
otherwise mean "Any" and block everything).

## Requirements

- Windows 10/11 or Windows Server.
- Python 3.8+.
- **Administrator privileges** (firewall changes). The script auto-elevates via UAC if needed —
  but launching from an Administrator console keeps logs in your window and avoids a relaunch.
- No third-party packages (Python stdlib + built-in PowerShell only).

## Quick start

```cmd
python honeypot.py
```

Or copy `run-honeypot.example.cmd` to `run-honeypot.cmd`, fill in your values, and run it from
an Administrator console. `run-honeypot.cmd` is git-ignored so your API key is never committed.

If port 22 fails to bind, another service owns it (disable the Windows **OpenSSH Server**
service or pick another port via `HP_PORTS`).

## Configuration

All parameters are environment variables (defaults shown):

| Variable             | Default                                   | Meaning                                            |
|----------------------|-------------------------------------------|----------------------------------------------------|
| `HP_PORTS`           | `22`                                      | Comma-separated ports to expose                    |
| `HP_BANNER`          | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4` | Fake SSH banner                                    |
| `HP_BLOCK_OUT`       | `1`                                       | Also block outbound (`0` = inbound-only)           |
| `HP_AGGREGATE`       | `1`                                       | Collapse IPs into CIDR ranges                      |
| `HP_MAX`             | `2000`                                    | Max tracked IPs; `0` = unlimited. FIFO eviction    |
| `HP_FLUSH`           | `5`                                       | Debounce interval in seconds                       |
| `HP_REFRESH_ON_HIT`  | `0`                                       | `1` = re-hit moves IP to newest slot (anti-evict)  |
| `HP_SYNC_ON_START`   | `1`                                       | Rebuild rule from saved set at boot (`0` to skip)  |
| `HP_ADMIN`           | `1`                                       | Enable local admin HTTP endpoint                   |
| `HP_ADMIN_PORT`      | `65432`                                   | Admin port (bound to 127.0.0.1 only)               |
| `HP_IPTHREAT_KEY`    | *(empty)*                                 | IPThreat.net API key (enables reporting if set)    |
| `HP_IPTHREAT`        | auto                                      | Force-enable/disable IPThreat reporting            |
| `HP_IPTHREAT_FLAGS`  | `BruteForce,PortScan`                     | IPThreat flags (names CSV or bitwise-OR int)       |
| `HP_IPTHREAT_SYSTEM` | `SSH`                                     | Attacked-system label (≤32 chars)                  |
| `HP_IPTHREAT_NOTES`  | *(generic)*                               | Report note (no PII/usernames/timestamps)          |
| `HP_TG_TOKEN`        | *(empty)*                                 | Telegram bot token                                 |
| `HP_TG_CHAT`         | *(empty)*                                 | Telegram chat ID                                   |

The `WHITELIST` list (CIDR allowed, edited in the source) protects IPs from being banned.
Loopback is always whitelisted. **Add your own admin/LAN IPs to avoid locking yourself out.**

### Debounce and the FIFO cap

Hits accumulate in memory and the firewall is rebuilt at most once per `HP_FLUSH` seconds, so a
new ban becomes active up to that many seconds after the hit. `HP_MAX` bounds the number of
tracked IPs (and therefore rule entries, since aggregation only shrinks). When full, the
oldest-inserted IP is evicted — i.e. **unbanned** — to keep the rule within a safe size. Set
`HP_REFRESH_ON_HIT=1` so actively scanning IPs are not evicted before idle ones.

### Large-rule safety

- **Command line** length limit → avoided by feeding IPs from a file.
- **Per-connection cost** (each address is a firewall filter) → bounded by `HP_MAX` and reduced by aggregation.
- **Update cost** is O(n) plus one PowerShell process per update → amortized by the debounce.
- **Registry/rule bloat** → bounded by the FIFO cap. No cleanly documented hard cap exists; the cap keeps you well inside the safe zone.

Shutdown rewrites the rule only if bans were recorded since the last flush; when idle, the
firewall is left untouched (no full rewrite of a large rule).

## IPThreat.net reporting

When `HP_IPTHREAT_KEY` is set, each newly banned IP is submitted to IPThreat
(`POST https://api.ipthreat.net/api/report`, `X-API-KEY` header) with the configured cause.
Only genuinely new, non-aggregated IPs are reported, off the connection hot path. Requires
reporting permissions on your IPThreat account.

```powershell
$env:HP_IPTHREAT_KEY = 'your-api-key'
python honeypot.py
```

```cmd
set "HP_IPTHREAT_KEY=your-api-key"
python honeypot.py
```

The key is read from the environment only and is never stored in the source. A successful batch
logs `IPThreat: reported N/M new IP(s).`; failures log the HTTP status.

Verify the API quickly:

```powershell
$body = @{ ip='1.2.3.4'; flags='BruteForce,PortScan'; system='SSH'; notes='test'; ts=(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); count=1 } | ConvertTo-Json
try {
  Invoke-RestMethod -Method POST -Uri 'https://api.ipthreat.net/api/report' `
    -Headers @{ 'Accept'='application/json'; 'X-API-KEY'=$env:HP_IPTHREAT_KEY } `
    -ContentType 'application/json' -Body $body
} catch { "STATUS: $($_.Exception.Response.StatusCode.value__)"; $_.ErrorDetails.Message }
```

`2xx` = success; `401/403` = bad key or missing reporting permission; `400` = payload/flags.

## Telegram reporting

Set `HP_TG_TOKEN` and `HP_TG_CHAT` to receive one batched alert per flush, summarizing new bans
and cap evictions. Create a bot via [@BotFather](https://t.me/BotFather) and get your chat ID
from [@userinfobot](https://t.me/userinfobot).

## Local admin endpoint (unban)

Bound to **127.0.0.1:65432** only (loopback; no auth needed because only local processes can
connect). JSON API:

| Method   | Endpoint                          | Description                                  |
|----------|-----------------------------------|----------------------------------------------|
| GET/POST | `/list`                           | `{count, ips}` of currently banned IPs       |
| GET/POST | `/stats`                          | Runtime config and counters                  |
| GET/POST | `/unban?ip=<ip\|cidr>[&now=0]`    | Unban an IP, or all banned IPs within a CIDR |

`now=0` defers the rule rewrite to the next debounce flush; default applies immediately.

```cmd
curl http://127.0.0.1:65432/list
curl http://127.0.0.1:65432/stats
curl "http://127.0.0.1:65432/unban?ip=1.2.3.4"
curl "http://127.0.0.1:65432/unban?ip=185.220.101.0/24"
```

`unban.bat` provides an interactive prompt that calls this endpoint in a loop.

## Inspecting / removing bans manually

```powershell
Get-NetFirewallRule -DisplayName "HONEYPOT_BAN_*"
(Get-NetFirewallRule -DisplayName "HONEYPOT_BAN_IN" | Get-NetFirewallAddressFilter).RemoteAddress
Get-NetFirewallRule -DisplayName "HONEYPOT_BAN_*" | Remove-NetFirewallRule   # remove all
```

Then clear `banned_ips.json` / `banned_ips.txt`. To unban a single IP, remove it from
`banned_ips.json` and restart, or use the admin endpoint while running.

## Run on boot

Use Task Scheduler: trigger *At startup*, action `python C:\path\honeypot.py` (or your
`run-honeypot.cmd`), and check **Run with highest privileges**.

## Files

| File                         | Purpose                                            |
|------------------------------|----------------------------------------------------|
| `honeypot.py`                | The honeypot service                               |
| `unban.bat`                  | Interactive unban prompt (calls the admin API)     |
| `run-honeypot.example.cmd`   | Example launcher; copy to `run-honeypot.cmd`       |
| `LICENSE`                    | GPL-3.0 license text                               |
| `.gitignore`                 | Ignores runtime state, logs, and secrets           |

## Security notes

A honeypot on a real network attracts traffic and bans aggressively. A wrong whitelist can block
legitimate access (including your own). Never commit your IPThreat API key or any secret. Use
only on systems you own or administer.

## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. See the
[LICENSE](LICENSE) file or <https://www.gnu.org/licenses/gpl-3.0.html> for the full text.

## Author

[https://github.com/Leproide](https://github.com/Leproide)
