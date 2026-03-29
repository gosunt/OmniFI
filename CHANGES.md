# OmniFi — v2.0 Changes & Feature Additions

## New Modules

### `client_mode/rogue_ap.py`  ← NEW
Full rogue access point detector. Runs on every scan:
- **OUI vendor mismatch** — e.g. a "JioFiber" SSID served by a TP-Link OUI
- **BSSID history cross-check** — alerts if a known SSID appears with a BSSID never recorded before (SQLite)
- **Signal spike detection** — one AP is significantly stronger than others on same SSID → evil twin proximity alert
- **Duplicate SSID / multiple BSSID** — multiple APs with identical SSID visible simultaneously
- Integrated into `MonitorThread` on a 240-second poll cycle (adaptive)

### `client_mode/eavesdrop_monitor.py`  ← NEW
Unified continuous eavesdropping and MITM monitor:
- **ARP cache poisoning** — polls OS ARP table; alerts when any IP's MAC changes (gateway change = critical)
- **Gratuitous ARP flood** — counts GARPs per MAC per 5-second window; alerts on aggressive re-poisoning
- **Cleartext credential detection** — Scapy packet sniffer on ports 80/8080/21/23 watches for password= patterns in HTTP payloads
- **SSL strip detection** — flags HTTP Location redirects away from HTTPS
- **Default gateway change** — route table watcher detects rogue DHCP / ICMP redirect aftermath
- Falls back gracefully without Scapy (ARP table polling still works without root)

### `core/nac_engine.py`  ← NEW
Full Network Access Control with quarantine-first onboarding:
- Every new device MAC (not seen before) is **automatically quarantined** by pushing to router VLAN via `openwrt_client` or `router_sitemap`
- Persists device history in `db/nac.db` (SQLite): state = quarantine / approved / blocked
- Admin can **Approve** (releases quarantine, whitelist) or **Block** (blacklist) from the NAC Panel
- Non-admin mode: tracks new devices and alerts user but skips router-level VLAN push
- Background thread polls ARP table every 15 seconds

### `core/bandwidth_worker.py`  ← NEW
QThread bridge between TelemetryEngine and BandwidthMeterWidget:
- Emits `stats_ready(dict)` every 2 seconds with per-device `rx_bps / tx_bps`
- Falls back to `psutil.net_io_counters()` if TelemetryEngine not yet wired (pre-login)
- Skips virtual/loopback adapters automatically

### `ui/widgets/bandwidth_meter.py`  ← NEW
Live per-device bandwidth display widget:
- Animated TX/RX bars (green / blue gradient) that scale proportionally to peak device speed
- Aggregate total `↑ TX  ↓ RX` in header
- Per-device: IP, hostname, signal dBm, individual bars and numeric speeds
- Auto-refreshes every 2 seconds from `BandwidthWorker`
- **Injected into Dashboard via `dashboard_patch.py`** as a new "📊 Bandwidth" tab

### `ui/widgets/password_strength_widget.py`  ← NEW
Per-SSID saved-password strength display for the scanner:
- Shows every scanned network that has a saved password
- Colour-coded badges: Critical / Weak / Fair / Strong / Excellent
- Entropy value (bits) per password
- Policy violations listed inline (too short, no symbols, dictionary word, etc.)
- Admin-only "🔑 Change Password" button (opens router wireless page)
- **Injected into Dashboard** as "🔐 Passwords" tab; updates on every scan

### `ui/panels/nac_panel.py`  ← NEW
Full UI for NAC Engine:
- "⚠ Quarantined" tab — devices awaiting admin decision
- "📋 All Devices" tab — full history with colour-coded states
- One-click **Approve** / **Block** with router-level enforcement
- Auto-refreshes every 10 seconds
- Accessible from sidebar nav (🔒 icon, index 12)

### `ui/panels/eavesdrop_panel.py`  ← NEW
Live eavesdropping monitor panel:
- Start / Stop toggle button
- Scrolling event feed with severity colours (Critical / High / Medium / Low)
- **Role-aware advice** — Admin advice vs Client advice per event type
- Accessible from sidebar nav (👁 icon, index 13)

### `ui/panels/dashboard_patch.py`  ← NEW
Non-destructive patch that injects new tabs into existing DashboardPanel:
- Called once from `MainWindow.__init__()` after `_build_ui()`
- Finds the existing QTabWidget and appends "📊 Bandwidth" and "🔐 Passwords" tabs
- Falls back gracefully if dashboard has no QTabWidget

---

## Existing Module Improvements

### `ui/main_window.py`
- Added `rogue_ap` (240s) to `MonitorThread.BASE_POLL` — rogue AP scan runs automatically
- Added `_do_rogue_ap()` method to MonitorThread
- Added NAC engine wiring on admin login: auto-starts `NACEngine`, connects to `NACPanel`
- Added "rogue_ap", "eavesdrop", "nac" to `_MOD_MAP` for alert routing
- Added sidebar nav buttons for NAC (🔒) and Eavesdrop Monitor (👁)
- New panels added to `QStackedWidget`: `ThreatScanPanel`, `NACPanel`, `EavesdropPanel`
- `patch_dashboard()` called in `__init__()` to inject bandwidth + password tabs
- Scanner `nets_ready` signal wired to dashboard password-strength widget

### `client_mode/__init__.py`
- Exports: `NACPanel`, `EavesdropPanel` (via `ui/panels/__init__.py`)

### `ui/widgets/__init__.py`
- Exports: `BandwidthMeterWidget`, `BandwidthCalculator`, `PasswordStrengthWidget`

---

## Feature Coverage Matrix (Final)

| # | Feature                              | Status       | Module(s)                              |
|---|--------------------------------------|--------------|----------------------------------------|
| 1 | Saved WiFi password strength checker | ✅ Complete   | `wifi_posture.py` + `password_strength_widget.py` |
| 2 | WPS / WEP / open misconfiguration    | ✅ Complete   | `wifi_posture.py`                      |
| 3 | Security protocol audit              | ✅ Complete   | `wifi_posture.py`, `network_advisor.py` |
| 4 | Eavesdropping alerts                 | ✅ Complete   | `eavesdrop_monitor.py` + `eavesdrop_panel.py` |
| 5 | MAC blacklist/whitelist              | ✅ Complete   | `enforcer.py`, `router_sitemap.py`     |
| 6 | MAC spoofing / legitimacy check      | ✅ Complete   | `mac_privacy.py`, `oui_lookup.py`      |
| 7 | DNS spoofing detection               | ✅ Complete   | `dns_spoof.py`                         |
| 8 | Enforce encrypted communication      | ✅ Complete   | `doh_resolver.py`, `vpn_launcher.py`  |
| 9 | Number of connected devices          | ✅ Complete   | `monitor_utils.py`, `devices_panel.py` |
|10 | Bandwidth + signal strength          | ✅ Complete   | `bandwidth_worker.py` + `bandwidth_meter.py` |
|11 | Best network recommendation          | ✅ Complete   | `network_advisor.py` (8-vector score) |
|12 | Rogue AP detection                   | ✅ Complete   | `rogue_ap.py`                          |
|13 | Evil twin detection                  | ✅ Complete   | `network_advisor.py`, `rogue_ap.py`   |
|14 | Admin block spoofed devices          | ✅ Complete   | `enforcer.py`, `nac_engine.py`         |
|15 | Push alerts (spoofing/rogue/misconfig)| ✅ Complete  | `monitor_utils.py` (plyer desktop)    |
|16 | Initial quarantine → promote         | ✅ Complete   | `nac_engine.py`, `nac_panel.py`        |
|17 | Captive portal fingerprinting        | ✅ Complete   | `captive_portal.py`                    |
|18 | SSID/BSSID history tracking          | ✅ Complete   | `bssid_history.py`, `ssid_history.py` |
|19 | Beacon interval anomaly              | ✅ Complete   | `beacon_anomaly.py`                    |
|20 | DHCP rogue server detection          | ✅ Complete   | `dhcp_rogue.py`                        |
|21 | ICMP redirect attack detection       | ✅ Complete   | `icmp_redirect.py`                     |

---

## Run Instructions

```bash
# Linux (recommended — full features)
sudo python main.py

# Windows (install Npcap from npcap.com first)
python main.py    # Run as Administrator for Scapy features

# Install deps
pip install -r requirements.txt
```
