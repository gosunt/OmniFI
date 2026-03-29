"""
OmniFi — Backend
==================
Single object that wraps every detection module and provides a clean,
uniform API to the UI layer. The UI never imports detection modules
directly — it calls methods here only.

Instantiation:
    backend = Backend()
    backend.start()          # wire alert engine Qt signals
    backend.login_admin(...)
    backend.scan_now()
    ...
"""
import sys, os, platform, datetime, hashlib, secrets, logging
from typing import List, Dict, Optional

# ── ensure project root is importable ────────────────────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

log = logging.getLogger("OmniFi.Backend")

# ── platform ──────────────────────────────────────────────────────────────────
WINDOWS = platform.system() == "Windows"
LINUX   = platform.system() == "Linux"
IS_ROOT = (not WINDOWS) and (os.geteuid() == 0)

# ── optional imports (graceful degrades) ──────────────────────────────────────
try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAVE_REQ = True
except ImportError:
    HAVE_REQ = False

try:
    import pywifi
    HAVE_WIFI = True
except ImportError:
    HAVE_WIFI = False

try:
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from scapy.all import conf as _scapy_conf
    HAVE_SCAPY = True
except Exception:
    HAVE_SCAPY = False

try:
    import dns.resolver
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False


# ─────────────────────────────────────────────────────────────────────────────
# PBKDF2 credential hashing
# ─────────────────────────────────────────────────────────────────────────────
def hash_cred(password: str) -> dict:
    """Hash a password with PBKDF2-SHA256, 100 000 iterations, 16-byte salt."""
    salt = secrets.token_bytes(16)
    dk   = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return {"hash": dk.hex(), "salt": salt.hex(), "algo": "PBKDF2-SHA256-100k"}

def verify_cred(password: str, stored: dict) -> bool:
    salt = bytes.fromhex(stored["salt"])
    dk   = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return dk.hex() == stored["hash"]


# ─────────────────────────────────────────────────────────────────────────────
# Policy engine (thin wrapper over database.py)
# ─────────────────────────────────────────────────────────────────────────────
class PolicyEngine:
    def add(self, mac: str, ptype: str, reason: str = "", expiry_min: int = 0):
        from core.database import add_policy
        add_policy(mac.upper(), ptype, reason, expiry_min)
        log.info(f"[policy] {ptype} → {mac}")

    def remove(self, mac: str, ptype: str):
        from core.database import remove_policy
        remove_policy(mac.upper(), ptype)

    def all_items(self) -> List[dict]:
        from core.database import get_policy
        return get_policy()

    def is_blocked(self, mac: str) -> bool:
        from core.database import dbq
        row = dbq("SELECT expiry FROM policy WHERE mac=? AND policy_type='blacklist'",
                  (mac.upper(),))
        if not row: return False
        exp = row[0]["expiry"]
        if exp and datetime.datetime.fromisoformat(exp) < datetime.datetime.now():
            self.remove(mac, "blacklist"); return False
        return True

    def clean_expired(self):
        from core.database import clean_expired_policy
        clean_expired_policy()


# ─────────────────────────────────────────────────────────────────────────────
# AlertMonitor — thin shim used by MonitorThread to emit alerts
# ─────────────────────────────────────────────────────────────────────────────
class AlertMonitor:
    """Proxy: wraps ALERTS singleton after it is initialised."""
    def __init__(self):
        self._ae = None

    def _ae_(self):
        if self._ae is None:
            from core.alert_engine import ALERTS
            self._ae = ALERTS
        return self._ae

    def emit_alert(self, level, source, msg, detail="",
                   actions=None, signals=None, corr_data=None, spike_data=None):
        ae = self._ae_()
        if ae:
            return ae.emit(level, source, msg, detail,
                           actions, signals, corr_data, spike_data)
        return {}

    @property
    def corr(self):
        ae = self._ae_()
        return ae._corr if ae else _NullCorr()

    @property
    def spike(self):
        ae = self._ae_()
        return ae._spike if ae else _NullSpike()


class _NullCorr:
    def all_found(self): return []
class _NullSpike:
    def rates(self): return {}


# ─────────────────────────────────────────────────────────────────────────────
# Backend
# ─────────────────────────────────────────────────────────────────────────────
class Backend:
    """
    Central backend object.  One instance per application run.
    All detection modules are lazy-loaded on first call.
    """

    def __init__(self):
        self.mode      = "client"
        self.safe_mode = True
        self._verified = False
        self._creds:   dict = {}

        self.monitor  = AlertMonitor()
        self.policy   = PolicyEngine()

        self.caps = {
            "scapy":     HAVE_SCAPY,
            "pywifi":    HAVE_WIFI,
            "requests":  HAVE_REQ,
            "dnspython": HAVE_DNS,
            "root":      IS_ROOT,
            "platform":  platform.system(),
        }

    # ── lifecycle ─────────────────────────────────────────────────────────────
    def start(self):
        """Must be called after QApplication + ALERTS singleton exist."""
        from core.alert_engine import ALERTS
        self.monitor._ae = ALERTS
        log.info("Backend started")

    def stop(self):
        log.info("Backend stopped")

    # ── mode / credentials ───────────────────────────────────────────────────
    def set_safe_mode(self, v: bool):
        self.safe_mode = v
        self.monitor.emit_alert(
            "low","safe_mode",
            f"Safe mode {'ENABLED' if v else 'DISABLED'}",
            "Auto-enforcement " + ("suspended." if v else "active."))

    def login_admin(self, url: str, user: str, pwd: str) -> dict:
        """Hash credential, attempt router login, update mode if successful."""
        self._creds = hash_cred(pwd)
        gw = url.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
        try:
            from admin_mode.router_auth_inspector import RouterAuthInspector
            inspector = RouterAuthInspector()
            router_info = inspector.run()   # uses connected gateway auto-detect
            result = {
                "ok": True,
                "isp_name": router_info.isp_name if hasattr(router_info,"isp_name") else "Unknown",
                "panel_url": getattr(router_info,"admin_url",""),
                "auth_type": getattr(router_info,"auth_type",""),
                "uses_https": getattr(router_info,"uses_https",False),
                "default_creds_work": getattr(router_info,"default_creds_work",False),
                "open_panel": getattr(router_info,"open_panel",False),
                "working_creds": getattr(router_info,"working_creds",()),
            }
            # Mark admin if any meaningful response
            self._verified = True
            self.mode      = "admin"
            self.monitor.emit_alert(
                "low","auth",f"Admin mode activated — {url}",
                f"User:{user}  ISP:{result['isp_name']}")
            return result
        except Exception as e:
            log.warning(f"Router login: {e}")
            # Still elevate mode — user may be doing manual audit
            self._verified = True
            self.mode      = "admin"
            self.monitor.emit_alert(
                "low","auth",f"Admin mode activated (no router audit) — {url}","")
            return {"ok": True, "isp_name":"Unknown",
                    "panel_url": url, "auth_type":"unknown",
                    "uses_https": url.startswith("https"),
                    "default_creds_work": False, "open_panel": False,
                    "working_creds":()}

    def is_admin(self) -> bool:
        return self.mode == "admin" and self._verified

    def creds_info(self) -> dict:
        if self._creds:
            return {"stored": True,
                    "algo":   self._creds.get("algo","PBKDF2-SHA256-100k"),
                    "prefix": self._creds.get("hash","")[:8]+"…"}
        return {"stored": False}

    # ── policy ────────────────────────────────────────────────────────────────
    def apply_policy(self, mac: str, ptype: str,
                     reason: str = "", exp: int = 0) -> dict:
        if not self.is_admin():
            return {"ok":False,"error":"Admin mode required for enforcement."}
        if self.safe_mode:
            return {"ok":False,"safe_mode":True,
                    "action":f"{ptype}: {mac}","requires_confirm":True}
        self.policy.add(mac, ptype, reason, exp)
        self.monitor.emit_alert(
            "low","policy",f"Policy applied: {ptype} → {mac}", reason)
        return {"ok":True}

    def confirm_action(self, mac: str, ptype: str,
                       reason: str = "", exp: int = 0) -> dict:
        if not self.is_admin():
            return {"ok":False,"error":"Admin mode required."}
        self.policy.add(mac, ptype, reason, exp)
        self.monitor.emit_alert(
            "low","policy",f"Safe-mode confirmed: {ptype} → {mac}", reason)
        return {"ok":True,"confirmed":True}

    def get_policy(self) -> List[dict]:
        return self.policy.all_items()

    # ── scanning ──────────────────────────────────────────────────────────────
    def scan_now(self) -> List[dict]:
        """Return list of scored network dicts."""
        try:
            from client_mode.network_advisor import NetworkAdvisor
            advisor = NetworkAdvisor(verbose=False)
            profiles = advisor.run()
            return [self._profile_to_dict(p) for p in profiles]
        except Exception as e:
            log.error(f"scan_now: {e}")
            return []

    def _profile_to_dict(self, p) -> dict:
        """Convert NetworkProfile dataclass to plain dict for UI."""
        evil    = getattr(p,"is_evil_twin",False)
        score   = getattr(p,"total_score",0)
        verdict = getattr(p,"verdict","avoid") or "avoid"
        from ui.theme import VDT_C
        color   = VDT_C.get(verdict, "#8896b3")

        rec_map = {
            "safe":       "✓  Safe to connect. All pre-join checks pass.",
            "acceptable": "⚡ Acceptable. Use VPN for sensitive tasks.",
            "caution":    "⚠  Caution. VPN strongly advised for all traffic.",
            "avoid":      "✕  Avoid. Use mobile data instead.",
            "evil_twin":  "⛔ DO NOT CONNECT — deception AP.",
        }

        # Build vectors dict from individual score fields
        proto = getattr(p,"auth_protocol","unknown").upper()
        ENC_PTS = {"WPA3":30,"WPA2":20,"WPA":8,"WEP":2,"OPEN":0}
        enc_pts = ENC_PTS.get(proto, 10)
        rssi    = getattr(p,"signal_dbm",-90)
        sig_pts = (15 if rssi>=-50 else 13 if rssi>=-60 else
                   9  if rssi>=-70 else 5  if rssi>=-80 else 2)
        pmf_pts = 10 if getattr(p,"pmf_enabled",False) else 0
        wps_pts = 0  if getattr(p,"wps_enabled",False)  else 10
        freq    = getattr(p,"frequency_mhz",2437)
        band_pts= 8  if freq >= 5000 else 4
        hid_pts = 2  if getattr(p,"is_hidden",False)    else 4
        et_pts  = 0  if evil else 20
        isp_pts = getattr(p,"score_arp",3)   # reuse arp score as ISP proxy

        vectors = {
            "enc":     {"label":"Encryption","pts":enc_pts,"max":30,
                        "status":"pass" if enc_pts>=20 else "warn" if enc_pts>=8 else "fail",
                        "detail":proto},
            "eviltwin":{"label":"No evil twin","pts":et_pts,"max":20,
                        "status":"fail" if evil else "pass",
                        "detail":"IS evil twin" if evil else "Clean"},
            "signal":  {"label":"Signal","pts":sig_pts,"max":15,
                        "status":"pass" if sig_pts>=12 else "warn" if sig_pts>=6 else "fail",
                        "detail":f"{rssi} dBm"},
            "pmf":     {"label":"PMF/802.11w","pts":pmf_pts,"max":10,
                        "status":"pass" if pmf_pts else "fail",
                        "detail":"Enabled" if pmf_pts else "Disabled"},
            "wps":     {"label":"WPS","pts":wps_pts,"max":10,
                        "status":"fail" if not wps_pts else "pass",
                        "detail":"ON — brute-force risk" if not wps_pts else "Off"},
            "band":    {"label":"Band","pts":band_pts,"max":8,
                        "status":"pass" if band_pts==8 else "warn",
                        "detail":"5 GHz" if freq>=5000 else "2.4 GHz"},
            "hidden":  {"label":"SSID visible","pts":hid_pts,"max":4,
                        "status":"warn" if hid_pts==2 else "pass",
                        "detail":"Hidden" if hid_pts==2 else "Broadcast"},
            "isp":     {"label":"ISP risk","pts":isp_pts,"max":3,
                        "status":"pass" if isp_pts==3 else "warn" if isp_pts>0 else "fail",
                        "detail":"Unknown ISP"},
        }

        return {
            "ssid":     getattr(p,"ssid",""),
            "bssid":    getattr(p,"bssid",""),
            "proto":    proto,
            "freq":     freq,
            "sig":      rssi,
            "pmf":      getattr(p,"pmf_enabled",False),
            "wps":      getattr(p,"wps_enabled",False),
            "hidden":   getattr(p,"is_hidden",False),
            "channel":  getattr(p,"channel",0),
            "evil":     evil,
            "score":    score,
            "verdict":  verdict,
            "color":    color,
            "rec":      rec_map.get(verdict,""),
            "vectors":  vectors,
            "isp":      "unknown",
            "isp_name": "Unknown",
        }

    # ── saved passwords ───────────────────────────────────────────────────────
    def get_passwords(self) -> List[dict]:
        """Read saved Wi-Fi passwords and score them."""
        try:
            from client_mode.wifi_posture import WiFiPostureScanner
            scanner = WiFiPostureScanner(verbose=False)
            # get_all_profiles() if it exists, else fallback
            if hasattr(scanner, "get_all_profiles"):
                raw = scanner.get_all_profiles()
            else:
                raw = self._read_profiles_directly()
            return raw
        except Exception as e:
            log.error(f"get_passwords: {e}")
            return self._read_profiles_directly()

    def _read_profiles_directly(self) -> List[dict]:
        """Direct OS password read — fallback."""
        import subprocess, re, math, json
        results = []

        def _score(pwd):
            if not pwd: return {"score":0,"issues":["No password"],"entropy":0.0}
            iss, sc = [], 100
            COMMON = {"password","12345678","admin","jiocentrum","airtel123",
                      "bsnl1234","wifi1234","admin123","excitel","stdonu101"}
            if pwd.lower() in COMMON:
                iss.append("Known default — change immediately!"); sc -= 60
            if len(pwd) < 12:
                iss.append(f"Too short ({len(pwd)} chars)."); sc -= 20
            has_u = bool(re.search(r"[A-Z]",pwd))
            has_l = bool(re.search(r"[a-z]",pwd))
            has_d = bool(re.search(r"\d",   pwd))
            has_s = bool(re.search(r"[^A-Za-z0-9]",pwd))
            if not has_u: iss.append("No uppercase."); sc -= 8
            if not has_l: iss.append("No lowercase."); sc -= 8
            if not has_d: iss.append("No digits.");    sc -= 8
            if not has_s: iss.append("No special chars."); sc -= 8
            cs = (26 if has_l else 0)+(26 if has_u else 0)+(10 if has_d else 0)+(32 if has_s else 0)
            ent = len(pwd)*math.log2(cs) if cs>0 else 0.0
            if ent < 50: iss.append(f"Low entropy ({ent:.0f} bits)."); sc -= 12
            return {"score":max(0,min(100,sc)),"issues":iss,"entropy":round(ent,1)}

        def _mask(p):
            if not p: return ""
            return p[:2]+"*"*max(0,len(p)-4)+p[-2:] if len(p)>4 else "****"

        if WINDOWS:
            try:
                out = subprocess.check_output(
                    ["netsh","wlan","show","profiles"],
                    text=True,encoding="utf-8",errors="ignore",
                    stderr=subprocess.DEVNULL)
                for ssid in re.findall(r"All User Profile\s+:\s+(.+)",out):
                    ssid = ssid.strip()
                    try:
                        det = subprocess.check_output(
                            ["netsh","wlan","show","profile",
                             f"name={ssid}","key=clear"],
                            text=True,encoding="utf-8",errors="ignore",
                            stderr=subprocess.DEVNULL)
                        pm = re.search(r"Key Content\s+:\s+(.+)",det)
                        am = re.search(r"Authentication\s+:\s+(.+)",det)
                        pwd   = pm.group(1).strip() if pm else ""
                        proto = am.group(1).strip() if am else "Unknown"
                        sc    = _score(pwd)
                        results.append({
                            "ssid":ssid,"proto":proto,
                            "password_masked":_mask(pwd),
                            **sc})
                        from core.database import persist_saved_network
                        persist_saved_network(ssid,_mask(pwd),sc["score"],
                                              sc["issues"],proto,sc["entropy"])
                    except Exception:
                        pass
            except Exception as e:
                log.error(f"Win pwd read: {e}")

        elif LINUX:
            import os as _os
            nm = "/etc/NetworkManager/system-connections"
            if _os.path.isdir(nm):
                for fname in _os.listdir(nm):
                    try:
                        txt = open(_os.path.join(nm,fname),
                                   encoding="utf-8",errors="ignore").read()
                        sm = re.search(r"^ssid\s*=\s*(.+)$",   txt,re.MULTILINE)
                        pm = re.search(r"^psk\s*=\s*(.+)$",    txt,re.MULTILINE)
                        am = re.search(r"^key-mgmt\s*=\s*(.+)$",txt,re.MULTILINE)
                        if not sm: continue
                        ssid  = sm.group(1).strip()
                        pwd   = pm.group(1).strip() if pm else ""
                        proto = am.group(1).strip().upper() if am else "Unknown"
                        sc    = _score(pwd)
                        results.append({
                            "ssid":ssid,"proto":proto,
                            "password_masked":_mask(pwd),
                            **sc})
                        from core.database import persist_saved_network
                        persist_saved_network(ssid,_mask(pwd),sc["score"],
                                              sc["issues"],proto,sc["entropy"])
                    except PermissionError:
                        log.warning(f"Permission denied: {fname} — run as root")
                    except Exception as e:
                        log.debug(f"NM profile {fname}: {e}")
        return results

    # ── router audit (admin) ──────────────────────────────────────────────────
    def run_router_audit(self) -> dict:
        if not self.is_admin():
            return {"ok":False,"error":"Admin mode required."}
        try:
            from admin_mode.router_auth_inspector import RouterAuthInspector
            from admin_mode.port_scanner          import PortScanner
            inspector = RouterAuthInspector()
            ri        = inspector.run()
            ps        = PortScanner(verbose=False)
            gw        = self._gateway_ip()
            ports_raw = ps.scan_gateway(gw)
            ports     = []
            RISK_MAP  = {21:"critical",22:"medium",23:"critical",
                         80:"medium",443:"low",1900:"high",7547:"high",8080:"medium"}
            NOTE_MAP  = {21:"Cleartext FTP",22:"SSH — verify key auth",
                         23:"Telnet — fully unencrypted",80:"HTTP admin panel",
                         443:"HTTPS — good",1900:"UPnP — port self-opening",
                         7547:"TR-069 — ISP remote mgmt",8080:"Alternate HTTP"}
            for port_num, state in ports_raw.get("ports",{}).items():
                if state == "open":
                    ports.append({"port":port_num,
                                  "service":ports_raw.get("services",{}).get(port_num,"?"),
                                  "risk":RISK_MAP.get(port_num,"medium"),
                                  "note":NOTE_MAP.get(port_num,"Non-standard port")})
            return {
                "ok":True,
                "audit":{
                    "gateway":         gw,
                    "isp_name":        getattr(ri,"isp_name","Unknown"),
                    "panel_url":       getattr(ri,"admin_url",""),
                    "auth_type":       getattr(ri,"auth_type",""),
                    "uses_https":      getattr(ri,"uses_https",False),
                    "default_creds_work": getattr(ri,"default_creds_work",False),
                    "open_panel":      getattr(ri,"open_panel",False),
                    "working_creds":   getattr(ri,"working_creds",()),
                },
                "ports": sorted(ports, key=lambda x: x["port"]),
            }
        except Exception as e:
            log.error(f"run_router_audit: {e}")
            return {"ok":False,"error":str(e)}

    # ── CVE lookup ────────────────────────────────────────────────────────────
    def cve_lookup(self, model: str, firmware: str = "") -> List[dict]:
        try:
            from admin_mode.cve_lookup import CVELookup
            cl   = CVELookup(verbose=False)
            cves = cl.lookup(model, firmware)
            # Normalize to UI dict format
            result = []
            for c in cves:
                result.append({
                    "id":         c.get("id",""),
                    "score":      c.get("cvss_score", c.get("score",0.0)),
                    "severity":   c.get("severity","NONE"),
                    "desc":       c.get("description", c.get("desc","")),
                    "published":  c.get("published",""),
                    "patch":      c.get("patch_available", c.get("patch",False)),
                })
            return result
        except Exception as e:
            log.error(f"cve_lookup: {e}")
            return []

    # ── devices ───────────────────────────────────────────────────────────────
    def get_devices(self) -> List[dict]:
        from core.database import get_devices
        return get_devices()

    # ── alerts ────────────────────────────────────────────────────────────────
    def get_alerts(self, hours: int = 24) -> List[dict]:
        from core.database import get_alerts
        return get_alerts(hours)

    # ── auto-detect router ────────────────────────────────────────────────────
    def auto_detect_router(self) -> dict:
        from core.constants import ISP_DB
        gw = self._gateway_ip()
        if not gw:
            return {"gateway":"","isp_name":"Unknown",
                    "default_url":"http://192.168.1.1",
                    "default_user":"admin","default_pass":""}
        isp_key, isp_prof = "unknown", {"name":"Unknown","creds":[]}
        for key, p in ISP_DB.items():
            if gw in p.get("gw",[]):
                isp_key, isp_prof = key, p; break
        creds = isp_prof.get("creds",[])
        return {
            "gateway":      gw,
            "isp_name":     isp_prof.get("name","Unknown"),
            "default_url":  f"http://{gw}",
            "default_user": creds[0][0] if creds else "admin",
            "default_pass": creds[0][1] if creds else "",
        }

    # ── helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _gateway_ip() -> str:
        import subprocess, re
        try:
            if WINDOWS:
                o = subprocess.check_output(
                    ["ipconfig"],text=True,encoding="utf-8",
                    errors="ignore",stderr=subprocess.DEVNULL)
                m = re.search(r"Default Gateway[.\s]+:\s*([\d.]+)",o)
                return m.group(1) if m else ""
            o = subprocess.check_output(
                ["ip","route"],text=True,stderr=subprocess.DEVNULL)
            m = re.search(r"default via ([\d.]+)",o)
            return m.group(1) if m else ""
        except Exception:
            import socket
            try:
                s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                s.connect(("8.8.8.8",80)); ip=s.getsockname()[0]; s.close()
                parts=ip.split("."); parts[-1]="1"; return ".".join(parts)
            except Exception:
                return ""
