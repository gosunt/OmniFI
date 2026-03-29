# OmniFi v1 – Hybrid WiFi Analysis and Security Enforcement Toolkit
Hybrid WiFi Analysis and Security Enforcement Toolkit

 A **full-stack WiFi security platform** that integrates real-time monitoring, threat detection, behavioral intelligence, and network enforcement.

---

##  Overview

OmniFi is an advanced **Hybrid WiFi Security Enforcement Toolkit** designed to:

* Monitor wireless networks in real-time
* Detect multiple types of attacks
* Analyze device behavior
* Enforce security policies
* Provide an interactive dashboard

Unlike traditional tools, OmniFi combines:

✔ Client-side detection
✔ Router-side intelligence
✔ Behavioral analysis
✔ Automated enforcement

---

##  Core Capabilities

###  Advanced Threat Detection

* Evil Twin detection (SSID/BSSID tracking)
* Deauthentication attack detection
* DNS spoofing detection
* Rogue DHCP detection
* ICMP redirect detection
* ARP MITM detection
* Captive portal fingerprinting
* Beacon anomaly detection

---

###  Behavioral Intelligence

* Dynamic **trust scoring per device**
* Device baseline profiling
* MAC privacy & spoof detection
* Session hijack detection

---

###  Network Monitoring

* Real-time packet analysis (Scapy)
* Telemetry tracking
* Bandwidth monitoring
* Signal & posture analysis

---

### Security Enforcement (NAC System)

* Policy-based enforcement engine
* Device quarantine & blocking
* Network Access Control (NAC)
* Automated response system

---

### Router Intelligence (Admin Mode)

* Router authentication inspection
* Router sitemap mapping
* OpenWrt client integration
* CVE-based vulnerability insights
* Port scanning & device profiling

---

### Smart Advisor

* Suggests best network to connect
* Evaluates:

  * Signal strength
  * Security posture
  * Active threats

---

### Advanced GUI Dashboard

Built using PyQt with modular panels:

#### Panels:

* Dashboard
* Devices
* Threat Scan
* Network Advisor
* Router Management
* Policy & Enforcement
* Eavesdropping Monitor

#### Widgets:

* Trust Graph
* Network Map
* Bandwidth Meter
* Timeline View
* Score Ring

---

## Architecture

```text
Client Monitoring → Detection Engine → Telemetry → Trust Engine → Policy Engine 
→ NAC Enforcement → Router Intelligence → GUI Dashboard
```

---

## Project Structure (Actual)

```text
OmniFi_v1/
│
├── core/              # Core engines (NAC, trust, policy, telemetry)
├── client_mode/       # Attack detection modules
├── admin_mode/        # Router intelligence & device profiling
├── ui/                # Full PyQt GUI (panels + widgets)
├── db/                # Database layer
├── reports/           # Report generation
├── config/            # Configurations
│
├── main.py
├── backend.py
└── requirements.txt
```

---

##  Technologies Used

*  Python
*  Scapy (packet analysis)
*  PyQt5 (GUI framework)
*  SQLite (database)
*  Networking libraries

---

##  Installation

```bash
git clone https://github.com/gosunt/OmniFi.git
cd OmniFi
pip3 install -r requirements.txt
```

---

##  Run

```bash
python3 main.py
```

---

##  Modes of Operation

###  Client Mode

* Passive monitoring
* Threat detection
* Alerts & recommendations

###  Admin Mode

* Router intelligence
* Device control
* Policy enforcement
* NAC system

---

##  Key Highlights

✔ Multi-layer attack detection
✔ Real-time monitoring system
✔ Behavioral trust scoring
✔ NAC-based enforcement
✔ Router integration
✔ Modular GUI dashboard

---

##  Limitations

* Router automation varies by vendor
* MAC spoof detection is heuristic
* Requires monitor mode for full capability

---

##  Future Enhancements

* Machine learning-based anomaly detection
* Full router automation (multi-ISP)
* Deep packet inspection
* Cloud-based monitoring

---

##  Author

**Gowtham Sunkara**

Cybersecurity & Network Security Developer

---

##  Final Note

OmniFi is not just a tool — it is a **hybrid WiFi defense platform** combining:

✔ Detection
✔ Intelligence
✔ Enforcement
