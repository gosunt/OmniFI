"""
OmniFi — Entry Point
=====================
Run:    python main.py
Win:    Run as Administrator for full ARP / Scapy features
Linux:  sudo python main.py

pip install -r requirements.txt
Windows: also install Npcap from https://npcap.com
"""
import sys, os, platform, logging, warnings

warnings.filterwarnings("ignore", message=".*TripleDES.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module=".*scapy.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module=".*cryptography.*")
try:
    from cryptography.utils import CryptographyDeprecationWarning as _CDW
    warnings.filterwarnings("ignore", category=_CDW)
except Exception:
    pass

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)-22s] %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(ROOT,"logs","omnifi.log"),encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("OmniFi.Main")
WINDOWS = platform.system() == "Windows"
LINUX   = platform.system() == "Linux"


def main():
    from PyQt6.QtWidgets import QApplication, QMessageBox
    from PyQt6.QtGui     import QFont
    from ui.theme        import APP_QSS

    app = QApplication(sys.argv)
    app.setApplicationName("OmniFi")
    app.setApplicationVersion("1.0")
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI",10) if WINDOWS else QFont("Ubuntu",10))
    app.setStyleSheet(APP_QSS)

    if LINUX and os.geteuid() != 0:
        msg = QMessageBox()
        msg.setWindowTitle("OmniFi — Limited mode")
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setText(
            "OmniFi is running without root privileges.\n\n"
            "Features unavailable without root:\n"
            "  • ARP / Scapy packet capture\n"
            "  • Wi-Fi password reading (NetworkManager)\n"
            "  • Deauth, beacon, DHCP, session hijack detection\n\n"
            "Restart with:    sudo python main.py\n\n"
            "Continue in limited mode?")
        msg.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if msg.exec() == QMessageBox.StandardButton.No:
            sys.exit(0)

    from core.backend      import Backend
    from core.alert_engine import init_alerts
    backend = Backend()
    ae = init_alerts()
    backend.init_alert_engine(ae)

    log.info(f"OmniFi starting — {platform.system()} "
             f"scapy:{backend.caps['scapy']} pywifi:{backend.caps['pywifi']} "
             f"root:{backend.caps['root']}")

    from ui.main_window import MainWindow
    window = MainWindow(backend)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
