import sys
import subprocess
import re
import json
import os
import platform # İşletim sistemi kontrolü eklendi
import locale # Sistem dilini tespit etmek için eklendi
import ctypes # Windows temasını tespit etmek için eklendi

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QGridLayout, QScrollArea, QFrame, QSizePolicy, QMessageBox, QInputDialog,
    QProgressBar, QGroupBox, QLineEdit, QCheckBox, QFileDialog, QTabWidget,
    QComboBox # Dil seçimi için eklendi
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, pyqtSlot, QTimer
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor

# --- DNS Sağlayıcıları Verisi ---
# Uygulamada gösterilecek DNS sağlayıcıları listesi
DNS_PROVIDERS = [
    {
        "name": "Google DNS",
        "ipv4": ["8.8.8.8", "8.8.4.4"],
        "ipv6": ["2001:4860:4860::8888", "2001:4860:4860::8844"],
        "doh_url": None,
        "dot_url": None,
        "ad_blocking": False,
        "dnssec_enabled": True
    },
    {
        "name": "Cloudflare DNS",
        "ipv4": ["1.1.1.1", "1.0.0.1"],
        "ipv6": ["2606:4700:4700::1111", "2606:4700:4700::1001"],
        "doh_url": "https://cloudflare-dns.com/dns-query",
        "dot_url": "tls://1.1.1.1",
        "ad_blocking": False,
        "dnssec_enabled": True
    },
    {
        "name": "AdGuard DNS (Varsayılan)",
        "ipv4": ["94.140.14.14", "94.140.15.15"],
        "ipv6": ["2a10:4a60::1414", "2a10:4a60::1515"],
        "doh_url": "https://dns.adguard.com/dns-query",
        "dot_url": "tls://dns.adguard.com",
        "ad_blocking": True,
        "dnssec_enabled": True
    },
    {
        "name": "AdGuard DNS (Aile)",
        "ipv4": ["94.140.14.15", "94.140.15.16"],
        "ipv6": ["2a10:4a60::1415", "2a10:4a60::1516"],
        "doh_url": "https://dns-family.adguard.com/dns-query",
        "dot_url": "tls://dns-family.adguard.com",
        "ad_blocking": True,
        "dnssec_enabled": True
    },
    {
        "name": "OpenDNS Home",
        "ipv4": ["208.67.222.222", "208.67.220.220"],
        "ipv6": None, # OpenDNS genel IPv6 sunmuyor
        "doh_url": None,
        "dot_url": None,
        "ad_blocking": False,
        "dnssec_enabled": False # DNSSEC desteklemiyor
    },
    {
        "name": "Quad9 (Filtresiz, DNSSEC)",
        "ipv4": ["9.9.9.9", "149.112.112.112"],
        "ipv6": ["2620:fe::fe", "2620:fe::9"],
        "doh_url": "https://dns.quad9.net/dns-query",
        "dot_url": "tls://dns.quad9.net",
        "ad_blocking": True, # Kötü amaçlı yazılım engelleme
        "dnssec_enabled": True
    },
    {
        "name": "Yandex DNS (Temel)",
        "ipv4": ["77.88.8.8", "77.88.8.1"],
        "ipv6": None, # Yandex DNS genel IPv6 sunmuyor
        "doh_url": None,
        "dot_url": None,
        "ad_blocking": False,
        "dnssec_enabled": False
    },
    {
        "name": "CleanBrowsing (Aile Filtresi)",
        "ipv4": ["185.228.168.168", "185.228.169.168"],
        "ipv6": ["2a0d:2a00:1::", "2a0d:2a00:2::"],
        "doh_url": "https://doh.cleanbrowsing.org/doh/family-filter/",
        "dot_url": None,
        "ad_blocking": True,
        "dnssec_enabled": True
    },
    {
        "name": "Comodo Secure DNS",
        "ipv4": ["8.26.56.26", "8.20.247.20"],
        "ipv6": None,
        "doh_url": None,
        "dot_url": None,
        "ad_blocking": True, # Kötü amaçlı yazılım/kimlik avı engelleme
        "dnssec_enabled": False
    },
    {
        "name": "Neustar DNS (Advantage)",
        "ipv4": ["156.154.70.1", "156.154.71.1"],
        "ipv6": None,
        "doh_url": None,
        "dot_url": None,
        "ad_blocking": True, # Kötü amaçlı yazılım/kimlik avı engelleme
        "dnssec_enabled": False
    },
    {
        "name": "DNS.Watch",
        "ipv4": ["84.200.69.80", "84.200.70.40"],
        "ipv6": ["2001:1608:10:25::1c04:b12f", "2001:1608:10:25::9249:d69b"],
        "doh_url": None,
        "dot_url": None,
        "ad_blocking": False,
        "dnssec_enabled": False
    },
    {
        "name": "Mullvad DNS (Reklam Engelleyici)",
        "ipv4": ["193.138.218.74", "193.138.218.75"],
        "ipv6": ["2001:67c:28a0::", "2001:67c:28a0::1"],
        "doh_url": "https://adblock.dns.mullvad.net/dns-query",
        "dot_url": None,
        "ad_blocking": True,
        "dnssec_enabled": False # Mullvad'ın DoH/DoT'si DNSSEC destekleyebilir, genel IPv4 için belirtilmedi
    },
    {
        "name": "Alternate DNS",
        "ipv4": ["76.76.19.19", "76.76.19.20"],
        "ipv6": None,
        "doh_url": None,
        "dot_url": None,
        "ad_blocking": True, # Kötü amaçlı yazılım/reklamlar
        "dnssec_enabled": False
    },
    {
        "name": "CyberGhost DNS",
        "ipv4": ["38.113.1.2", "198.18.0.2"], # Örnek placeholder IP'ler
        "ipv6": None,
        "doh_url": None,
        "dot_url": None,
        "ad_blocking": False,
        "dnssec_enabled": False
    },
    {
        "name": "ControlD (Özel URL ile)",
        "ipv4": None,
        "ipv6": None,
        "doh_url": "https://your-unique-id.controld.com/dns-query", # Kullanıcının kendi URL'sini girmesi gerekir
        "dot_url": None,
        "ad_blocking": True, # Özelleştirilebilir
        "dnssec_enabled": True # Genellikle özelleştirilebilir hizmetler DNSSEC destekler
    }
]

# --- Tema Stilleri ---
LIGHT_THEME_STYLES = """
    QWidget {
        font-family: 'Inter', sans-serif;
        background-color: #f8f9fa; /* Very light gray background */
        color: #212529; /* Dark text */
    }
    QPushButton {
        background-color: #007bff; /* Blue button */
        color: white;
        border: none;
        padding: 12px 25px;
        border-radius: 8px;
        font-size: 15px;
        font-weight: bold;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    QPushButton:hover {
        background-color: #0056b3; /* Darker blue on hover */
    }
    QPushButton:pressed {
        background-color: #004085; /* Even darker on press */
    }
    QPushButton:disabled {
        background-color: #e9ecef;
        color: #adb5bd;
        box-shadow: none;
    }
    QGroupBox {
        border: 1px solid #ced4da;
        border-radius: 10px;
        margin-top: 15px;
        padding: 15px;
        font-weight: bold;
        background-color: #ffffff;
        /* box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05); */ /* Removed to prevent console spam */
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        padding: 0 8px;
        background-color: #e9ecef;
        border-radius: 5px;
        color: #495057;
        font-size: 15px;
    }
    QLabel {
        font-size: 14px;
        color: #343a40;
    }
    QLabel#adminStatusLabel {
        font-weight: bold;
        padding: 5px;
        border-radius: 5px;
        color: white;
    }
    QLabel#adminStatusLabel[admin_status="true"] {
        background-color: #28a745; /* Green */
    }
    QLabel#adminStatusLabel[admin_status="false"] {
        background-color: #dc3545; /* Red */
    }
    QProgressBar {
        border: 1px solid #ced4da;
        border-radius: 5px;
        text-align: center;
        background-color: #e9ecef;
        height: 25px;
        color: #495057;
    }
    QProgressBar::chunk {
        background-color: #28a745;
        border-radius: 5px;
    }
    QLineEdit {
        border: 1px solid #ced4da;
        border-radius: 5px;
        padding: 8px;
        background-color: #ffffff;
        color: #212529;
    }
    QLineEdit:focus {
        border: 1px solid #007bff;
    }
    QCheckBox {
        color: #343a40;
    }
    QCheckBox::indicator {
        width: 18px;
        height: 18px;
        border: 1px solid #ced4da;
        border-radius: 4px;
        background-color: #ffffff;
    }
    QCheckBox::indicator:checked {
        background-color: #007bff;
        border: 1px solid #007bff;
    }

    /* DNS Kartı Stilleri (Aydınlık Tema) */
    QFrame#dnsCard {
        background-color: #ffffff;
        border: 1px solid #dee2e6;
        border-radius: 12px;
        padding: 15px;
    }
    QFrame#dnsCard:hover {
        background-color: #e9ecef;
        border: 1px solid #adb5bd;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
    }
    QFrame#dnsCard[selected="true"] {
        border: 2px solid #007bff;
        background-color: #e6f2ff;
        box-shadow: 0 4px 12px rgba(0, 123, 255, 0.25);
    }
    QLabel#dnsCard QLabel {
        color: #343a40;
    }
    QLabel#dnsCard QLabel.name_label {
        color: #212529;
    }
    QLabel#dnsCard QLabel.ad_block_label {
        color: #28a745;
    }
    QLabel#dnsCard QLabel.ping_label {
        color: #6c757d;
    }
    QLabel#dnsCard QLabel.ping_label[ping_status="ok"] {
        color: #007bff;
    }
    QLabel#dnsCard QLabel.ping_label[ping_status="fail"] {
        color: #dc3545;
    }
    QLabel#dnsCard QLabel.ping_label[ping_status="na"] {
        color: #6c757d;
    }
    QLabel#dnsCard QLabel.dnssec_label[dnssec_status="true"] {
        color: #007bff; /* Mavi */
        font-weight: bold;
    }
    QLabel#dnsCard QLabel.dnssec_label[dnssec_status="false"] {
        color: #dc3545; /* Kırmızı */
    }
    QLabel#dnsLeakLabel a {
        color: #007bff;
        text-decoration: none;
    }
    /* Tab Widget Stilleri */
    QTabWidget::pane { /* The tab widget frame */
        border: 1px solid #ced4da;
        border-radius: 10px;
        background-color: #ffffff;
    }
    QTabWidget::tab-bar {
        left: 5px; /* move to the right by 5px */
    }
    QTabBar::tab {
        background: #e9ecef;
        border: 1px solid #ced4da;
        border-bottom-color: #ced4da; /* same as pane color */
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
        padding: 10px 35px; /* Daha fazla boşluk */
        margin-right: 2px;
        font-size: 15px;
        color: #495057;
    }
    QTabBar::tab:selected {
        background: #007bff;
        color: white;
        border-color: #007bff;
        border-bottom-color: transparent; /* make the bottom line transparent */
        font-weight: bold;
    }
    QTabBar::tab:hover:!selected {
        background-color: #dee2e6;
    }
    QComboBox {
        border: 1px solid #ced4da;
        border-radius: 5px;
        padding: 8px;
        background-color: #ffffff;
        color: #212529;
    }
    QComboBox::drop-down {
        border: 0px;
    }
    QComboBox::down-arrow {
        image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAh0lEQVQ4T2NkoBAwA/e/fv0GqC+A+D8QvgeIFdDU0NHRMQ2pM/LwMjAwMDAw+M/AxMDAwLDgP1AE4hV+k8B20BwQ/g/EL9D1h10H0k90HsgPQPg/EP9HxA/Q/qDkHwgPQPg/EP9HxA/Q/qDgHwgPQPg/EP9HxA/Q/gAAfQYk66y/NjwAAAAASUVORK5CYII=); /* Example down arrow icon */
        width: 16px;
        height: 16px;
    }
    QComboBox QAbstractItemView {
        border: 1px solid #ced4da;
        border-radius: 5px;
        background-color: #ffffff;
        selection-background-color: #007bff;
        color: #212529;
    }
"""

DARK_THEME_STYLES = """
    QWidget {
        font-family: 'Inter', sans-serif;
        background-color: #2c2c2c; /* Dark background */
        color: #e0e0e0; /* Light text */
    }
    QPushButton {
        background-color: #8a2be2; /* Bright purple button */
        color: white;
        border: none;
        padding: 12px 25px;
        border-radius: 8px;
        font-size: 15px;
        font-weight: bold;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
    }
    QPushButton:hover {
        background-color: #9932cc; /* Darker purple on hover */
    }
    QPushButton:pressed {
        background-color: #6a0dad; /* Even darker purple on press */
    }
    QPushButton:disabled {
        background-color: #555555;
        color: #aaaaaa;
        box-shadow: none;
    }
    QGroupBox {
        border: 1px solid #444444;
        border-radius: 10px;
        margin-top: 15px;
        padding: 15px;
        font-weight: bold;
        background-color: #3c3c3c; /* Dark group box background */
        /* box-shadow: 0 2px 6px rgba(0, 0, 0, 0.25); */ /* Removed to prevent console spam */
    }
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        padding: 0 8px;
        background-color: #4a4a4a;
        border-radius: 5px;
        color: #f0f0f0;
        font-size: 15px;
    }
    QLabel {
        font-size: 14px;
        color: #e0e0e0;
    }
    QLabel#adminStatusLabel {
        font-weight: bold;
        padding: 5px;
        border-radius: 5px;
        color: white;
    }
    QLabel#adminStatusLabel[admin_status="true"] {
        background-color: #28a745; /* Green */
    }
    QLabel#adminStatusLabel[admin_status="false"] {
        background-color: #dc3545; /* Red */
    }
    QProgressBar {
        border: 1px solid #444444;
        border-radius: 5px;
        text-align: center;
        background-color: #3a3a3a;
        height: 25px;
        color: white;
    }
    QProgressBar::chunk {
        background-color: #8a2be2; /* Purple fill */
        border-radius: 5px;
    }
    QLineEdit {
        border: 1px solid #444444;
        border-radius: 5px;
        padding: 8px;
        background-color: #3a3a3a;
        color: #e0e0e0;
    }
    QLineEdit:focus {
        border: 1px solid #8a2be2;
    }
    QCheckBox {
        color: #e0e0e0;
    }
    QCheckBox::indicator {
        width: 18px;
        height: 18px;
        border: 1px solid #444444;
        border-radius: 4px;
        background-color: #3a3a3a;
    }
    QCheckBox::indicator:checked {
        background-color: #8a2be2;
        border: 1px solid #8a2be2;
    }

    /* DNS Kartı Stilleri (Karanlık Tema) */
    QFrame#dnsCard {
        background-color: #3a3a3a;
        border: 1px solid #4a4a4a;
        border-radius: 12px;
        padding: 15px;
    }
    QFrame#dnsCard:hover {
        background-color: #4a4a4a;
        border: 1px solid #5a5a5a;
        box-shadow: 0 4px 10px rgba(0, 0, 0, 0.4);
    }
    QFrame#dnsCard[selected="true"] {
        border: 2px solid #a052e6; /* Brighter purple highlight */
        background-color: #4f3c5f; /* Darker purple background */
        box-shadow: 0 4px 15px rgba(160, 82, 230, 0.4);
    }
    QLabel#dnsCard QLabel {
        color: #f0f0f0;
    }
    QLabel#dnsCard QLabel.name_label {
        color: #ffffff;
    }
    QLabel#dnsCard QLabel.ad_block_label {
        color: #98fb98;
    }
    QLabel#dnsCard QLabel.ping_label {
        color: #cccccc;
    }
    QLabel#dnsCard QLabel.ping_label[ping_status="ok"] {
        color: #a052e6; /* Mor */
    }
    QLabel#dnsCard QLabel.ping_label[ping_status="fail"] {
        color: #ff4500; /* Turuncu kırmızı */
    }
    QLabel#dnsCard QLabel.ping_label[ping_status="na"] {
        color: #cccccc;
    }
    QLabel#dnsCard QLabel.dnssec_label[dnssec_status="true"] {
        color: #a052e2; /* Mor */
        font-weight: bold;
    }
    QLabel#dnsCard QLabel.dnssec_label[dnssec_status="false"] {
        color: #ff4500; /* Turuncu kırmızı */
    }
    QLabel#dnsLeakLabel a {
        color: #a052e6;
        text-decoration: none;
    }
    /* Tab Widget Stilleri */
    QTabWidget::pane { /* The tab widget frame */
        border: 1px solid #444444;
        border-radius: 10px;
        background-color: #2c2c2c;
    }
    QTabWidget::tab-bar {
        left: 5px; /* move to the right by 5px */
    }
    QTabBar::tab {
        background: #3c3c3c;
        border: 1px solid #444444;
        border-bottom-color: #444444; /* same as pane color */
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
        padding: 10px 35px; /* Daha fazla boşluk */
        margin-right: 2px;
        font-size: 15px;
        color: #e0e0e0;
    }
    QTabBar::tab:selected {
        background: #8a2be2;
        color: white;
        border-color: #8a2be2;
        border-bottom-color: transparent; /* make the bottom line transparent */
        font-weight: bold;
    }
    QTabBar::tab:hover:!selected {
        background-color: #4a4a4a;
    }
    QComboBox {
        border: 1px solid #444444;
        border-radius: 5px;
        padding: 8px;
        background-color: #3c3c3c;
        color: #e0e0e0;
    }
    QComboBox::drop-down {
        border: 0px;
    }
    QComboBox::down-arrow {
        image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAh0lEQVQ4T2NkoBAwA/e/fv0GqC+A+D8QvgeIFdDU0NHRMQ2pM/LwMjAwMDAw+M/AxMDAwLDgP1AE4hV+k8B20BwQ/g/EL9D1h10H0k90HsgPQPg/EP9HxA/Q/qDkHwgPQPg/EP9HxA/Q/qDgHwgPQPg/EP9HxA/Q/gAAfQYk66y/NjwAAAAASUVORK5CYII=); /* Example down arrow icon (can be made dark theme compatible) */
        width: 16px;
        height: 16px;
    }
    QComboBox QAbstractItemView {
        border: 1px solid #444444;
        border-radius: 5px;
        background-color: #3c3c3c;
        selection-background-color: #8a2be2;
        color: #e0e0e0;
    }
"""

# Regex patterns for IP validation
IPV4_PATTERN = re.compile(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
IPV6_PATTERN = re.compile(r"^[0-9a-fA-F:]{2,40}$") # Basic IPv6, can be more strict

# --- Translations ---
TRANSLATIONS = {
    'en': {
        'window_title': "DNS Manager",
        'tab_dns_list': "DNS List",
        'tab_settings_actions': "Settings & Actions",
        'group_search_filter': "Search and Filter DNS",
        'placeholder_search': "Search DNS Provider...",
        'checkbox_ad_block': "Show Ad and Malware Blocking DNS",
        'button_apply_dns': "Apply Selected DNS",
        'group_current_dns': "Current DNS Settings",
        'label_loading': "Loading...",
        'group_actions': "Actions",
        'button_speed_test': "Run All DNS Speed Test",
        'button_flush_cache': "Flush DNS Cache",
        'button_restore_dhcp': "Revert to Automatic DNS (DHCP)",
        'button_add_custom': "Add Custom DNS",
        'button_gaming_mode': "Gaming Mode (Fastest DNS)",
        'button_toggle_theme_dark': "Dark Theme",
        'button_toggle_theme_light': "Light Theme",
        'button_backup_settings': "Backup Settings",
        'button_restore_settings': "Restore Settings",
        'label_dns_leak_test': 'DNS Leak Test: <a href="https://www.dnsleaktest.com/">www.dnsleaktest.com</a>',
        'label_admin_status_checking': "Admin Privileges: Checking...",
        'label_admin_status_granted': "Admin Privileges: <b>Granted</b>",
        'label_admin_status_required': "Admin Privileges: <b>Required</b>",
        'msg_no_dns_selected_title': "No DNS Selected",
        'msg_no_dns_selected_text': "Please select a DNS provider.",
        'msg_admin_priv_required_title': "Admin Privileges Required",
        'msg_admin_priv_required_text': "Administrator privileges are required to change DNS settings. Please run the application as administrator.",
        'msg_platform_not_supported_title': "Platform Not Supported",
        'msg_platform_not_supported_dns_mod_text': "DNS modification is only supported on Windows. This feature will not work on your current operating system.",
        'msg_platform_not_supported_speed_test_text': "DNS speed test functionality is only supported on Windows. This feature will not work on your current operating system.",
        'msg_platform_not_supported_flush_text': "Flushing DNS cache is only supported on Windows. This feature will not work on your current operating system.",
        'msg_platform_not_supported_dhcp_text': "Restoring DHCP DNS is only supported on Windows. This feature will not work on your current operating system.",
        'msg_invalid_dns_title': "Invalid DNS",
        'msg_invalid_dns_text': "The selected DNS provider has no valid IP or DoH/DoT address.",
        'msg_confirm_dns_change': "Are you sure you want to apply <b>{name}</b> DNS?<br><br>",
        'msg_doh_dot_info': "'{name}' is an encrypted DNS (DoH/DoT) provider. These settings cannot be automatically applied system-wide. Please manually configure DoH/DoT support in your browser or operating system's network settings.",
        'msg_dns_apply_success': "DNS settings successfully changed for:<br>{adapters}",
        'msg_dns_apply_partial_error': "An error occurred while changing DNS settings for some adapters:<br>{adapters}",
        'msg_dns_apply_no_change': "No DNS settings were applied. Perhaps the selected DNS had no IP addresses.",
        'msg_no_network_adapters': "No active network adapters found. DNS modification features may not work.",
        'msg_speed_test_no_providers': "No DNS providers found to test. Please check your filters.",
        'label_ping_measuring': "Ping: Measuring...",
        'label_ping_na': "Ping: N/A",
        'label_ping_failed_generic': "Ping: Failed (Unknown)",
        'msg_speed_test_results_title': "DNS Speed Test Results",
        'msg_speed_test_results_no_test': "No DNS providers could be tested or matched the filters.",
        'msg_gaming_mode_activating': "Gaming Mode is activating... A speed test will be performed for all DNS, and the fastest one will be automatically applied (based on ping time).",
        'msg_gaming_mode_active': "Gaming Mode activated! The fastest DNS, '{name}', was automatically applied (based on ping time).",
        'msg_gaming_mode_error': "Fastest DNS could not be found or applied.",
        'msg_gaming_mode_no_results': "No valid speed test results were obtained for any DNS.",
        'msg_flush_success': "DNS cache successfully flushed.",
        'msg_flush_error': "An error occurred while flushing DNS cache: {error}",
        'msg_ipconfig_not_found': "ipconfig command not found.",
        'msg_dhcp_confirm': "Are you sure you want to revert DNS settings to automatic (DHCP) for all network adapters?",
        'msg_dhcp_success': "DNS settings successfully reverted to automatic (DHCP) for:<br>{adapters}",
        'msg_dhcp_partial_error': "An error occurred while resetting DNS settings for some adapters:<br>{adapters}",
        'msg_dhcp_no_revert': "No DNS settings were reverted. Perhaps there were no active adapters.",
        'input_custom_dns_name': "Please enter a name for this provider:",
        'input_ipv4_addresses': "Optional: Enter IPv4 addresses separated by commas (e.g., 1.1.1.1,1.0.0.1):",
        'input_ipv6_addresses': "Optional: Enter IPv6 addresses separated by commas (e.g., 2606:4700::1111):",
        'input_doh_url': "Optional: Enter DoH URL (e.g., https://my.custom.dns/dns-query):",
        'input_dot_url': "Optional: Enter DoT URL (e.g., tls://my.custom.dns):",
        'msg_invalid_input_title': "Invalid Input",
        'msg_invalid_input_no_data': "You must enter at least one valid IPv4, IPv6, DoH, or DoT address.",
        'msg_invalid_ipv4': "The IPv4 address '{ip}' is invalid and will be ignored.",
        'msg_invalid_ipv6': "The IPv6 address '{ip}' is invalid and will be ignored.",
        'msg_custom_dns_added_success': "Custom DNS provider '{name}' added. Select the card and click 'Apply' to use it.<br>Note: DoH/DoT settings may require manual configuration.",
        'msg_settings_load_error_decode': "Error decoding settings file: {file}. File might be corrupted.",
        'msg_settings_load_error_io': "Error reading settings file: {error}",
        'msg_settings_load_error_unexpected': "An unexpected error occurred while loading settings: {error}",
        'msg_settings_save_error_io': "Error saving settings file: {error}",
        'msg_settings_save_error_unexpected': "An unexpected error occurred while saving settings: {error}",
        'msg_backup_settings_title': "Backup Settings",
        'msg_backup_success': "Settings successfully backed up to '{file_name}'.",
        'msg_backup_error': "Error backing up settings: {error}",
        'msg_backup_error_unexpected': "An unexpected error occurred while backing up settings: {error}",
        'msg_restore_settings_title': "Restore Settings",
        'msg_restore_success': "Settings successfully restored from '{file_name}'.",
        'msg_restore_invalid_file': "The selected file is not a valid DNS manager settings file or the 'custom_dns_providers' key was not found.",
        'msg_restore_error_decode': "Error decoding settings file: {file}. File might be corrupted.",
        'msg_restore_error_io': "Error reading settings file: {error}",
        'msg_restore_error_unexpected': "An unexpected error occurred while restoring settings: {error}",
        'label_ipv4': "IPv4:",
        'label_ipv6': "IPv6:",
        'label_doh': "DoH:",
        'label_dot': "DoT:",
        'label_dnssec': "DNSSEC:",
        'label_dnssec_yes': "Var",
        'label_dnssec_no': "Yok",
        'label_dnssec_unknown': "Bilinmiyor",
        'label_ad_blocking_enabled': "🛡️ Ad and Malware Blocking",
        'label_automatic_dhcp': "  - Automatic (DHCP)<br>"
    },
    'tr': {
        'window_title': "DNS Yönetici",
        'tab_dns_list': "DNS Listesi",
        'tab_settings_actions': "Ayarlar & İşlemler",
        'group_search_filter': "DNS Ara ve Filtrele",
        'placeholder_search': "DNS Sağlayıcı Ara...",
        'checkbox_ad_block': "Reklam ve Kötü Amaçlı Yazılım Engelleyenleri Göster",
        'button_apply_dns': "Seçilen DNS'i Uygula",
        'group_current_dns': "Mevcut DNS Ayarları",
        'label_loading': "Yükleniyor...",
        'group_actions': "İşlemler",
        'button_speed_test': "Tümünü Hız Testi Yap",
        'button_flush_cache': "DNS Önbelleğini Temizle",
        'button_restore_dhcp': "Otomatik DNS'e Geri Dön (DHCP)",
        'button_add_custom': "Özel DNS Ekle",
        'button_gaming_mode': "Oyun Modu (En Hızlı DNS)",
        'button_toggle_theme_dark': "Karanlık Tema",
        'button_toggle_theme_light': "Aydınlık Tema",
        'button_backup_settings': "Ayarları Yedekle",
        'button_restore_settings': "Ayarları Geri Yükle",
        'label_dns_leak_test': 'DNS Sızıntı Testi: <a href="https://www.dnsleaktest.com/">www.dnsleaktest.com</a>',
        'label_admin_status_checking': "Yönetici Yetkisi: Kontrol Ediliyor...",
        'label_admin_status_granted': "Yönetici Yetkisi: <b style='color:#28a745;'>Var</b>",
        'label_admin_status_required': "Yönetici Yetkisi: <b style='color:#dc3545;'>Gerekli</b>",
        'msg_no_dns_selected_title': "DNS Seçilmedi",
        'msg_no_dns_selected_text': "Lütfen bir DNS sağlayıcısı seçin.",
        'msg_admin_priv_required_title': "Yönetici Yetkisi Gerekli",
        'msg_admin_priv_required_text': "DNS ayarlarını değiştirmek için yönetici yetkileri gereklidir. Lütfen uygulamayı yönetici olarak çalıştırın.",
        'msg_platform_not_supported_title': "Platform Desteklenmiyor",
        'msg_platform_not_supported_dns_mod_text': "DNS değişikliği yalnızca Windows'ta desteklenmektedir. Bu özellik mevcut işletim sisteminizde çalışmayacaktır.",
        'msg_platform_not_supported_speed_test_text': "DNS hız testi işlevi yalnızca Windows'ta desteklenmektedir. Bu özellik mevcut işletim sisteminizde çalışmayacaktır.",
        'msg_platform_not_supported_flush_text': "DNS önbelleği temizleme yalnızca Windows'ta desteklenmektedir. Bu özellik mevcut işletim sisteminizde çalışmayacaktır.",
        'msg_platform_not_supported_dhcp_text': "DHCP DNS'e geri dönme yalnızca Windows'ta desteklenmektedir. Bu özellik mevcut işletim sisteminizde çalışmayacaktır.",
        'msg_invalid_dns_title': "Geçersiz DNS",
        'msg_invalid_dns_text': "Seçilen DNS sağlayıcısının geçerli bir IP veya DoH/DoT adresi yok.",
        'msg_confirm_dns_change': "<b>{name}</b> DNS'ini uygulamak istediğinize emin misiniz?<br><br>",
        'msg_doh_dot_info': "'{name}' bir şifreli DNS (DoH/DoT) sağlayıcısıdır. Bu ayarlar otomatik olarak sistem geneline uygulanamaz. Lütfen tarayıcınızın veya işletim sisteminizin ağ ayarlarından DoH/DoT desteğini manuel olarak yapılandırın.",
        'msg_dns_apply_success': "DNS ayarları başarıyla değiştirildi:<br>{adapters}",
        'msg_dns_apply_partial_error': "Bazı bağdaştırıcılarda DNS ayarı değiştirilirken hata oluştu:<br>{adapters}",
        'msg_dns_apply_no_change': "Herhangi bir DNS ayarı uygulanmadı. Belki de seçili DNS için IP adresi yoktu.",
        'msg_no_network_adapters': "Aktif ağ bağdaştırıcısı bulunamadı. DNS değiştirme özellikleri çalışmayabilir.",
        'msg_speed_test_no_providers': "Test edilecek DNS sağlayıcısı bulunamadı. Lütfen filtrelerinizi kontrol edin.",
        'label_ping_measuring': "Ping: Ölçülüyor...",
        'label_ping_na': "Ping: N/A",
        'label_ping_failed_generic': "Ping: Hata (Bilinmeyen)",
        'msg_speed_test_results_title': "DNS Hız Testi Sonuçları",
        'msg_speed_test_results_no_test': "Hiçbir DNS sağlayıcısı test edilemedi veya filtrelere uymadı.",
        'msg_gaming_mode_activating': "Oyun Modu etkinleştiriliyor... Tüm DNS'ler için hız testi yapılacak ve en hızlı olan otomatik olarak uygulanacaktır (ping süresine göre).",
        'msg_gaming_mode_active': "Oyun Modu etkinleştirildi! En hızlı DNS olan '{name}' otomatik olarak uygulandı (ping süresine göre).",
        'msg_gaming_mode_error': "En hızlı DNS bulunamadı veya uygulanamadı.",
        'msg_gaming_mode_no_results': "Hiçbir DNS için geçerli hız testi sonucu alınamadı.",
        'msg_flush_success': "DNS önbelleği başarıyla temizlendi.",
        'msg_flush_error': "DNS önbelleği temizlenirken hata oluştu: {error}",
        'msg_ipconfig_not_found': "ipconfig komutu bulunamadı.",
        'msg_dhcp_confirm': "Tüm ağ bağdaştırıcıları için DNS ayarlarını otomatik (DHCP) olarak geri yüklemek istediğinize emin misiniz?",
        'msg_dhcp_success': "DNS ayarları başarıyla otomatik (DHCP) olarak geri yüklendi:<br>{adapters}",
        'msg_dhcp_partial_error': "Bazı bağdaştırıcılarda DNS ayarları sıfırlanırken hata oluştu:<br>{adapters}",
        'msg_dhcp_no_revert': "Herhangi bir DNS ayarı geri yüklenmedi. Belki de aktif bir bağdaştırıcı yoktu.",
        'input_custom_dns_name': "Lütfen bu sağlayıcı için bir isim girin:",
        'input_ipv4_addresses': "İsteğe bağlı IPv4 adreslerini virgülle ayırarak girin (örn: 1.1.1.1,1.0.0.1):",
        'input_ipv6_addresses': "İsteğe bağlı IPv6 adreslerini virgülle ayırarak girin (örn: 2606:4700::1111):",
        'input_doh_url': "İsteğe bağlı DoH URL'sini girin (örn: https://my.custom.dns/dns-query):",
        'input_dot_url': "İsteğe bağlı DoT URL'sini girin (örn: tls://my.custom.dns):",
        'msg_invalid_input_title': "Geçersiz Giriş",
        'msg_invalid_input_no_data': "En az bir geçerli IPv4, IPv6, DoH veya DoT adresi girmelisiniz.",
        'msg_invalid_ipv4': "IPv4 adresi '{ip}' geçersizdir ve yok sayılacaktır.",
        'msg_invalid_ipv6': "IPv6 adresi '{ip}' geçersizdir ve yok sayılacaktır.",
        'msg_custom_dns_added_success': "Özel DNS sağlayıcısı '{name}' eklendi. Kullanmak için kartı seçip 'Uygula' butonuna tıklayın.<br>Not: DoH/DoT ayarları manuel yapılandırma gerektirebilir.",
        'msg_settings_load_error_decode': "Ayarlar dosyası çözümlenirken hata oluştu: {file}. Dosya bozulmuş olabilir.",
        'msg_settings_load_error_io': "Ayarlar dosyası okunurken hata oluştu: {error}",
        'msg_settings_load_error_unexpected': "Ayarlar yüklenirken beklenmedik bir hata oluştu: {error}",
        'msg_settings_save_error_io': "Ayarlar dosyası kaydedilirken hata oluştu: {error}",
        'msg_settings_save_error_unexpected': "Ayarlar kaydedilirken beklenmedik bir hata oluştu: {error}",
        'msg_backup_settings_title': "Ayarları Yedekle",
        'msg_backup_success': "Ayarlar '{file_name}' dosyasına başarıyla yedeklendi.",
        'msg_backup_error': "Ayarlar yedeklenirken hata oluştu: {error}",
        'msg_backup_error_unexpected': "Ayarlar yedeklenirken beklenmedik bir hata oluştu: {error}",
        'msg_restore_settings_title': "Ayarları Geri Yükle",
        'msg_restore_success': "Ayarlar '{file_name}' dosyasından başarıyla geri yüklendi.",
        'msg_restore_invalid_file': "Seçilen dosya geçerli bir DNS yönetici ayar dosyası değil veya 'custom_dns_providers' anahtarı bulunamadı.",
        'msg_restore_error_decode': "Ayarlar dosyası çözümlenirken hata oluştu: {file}. Dosya bozulmuş olabilir.",
        'msg_restore_error_io': "Ayarlar dosyası okunurken hata oluştu: {error}",
        'msg_restore_error_unexpected': "Ayarlar geri yüklenirken beklenmedik bir hata oluştu: {error}",
        'label_ipv4': "IPv4:",
        'label_ipv6': "IPv6:",
        'label_doh': "DoH:",
        'label_dot': "DoT:",
        'label_dnssec': "DNSSEC:",
        'label_dnssec_yes': "Var",
        'label_dnssec_no': "Yok",
        'label_dnssec_unknown': "Bilinmiyor",
        'label_ad_blocking_enabled': "🛡️ Reklam ve Kötü Amaçlı Yazılım Engelleme",
        'label_automatic_dhcp': "  - Otomatik (DHCP)<br>"
    }
}


# --- Yardımcı Fonksiyonlar ---

def is_admin():
    """
    Betik Windows üzerinde yönetici ayrıcalıklarıyla çalışıyor mu kontrol eder.
    Linux/macOS için AttributeError yakalar ve False döndürür.
    """
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    return False # Windows olmayan sistemler için bu kontrolü atlar

def get_current_dns_settings():
    """
    Windows'taki tüm ağ bağdaştırıcıları için mevcut DNS ayarlarını alır.
    Hem IPv4 hem de IPv6 adreslerini dahil eder.
    Anahtarları bağdaştırıcı adları ve değerleri DNS sunucuları listeleri olan bir sözlük döndürür.
    """
    if platform.system() != "Windows":
        return {"Error": TRANSLATIONS.get(DNSManagerApp.current_lang, TRANSLATIONS['en'])['msg_platform_not_supported_dns_mod_text']}

    # PowerShell komutu, her bağdaştırıcının DNS sunucularını listeler.
    # Hem IPv4 hem de IPv6 adreslerini almak için AddressFamily parametresi kullanılır.
    cmd = ["powershell", "Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 | Select-Object InterfaceAlias, AddressFamily, ServerAddresses"]
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        output = process.stdout.strip()

        dns_settings = {}
        lines = output.splitlines()

        current_alias = None
        for line in lines:
            line = line.strip()
            if not line or "----" in line or "InterfaceAlias" in line:
                continue

            # Match lines with InterfaceAlias, AddressFamily, and ServerAddresses
            match_alias_line = re.match(r"(\S+)\s*(\S+)\s*{(.*)}", line)
            if match_alias_line:
                alias = match_alias_line.group(1).strip()
                addr_family = match_alias_line.group(2).strip()
                addresses_str = match_alias_line.group(3).strip()
                dns_servers = [addr.strip() for addr in addresses_str.split(',') if addr.strip()]

                if alias not in dns_settings:
                    dns_settings[alias] = {"IPv4": [], "IPv6": [], "DHCP": False}

                if addr_family == "IPv4":
                    dns_settings[alias]["IPv4"].extend(dns_servers)
                elif addr_family == "IPv6":
                    dns_settings[alias]["IPv6"].extend(dns_servers)
                current_alias = alias # Track the current adapter

            # Match lines with just the interface name (for DHCP detection)
            elif re.match(r"(\S+)\s*$", line) and not line.startswith(" "):
                alias = line.strip()
                # If this adapter hasn't been processed yet and only its name is found, assume DHCP
                if alias not in dns_settings:
                    dns_settings[alias] = {"IPv4": [], "IPv6": [], "DHCP": True}
                elif not dns_settings[alias]["IPv4"] and not dns_settings[alias]["IPv6"]:
                    # If no IPv4/IPv6 address was found before and only the name is present, it's DHCP.
                    dns_settings[alias]["DHCP"] = True
                current_alias = alias

            # Handle cases where IP addresses might come on separate lines (older PowerShell versions or formats)
            elif current_alias and IPV4_PATTERN.match(line):
                ip = line.strip()
                if ip not in dns_settings[current_alias]["IPv4"]:
                    dns_settings[current_alias]["IPv4"].append(ip)
            elif current_alias and IPV6_PATTERN.match(line):
                ipv6 = line.strip()
                if ipv6 not in dns_settings[current_alias]["IPv6"]:
                    dns_settings[current_alias]["IPv6"].append(ipv6)
        
        # Format the final output
        formatted_dns_settings = {}
        for alias, data in dns_settings.items():
            combined_addresses = []
            if data["IPv4"]:
                combined_addresses.extend(data["IPv4"])
            if data["IPv6"]:
                combined_addresses.extend(data["IPv6"])
            
            if not combined_addresses and data["DHCP"]:
                formatted_dns_settings[alias] = [] # Empty list for DHCP
            else:
                formatted_dns_settings[alias] = combined_addresses

        return formatted_dns_settings
    except subprocess.CalledProcessError as e:
        return {"Error": f"DNS ayarları alınamadı: {e.stderr.strip() if e.stderr else 'Bilinmeyen hata'}"}
    except FileNotFoundError:
        return {"Error": "PowerShell bulunamadı. DNS ayarları alınamıyor."}
    except Exception as e:
        return {"Error": f"Beklenmedik hata: {e}"}


def get_network_interfaces():
    """
    Windows'taki aktif ağ bağdaştırıcılarının (adlarının) bir listesini alır.
    netsh komutları için kullanılır.
    """
    if platform.system() != "Windows":
        return []

    cmd = ["netsh", "interface", "ip", "show", "interface"]
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        output = process.stdout.strip() # Baştaki ve sondaki boşlukları kaldır
        interfaces = []
        # Her satırı işler, "Bağdaştırıcı Adı" veya "Arayüz Adı" formatlarını arar.
        for line in output.splitlines():
            line = line.strip()
            if not line: # Boş satırları atla
                continue
            # Arayüz adını tırnak içinde arar (örn: "Ethernet")
            match = re.search(r"\"(.+)\"\s*$", line)
            if match:
                interfaces.append(match.group(1).strip())
            # "Yerel Ağ Bağlantısı" gibi tırnaksız adları arar (yalnızca "Bağdaştırıcı Adı" içeren satırlar)
            elif "Bağdaştırıcı Adı" in line or "Interface Name" in line: # Added Turkish string
                parts = line.split(":")
                if len(parts) > 1:
                    name = parts[1].strip()
                    if name and name != "Loopback Pseudo-Interface 1": # Loopback'i hariç tut
                        interfaces.append(name)
        return interfaces
    except subprocess.CalledProcessError as e:
        return []
    except FileNotFoundError:
        return []
    except Exception as e:
        return []

def get_system_theme():
    """
    Windows'un sistem temasını algılar (aydınlık veya karanlık).
    Diğer OS'ler için varsayılanı döndürür.
    """
    if platform.system() == "Windows":
        try:
            # Registry'den AppsUseLightTheme değerini okur
            # 0 = Dark, 1 = Light
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            value, regtype = winreg.QueryValueEx(key, "AppsUseLightTheme")
            winreg.CloseKey(key)
            return 'light' if value == 1 else 'dark'
        except Exception:
            return 'light' # Hata durumunda varsayılan olarak aydınlık tema
    return 'light' # Windows olmayan sistemler için varsayılan

# --- Ping İş Parçacığı ---
class PingThread(QThread):
    # DNS adı ve ping süresini (float) sinyal olarak yayınlar
    ping_result = pyqtSignal(str, float, str) # Hata mesajı eklendi
    finished = pyqtSignal() # İş parçasının tamamlandığını bildiren sinyal

    def __init__(self, dns_name, ip_address, ip_version=4):
        super().__init__()
        self.dns_name = dns_name
        self.ip_address = ip_address
        self.ip_version = ip_version
        self._is_running = True # İş parçasının durdurulup durdurulmadığını kontrol eder

    def run(self):
        """Ping komutunu çalıştırır ve sonucu sinyal olarak yayınlar."""
        if not self._is_running:
            self.finished.emit()
            return

        # Ping komutunu IP sürümüne göre ayarla
        cmd = ["ping", "-n", "4"]
        if self.ip_version == 6:
            cmd.append("-6")
        cmd.append(self.ip_address)

        try:
            process = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', check=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=10)
            output = process.stdout

            match = re.search(r"Ortalama = (\d+)ms|Average = (\d+)ms", output)
            if match:
                avg_ping = float(match.group(1) if match.group(1) else match.group(2))
                self.ping_result.emit(self.dns_name, avg_ping, "") # Hata yok
            else:
                self.ping_result.emit(self.dns_name, -1.0, "Ping başarısız: Çıktıda ortalama bulunamadı.")
        except subprocess.TimeoutExpired:
            self.ping_result.emit(self.dns_name, -1.0, "Ping zaman aşımına uğradı.")
        except subprocess.CalledProcessError as e:
            self.ping_result.emit(self.dns_name, -1.0, f"Ping komutu başarısız oldu: {e.stderr.strip() if e.stderr else 'Bilinmeyen hata'}")
        except FileNotFoundError:
            self.ping_result.emit(self.dns_name, -2.0, "Ping komutu bulunamadı.")
        except Exception as e:
            self.ping_result.emit(self.dns_name, -1.0, f"Beklenmedik ping hatası: {e}")
        finally:
            self.finished.emit()

    def stop(self):
        """İş parçasının çalışmasını durdurmak için bayrağı ayarlar."""
        self._is_running = False

# --- DNS Kartı Widget'ı ---
class DNSCard(QFrame):
    # Kart seçildiğinde DNS verilerini sinyal olarak yayınlar
    selected = pyqtSignal(dict)

    def __init__(self, dns_data, parent=None):
        super().__init__(parent)
        self.dns_data = dns_data
        self.ping_value = None # Ping değerini saklar
        self.init_ui()
        self.setCursor(Qt.PointingHandCursor) # Fare imlecini el olarak ayarlar
        # setFixedSize yerine esnek boyutlandırma
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        self.setMinimumSize(280, 180) # Minimum boyut belirle

    def init_ui(self):
        """Kullanıcı arayüzünü başlatır ve stilleri ayarlar."""
        self.setFrameShape(QFrame.StyledPanel) # Çerçeve şeklini ayarlar
        self.setFrameShadow(QFrame.Raised) # Çerçeve gölgesini yükseltir
        self.setLineWidth(1) # Çerçeve genişliğini ayarlar
        self.setObjectName("dnsCard") # CSS seçicisi için objectName ayarlar
        self.setStyleSheet("""
            QFrame#dnsCard {
                border-radius: 12px;
                padding: 15px;
            }
            QLabel {
                font-size: 14px;
            }
            QLabel.name_label {
                font-size: 16px;
                font-weight: bold;
                margin-bottom: 5px;
            }
            QLabel.ad_block_label {
                font-size: 15px;
                font-weight: bold;
                margin-top: 5px;
            }
            QLabel.ping_label {
                font-size: 13px;
                margin-top: 8px;
            }
            QLabel.dnssec_label {
                font-size: 13px;
                font-weight: normal; /* Normal ağırlık, renk property ile değişecek */
                margin-top: 2px;
            }
        """)

        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(5)

        self.name_label = QLabel(self.dns_data['name'])
        self.name_label.setObjectName("name_label")
        self.name_label.setWordWrap(True) # Metin sığmazsa alt satıra geç
        layout.addWidget(self.name_label)

        self.ad_block_label = QLabel("")
        if self.dns_data.get('ad_blocking'):
            self.ad_block_label.setObjectName("ad_block_label")
            self.ad_block_label.setWordWrap(True) # Metin sığmazsa alt satıra geç
            layout.addWidget(self.ad_block_label)
        else:
            layout.addWidget(QLabel(" ")) # Yer tutucu (boşluk sağlamak için)

        self.ipv4_label = QLabel("")
        self.ipv4_label.setObjectName("ipv4_label")
        self.ipv4_label.setWordWrap(True) # Metin sığmazsa alt satıra geç
        layout.addWidget(self.ipv4_label)

        self.ipv6_label = QLabel("")
        self.ipv6_label.setObjectName("ipv6_label")
        self.ipv6_label.setWordWrap(True) # Metin sığmazsa alt satıra geç
        layout.addWidget(self.ipv6_label)

        self.doh_label = QLabel("")
        self.doh_label.setObjectName("doh_label")
        self.doh_label.setWordWrap(True) # Metin sığmazsa alt satıra geç
        layout.addWidget(self.doh_label)

        self.dot_label = QLabel("")
        self.dot_label.setObjectName("dot_label")
        self.dot_label.setWordWrap(True) # Metin sığmazsa alt satıra geç
        layout.addWidget(self.dot_label)

        self.dnssec_label = QLabel("")
        self.dnssec_label.setObjectName("dnssec_label")
        layout.addWidget(self.dnssec_label)

        self.ping_label = QLabel("") # Başlangıçta boş
        self.ping_label.setObjectName("ping_label")
        layout.addWidget(self.ping_label)

        self.setLayout(layout)
        self.update_card_text() # Başlangıçta metinleri ayarla

    def update_card_text(self):
        """Kartın metinlerini mevcut dile göre günceller."""
        lang = DNSManagerApp.current_lang
        
        self.name_label.setText(self.dns_data['name'])

        if self.dns_data.get('ad_blocking'):
            self.ad_block_label.setText(TRANSLATIONS[lang]['label_ad_blocking_enabled'])
        else:
            self.ad_block_label.setText(" ")

        if self.dns_data.get('ipv4'):
            self.ipv4_label.setText(f"{TRANSLATIONS[lang]['label_ipv4']} {', '.join(self.dns_data['ipv4'])}")
        else:
            self.ipv4_label.setText(f"{TRANSLATIONS[lang]['label_ipv4']} {TRANSLATIONS[lang]['label_dnssec_no']}")

        if self.dns_data.get('ipv6'):
            self.ipv6_label.setText(f"{TRANSLATIONS[lang]['label_ipv6']} {', '.join(self.dns_data['ipv6'])}")
        else:
            self.ipv6_label.setText(f"{TRANSLATIONS[lang]['label_ipv6']} {TRANSLATIONS[lang]['label_dnssec_no']}")

        if self.dns_data.get('doh_url'):
            doh_display = self.dns_data['doh_url'].replace("https://", "").replace("/dns-query", "").split('/')[0]
            self.doh_label.setText(f"{TRANSLATIONS[lang]['label_doh']} {doh_display}...")
            self.doh_label.setToolTip(self.dns_data['doh_url'])
        else:
            self.doh_label.setText(f"{TRANSLATIONS[lang]['label_doh']} {TRANSLATIONS[lang]['label_dnssec_no']}")

        if self.dns_data.get('dot_url'):
            dot_display = self.dns_data['dot_url'].replace("tls://", "").split('/')[0]
            self.dot_label.setText(f"{TRANSLATIONS[lang]['label_dot']} {dot_display}...")
            self.dot_label.setToolTip(self.dns_data['dot_url'])
        else:
            self.dot_label.setText(f"{TRANSLATIONS[lang]['label_dot']} {TRANSLATIONS[lang]['label_dnssec_no']}")

        if self.dns_data.get('dnssec_enabled') is not None:
            dnssec_status_text = TRANSLATIONS[lang]['label_dnssec_yes'] if self.dns_data['dnssec_enabled'] else TRANSLATIONS[lang]['label_dnssec_no']
            self.dnssec_label.setText(f"{TRANSLATIONS[lang]['label_dnssec']} {dnssec_status_text}")
            self.dnssec_label.setProperty("dnssec_status", "true" if self.dns_data['dnssec_enabled'] else "false")
        else:
            self.dnssec_label.setText(f"{TRANSLATIONS[lang]['label_dnssec']} {TRANSLATIONS[lang]['label_dnssec_unknown']}")
            self.dnssec_label.setProperty("dnssec_status", "na")
        self.style().polish(self.dnssec_label)

        self.ping_label.setText(TRANSLATIONS[lang]['label_ping_measuring'])
        self.ping_label.setProperty("ping_status", "na")
        self.style().polish(self.ping_label)


    @pyqtSlot(str, float, str)
    def update_ping(self, dns_name, ping_time, error_message):
        """Ping sonucunu karta yansıtır."""
        lang = DNSManagerApp.current_lang
        if dns_name == self.dns_data['name']:
            if ping_time >= 0 and ping_time != float('inf'): # Ping başarılı ise
                self.ping_value = ping_time
                self.ping_label.setText(f"Ping: <b>{int(ping_time)} ms</b>")
                self.ping_label.setProperty("ping_status", "ok")
            elif error_message: # Belirli bir hata varsa
                self.ping_value = float('inf') # Sıralama için sonsuz olarak ayarla
                self.ping_label.setText(f"Ping: Hata ({error_message})")
                self.ping_label.setProperty("ping_status", "fail")
            else: # Genel hata veya N/A
                self.ping_value = float('inf')
                self.ping_label.setText(TRANSLATIONS[lang]['label_ping_na'])
                self.ping_label.setProperty("ping_status", "na")
            self.style().polish(self.ping_label) # Ping etiketi stilini güncelle

    def mousePressEvent(self, event):
        """Kart tıklandığında seçildi sinyalini yayınlar."""
        self.selected.emit(self.dns_data)
        super().mousePressEvent(event)

    def select(self, is_selected):
        """Kartın seçili durumunu ayarlar ve stilini günceller."""
        self.setProperty("selected", is_selected)
        self.style().polish(self) # Stil sayfasının özelliğe göre güncellenmesini sağlar

    def set_theme(self, theme_name):
        """Kartın temasını ayarlar ve stilini günceller."""
        self.setProperty("current_theme", theme_name)
        # Kartın altındaki tüm etiketlerin temasını da güncelle
        for child_label in self.findChildren(QLabel):
            child_label.setProperty("current_theme", theme_name)
            self.style().polish(child_label)
        self.style().polish(self)

# --- Ana Uygulama Penceresi ---
class DNSManagerApp(QWidget):
    # Statik sınıf değişkeni olarak mevcut dili tanımla
    current_lang = 'en' # Varsayılan dil
    
    def __init__(self):
        super().__init__()
        self.current_dns_data = None
        self.network_interfaces = []
        self.ping_threads = [] # Çalışan ping iş parçacıklarını saklar
        self.selected_dns = None # Seçili DNS sağlayıcısı verisi
        self.dns_cards = {} # DNS kartı widget'larını isme göre saklar
        self.current_theme = 'light' # Varsayılan tema
        self.completed_tasks = 0 # Tamamlanan görev sayacını burada başlatıyoruz.
        self.ping_results_for_speed_test = [] # Hız testi sonuçlarını saklamak için başlatıldı
        self.custom_dns_providers = [] # Kullanıcının eklediği özel DNS'leri saklar
        self.settings_file = "dns_manager_settings.json" # Ayarlar dosyasının adı
        
        self.detect_system_settings() # Sistem dilini ve temasını otomatik algıla
        self.load_settings() # Uygulama başlangıcında ayarları yükle
        self.init_ui()
        self.update_ui_texts() # Başlangıçta UI metinlerini ayarla
        self.check_admin_status() # Yönetici yetkisini kontrol et
        self.update_current_dns_info() # Mevcut DNS bilgilerini al ve göster
        self.populate_dns_cards() # DNS kartlarını oluştur ve doldur

    def detect_system_settings(self):
        """Sistem dilini ve temasını otomatik olarak algılar."""
        # Dil tespiti
        system_locale = locale.getdefaultlocale()[0]
        if system_locale and system_locale.startswith('tr'):
            DNSManagerApp.current_lang = 'tr'
        else:
            DNSManagerApp.current_lang = 'en'
        
        # Tema tespiti (sadece Windows için)
        self.current_theme = get_system_theme()

    def init_ui(self):
        """Ana pencerenin kullanıcı arayüzünü başlatır."""
        self.setWindowTitle(TRANSLATIONS[DNSManagerApp.current_lang]['window_title'])
        self.setMinimumSize(800, 600) # Minimum pencere boyutu
        
        # Ana layout, tab widget'ı barındıracak
        main_layout = QVBoxLayout(self) 
        self.tab_widget = QTabWidget(self)
        main_layout.addWidget(self.tab_widget)

        # --- DNS Listesi Sekmesi ---
        dns_list_tab = QWidget()
        dns_list_layout = QVBoxLayout(dns_list_tab)
        dns_list_layout.setContentsMargins(20, 20, 20, 20) # Daha fazla boşluk

        # DNS Arama ve Filtreleme Grubu
        self.filter_group = QGroupBox(TRANSLATIONS[DNSManagerApp.current_lang]['group_search_filter'])
        filter_layout = QVBoxLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(TRANSLATIONS[DNSManagerApp.current_lang]['placeholder_search'])
        self.search_input.textChanged.connect(self.filter_dns_cards)
        filter_layout.addWidget(self.search_input)

        self.ad_block_checkbox = QCheckBox(TRANSLATIONS[DNSManagerApp.current_lang]['checkbox_ad_block'])
        self.ad_block_checkbox.stateChanged.connect(self.filter_dns_cards)
        filter_layout.addWidget(self.ad_block_checkbox)

        self.filter_group.setLayout(filter_layout)
        dns_list_layout.addWidget(self.filter_group)

        self.dns_card_grid = QGridLayout() # Kartları yerleştirmek için ızgara düzenleyici
        self.dns_card_grid.setSpacing(20) # Kartlar arasındaki boşluk
        self.dns_card_grid.setAlignment(Qt.AlignTop | Qt.AlignLeft)

        self.scroll_widget = QWidget()
        self.scroll_widget.setLayout(self.dns_card_grid)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True) # İçindeki widget'ın boyutunu otomatik ayarlar
        scroll_area.setWidget(self.scroll_widget)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff) # Yatay kaydırma çubuğunu kapatır
        scroll_area.setStyleSheet("QScrollArea { border: none; background-color: transparent; }") # Kenarlığı kaldırır
        dns_list_layout.addWidget(scroll_area)

        # DNS Uygula Butonu
        apply_button_layout = QHBoxLayout()
        apply_button_layout.setAlignment(Qt.AlignCenter)
        self.btn_apply_dns = QPushButton(TRANSLATIONS[DNSManagerApp.current_lang]['button_apply_dns'])
        self.btn_apply_dns.setFixedSize(220, 45)
        self.btn_apply_dns.clicked.connect(self.apply_selected_dns)
        self.btn_apply_dns.setEnabled(False) # Bir DNS seçilene kadar devre dışı
        apply_button_layout.addWidget(self.btn_apply_dns)
        dns_list_layout.addLayout(apply_button_layout)

        self.tab_widget.addTab(dns_list_tab, TRANSLATIONS[DNSManagerApp.current_lang]['tab_dns_list'])

        # --- Ayarlar & İşlemler Sekmesi ---
        settings_actions_tab = QWidget()
        settings_actions_layout = QVBoxLayout(settings_actions_tab)
        settings_actions_layout.setContentsMargins(20, 20, 20, 20) # Daha fazla boşluk
        settings_actions_layout.setSpacing(15) # Boşlukları azalt
        settings_actions_layout.setAlignment(Qt.AlignTop) # İçerik üstte hizalanır

        # Dil Seçimi
        language_layout = QHBoxLayout()
        language_label = QLabel("Dil Seçimi:")
        language_layout.addWidget(language_label)
        self.language_combo = QComboBox()
        self.language_combo.addItem("English", "en")
        self.language_combo.addItem("Türkçe", "tr")
        self.language_combo.setCurrentText("Türkçe" if DNSManagerApp.current_lang == 'tr' else "English")
        self.language_combo.currentIndexChanged.connect(self.change_language)
        language_layout.addWidget(self.language_combo)
        language_layout.addStretch(1)
        settings_actions_layout.addLayout(language_layout)

        # Mevcut DNS Ayarları Grubu
        self.current_dns_group = QGroupBox(TRANSLATIONS[DNSManagerApp.current_lang]['group_current_dns'])
        self.current_dns_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.MinimumExpanding) 
        current_dns_layout = QVBoxLayout()
        self.current_dns_label = QLabel(TRANSLATIONS[DNSManagerApp.current_lang]['label_loading'])
        self.current_dns_label.setWordWrap(True) # Uzun metinleri sarar
        current_dns_layout.addWidget(self.current_dns_label)
        self.current_dns_group.setLayout(current_dns_layout)
        settings_actions_layout.addWidget(self.current_dns_group)

        # İşlemler Grubu
        self.actions_group = QGroupBox(TRANSLATIONS[DNSManagerApp.current_lang]['group_actions'])
        self.actions_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed) # Fixed policy to keep buttons visible
        actions_layout = QVBoxLayout()
        actions_layout.setSpacing(10)

        self.btn_speed_test = QPushButton(TRANSLATIONS[DNSManagerApp.current_lang]['button_speed_test'])
        self.btn_speed_test.clicked.connect(self.run_all_dns_speed_test)
        actions_layout.addWidget(self.btn_speed_test)

        self.btn_flush_dns = QPushButton(TRANSLATIONS[DNSManagerApp.current_lang]['button_flush_cache'])
        self.btn_flush_dns.clicked.connect(self.flush_dns_cache)
        actions_layout.addWidget(self.btn_flush_dns)

        self.btn_restore_dhcp = QPushButton(TRANSLATIONS[DNSManagerApp.current_lang]['button_restore_dhcp'])
        self.btn_restore_dhcp.clicked.connect(self.restore_dhcp_dns)
        actions_layout.addWidget(self.btn_restore_dhcp)

        self.btn_add_custom_dns = QPushButton(TRANSLATIONS[DNSManagerApp.current_lang]['button_add_custom'])
        self.btn_add_custom_dns.clicked.connect(self.add_custom_dns_provider)
        actions_layout.addWidget(self.btn_add_custom_dns)

        self.btn_gaming_mode = QPushButton(TRANSLATIONS[DNSManagerApp.current_lang]['button_gaming_mode'])
        self.btn_gaming_mode.clicked.connect(self.activate_gaming_mode)
        actions_layout.addWidget(self.btn_gaming_mode)
        
        self.btn_toggle_theme = QPushButton("") # Metin update_ui_texts tarafından ayarlanacak
        self.btn_toggle_theme.clicked.connect(self.toggle_theme)
        actions_layout.addWidget(self.btn_toggle_theme)

        self.btn_backup_settings = QPushButton(TRANSLATIONS[DNSManagerApp.current_lang]['button_backup_settings'])
        self.btn_backup_settings.clicked.connect(self.backup_settings)
        actions_layout.addWidget(self.btn_backup_settings)

        self.btn_restore_settings = QPushButton(TRANSLATIONS[DNSManagerApp.current_lang]['button_restore_settings'])
        self.btn_restore_settings.clicked.connect(self.restore_settings)
        actions_layout.addWidget(self.btn_restore_settings)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setVisible(False)
        actions_layout.addWidget(self.progress_bar)

        self.actions_group.setLayout(actions_layout)
        settings_actions_layout.addWidget(self.actions_group)

        # DNS Sızıntı Testi Bağlantısı
        self.dns_leak_label = QLabel(TRANSLATIONS[DNSManagerApp.current_lang]['label_dns_leak_test'])
        self.dns_leak_label.setOpenExternalLinks(True)
        self.dns_leak_label.setAlignment(Qt.AlignCenter)
        self.dns_leak_label.setObjectName("dnsLeakLabel")
        settings_actions_layout.addWidget(self.dns_leak_label)

        # Yönetici Durumu Etiketi
        self.admin_status_label = QLabel(TRANSLATIONS[DNSManagerApp.current_lang]['label_admin_status_checking'])
        self.admin_status_label.setObjectName("adminStatusLabel")
        self.admin_status_label.setAlignment(Qt.AlignCenter)
        settings_actions_layout.addWidget(self.admin_status_label)

        settings_actions_layout.addStretch(1) # Boş alanı doldurmak için esneklik ekler

        self.tab_widget.addTab(settings_actions_tab, TRANSLATIONS[DNSManagerApp.current_lang]['tab_settings_actions'])
        
        # Tema uygulama çağrısını buraya taşıdık, böylece btn_toggle_theme zaten oluşturulmuş olur
        self.apply_theme(self.current_theme) 

    def update_ui_texts(self):
        """Uygulamanın tüm UI metinlerini mevcut dile göre günceller."""
        lang = DNSManagerApp.current_lang
        self.setWindowTitle(TRANSLATIONS[lang]['window_title'])
        self.tab_widget.setTabText(0, TRANSLATIONS[lang]['tab_dns_list'])
        self.tab_widget.setTabText(1, TRANSLATIONS[lang]['tab_settings_actions'])

        self.filter_group.setTitle(TRANSLATIONS[lang]['group_search_filter'])
        self.search_input.setPlaceholderText(TRANSLATIONS[lang]['placeholder_search'])
        self.ad_block_checkbox.setText(TRANSLATIONS[lang]['checkbox_ad_block'])
        self.btn_apply_dns.setText(TRANSLATIONS[lang]['button_apply_dns'])

        self.current_dns_group.setTitle(TRANSLATIONS[lang]['group_current_dns'])
        self.current_dns_label.setText(TRANSLATIONS[lang]['label_loading']) # Bu daha sonra update_current_dns_info tarafından güncellenecek

        self.actions_group.setTitle(TRANSLATIONS[lang]['group_actions'])
        self.btn_speed_test.setText(TRANSLATIONS[lang]['button_speed_test'])
        self.btn_flush_dns.setText(TRANSLATIONS[lang]['button_flush_cache'])
        self.btn_restore_dhcp.setText(TRANSLATIONS[lang]['button_restore_dhcp'])
        self.btn_add_custom_dns.setText(TRANSLATIONS[lang]['button_add_custom'])
        self.btn_gaming_mode.setText(TRANSLATIONS[lang]['button_gaming_mode'])
        self.btn_toggle_theme.setText(TRANSLATIONS[lang]['button_toggle_theme_light'] if self.current_theme == 'dark' else TRANSLATIONS[lang]['button_toggle_theme_dark'])
        self.btn_backup_settings.setText(TRANSLATIONS[lang]['button_backup_settings'])
        self.btn_restore_settings.setText(TRANSLATIONS[lang]['button_restore_settings'])
        
        self.dns_leak_label.setText(TRANSLATIONS[lang]['label_dns_leak_test'])
        self.check_admin_status() # Yönetici durumu etiketini de günceller

        # Tüm DNS kartlarının metinlerini güncelle
        for card in self.dns_cards.values():
            card.update_card_text()
            card.update_ping(card.dns_data['name'], card.ping_value if card.ping_value is not None else float('inf'), "") # Ping durumunu koru


    def change_language(self, index):
        """Kullanıcı dil seçeneğini değiştirdiğinde çalışır."""
        selected_lang = self.language_combo.itemData(index)
        if DNSManagerApp.current_lang != selected_lang:
            DNSManagerApp.current_lang = selected_lang
            self.update_ui_texts()
            # Mevcut DNS bilgisini de güncelle (dil değiştikçe)
            self.update_current_dns_info()


    def apply_theme(self, theme_name):
        """Uygulamanın temasını ayarlar."""
        self.current_theme = theme_name
        if theme_name == 'light':
            QApplication.instance().setStyleSheet(LIGHT_THEME_STYLES)
            self.btn_toggle_theme.setText(TRANSLATIONS[DNSManagerApp.current_lang]['button_toggle_theme_dark'])
            # leftPanel'in stilini tema ile uyumlu hale getir (artık tab içindeki widgetlar için geçerli olacak)
            self.tab_widget.widget(1).setStyleSheet("QWidget { background-color: #f8f9fa; } QGroupBox { background-color: #ffffff; }")
        else:
            QApplication.instance().setStyleSheet(DARK_THEME_STYLES)
            self.btn_toggle_theme.setText(TRANSLATIONS[DNSManagerApp.current_lang]['button_toggle_theme_light'])
            self.tab_widget.widget(1).setStyleSheet("QWidget { background-color: #2c2c2c; } QGroupBox { background-color: #3c3c3c; }")

        # Tüm DNS kartlarını güncel temaya göre ayarla
        for card in self.dns_cards.values():
            card.set_theme(self.current_theme)

        # Admin status label rengini de tema ile uyumlu hale getir
        self.check_admin_status()


    def toggle_theme(self):
        """Temayı aydınlık ve karanlık arasında değiştirir."""
        if self.current_theme == 'light':
            self.apply_theme('dark')
        else:
            self.apply_theme('light')

    def check_admin_status(self):
        """Yönetici yetkisini kontrol eder ve etiketi günceller."""
        lang = DNSManagerApp.current_lang
        if is_admin():
            self.admin_status_label.setText(TRANSLATIONS[lang]['label_admin_status_granted'])
            self.admin_status_label.setProperty("admin_status", "true")
        else:
            self.admin_status_label.setText(TRANSLATIONS[lang]['label_admin_status_required'])
            self.admin_status_label.setProperty("admin_status", "false")
        self.style().polish(self.admin_status_label) # Stil sayfasının özelliğe göre güncellenmesini sağlar


    def update_current_dns_info(self):
        """Mevcut DNS ayarlarını alır ve görüntüler."""
        lang = DNSManagerApp.current_lang
        self.current_dns_data = get_current_dns_settings()
        info_text = ""
        if not self.current_dns_data or "Error" in self.current_dns_data:
            info_text = TRANSLATIONS[lang]['label_loading'] + "<br>"
            if "Error" in self.current_dns_data:
                info_text = self.current_dns_data["Error"] + "<br>"
            info_text += TRANSLATIONS[lang]['msg_platform_not_supported_dns_mod_text']
        else:
            for adapter, dns_list in self.current_dns_data.items():
                info_text += f"<b>{adapter}</b>:<br>"
                if dns_list:
                    for dns_ip in dns_list:
                        info_text += f"  - {dns_ip}<br>"
                else:
                    info_text += TRANSLATIONS[lang]['label_automatic_dhcp']
        self.current_dns_label.setText(info_text)

        # Ağ arayüzlerini de sonraki kullanımlar için al
        self.network_interfaces = get_network_interfaces()
        if not self.network_interfaces and platform.system() == "Windows":
             QMessageBox.warning(self, TRANSLATIONS[lang]['msg_no_network_adapters'], TRANSLATIONS[lang]['msg_no_network_adapters'], QMessageBox.Ok)


    def get_filtered_dns_providers(self):
        """Arama metnine ve filtreleme seçeneklerine göre DNS sağlayıcılarını filtreler."""
        all_providers = DNS_PROVIDERS + self.custom_dns_providers # Özel DNS'leri de dahil et
        search_text = self.search_input.text().strip().lower()
        show_ad_blockers = self.ad_block_checkbox.isChecked()

        filtered_providers = []
        for provider in all_providers:
            name_match = search_text in provider['name'].lower()
            ad_block_match = True
            if show_ad_blockers and not provider.get('ad_blocking', False):
                ad_block_match = False
            
            if name_match and ad_block_match:
                filtered_providers.append(provider)
        return filtered_providers

    def filter_dns_cards(self):
        """DNS kartlarını filtreler ve UI'yı günceller."""
        # Mevcut kartları temizle
        for i in reversed(range(self.dns_card_grid.count())):
            widget_item = self.dns_card_grid.itemAt(i)
            if widget_item:
                widget = widget_item.widget()
                if widget:
                    widget.deleteLater() # Widget'ı güvenli bir şekilde sil
        self.dns_cards = {} # Sözlüğü sıfırla

        filtered_providers = self.get_filtered_dns_providers()

        row = 0
        col = 0
        max_cols = 3 # Satır başına maksimum 3 kart

        for dns_data in filtered_providers:
            card = DNSCard(dns_data)
            card.selected.connect(self.on_dns_card_selected)
            self.dns_card_grid.addWidget(card, row, col)
            self.dns_cards[dns_data['name']] = card
            card.set_theme(self.current_theme)

            col += 1
            if col >= max_cols:
                col = 0
                row += 1
            
            # Ping işlemini başlat, tercih sırası: IPv4, sonra IPv6
            if dns_data.get('ipv4'):
                self.start_ping_for_card(card, dns_data['ipv4'][0], ip_version=4)
            elif dns_data.get('ipv6'):
                self.start_ping_for_card(card, dns_data['ipv6'][0], ip_version=6)
            else:
                card.update_ping(dns_data['name'], float('inf'), TRANSLATIONS[DNSManagerApp.current_lang]['label_ping_na'])


    def populate_dns_cards(self):
        """Tüm DNS kartlarını oluşturur ve düzenleyiciye ekler (filtreleme ile)."""
        self.filter_dns_cards() # Populate, filter_dns_cards'ı çağırarak yapılır.

    def start_ping_for_card(self, card, ip_address, ip_version):
        """Tek bir DNS kartı için ping iş parçacığını başlatır."""
        ping_thread = PingThread(card.dns_data['name'], ip_address, ip_version)
        ping_thread.ping_result.connect(self.collect_speed_test_result) # Direct to collect_speed_test_result
        ping_thread.finished.connect(self.task_completed)
        self.ping_threads.append(ping_thread)
        ping_thread.start()

    def on_dns_card_selected(self, dns_data):
        """Bir DNS kartı seçildiğinde çalışır."""
        self.selected_dns = dns_data
        for name, card in self.dns_cards.items():
            card.select(name == dns_data['name'])
        self.btn_apply_dns.setEnabled(True)

    def apply_selected_dns(self):
        """Seçilen DNS ayarlarını sisteme uygular."""
        lang = DNSManagerApp.current_lang
        if not self.selected_dns:
            QMessageBox.warning(self, TRANSLATIONS[lang]['msg_no_dns_selected_title'], TRANSLATIONS[lang]['msg_no_dns_selected_text'], QMessageBox.Ok)
            return

        if not is_admin():
            QMessageBox.warning(self, TRANSLATIONS[lang]['msg_admin_priv_required_title'],
                                TRANSLATIONS[lang]['msg_admin_priv_required_text'], QMessageBox.Ok)
            return

        if platform.system() != "Windows":
            QMessageBox.critical(self, TRANSLATIONS[lang]['msg_platform_not_supported_title'],
                                 TRANSLATIONS[lang]['msg_platform_not_supported_dns_mod_text'], QMessageBox.Ok)
            return

        ipv4_addresses = self.selected_dns.get('ipv4')
        ipv6_addresses = self.selected_dns.get('ipv6')
        doh_url = self.selected_dns.get('doh_url')
        dot_url = self.selected_dns.get('dot_url')

        if not ipv4_addresses and not ipv6_addresses and not doh_url and not dot_url:
            QMessageBox.warning(self, TRANSLATIONS[lang]['msg_invalid_dns_title'], TRANSLATIONS[lang]['msg_invalid_dns_text'], QMessageBox.Ok)
            return

        confirmation_text = TRANSLATIONS[lang]['msg_confirm_dns_change'].format(name=self.selected_dns['name'])
        if ipv4_addresses:
            confirmation_text += f"{TRANSLATIONS[lang]['label_ipv4']} {', '.join(ipv4_addresses)}<br>"
        if ipv6_addresses:
            confirmation_text += f"{TRANSLATIONS[lang]['label_ipv6']} {', '.join(ipv6_addresses)}<br>"
        if doh_url:
            confirmation_text += f"{TRANSLATIONS[lang]['label_doh']} {doh_url}<br>"
        if dot_url:
            confirmation_text += f"{TRANSLATIONS[lang]['label_dot']} {dot_url}<br>"

        reply = QMessageBox.question(self, TRANSLATIONS[lang]['msg_confirm_dns_change'],
                                     confirmation_text,
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            if doh_url or dot_url:
                QMessageBox.information(self, "DoH/DoT Bilgilendirme",
                                        TRANSLATIONS[lang]['msg_doh_dot_info'].format(name=self.selected_dns['name']), QMessageBox.Ok)
                # Eğer sadece DoH/DoT ise ve IP adresi yoksa buradan çık, aksi halde IP'leri uygula
                if not ipv4_addresses and not ipv6_addresses:
                    self.update_current_dns_info()
                    return

            success_adapters = []
            failed_adapters = []
            
            for adapter in self.network_interfaces:
                try:
                    # Mevcut DNS ayarlarını DHCP'ye sıfırla (temiz bir başlangıç için)
                    subprocess.run(["netsh", "interface", "ipv4", "set", "dnsservers", adapter, "dhcp"], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    subprocess.run(["netsh", "interface", "ipv6", "set", "dnsservers", adapter, "dhcp"], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    
                    if ipv4_addresses:
                        cmd_primary_v4 = ["netsh", "interface", "ipv4", "set", "dnsservers", adapter, "static", ipv4_addresses[0], "primary"]
                        subprocess.run(cmd_primary_v4, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                        if len(ipv4_addresses) > 1:
                            cmd_secondary_v4 = ["netsh", "interface", "ipv4", "add", "dnsservers", adapter, ipv4_addresses[1], "index=2"]
                            subprocess.run(cmd_secondary_v4, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    
                    if ipv6_addresses:
                        cmd_primary_v6 = ["netsh", "interface", "ipv6", "set", "dnsservers", adapter, "static", ipv6_addresses[0], "primary"]
                        subprocess.run(cmd_primary_v6, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                        if len(ipv6_addresses) > 1:
                            cmd_secondary_v6 = ["netsh", "interface", "ipv6", "add", "dnsservers", adapter, ipv6_addresses[1], "index=2"]
                            subprocess.run(cmd_secondary_v6, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    
                    success_adapters.append(adapter)

                except subprocess.CalledProcessError as e:
                    failed_adapters.append(f"{adapter} ({e.stderr.strip() if e.stderr else 'Bilinmeyen hata'})")
                except Exception as e:
                    failed_adapters.append(f"{adapter} (Genel Hata: {e})")

            if success_adapters:
                QMessageBox.information(self, TRANSLATIONS[lang]['msg_dns_apply_success'],
                                        TRANSLATIONS[lang]['msg_dns_apply_success'].format(adapters=', '.join(success_adapters)), QMessageBox.Ok)
            if failed_adapters:
                QMessageBox.critical(self, TRANSLATIONS[lang]['msg_dns_apply_partial_error'],
                                     TRANSLATIONS[lang]['msg_dns_apply_partial_error'].format(adapters='<br>'.join(failed_adapters)), QMessageBox.Ok)
            if not success_adapters and not failed_adapters:
                 QMessageBox.information(self, TRANSLATIONS[lang]['msg_dns_apply_no_change'], TRANSLATIONS[lang]['msg_dns_apply_no_change'], QMessageBox.Ok)

            self.update_current_dns_info() # Uygulamadan sonra mevcut DNS'i yenile

    def run_all_dns_speed_test(self):
        """Tüm DNS sağlayıcıları için hız testi başlatır."""
        lang = DNSManagerApp.current_lang
        if not is_admin():
            QMessageBox.warning(self, TRANSLATIONS[lang]['msg_admin_priv_required_title'],
                                TRANSLATIONS[lang]['msg_admin_priv_required_text'], QMessageBox.Ok)
            return

        if platform.system() != "Windows":
            QMessageBox.critical(self, TRANSLATIONS[lang]['msg_platform_not_supported_title'],
                                 TRANSLATIONS[lang]['msg_platform_not_supported_speed_test_text'], QMessageBox.Ok)
            return

        providers_to_test = self.get_filtered_dns_providers()
        if not providers_to_test:
            QMessageBox.information(self, TRANSLATIONS[lang]['msg_speed_test_no_providers'], TRANSLATIONS[lang]['msg_speed_test_no_providers'], QMessageBox.Ok)
            self.btn_speed_test.setEnabled(True)
            self.btn_gaming_mode.setEnabled(True)
            return

        self.btn_speed_test.setEnabled(False) # Butonu devre dışı bırak
        self.btn_gaming_mode.setEnabled(False) # Oyun modu butonunu da devre dışı bırak
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True) # İlerleme çubuğunu göster
        self.ping_results_for_speed_test = []
        
        for thread in self.ping_threads:
            thread.stop()
            thread.wait(100) # İş parçasının zarifçe durmasını beklemek için küçük bir süre ver
        self.ping_threads = []
        self.completed_tasks = 0

        for name, card in self.dns_cards.items(): # Sadece görünen kartları sıfırla
            card.ping_label.setText(TRANSLATIONS[lang]['label_ping_measuring'])
            card.ping_label.setProperty("ping_status", "na")
            self.style().polish(card.ping_label)
            card.ping_value = None

        total_tasks_count = len(providers_to_test)
        self.progress_bar.setRange(0, total_tasks_count)

        for dns_data in providers_to_test:
            ip_to_ping = None
            ip_version = 0
            if dns_data.get('ipv4'):
                ip_to_ping = dns_data['ipv4'][0]
                ip_version = 4
            elif dns_data.get('ipv6'):
                ip_to_ping = dns_data['ipv6'][0]
                ip_version = 6
            
            if ip_to_ping:
                ping_thread = PingThread(dns_data['name'], ip_to_ping, ip_version)
                ping_thread.ping_result.connect(self.collect_speed_test_result)
                ping_thread.finished.connect(self.task_completed)
                self.ping_threads.append(ping_thread)
                ping_thread.start()
            else:
                self.collect_speed_test_result(dns_data['name'], float('inf'), TRANSLATIONS[lang]['label_ping_na'])
                self.task_completed() # Ping yapılmayanlar için de görevi tamamla

    @pyqtSlot(str, float, str)
    def collect_speed_test_result(self, dns_name, ping_time, error_message):
        """Hız testi için ping sonuçlarını toplar ve UI'yı günceller."""
        self.ping_results_for_speed_test.append({
            "name": dns_name,
            "ping": ping_time,
            "error": error_message
        })

        # Belirli kartın ping etiketini güncelle
        if dns_name in self.dns_cards:
            self.dns_cards[dns_name].update_ping(dns_name, ping_time, error_message)


    @pyqtSlot()
    def task_completed(self):
        """Tamamlanan görev sayacını günceller ve tüm görevler bittiğinde sonuçları işler."""
        self.completed_tasks += 1
        self.progress_bar.setValue(self.completed_tasks)

        if self.progress_bar.maximum() > 0 and self.completed_tasks >= self.progress_bar.maximum(): # Tüm beklenen görevler tamamlandıysa
            self.btn_speed_test.setEnabled(True) # Butonu etkinleştir
            self.btn_gaming_mode.setEnabled(True) # Oyun modu butonunu etkinleştir
            self.progress_bar.setVisible(False) # İlerleme çubuğunu gizle
            self.show_speed_test_results()

    def show_speed_test_results(self):
        """Sıralanmış hız testi sonuçlarını görüntüler."""
        lang = DNSManagerApp.current_lang
        # Ping değerine göre sırala (sonsuz değerler sona gelir)
        # Sadece geçerli ping değeri olanları sırala, N/A veya başarısız olanları sona at.
        sorted_results = sorted(self.ping_results_for_speed_test, key=lambda x: x['ping'] if x['ping'] >= 0 else float('inf'))

        result_message = f"<b>{TRANSLATIONS[lang]['msg_speed_test_results_title']}</b><br><br>"
        if not sorted_results:
            result_message += TRANSLATIONS[lang]['msg_speed_test_results_no_test']
        else:
            for i, res in enumerate(sorted_results):
                if res['ping'] >= 0 and res['ping'] != float('inf'):
                    result_message += f"{i+1}. {res['name']}: <b>{int(res['ping'])} ms</b><br>"
                else:
                    error_text = res['error'] if res['error'] else TRANSLATIONS[lang]['label_ping_failed_generic']
                    result_message += f"{i+1}. {res['name']}: {TRANSLATIONS[lang]['label_ping_na']} veya Hata ({error_text})<br>"

        # Eğer oyun modu aktifse, buradan sonra en hızlı DNS'i uygulayalım.
        if hasattr(self, '_apply_fastest_after_speed_test') and self._apply_fastest_after_speed_test:
            self._apply_fastest_after_speed_test = False # Tek kullanımlık flag
            if sorted_results and sorted_results[0]['ping'] != float('inf'):
                fastest_dns_name = sorted_results[0]['name']
                fastest_dns_data = None
                # Orijinal DNS_PROVIDERS veya custom_dns_providers listelerinde bul
                for provider in DNS_PROVIDERS + self.custom_dns_providers:
                    if provider['name'] == fastest_dns_name:
                        fastest_dns_data = provider
                        break
                
                if fastest_dns_data:
                    self.selected_dns = fastest_dns_data
                    # DNS kartları UI'da görsel olarak seçili hale getir
                    for name, card in self.dns_cards.items():
                        card.select(name == fastest_dns_data['name'])
                    self.apply_selected_dns() # En hızlı DNS'i uygula
                    QMessageBox.information(self, TRANSLATIONS[lang]['msg_gaming_mode_active'],
                                            TRANSLATIONS[lang]['msg_gaming_mode_active'].format(name=fastest_dns_name),
                                            QMessageBox.Ok)
                else:
                    QMessageBox.warning(self, TRANSLATIONS[lang]['msg_gaming_mode_error'], TRANSLATIONS[lang]['msg_gaming_mode_error'], QMessageBox.Ok)
            else:
                QMessageBox.warning(self, TRANSLATIONS[lang]['msg_gaming_mode_error'], TRANSLATIONS[lang]['msg_gaming_mode_no_results'], QMessageBox.Ok)
        else:
            # Normal hız testi sonuçlarını göster
            QMessageBox.information(self, TRANSLATIONS[lang]['msg_speed_test_results_title'], result_message, QMessageBox.Ok)


    def activate_gaming_mode(self):
        """Oyun Modunu etkinleştirir: En hızlı DNS'i bulur ve uygular."""
        lang = DNSManagerApp.current_lang
        if not is_admin():
            QMessageBox.warning(self, TRANSLATIONS[lang]['msg_admin_priv_required_title'],
                                TRANSLATIONS[lang]['msg_admin_priv_required_text'], QMessageBox.Ok)
            return
        
        QMessageBox.information(self, TRANSLATIONS[lang]['button_gaming_mode'],
                                TRANSLATIONS[lang]['msg_gaming_mode_activating'],
                                QMessageBox.Ok)
        
        self.run_all_dns_speed_test()
        self._apply_fastest_after_speed_test = True # Oyun modu bayrağını ayarla

    def flush_dns_cache(self):
        """DNS önbelleğini temizler."""
        lang = DNSManagerApp.current_lang
        if not is_admin():
            QMessageBox.warning(self, TRANSLATIONS[lang]['msg_admin_priv_required_title'],
                                TRANSLATIONS[lang]['msg_admin_priv_required_text'], QMessageBox.Ok)
            return

        if platform.system() != "Windows":
            QMessageBox.critical(self, TRANSLATIONS[lang]['msg_platform_not_supported_title'],
                                 TRANSLATIONS[lang]['msg_platform_not_supported_flush_text'], QMessageBox.Ok)
            return

        try:
            subprocess.run(["ipconfig", "/flushdns"], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            QMessageBox.information(self, TRANSLATIONS[lang]['msg_flush_success'], TRANSLATIONS[lang]['msg_flush_success'], QMessageBox.Ok)
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, TRANSLATIONS[lang]['msg_flush_error'], TRANSLATIONS[lang]['msg_flush_error'].format(error=e.stderr.strip() if e.stderr else 'Bilinmeyen hata'), QMessageBox.Ok)
        except FileNotFoundError:
            QMessageBox.critical(self, TRANSLATIONS[lang]['msg_ipconfig_not_found'], TRANSLATIONS[lang]['msg_ipconfig_not_found'], QMessageBox.Ok)
        except Exception as e:
            QMessageBox.critical(self, TRANSLATIONS[lang]['msg_settings_load_error_unexpected'], TRANSLATIONS[lang]['msg_settings_load_error_unexpected'].format(error=e), QMessageBox.Ok)

    def restore_dhcp_dns(self):
        """DNS ayarlarını otomatik (DHCP) olarak geri yükler."""
        lang = DNSManagerApp.current_lang
        if not is_admin():
            QMessageBox.warning(self, TRANSLATIONS[lang]['msg_admin_priv_required_title'],
                                TRANSLATIONS[lang]['msg_admin_priv_required_text'], QMessageBox.Ok)
            return

        if platform.system() != "Windows":
            QMessageBox.critical(self, TRANSLATIONS[lang]['msg_platform_not_supported_title'],
                                 TRANSLATIONS[lang]['msg_platform_not_supported_dhcp_text'], QMessageBox.Ok)
            return

        reply = QMessageBox.question(self, TRANSLATIONS[lang]['button_restore_dhcp'],
                                     TRANSLATIONS[lang]['msg_dhcp_confirm'],
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            success_adapters = []
            failed_adapters = []
            for adapter in self.network_interfaces:
                try:
                    cmd_v4 = ["netsh", "interface", "ipv4", "set", "dnsservers", adapter, "dhcp"]
                    subprocess.run(cmd_v4, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    cmd_v6 = ["netsh", "interface", "ipv6", "set", "dnsservers", adapter, "dhcp"]
                    subprocess.run(cmd_v6, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    success_adapters.append(adapter)
                except subprocess.CalledProcessError as e:
                    failed_adapters.append(f"{adapter} ({e.stderr.strip() if e.stderr else 'Bilinmeyen hata'})")
                except Exception as e:
                    failed_adapters.append(f"{adapter} (Genel Hata: {e})")
            
            if success_adapters:
                QMessageBox.information(self, TRANSLATIONS[lang]['msg_dhcp_success'],
                                        TRANSLATIONS[lang]['msg_dhcp_success'].format(adapters=', '.join(success_adapters)), QMessageBox.Ok)
            if failed_adapters:
                QMessageBox.critical(self, TRANSLATIONS[lang]['msg_dhcp_partial_error'],
                                     TRANSLATIONS[lang]['msg_dhcp_partial_error'].format(adapters='<br>'.join(failed_adapters)), QMessageBox.Ok)
            if not success_adapters and not failed_adapters:
                QMessageBox.information(self, TRANSLATIONS[lang]['msg_dhcp_no_revert'], TRANSLATIONS[lang]['msg_dhcp_no_revert'], QMessageBox.Ok)
            
            self.update_current_dns_info() # Mevcut DNS'i yenile

    def add_custom_dns_provider(self):
        """Kullanıcının özel bir DNS sağlayıcısı eklemesine olanak tanır (IPv4, IPv6, DoH, DoT)."""
        lang = DNSManagerApp.current_lang
        name, ok_name = QInputDialog.getText(self, TRANSLATIONS[lang]['button_add_custom'], TRANSLATIONS[lang]['input_custom_dns_name'])
        if not ok_name or not name.strip():
            return

        ipv4_str, ok_ipv4 = QInputDialog.getText(self, TRANSLATIONS[lang]['button_add_custom'], TRANSLATIONS[lang]['input_ipv4_addresses'])
        ipv6_str, ok_ipv6 = QInputDialog.getText(self, TRANSLATIONS[lang]['button_add_custom'], TRANSLATIONS[lang]['input_ipv6_addresses'])
        doh_url, ok_doh = QInputDialog.getText(self, TRANSLATIONS[lang]['button_add_custom'], TRANSLATIONS[lang]['input_doh_url'])
        dot_url, ok_dot = QInputDialog.getText(self, TRANSLATIONS[lang]['button_add_custom'], TRANSLATIONS[lang]['input_dot_url'])
        
        ipv4_list = [ip.strip() for ip in ipv4_str.split(',') if ip.strip()] if ipv4_str else []
        ipv6_list = [ip_v6.strip() for ip_v6 in ipv6_str.split(',') if ip_v6.strip()] if ipv6_str else []

        # IP adreslerini doğrula
        valid_ipv4s = []
        for ip in ipv4_list:
            if IPV4_PATTERN.match(ip):
                valid_ipv4s.append(ip)
            else:
                QMessageBox.warning(self, TRANSLATIONS[lang]['msg_invalid_ipv4'], TRANSLATIONS[lang]['msg_invalid_ipv4'].format(ip=ip), QMessageBox.Ok)
        
        valid_ipv6s = []
        for ip in ipv6_list:
            if IPV6_PATTERN.match(ip):
                valid_ipv6s.append(ip)
            else:
                QMessageBox.warning(self, TRANSLATIONS[lang]['msg_invalid_ipv6'], TRANSLATIONS[lang]['msg_invalid_ipv6'].format(ip=ip), QMessageBox.Ok)

        if not valid_ipv4s and not valid_ipv6s and not doh_url.strip() and not dot_url.strip():
            QMessageBox.warning(self, TRANSLATIONS[lang]['msg_invalid_input_title'], TRANSLATIONS[lang]['msg_invalid_input_no_data'], QMessageBox.Ok)
            return

        new_provider = {
            "name": name.strip(),
            "ipv4": valid_ipv4s if valid_ipv4s else None,
            "ipv6": valid_ipv6s if valid_ipv6s else None,
            "doh_url": doh_url.strip() if doh_url.strip() else None,
            "dot_url": dot_url.strip() if dot_url.strip() else None,
            "ad_blocking": False, # Varsayılan olarak reklam engelleme yok (kullanıcı daha sonra manuel güncelleyebilir)
            "dnssec_enabled": False # Varsayılan olarak DNSSEC bilinmiyor
        }
        
        self.custom_dns_providers.append(new_provider)
        self.populate_dns_cards() # Kartları yeniden oluştur
        self.save_settings() # Ayarları kaydet
        QMessageBox.information(self, TRANSLATIONS[lang]['msg_custom_dns_added_success'],
                                TRANSLATIONS[lang]['msg_custom_dns_added_success'].format(name=name.strip()), QMessageBox.Ok)

    def load_settings(self):
        """Ayarları (özel DNS sağlayıcıları) bir dosyadan yükler."""
        lang = DNSManagerApp.current_lang
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if "custom_dns_providers" in data and isinstance(data["custom_dns_providers"], list):
                        self.custom_dns_providers = data["custom_dns_providers"]
            except json.JSONDecodeError:
                QMessageBox.critical(self, TRANSLATIONS[lang]['msg_settings_load_error_decode'], TRANSLATIONS[lang]['msg_settings_load_error_decode'].format(file=self.settings_file), QMessageBox.Ok)
            except IOError as e:
                QMessageBox.critical(self, TRANSLATIONS[lang]['msg_settings_load_error_io'], TRANSLATIONS[lang]['msg_settings_load_error_io'].format(error=e), QMessageBox.Ok)
            except Exception as e:
                QMessageBox.critical(self, TRANSLATIONS[lang]['msg_settings_load_error_unexpected'], TRANSLATIONS[lang]['msg_settings_load_error_unexpected'].format(error=e), QMessageBox.Ok)

    def save_settings(self):
        """Ayarları (özel DNS sağlayıcıları) bir dosyaya kaydeder."""
        lang = DNSManagerApp.current_lang
        try:
            with open(self.settings_file, 'w', encoding='utf-8') as f:
                json.dump({"custom_dns_providers": self.custom_dns_providers}, f, indent=4)
        except IOError as e:
            QMessageBox.critical(self, TRANSLATIONS[lang]['msg_settings_save_error_io'], TRANSLATIONS[lang]['msg_settings_save_error_io'].format(error=e), QMessageBox.Ok)
        except Exception as e:
            QMessageBox.critical(self, TRANSLATIONS[lang]['msg_settings_save_error_unexpected'], TRANSLATIONS[lang]['msg_settings_save_error_unexpected'].format(error=e), QMessageBox.Ok)

    def backup_settings(self):
        """Mevcut ayarları ve özel DNS'leri bir dosyaya yedekler."""
        lang = DNSManagerApp.current_lang
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, TRANSLATIONS[lang]['msg_backup_settings_title'], "dns_manager_backup.json", "JSON Files (*.json)", options=options)
        if file_name:
            try:
                backup_data = {"custom_dns_providers": self.custom_dns_providers} # Sadece özel DNS'leri yedekle
                with open(file_name, 'w', encoding='utf-8') as f:
                    json.dump(backup_data, f, indent=4)
                QMessageBox.information(self, TRANSLATIONS[lang]['msg_backup_success'], TRANSLATIONS[lang]['msg_backup_success'].format(file_name=os.path.basename(file_name)), QMessageBox.Ok)
            except IOError as e:
                QMessageBox.critical(self, TRANSLATIONS[lang]['msg_backup_error'], TRANSLATIONS[lang]['msg_backup_error'].format(error=e), QMessageBox.Ok)
            except Exception as e:
                QMessageBox.critical(self, TRANSLATIONS[lang]['msg_backup_error_unexpected'], TRANSLATIONS[lang]['msg_backup_error_unexpected'].format(error=e), QMessageBox.Ok)

    def restore_settings(self):
        """Daha önce yedeklenmiş ayarları ve özel DNS'leri bir dosyadan geri yükler."""
        lang = DNSManagerApp.current_lang
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, TRANSLATIONS[lang]['msg_restore_settings_title'], "", "JSON Files (*.json)", options=options)
        if file_name:
            try:
                with open(file_name, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if "custom_dns_providers" in data and isinstance(data["custom_dns_providers"], list):
                        self.custom_dns_providers = data["custom_dns_providers"]
                        self.populate_dns_cards() # UI'yı güncelle
                        self.save_settings() # Geri yüklenen ayarları kalıcı olarak kaydet
                        QMessageBox.information(self, TRANSLATIONS[lang]['msg_restore_success'], TRANSLATIONS[lang]['msg_restore_success'].format(file_name=os.path.basename(file_name)), QMessageBox.Ok)
                    else:
                        QMessageBox.warning(self, TRANSLATIONS[lang]['msg_restore_invalid_file'], TRANSLATIONS[lang]['msg_restore_invalid_file'], QMessageBox.Ok)
            except json.JSONDecodeError:
                QMessageBox.critical(self, TRANSLATIONS[lang]['msg_restore_error_decode'], TRANSLATIONS[lang]['msg_restore_error_decode'].format(file=file_name), QMessageBox.Ok)
            except IOError as e:
                QMessageBox.critical(self, TRANSLATIONS[lang]['msg_restore_error_io'], TRANSLATIONS[lang]['msg_restore_error_io'].format(error=e), QMessageBox.Ok)
            except Exception as e:
                QMessageBox.critical(self, TRANSLATIONS[lang]['msg_restore_error_unexpected'], TRANSLATIONS[lang]['msg_restore_error_unexpected'].format(error=e), QMessageBox.Ok)


    def closeEvent(self, event):
        """Uygulama kapatıldığında çalışan ping iş parçacıklarını durdurur ve ayarları kaydeder."""
        self.save_settings() # Kapanışta özel ayarları kaydet
        for thread in self.ping_threads:
            thread.stop()
            thread.wait(1000) # İş parçasının bitmesini beklemek için 1 saniye bekle
        super().closeEvent(event)

# --- Ana Çalıştırma Bloğu ---
if __name__ == "__main__":
    # QApplication örneğini oluştur
    app = QApplication(sys.argv)
    # Uygulama penceresini oluştur
    window = DNSManagerApp()
    # Pencereyi göster
    window.show()
    # Uygulamanın olay döngüsünü başlat
    sys.exit(app.exec_())
