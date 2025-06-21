import sys
import subprocess
import re
import json
import os
import platform # Added to check OS

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QGridLayout, QScrollArea, QFrame, QSizePolicy, QMessageBox, QInputDialog,
    QProgressBar, QGroupBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, pyqtSlot, QTimer
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor

# --- DNS Sağlayıcıları Verisi ---
# Uygulamada gösterilecek DNS sağlayıcıları listesi
DNS_PROVIDERS = [
    {
        "name": "Google DNS",
        "ipv4": ["8.8.8.8", "8.8.4.4"],
        "doh_url": None,
        "dot_url": None,
        "ad_blocking": False
    },
    {
        "name": "Cloudflare DNS",
        "ipv4": ["1.1.1.1", "1.0.0.1"],
        "doh_url": "https://cloudflare-dns.com/dns-query",
        "dot_url": "tls://1.1.1.1",
        "ad_blocking": False
    },
    {
        "name": "AdGuard DNS (Varsayılan)",
        "ipv4": ["94.140.14.14", "94.140.15.15"],
        "doh_url": "https://dns.adguard.com/dns-query",
        "dot_url": "tls://dns.adguard.com",
        "ad_blocking": True
    },
    {
        "name": "AdGuard DNS (Aile)",
        "ipv4": ["94.140.14.15", "94.140.15.16"],
        "doh_url": "https://dns-family.adguard.com/dns-query",
        "dot_url": "tls://dns-family.adguard.com",
        "ad_blocking": True
    },
    {
        "name": "OpenDNS Home",
        "ipv4": ["208.67.222.222", "208.67.220.220"],
        "doh_url": None,
        "dot_url": None,
        "ad_blocking": False
    },
    {
        "name": "Quad9 (Filtresiz, DNSSEC)",
        "ipv4": ["9.9.9.9", "149.112.112.112"],
        "doh_url": "https://dns.quad9.net/dns-query",
        "dot_url": "tls://dns.quad9.net",
        "ad_blocking": True # Kötü amaçlı yazılım engelleme
    },
    {
        "name": "Yandex DNS (Temel)",
        "ipv4": ["77.88.8.8", "77.88.8.1"],
        "doh_url": None,
        "dot_url": None,
        "ad_blocking": False
    },
    {
        "name": "CleanBrowsing (Aile Filtresi)",
        "ipv4": ["185.228.168.168", "185.228.169.168"],
        "doh_url": "https://doh.cleanbrowsing.org/doh/family-filter/",
        "dot_url": None,
        "ad_blocking": True
    },
    {
        "name": "Comodo Secure DNS",
        "ipv4": ["8.26.56.26", "8.20.247.20"],
        "doh_url": None,
        "dot_url": None,
        "ad_blocking": True # Kötü amaçlı yazılım/kimlik avı engelleme
    },
    {
        "name": "Neustar DNS (Advantage)",
        "ipv4": ["156.154.70.1", "156.154.71.1"],
        "doh_url": None,
        "dot_url": None,
        "ad_blocking": True # Kötü amaçlı yazılım/kimlik avı engelleme
    },
    {
        "name": "DNS.Watch",
        "ipv4": ["84.200.69.80", "84.200.70.40"],
        "doh_url": None,
        "dot_url": None,
        "ad_blocking": False
    },
    {
        "name": "Mullvad DNS (Reklam Engelleyici)",
        "ipv4": ["193.138.218.74", "193.138.218.75"],
        "doh_url": "https://adblock.dns.mullvad.net/dns-query",
        "dot_url": None,
        "ad_blocking": True
    },
    {
        "name": "Alternate DNS",
        "ipv4": ["76.76.19.19", "76.76.19.20"],
        "doh_url": None,
        "dot_url": None,
        "ad_blocking": True # Kötü amaçlı yazılım/reklamlar
    },
    # CyberGhost DNS ve ControlD gibi sağlayıcılar genellikle özel yapılandırma veya VPN gerektirdiğinden,
    # doğrudan genel bir IPv4 sağlamazlar. Bu örnekte, sadece DoH URL'leri veya placeholder IP'ler
    # ile eklendiler ve kullanıcının manuel yapılandırması gerektiği bilgisi verildi.
    {
        "name": "CyberGhost DNS",
        "ipv4": ["38.113.1.2", "198.18.0.2"], # Örnek placeholder IP'ler
        "doh_url": None,
        "dot_url": None,
        "ad_blocking": False
    },
    {
        "name": "ControlD (Özel URL ile)",
        "ipv4": None,
        "doh_url": "https://your-unique-id.controld.com/dns-query", # Kullanıcının kendi URL'sini girmesi gerekir
        "dot_url": None,
        "ad_blocking": True # Özelleştirilebilir
    }
]

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
    return False # Non-Windows systems don't have this check

def get_current_dns_settings():
    """
    Windows'taki tüm ağ bağdaştırıcıları için mevcut DNS ayarlarını alır.
    Anahtarları bağdaştırıcı adları ve değerleri DNS sunucuları listeleri olan bir sözlük döndürür.
    """
    # PowerShell komutu, her bağdaştırıcının DNS sunucularını listeler.
    cmd = ["powershell", "Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses"]
    try:
        # subprocess.CREATE_NO_WINDOW: Komut çalışırken PowerShell penceresinin açılmasını engeller.
        process = subprocess.run(cmd, capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        output = process.stdout
        # print("PowerShell Çıkışı (DNS):", output) # Hata ayıklama için

        dns_settings = {}
        lines = output.splitlines()
        # Çıktının her satırını işleriz.
        for line in lines:
            line = line.strip()
            # Başlıkları veya ayırıcı çizgileri atla
            if "----" in line or "InterfaceAlias" in line:
                continue

            # Bağdaştırıcı adını ve DNS adreslerini yakalamak için regex kullanırız.
            # Örneğin: Ethernet    {8.8.8.8, 8.8.4.4}
            match_alias = re.match(r"(\S+)\s*{(.*)}", line)
            if match_alias:
                alias = match_alias.group(1).strip()
                addresses_str = match_alias.group(2).strip()
                # Adresleri virgülle ayırır ve boş olanları filtreler
                dns_servers = [addr.strip() for addr in addresses_str.split(',') if addr.strip()]
                dns_settings[alias] = dns_servers
            else:
                # Otomatik yapılandırılmış (DHCP) veya başka bir formatta olan bağdaştırıcıları yakala
                match_dhcp = re.match(r"(\S+)\s*$", line)
                if match_dhcp and match_dhcp.group(1).strip():
                     # Eğer sadece bağdaştırıcı adı varsa, DHCP olarak kabul et
                     dns_settings[match_dhcp.group(1).strip()] = [] # Boş liste DHCP'yi temsil eder
        return dns_settings
    except subprocess.CalledProcessError as e:
        print(f"DNS ayarları alınırken hata: {e}")
        return {"Hata": f"DNS ayarları alınamadı: {e.stderr}"}
    except FileNotFoundError:
        print("PowerShell bulunamadı. Lütfen PATH'inizde olduğundan emin olun.")
        return {"Hata": "PowerShell bulunamadı. DNS ayarları alınamıyor."}
    except Exception as e:
        print(f"Beklenmedik hata: {e}")
        return {"Hata": f"Beklenmedik hata: {e}"}


def get_network_interfaces():
    """
    Windows'taki aktif ağ bağdaştırıcılarının (adlarının) bir listesini alır.
    netsh komutları için kullanılır.
    """
    cmd = ["netsh", "interface", "ip", "show", "interface"]
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        output = process.stdout
        interfaces = []
        # Her satırı işler, "Bağdaştırıcı Adı" veya "Arayüz Adı" formatlarını arar.
        for line in output.splitlines():
            # Arayüz adını tırnak içinde arar (örn: "Ethernet")
            match = re.search(r"\"(.+)\"\s*$", line.strip())
            if match:
                interfaces.append(match.group(1).strip())
            # "Yerel Ağ Bağlantısı" gibi tırnaksız adları arar
            elif "Bağdaştırıcı Adı" in line or "Interface Name" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    name = parts[1].strip()
                    if name and name != "Loopback Pseudo-Interface 1": # Loopback'i hariç tut
                        interfaces.append(name)
        return interfaces
    except subprocess.CalledProcessError as e:
        print(f"Ağ arayüzleri alınırken hata: {e}")
        return []
    except FileNotFoundError:
        print("Netsh bulunamadı. Lütfen PATH'inizde olduğundan emin olun.")
        return []
    except Exception as e:
        print(f"Beklenmedik hata: {e}")
        return []

# --- Ping İş Parçacığı ---
class PingThread(QThread):
    # DNS adı ve ping süresini (float) sinyal olarak yayınlar
    ping_result = pyqtSignal(str, float)
    finished = pyqtSignal() # İş parçasının tamamlandığını bildiren sinyal

    def __init__(self, dns_name, ip_address):
        super().__init__()
        self.dns_name = dns_name
        self.ip_address = ip_address
        self._is_running = True # İş parçasının durdurulup durdurulmadığını kontrol eder

    def run(self):
        """Ping komutunu çalıştırır ve sonucu sinyal olarak yayınlar."""
        if not self._is_running:
            return

        cmd = ["ping", "-n", "4", self.ip_address] # 4 kez ping atar
        try:
            # subprocess.CREATE_NO_WINDOW: Komut çalışırken pencerenin açılmasını engeller.
            process = subprocess.run(cmd, capture_output=True, text=True, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            output = process.stdout
            # print(f"Ping Çıkışı ({self.ip_address}):\n{output}") # Hata ayıklama için

            # Hem Türkçe hem de İngilizce Windows çıktılarını desteklemek için regex
            match = re.search(r"Ortalama = (\d+)ms|Average = (\d+)ms", output)
            if match:
                # Hangi grubun eşleştiğini kontrol et ve değeri al
                avg_ping = float(match.group(1) if match.group(1) else match.group(2))
                self.ping_result.emit(self.dns_name, avg_ping)
            else:
                self.ping_result.emit(self.dns_name, -1.0) # Başarısızlığı veya ortalama bulunamadığını gösterir
        except subprocess.CalledProcessError:
            self.ping_result.emit(self.dns_name, -1.0) # Ping komutu başarısız oldu
        except FileNotFoundError:
            self.ping_result.emit(self.dns_name, -2.0) # Ping komutu bulunamadı
        except Exception as e:
            print(f"Ping hatası ({self.ip_address}): {e}")
            self.ping_result.emit(self.dns_name, -1.0) # Genel hata
        finally:
            self.finished.emit() # İş parçasının tamamlandığını bildir

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

    def init_ui(self):
        """Kullanıcı arayüzünü başlatır ve stilleri ayarlar."""
        self.setFrameShape(QFrame.StyledPanel) # Çerçeve şeklini ayarlar
        self.setFrameShadow(QFrame.Raised) # Çerçeve gölgesini yükseltir
        self.setLineWidth(1) # Çerçeve genişliğini ayarlar
        self.setObjectName("dnsCard") # CSS seçicisi için objectName ayarlar
        self.setStyleSheet("""
            QFrame#dnsCard {
                background-color: #f8f9fa; /* Hafif arka plan */
                border: 1px solid #dee2e6; /* Hafif kenarlık */
                border-radius: 12px; /* Daha yuvarlak köşeler */
                padding: 15px;
                transition: all 0.2s ease-in-out; /* Fare üzerine gelme efekti için geçiş */
            }
            QFrame#dnsCard:hover {
                background-color: #e9ecef;
                border: 1px solid #adb5bd;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); /* Hafif gölge */
            }
            QFrame#dnsCard[selected="true"] { /* Seçili kart için stil */
                border: 2px solid #007bff; /* Vurgulu kenarlık */
                background-color: #e6f2ff; /* Hafif mavi arka plan */
                box-shadow: 0 4px 12px rgba(0, 123, 255, 0.2); /* Mavi gölge */
            }
            QLabel {
                font-size: 14px;
                color: #495057; /* Koyu gri metin */
            }
            QLabel.name_label {
                font-size: 16px;
                font-weight: bold;
                color: #212529; /* Daha koyu başlık metni */
                margin-bottom: 5px;
            }
            QLabel.ad_block_label {
                font-size: 15px;
                color: #28a745; /* Yeşil renk */
                font-weight: bold;
                margin-top: 5px;
            }
            QLabel.ping_label {
                font-size: 13px;
                color: #6c757d; /* Açık gri ping metni */
                margin-top: 8px;
            }
        """)
        self.setFixedSize(280, 180) # Kartlar için sabit boyut

        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(5)

        name_label = QLabel(self.dns_data['name'])
        name_label.setObjectName("name_label")
        layout.addWidget(name_label)

        if self.dns_data['ad_blocking']:
            ad_block_label = QLabel("🛡️ Reklam ve Kötü Amaçlı Yazılım Engelleme")
            ad_block_label.setObjectName("ad_block_label")
            layout.addWidget(ad_block_label)
        else:
            # Yer tutucu ekle, böylece tüm kartlar aynı yüksekliğe sahip olur
            layout.addWidget(QLabel(" "))

        if self.dns_data['ipv4']:
            ipv4_label = QLabel(f"IPv4: {', '.join(self.dns_data['ipv4'])}")
            layout.addWidget(ipv4_label)
        else:
            layout.addWidget(QLabel("IPv4: Yok")) # IPv4 yoksa belirt

        if self.dns_data['doh_url']:
            # URL'nin sadece alan adını göster, tam URL'yi araç ipucuna ekle
            doh_display = self.dns_data['doh_url'].replace("https://", "").replace("/dns-query", "").split('/')[0]
            doh_label = QLabel(f"DoH: {doh_display}...")
            doh_label.setToolTip(self.dns_data['doh_url']) # Tam URL fare üzerine gelince gösterilir
            layout.addWidget(doh_label)
        else:
            layout.addWidget(QLabel("DoH: Yok"))

        if self.dns_data['dot_url']:
            dot_display = self.dns_data['dot_url'].replace("tls://", "").split('/')[0]
            dot_label = QLabel(f"DoT: {dot_display}...")
            dot_label.setToolTip(self.dns_data['dot_url'])
            layout.addWidget(dot_label)
        else:
            layout.addWidget(QLabel("DoT: Yok"))

        self.ping_label = QLabel("Ping: Ölçülüyor...")
        self.ping_label.setObjectName("ping_label")
        layout.addWidget(self.ping_label)

        self.setLayout(layout)

    @pyqtSlot(str, float)
    def update_ping(self, dns_name, ping_time):
        """Ping sonucunu karta yansıtır."""
        if dns_name == self.dns_data['name']:
            if ping_time >= 0 and ping_time != float('inf'): # Ping başarılı ise
                self.ping_value = ping_time
                self.ping_label.setText(f"Ping: <b>{int(ping_time)} ms</b>")
                self.ping_label.setStyleSheet("color: #007bff;") # Başarı için mavi
            elif ping_time == float('inf'): # Ping yapılamaz (örn. IPv4 yok)
                self.ping_value = float('inf')
                self.ping_label.setText("Ping: N/A (IPv4 Yok)")
                self.ping_label.setStyleSheet("color: #6c757d;") # Gri
            elif ping_time == -1.0: # Ping başarısız oldu
                self.ping_value = float('inf') # Sıralama için sonsuz olarak ayarla
                self.ping_label.setText("Ping: Başarısız")
                self.ping_label.setStyleSheet("color: #dc3545;") # Başarısızlık için kırmızı
            elif ping_time == -2.0: # Ping komutu bulunamadı
                self.ping_value = float('inf')
                self.ping_label.setText("Ping: Komut Bulunamadı")
                self.ping_label.setStyleSheet("color: #ffc107;") # Uyarı için sarı

    def mousePressEvent(self, event):
        """Kart tıklandığında seçildi sinyalini yayınlar."""
        self.selected.emit(self.dns_data)
        super().mousePressEvent(event)

    def select(self, is_selected):
        """Kartın seçili durumunu ayarlar ve stilini günceller."""
        self.setProperty("selected", is_selected)
        self.style().polish(self) # Stil sayfasının özelliğe göre güncellenmesini sağlar

# --- Ana Uygulama Penceresi ---
class DNSManagerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.current_dns_data = None
        self.network_interfaces = []
        self.ping_threads = [] # Çalışan ping iş parçacıklarını saklar
        self.selected_dns = None # Seçili DNS sağlayıcısı verisi
        self.dns_cards = {} # DNS kartı widget'larını isme göre saklar
        self.init_ui()
        self.check_admin_status() # Yönetici yetkisini kontrol et
        self.update_current_dns_info() # Mevcut DNS bilgilerini al ve göster
        self.populate_dns_cards() # DNS kartlarını oluştur ve doldur

    def init_ui(self):
        """Ana pencerenin kullanıcı arayüzünü başlatır."""
        self.setWindowTitle("DNS Yönetici")
        self.setMinimumSize(1000, 700) # Minimum pencere boyutu
        self.setStyleSheet("""
            QWidget {
                font-family: 'Inter', sans-serif;
                background-color: #f4f6f9; /* Çok hafif gri arka plan */
                color: #343a40; /* Koyu gri metin */
            }
            QPushButton {
                background-color: #007bff; /* Mavi düğme */
                color: white;
                border: none;
                padding: 12px 25px;
                border-radius: 8px; /* Yuvarlak köşeler */
                font-size: 15px;
                font-weight: bold;
                transition: background-color 0.2s ease;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); /* Hafif gölge */
            }
            QPushButton:hover {
                background-color: #0056b3; /* Üzerine gelince daha koyu mavi */
            }
            QPushButton:pressed {
                background-color: #004085; /* Basınca daha da koyu */
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
                box-shadow: none;
            }
            QGroupBox {
                border: 1px solid #ced4da; /* Açık gri kenarlık */
                border-radius: 10px;
                margin-top: 15px;
                padding: 15px;
                font-weight: bold;
                background-color: #ffffff; /* Beyaz grup kutusu arka planı */
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 8px;
                background-color: #e9ecef; /* Başlık arka planı */
                border-radius: 5px;
                color: #495057; /* Başlık metin rengi */
                font-size: 15px;
            }
            QLabel {
                font-size: 14px;
                color: #343a40;
            }
            QLabel#adminStatusLabel { /* Özel etiket için objectName */
                font-weight: bold;
                padding: 5px;
                border-radius: 5px;
            }
            QProgressBar {
                border: 1px solid #ced4da;
                border-radius: 5px;
                text-align: center;
                background-color: #e9ecef;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #28a745; /* Yeşil dolgu */
                border-radius: 5px;
            }
        """)

        main_layout = QHBoxLayout(self) # Ana düzenleyici

        # --- Sol Panel (Yan Çubuk) ---
        left_panel_layout = QVBoxLayout()
        left_panel_layout.setSpacing(20)
        left_panel_layout.setAlignment(Qt.AlignTop)
        left_panel_widget = QWidget()
        left_panel_widget.setFixedWidth(320) # Sabit genişlik
        left_panel_widget.setLayout(left_panel_layout)
        left_panel_widget.setStyleSheet("background-color: #ffffff; border-right: 1px solid #e9ecef; padding: 20px;")

        # Mevcut DNS Ayarları Grubu
        current_dns_group = QGroupBox("Mevcut DNS Ayarları")
        current_dns_layout = QVBoxLayout()
        self.current_dns_label = QLabel("Yükleniyor...")
        self.current_dns_label.setWordWrap(True) # Uzun metinleri sarar
        current_dns_layout.addWidget(self.current_dns_label)
        current_dns_group.setLayout(current_dns_layout)
        left_panel_layout.addWidget(current_dns_group)

        # İşlemler Grubu
        actions_group = QGroupBox("İşlemler")
        actions_layout = QVBoxLayout()
        actions_layout.setSpacing(10)

        self.btn_speed_test = QPushButton("Tümünü Hız Testi Yap")
        self.btn_speed_test.clicked.connect(self.run_all_dns_speed_test)
        actions_layout.addWidget(self.btn_speed_test)

        self.btn_flush_dns = QPushButton("DNS Cache Temizle")
        self.btn_flush_dns.clicked.connect(self.flush_dns_cache)
        actions_layout.addWidget(self.btn_flush_dns)

        self.btn_restore_dhcp = QPushButton("Otomatik DNS'e Geri Dön (DHCP)")
        self.btn_restore_dhcp.clicked.connect(self.restore_dhcp_dns)
        actions_layout.addWidget(self.btn_restore_dhcp)

        self.btn_add_custom_doh = QPushButton("Özel DoH Ekle")
        self.btn_add_custom_doh.clicked.connect(self.add_custom_doh_provider)
        actions_layout.addWidget(self.btn_add_custom_doh)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setRange(0, len(DNS_PROVIDERS))
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setVisible(False) # Başlangıçta gizli
        actions_layout.addWidget(self.progress_bar)

        actions_group.setLayout(actions_layout)
        left_panel_layout.addWidget(actions_group)

        # DNS Sızıntı Testi Bağlantısı
        dns_leak_label = QLabel('DNS Sızıntı Testi: <a href="https://www.dnsleaktest.com/" style="color:#007bff; text-decoration: none;">www.dnsleaktest.com</a>')
        dns_leak_label.setOpenExternalLinks(True) # Harici bağlantıların açılmasını sağlar
        dns_leak_label.setAlignment(Qt.AlignCenter)
        left_panel_layout.addWidget(dns_leak_label)

        # Yönetici Durumu Etiketi
        self.admin_status_label = QLabel("Yönetici Yetkisi: Kontrol Ediliyor...")
        self.admin_status_label.setObjectName("adminStatusLabel")
        self.admin_status_label.setAlignment(Qt.AlignCenter)
        left_panel_layout.addWidget(self.admin_status_label)

        left_panel_layout.addStretch(1) # Boş alanı doldurmak için esneklik ekler

        main_layout.addWidget(left_panel_widget)

        # --- Sağ Panel (DNS Kartları) ---
        right_panel_layout = QVBoxLayout()
        right_panel_layout.setContentsMargins(20, 20, 20, 20)

        self.dns_card_grid = QGridLayout() # Kartları yerleştirmek için ızgara düzenleyici
        self.dns_card_grid.setSpacing(20) # Kartlar arasındaki boşluk
        self.dns_card_grid.setAlignment(Qt.AlignTop | Qt.AlignLeft)

        self.scroll_widget = QWidget()
        self.scroll_widget.setLayout(self.dns_card_grid)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True) # İçindeki widget'ın boyutunu otomatik ayarlar
        scroll_area.setWidget(self.scroll_widget)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff) # Yatay kaydırma çubuğunu kapatır
        scroll_area.setStyleSheet("border: none; background-color: transparent;") # Kenarlığı kaldırır
        right_panel_layout.addWidget(scroll_area)

        # DNS Uygula Butonu
        apply_button_layout = QHBoxLayout()
        apply_button_layout.setAlignment(Qt.AlignCenter)
        self.btn_apply_dns = QPushButton("Seçilen DNS'i Uygula")
        self.btn_apply_dns.setFixedSize(220, 45)
        self.btn_apply_dns.clicked.connect(self.apply_selected_dns)
        self.btn_apply_dns.setEnabled(False) # Bir DNS seçilene kadar devre dışı
        apply_button_layout.addWidget(self.btn_apply_dns)
        right_panel_layout.addLayout(apply_button_layout)

        main_layout.addLayout(right_panel_layout)

    def check_admin_status(self):
        """Yönetici yetkisini kontrol eder ve etiketi günceller."""
        if is_admin():
            self.admin_status_label.setText("Yönetici Yetkisi: <b style='color:#28a745;'>Var</b>")
        else:
            self.admin_status_label.setText("Yönetici Yetkisi: <b style='color:#dc3545;'>Yok</b>")
            QMessageBox.warning(self, "Yönetici Uyarısı",
                                "Bu uygulama DNS ayarlarını değiştirmek için yönetici yetkileri gerektirir. "
                                "Lütfen uygulamayı yönetici olarak çalıştırın.",
                                QMessageBox.Ok) # Sadece Tamam butonu

    def update_current_dns_info(self):
        """Mevcut DNS ayarlarını alır ve görüntüler."""
        self.current_dns_data = get_current_dns_settings()
        info_text = ""
        if not self.current_dns_data or "Hata" in self.current_dns_data:
            info_text = "Mevcut DNS ayarları alınamadı veya bir hata oluştu.<br>"
            if "Hata" in self.current_dns_data:
                info_text += self.current_dns_data["Hata"]
        else:
            for adapter, dns_list in self.current_dns_data.items():
                info_text += f"<b>{adapter}</b>:<br>"
                if dns_list:
                    for dns_ip in dns_list:
                        info_text += f"  - {dns_ip}<br>"
                else:
                    info_text += "  - Otomatik (DHCP)<br>"
        self.current_dns_label.setText(info_text)

        # Ağ arayüzlerini de sonraki kullanımlar için al
        self.network_interfaces = get_network_interfaces()
        if not self.network_interfaces:
            print("Uyarı: Ağ arayüzleri bulunamadı. DNS değiştirme işlevi çalışmayabilir.")

    def populate_dns_cards(self):
        """DNS kartlarını oluşturur ve düzenleyiciye ekler."""
        # Mevcut kartları temizle
        for i in reversed(range(self.dns_card_grid.count())):
            widget_item = self.dns_card_grid.itemAt(i)
            if widget_item:
                widget = widget_item.widget()
                if widget:
                    widget.deleteLater() # Widget'ı güvenli bir şekilde sil
        self.dns_cards = {} # Sözlüğü sıfırla

        row = 0
        col = 0
        max_cols = 3 # Satır başına maksimum 3 kart

        # Tüm DNS sağlayıcılarını içeren listeyi dolaşır
        for dns_data in DNS_PROVIDERS:
            card = DNSCard(dns_data)
            card.selected.connect(self.on_dns_card_selected) # Kart seçildiğinde tetiklenecek sinyal
            self.dns_card_grid.addWidget(card, row, col)
            self.dns_cards[dns_data['name']] = card # Kart referansını saklar

            col += 1
            if col >= max_cols:
                col = 0
                row += 1

            # Eğer IPv4 adresi varsa ping atmaya başla
            if dns_data['ipv4']:
                self.start_ping_for_card(card, dns_data['ipv4'][0])
            else:
                # IPv4 yoksa, kartın ping durumunu "N/A" olarak ayarla
                card.update_ping(dns_data['name'], float('inf'))

    def start_ping_for_card(self, card, ip_address):
        """Tek bir DNS kartı için ping iş parçacığını başlatır."""
        ping_thread = PingThread(card.dns_data['name'], ip_address)
        ping_thread.ping_result.connect(card.update_ping) # Ping sonucu geldiğinde kartı güncelle
        self.ping_threads.append(ping_thread) # Referansı sakla
        ping_thread.start()

    def on_dns_card_selected(self, dns_data):
        """Bir DNS kartı seçildiğinde çalışır."""
        self.selected_dns = dns_data
        # Tüm kartların seçim durumunu sıfırla, sadece seçili kartı vurgula
        for name, card in self.dns_cards.items():
            card.select(name == dns_data['name'])
        self.btn_apply_dns.setEnabled(True) # Uygula butonunu etkinleştir

    def apply_selected_dns(self):
        """Seçilen DNS ayarlarını sisteme uygular."""
        if not self.selected_dns:
            QMessageBox.warning(self, "DNS Seçilmedi", "Lütfen bir DNS sağlayıcısı seçin.", QMessageBox.Ok)
            return

        if not is_admin():
            QMessageBox.warning(self, "Yönetici Yetkisi Gerekli",
                                "DNS ayarlarını değiştirmek için yönetici yetkileri gereklidir. "
                                "Lütfen uygulamayı yönetici olarak çalıştırın.", QMessageBox.Ok)
            return

        ipv4_addresses = self.selected_dns.get('ipv4')
        doh_url = self.selected_dns.get('doh_url')
        dot_url = self.selected_dns.get('dot_url')

        if not ipv4_addresses and not doh_url and not dot_url:
            QMessageBox.warning(self, "Geçersiz DNS", "Seçilen DNS sağlayıcısının geçerli bir IP veya DoH/DoT adresi yok.", QMessageBox.Ok)
            return

        confirmation_text = f"<b>{self.selected_dns['name']}</b> DNS'ini uygulamak istediğinize emin misiniz?<br><br>"
        if ipv4_addresses:
            confirmation_text += f"IPv4: {', '.join(ipv4_addresses)}<br>"
        if doh_url:
            confirmation_text += f"DoH URL: {doh_url}<br>"
        if dot_url:
            confirmation_text += f"DoT URL: {dot_url}<br>"

        reply = QMessageBox.question(self, "DNS Değişikliğini Onayla",
                                     confirmation_text,
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            if doh_url or dot_url:
                # DoH/DoT doğrudan netsh ile yapılandırılamaz, kullanıcıya bilgi ver
                QMessageBox.information(self, "DoH/DoT Bilgilendirme",
                                        f"'{self.selected_dns['name']}' bir şifreli DNS (DoH/DoT) sağlayıcısıdır. "
                                        "Bu ayarlar otomatik olarak sistem geneline uygulanamaz. "
                                        "Lütfen tarayıcınızın veya işletim sisteminizin ağ ayarlarından "
                                        "DoH/DoT desteğini manuel olarak yapılandırın.", QMessageBox.Ok)
                # IPv4 adresleri varsa yine de onları uygula
                if not ipv4_addresses:
                    self.update_current_dns_info()
                    return # Eğer sadece DoH/DoT ise ve IPv4 yoksa buradan çık

            success_adapters = []
            failed_adapters = []
            
            # Her aktif ağ bağdaştırıcısına DNS ayarlarını uygula
            for adapter in self.network_interfaces:
                try:
                    if ipv4_addresses:
                        # Birincil DNS'i ayarla
                        cmd_primary = ["netsh", "interface", "ipv4", "set", "dnsservers", adapter, "static", ipv4_addresses[0], "primary"]
                        subprocess.run(cmd_primary, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                        
                        if len(ipv4_addresses) > 1:
                            # İkincil DNS'i ekle
                            cmd_secondary = ["netsh", "interface", "ipv4", "add", "dnsservers", adapter, ipv4_addresses[1], "index=2"]
                            subprocess.run(cmd_secondary, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                        success_adapters.append(adapter)
                    else:
                        # IPv4 adresleri yoksa, bu bağdaştırıcı için bir şey yapma
                        pass

                except subprocess.CalledProcessError as e:
                    failed_adapters.append(f"{adapter} ({e.stderr.strip()})")
                except Exception as e:
                    failed_adapters.append(f"{adapter} (Genel Hata: {e})")

            # Sonuç mesajını göster
            if success_adapters:
                QMessageBox.information(self, "Başarılı",
                                        f"DNS ayarları başarıyla değiştirildi:<br>{', '.join(success_adapters)}", QMessageBox.Ok)
            if failed_adapters:
                QMessageBox.critical(self, "Kısmi Hata",
                                     f"Bazı bağdaştırıcılarda DNS ayarı değiştirilirken hata oluştu:<br>{'<br>'.join(failed_adapters)}", QMessageBox.Ok)
            if not success_adapters and not failed_adapters:
                 QMessageBox.information(self, "Bilgi", "Herhangi bir DNS ayarı uygulanmadı. Belki de seçili DNS için IPv4 adresi yoktu.", QMessageBox.Ok)

            self.update_current_dns_info() # Uygulamadan sonra mevcut DNS'i yenile

    def run_all_dns_speed_test(self):
        """Tüm DNS sağlayıcıları için hız testi başlatır."""
        if not is_admin():
            QMessageBox.warning(self, "Yönetici Yetkisi Gerekli",
                                "DNS hız testi yapmak için yönetici yetkileri gereklidir. "
                                "Lütfen uygulamayı yönetici olarak çalıştırın.", QMessageBox.Ok)
            return

        self.btn_speed_test.setEnabled(False) # Butonu devre dışı bırak
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True) # İlerleme çubuğunu göster
        self.ping_results_for_speed_test = []
        self.ping_threads = [] # Önceki iş parçacıklarını temizle
        self.completed_pings = 0

        # Tüm kartların ping etiketlerini "Ölçülüyor..." olarak sıfırla
        for name, card in self.dns_cards.items():
            card.ping_label.setText("Ping: Ölçülüyor...")
            card.ping_label.setStyleSheet("color: #6c757d;") # Varsayılan renk
            card.ping_value = None

        total_ping_count = 0
        for dns_data in DNS_PROVIDERS:
            if dns_data['ipv4']:
                total_ping_count += 1
                ip_to_ping = dns_data['ipv4'][0] # Birincil IPv4'ü pingle
                ping_thread = PingThread(dns_data['name'], ip_to_ping)
                ping_thread.ping_result.connect(self.collect_speed_test_result)
                ping_thread.finished.connect(self.ping_thread_finished)
                self.ping_threads.append(ping_thread)
                ping_thread.start()
            else:
                # IPv4 yoksa, hız testi için hemen "N/A" olarak işaretle
                self.collect_speed_test_result(dns_data['name'], float('inf')) # Çok yavaş olarak işaretle
                # self.ping_thread_finished() # Ping işlemi yapılmadığı için manuel olarak bitişi say

        # İlerleme çubuğunun aralığını gerçek ping sayısı kadar ayarla
        self.progress_bar.setRange(0, total_ping_count)


    @pyqtSlot(str, float)
    def collect_speed_test_result(self, dns_name, ping_time):
        """Hız testi için ping sonuçlarını toplar ve UI'yı günceller."""
        for dns_data in DNS_PROVIDERS:
            if dns_data['name'] == dns_name:
                # Belirli kartın ping etiketini güncelle
                if dns_name in self.dns_cards:
                    self.dns_cards[dns_name].update_ping(dns_name, ping_time)

                self.ping_results_for_speed_test.append({
                    "name": dns_name,
                    "ping": ping_time
                })
                break

    @pyqtSlot()
    def ping_thread_finished(self):
        """Tamamlanan ping iş parçacıklarını sayar ve hepsi bittiğinde sonuçları işler."""
        self.completed_pings += 1
        self.progress_bar.setValue(self.completed_pings)

        if self.completed_pings == self.progress_bar.maximum(): # Tüm beklenen pingler tamamlandıysa
            self.btn_speed_test.setEnabled(True) # Butonu etkinleştir
            self.progress_bar.setVisible(False) # İlerleme çubuğunu gizle
            self.show_speed_test_results()

    def show_speed_test_results(self):
        """Sıralanmış hız testi sonuçlarını görüntüler."""
        # Ping değerine göre sırala (sonsuz değerler sona gelir)
        sorted_results = sorted(self.ping_results_for_speed_test, key=lambda x: x['ping'])

        result_message = "<b>DNS Hız Testi Sonuçları:</b><br><br>"
        for i, res in enumerate(sorted_results):
            if res['ping'] >= 0 and res['ping'] != float('inf'):
                result_message += f"{i+1}. {res['name']}: <b>{int(res['ping'])} ms</b><br>"
            elif res['ping'] == float('inf'):
                result_message += f"{i+1}. {res['name']}: N/A (IPv4 yok / Test edilemedi)<br>"
            else: # -1.0 veya -2.0
                result_message += f"{i+1}. {res['name']}: Başarısız<br>"

        QMessageBox.information(self, "Hız Testi Sonuçları", result_message, QMessageBox.Ok)

    def flush_dns_cache(self):
        """DNS önbelleğini temizler."""
        if not is_admin():
            QMessageBox.warning(self, "Yönetici Yetkisi Gerekli",
                                "DNS önbelleğini temizlemek için yönetici yetkileri gereklidir. "
                                "Lütfen uygulamayı yönetici olarak çalıştırın.", QMessageBox.Ok)
            return
        try:
            # subprocess.CREATE_NO_WINDOW: Komut çalışırken pencerenin açılmasını engeller.
            subprocess.run(["ipconfig", "/flushdns"], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            QMessageBox.information(self, "Başarılı", "DNS önbelleği başarıyla temizlendi.", QMessageBox.Ok)
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, "Hata", f"DNS önbelleği temizlenirken hata oluştu: {e.stderr}", QMessageBox.Ok)
        except FileNotFoundError:
            QMessageBox.critical(self, "Hata", "ipconfig komutu bulunamadı.", QMessageBox.Ok)
        except Exception as e:
            QMessageBox.critical(self, "Genel Hata", f"Beklenmedik bir hata oluştu: {e}", QMessageBox.Ok)

    def restore_dhcp_dns(self):
        """DNS ayarlarını otomatik (DHCP) olarak geri yükler."""
        if not is_admin():
            QMessageBox.warning(self, "Yönetici Yetkisi Gerekli",
                                "DNS ayarlarını otomatik yaplandırmak için yönetici yetkileri gereklidir. "
                                "Lütfen uygulamayı yönetici olarak çalıştırın.", QMessageBox.Ok)
            return

        reply = QMessageBox.question(self, "Otomatik DNS'e Geri Dön",
                                     "Tüm ağ bağdaştırıcıları için DNS ayarlarını otomatik (DHCP) olarak geri yüklemek istediğinize emin misiniz?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            success_adapters = []
            failed_adapters = []
            for adapter in self.network_interfaces:
                try:
                    cmd = ["netsh", "interface", "ipv4", "set", "dnsservers", adapter, "dhcp"]
                    subprocess.run(cmd, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    success_adapters.append(adapter)
                except subprocess.CalledProcessError as e:
                    failed_adapters.append(f"{adapter} ({e.stderr.strip()})")
                except Exception as e:
                    failed_adapters.append(f"{adapter} (Genel Hata: {e})")
            
            if success_adapters:
                QMessageBox.information(self, "Başarılı",
                                        f"DNS ayarları başarıyla otomatik (DHCP) olarak geri yüklendi:<br>{', '.join(success_adapters)}", QMessageBox.Ok)
            if failed_adapters:
                QMessageBox.critical(self, "Kısmi Hata",
                                     f"Bazı bağdaştırıcılarda DNS ayarları sıfırlanırken hata oluştu:<br>{'<br>'.join(failed_adapters)}", QMessageBox.Ok)
            if not success_adapters and not failed_adapters:
                QMessageBox.information(self, "Bilgi", "Herhangi bir DNS ayarı geri yüklenmedi. Belki de aktif bir bağdaştırıcı yoktu.", QMessageBox.Ok)
            
            self.update_current_dns_info() # Mevcut DNS'i yenile

    def add_custom_doh_provider(self):
        """Kullanıcının özel bir DoH sağlayıcısı eklemesine olanak tanır."""
        text, ok = QInputDialog.getText(self, 'Özel DoH URL Ekle', 'Lütfen DoH URL\'sini girin (örn: https://my.custom.dns/dns-query):')
        if ok and text:
            text = text.strip()
            # Basit bir URL doğrulaması
            if not (text.startswith("https://") and "/dns-query" in text):
                QMessageBox.warning(self, "Geçersiz URL", "Lütfen geçerli bir DoH URL'si girin (örn: https://example.com/dns-query).", QMessageBox.Ok)
                return

            name, ok_name = QInputDialog.getText(self, 'Sağlayıcı Adı', 'Lütfen bu sağlayıcı için bir isim girin:')
            if ok_name and name:
                new_provider = {
                    "name": name.strip(),
                    "ipv4": None, # Özel DoH genellikle IPv4 adresiyle gelmez
                    "doh_url": text,
                    "dot_url": None,
                    "ad_blocking": False # Varsayılan olarak reklam engelleme yok
                }
                # DNS sağlayıcıları listesine yeni sağlayıcıyı ekle
                DNS_PROVIDERS.insert(0, new_provider)
                self.populate_dns_cards() # Kartları yeniden oluştur
                QMessageBox.information(self, "Başarılı",
                                        f"'{name.strip()}' özel DoH sağlayıcısı eklendi. "
                                        "Uygulamak için kartı seçip 'Uygula' butonuna tıklayın.<br>"
                                        "Unutmayın, DoH ayarları manuel olarak tarayıcınızdan veya işletim sisteminizden yapılandırılmalıdır.", QMessageBox.Ok)

    def closeEvent(self, event):
        """Uygulama kapatıldığında çalışan ping iş parçacıklarını durdurur."""
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
