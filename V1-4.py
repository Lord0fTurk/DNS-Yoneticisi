import sys
import subprocess
import re
import json
import os
import platform # İşletim sistemi kontrolü
import locale # Sistem dilini tespit etmek için
import asyncio # Flet asenkron çalıştığı için
import ctypes # Windows temasını tespit etmek için

# Flet modüllerini içe aktar
import flet as ft

# --- DNS Sağlayıcıları Verisi ---
# Uygulamada gösterilecek DNS sağlayıcıları listesi
DNS_PROVIDers = [
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
        "dnssec_enabled": False
    },
    {
        "name": "Alternate DNS",
        "ipv4": ["76.76.19.19", "76.76.19.20"],
        "ipv6": None,
        "doh_url": None,
        "dot_url": None,
        "ad_blocking": True,
        "dnssec_enabled": False
    },
    {
        "name": "CyberGhost DNS",
        "ipv4": ["38.113.1.2", "198.18.0.2"],
        "ipv6": None,
        "dot_url": None,
        "ad_blocking": False,
        "dnssec_enabled": False
    },
    {
        "name": "ControlD (Özel URL ile)",
        "ipv4": None,
        "ipv6": None,
        "doh_url": "https://your-unique-id.controld.com/dns-query",
        "dot_url": None,
        "ad_blocking": True,
        "dnssec_enabled": True
    }
]

# Regex desenleri IP doğrulaması için
IPV4_PATTERN = re.compile(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
IPV6_PATTERN = re.compile(r"^[0-9a-fA-F:]{2,40}$")

# --- Çeviriler ---
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
        'msg_backup_settings_title': "Ayarları Yedekle",
        'msg_backup_success': "Ayarlar '{file_name}' dosyasına başarıyla yedeklendi.",
        'msg_backup_error': "Ayarlar yedeklenirken hata oluştu: {error}",
        'msg_backup_error_unexpected': "An unexpected error occurred while backing up settings: {error}",
        'msg_restore_settings_title': "Ayarları Geri Yükle",
        'msg_restore_success': "Ayarlar '{file_name}' dosyasından başarıyla geri yüklendi.",
        'msg_restore_invalid_file': "The selected file is not a valid DNS manager settings file or the 'custom_dns_providers' key was not found.",
        'msg_restore_error_decode': "Error decoding settings file: {file}. File might be corrupted.",
        'msg_restore_error_io': "Error reading settings file: {error}",
        'msg_restore_error_unexpected': "An unexpected error occurred while restoring settings: {error}",
        'label_ipv4': "IPv4:",
        'label_ipv6': "IPv6:",
        'label_doh': "DoH:",
        'label_dot': "DoT:",
        'label_dnssec': "DNSSEC:",
        'label_dnssec_yes': "Yes",
        'label_dnssec_no': "No",
        'label_dnssec_unknown': "Unknown",
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
        'msg_settings_load_error_decode': "Error decoding settings file: {file}. File might be corrupted.",
        'msg_settings_load_error_io': "Error reading settings file: {error}",
        'msg_settings_load_error_unexpected': "An unexpected error occurred while loading settings: {error}",
        'msg_settings_save_error_io': "Error saving settings file: {error}",
        'msg_settings_save_error_unexpected': "An unexpected error occurred while saving settings: {error}",
        'msg_backup_settings_title': "Ayarları Yedekle",
        'msg_backup_success': "Ayarlar '{file_name}' dosyasına başarıyla yedeklendi.",
        'msg_backup_error': "Ayarlar yedeklenirken hata oluştu: {error}",
        'msg_backup_error_unexpected': "An unexpected error occurred while backing up settings: {error}",
        'msg_restore_settings_title': "Ayarları Geri Yükle",
        'msg_restore_success': "Ayarlar '{file_name}' dosyasından başarıyla geri yüklendi.",
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
            # KRİTİK HATA DÜZELTİLDİ: Yanlış fonksiyon adı düzeltildi
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    return False

def get_current_dns_settings(current_lang):
    """
    Windows'taki tüm ağ bağdaştırıcıları için mevcut DNS ayarlarını alır.
    Hem IPv4 hem de IPv6 adreslerini dahil eder.
    Anahtarları bağdaştırıcı adları ve değerleri DNS sunucuları listeleri olan bir sözlük döndürür.
    """
    if platform.system() != "Windows":
        return {"Error": TRANSLATIONS.get(current_lang, TRANSLATIONS['en'])['msg_platform_not_supported_dns_mod_text']}

    cmd = ["powershell", "Get-DnsClientServerAddress -AddressFamily IPv4,IPv6 | Select-Object InterfaceAlias, AddressFamily, ServerAddresses"]
    try:
        # subprocess.run'da check=True zaten CalledProcessError'ı yükseltir.
        # Asenkron işlem için ise run_ping fonksiyonunda özel kontrol var.
        process = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        output = process.stdout.strip()

        dns_settings = {}
        lines = output.splitlines()

        current_alias = None
        for line in lines:
            line = line.strip()
            # KOD TASARIM PROBLEMİ ÇÖZÜMÜ: Netsh çıktı analizi daha sağlamlaştırıldı.
            # Başlık ve ayırıcı çizgileri atlamak için daha kesin kontroller
            if not line or "----" in line or "InterfaceAlias" in line or line.startswith("InterfaceAlias"):
                continue

            # Çıktıdaki bağdaştırıcı adlarını ve DNS adreslerini ayıkla
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
                current_alias = alias

            elif re.match(r"(\S+)\s*$", line) and not line.startswith(" "):
                alias = line.strip()
                if alias not in dns_settings:
                    dns_settings[alias] = {"IPv4": [], "IPv6": [], "DHCP": True}
                elif not dns_settings[alias]["IPv4"] and not dns_settings[alias]["IPv6"]:
                    dns_settings[alias]["DHCP"] = True
                current_alias = alias

            elif current_alias and IPV4_PATTERN.match(line):
                ip = line.strip()
                if ip not in dns_settings[current_alias]["IPv4"]:
                    dns_settings[current_alias]["IPv4"].append(ip)
            elif current_alias and IPV6_PATTERN.match(line):
                ipv6 = line.strip()
                if ipv6 not in dns_settings[current_alias]["IPv6"]:
                    dns_settings[current_alias]["IPv6"].append(ipv6)
        
        formatted_dns_settings = {}
        for alias, data in dns_settings.items():
            combined_addresses = []
            if data["IPv4"]:
                combined_addresses.extend(data["IPv4"])
            if data["IPv6"]:
                combined_addresses.extend(data["IPv6"])
            
            if not combined_addresses and data["DHCP"]:
                formatted_dns_settings[alias] = []
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
        output = process.stdout.strip()
        interfaces = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            match = re.search(r"\"(.+)\"\s*$", line)
            if match:
                interfaces.append(match.group(1).strip())
            elif "Bağdaştırıcı Adı" in line or "Interface Name" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    name = parts[1].strip()
                    if name and name != "Loopback Pseudo-Interface 1":
                        interfaces.append(name)
        return interfaces
    except subprocess.CalledProcessError as e:
        return []
    except FileNotFoundError:
        return []
    except Exception as e:
        return []

def get_system_theme_mode():
    """
    Windows'un sistem temasını algılar (aydınlık veya karanlık).
    Diğer OS'ler için varsayılanı döndürür.
    """
    if platform.system() == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            value, regtype = winreg.QueryValueEx(key, "AppsUseLightTheme")
            winreg.CloseKey(key)
            return ft.ThemeMode.LIGHT if value == 1 else ft.ThemeMode.DARK
        except Exception:
            return ft.ThemeMode.LIGHT
    return ft.ThemeMode.LIGHT # Windows olmayan sistemler için varsayılan


async def show_alert(page, title, message, alert_type="info"):
    """Flet'te alert iletişim kutusu gösterir."""
    page.dialog.title = ft.Text(title)
    page.dialog.content = ft.Text(message)
    page.dialog.actions = [
        ft.FilledButton("OK", on_click=lambda e: close_alert(page))
    ]
    page.dialog.open = True
    page.update()

async def close_alert(page):
    """Alert iletişim kutusunu kapatır."""
    page.dialog.open = False
    page.update()

async def get_text_input(page, title, label, initial_value="", password=False):
    """Flet'te metin girişi iletişim kutusu gösterir."""
    text_field = ft.TextField(label=label, value=initial_value, password=password, can_reveal_password=password)
    
    result = None
    
    def on_submit(e):
        nonlocal result
        result = text_field.value
        page.dialog.open = False
        page.update()

    page.dialog.title = ft.Text(title)
    page.dialog.content = text_field
    page.dialog.actions = [
        ft.FilledButton("OK", on_submit),
        ft.OutlinedButton("Cancel", on_click=lambda e: close_alert(page))
    ]
    page.dialog.open = True
    page.update()
    
    # Wait for the dialog to be closed (either OK or Cancel)
    while page.dialog.open:
        await asyncio.sleep(0.1)
    
    return result

async def show_confirm_dialog(page, title, message):
    """Flet'te onay iletişim kutusu gösterir."""
    result = False
    
    def on_yes(e):
        nonlocal result
        result = True
        page.dialog.open = False
        page.update()

    def on_no(e):
        nonlocal result
        result = False
        page.dialog.open = False
        page.update()

    page.dialog.title = ft.Text(title)
    page.dialog.content = ft.Text(message)
    page.dialog.actions = [
        ft.FilledButton("Yes", on_yes),
        ft.OutlinedButton("No", on_no)
    ]
    page.dialog.open = True
    page.update()

    while page.dialog.open:
        await asyncio.sleep(0.1)
    
    return result

# --- Ping Fonuşyonu (Flet uyumlu) ---
async def run_ping(ip_address, ip_version=4):
    """Asenkron ping komutunu çalıştırır ve sonucu döndürür."""
    cmd = ["ping", "-n", "4"]
    if ip_version == 6:
        cmd.append("-6")
    cmd.append(ip_address)

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10)
        output = stdout.decode('utf-8', errors='replace')

        # Ping sonuçlarını daha güvenli ayrıştırma (Ortalama/Average)
        # KRİTİK HATA DÜZELTİLDİ: subprocess.CalledProcessError doğrudan yakalanmaz, returncode kontrolü
        if process.returncode != 0:
            return -1.0, f"Ping komutu {ip_address} için başarısız oldu (Çıkış kodu: {process.returncode}, Hata: {stderr.decode('utf-8', errors='replace').strip()})"

        match = re.search(r"Ortalama = (\d+)ms|Average = (\d+)ms", output)
        if match:
            return float(match.group(1) if match.group(1) else match.group(2)), ""
        else:
            return -1.0, "Ping başarısız oldu: Çıktıda ortalama bulunamadı."
    except asyncio.TimeoutError:
        return -1.0, "Ping zaman aşımına uğradı."
    except FileNotFoundError:
        return -2.0, "Ping komutu bulunamadı."
    except Exception as e:
        return -1.0, f"Beklenmedik ping hatası: {e}"

# --- Ana Uygulama Mantığı ---
class DNSManagerApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.current_dns_data = None
        self.network_interfaces = []
        self.ping_tasks = []
        self.selected_dns = None
        self.dns_cards = {} # Flet Container'larını ve ilgili veriyi saklar
        self.current_lang = 'en' # Varsayılan dil
        self.current_theme = ft.ThemeMode.LIGHT # Varsayılan tema
        self.completed_tasks = 0
        self.ping_results_for_speed_test = []
        self.custom_dns_providers = []
        self.settings_file = "dns_manager_settings.json"
        
        # KOD TASARIM PROBLEMİ ÇÖZÜMÜ: Tekrar eden çeviri erişimini kolaylaştırmak için yardımcı fonksiyon
        self._ = lambda key: TRANSLATIONS[self.current_lang][key]

        self.detect_system_settings()
        self.load_settings()
        self.setup_page()
        self.init_ui()

    def detect_system_settings(self):
        """Sistem dilini ve temasını otomatik olarak algılar."""
        system_locale_tuple = locale.getlocale()
        system_locale = system_locale_tuple[0] if system_locale_tuple and system_locale_tuple[0] else None

        if system_locale and system_locale.startswith('tr'):
            self.current_lang = 'tr'
        else:
            self.current_lang = 'en'
        
        self.current_theme = get_system_theme_mode()

    def setup_page(self):
        """Flet sayfa ayarlarını yapar."""
        self.page.title = self._('window_title')
        self.page.window_width = 1000
        self.page.window_height = 700
        self.page.window_min_width = 800
        self.page.window_min_height = 600
        self.page.theme_mode = self.current_theme
        self.page.vertical_alignment = ft.CrossAxisAlignment.START # İçeriği üste hizala
        self.page.horizontal_alignment = ft.CrossAxisAlignment.STRETCH # Yatayda esnet
        self.page.on_connect = self.on_page_connect
        self.page.on_disconnect = self.on_page_disconnect

    async def on_page_connect(self, e):
        """Sayfa bağlandığında çağrılır."""
        await self.check_admin_status()
        await self.update_current_dns_info()
        await self.populate_dns_cards()
        self.page.update() # Başlangıç UI renderı için gerekli

    async def on_page_disconnect(self, e):
        """Sayfa bağlantısı kesildiğinde çağrılır."""
        self.save_settings()
        # Tüm çalışan ping görevlerini iptal et
        for task in self.ping_tasks:
            task.cancel()
        await asyncio.gather(*self.ping_tasks, return_exceptions=True) # İptal edilmiş görevlerin bitmesini bekle

    def init_ui(self):
        """Kullanıcı arayüzünü başlatır."""
        self.page.clean() # Mevcut tüm kontrolleri temizle

        # Dil seçimi dropdown
        self.language_dropdown = ft.Dropdown(
            options=[
                ft.dropdown.Option(key="en", text="English"),
                ft.dropdown.Option(key="tr", text="Türkçe"),
            ],
            value=self.current_lang,
            on_change=self.change_language,
            width=150
        )

        # Arama kutusu ve filtre checkbox
        self.search_input = ft.TextField(
            label=self._('placeholder_search'),
            on_change=self.filter_dns_cards_async,
            expand=True
        )
        self.ad_block_checkbox = ft.Checkbox(
            label=self._('checkbox_ad_block'),
            on_change=self.filter_dns_cards_async
        )

        # DNS kartları için responsive GridView
        self.dns_card_grid_view = ft.GridView(
            runs_count=3, # Geçici düzeltme: ResponsiveNumber kaynaklı TypeError nedeniyle sabit sütun sayısı
            max_extent=300, # Her bir kartın maksimum genişliği
            child_aspect_ratio=1.0, # Çocukların en boy oranı
            spacing=20,
            padding=10,
            expand=True
        )

        # Uygula butonu
        self.btn_apply_dns = ft.ElevatedButton(
            text=self._('button_apply_dns'),
            on_click=self.apply_selected_dns,
            disabled=True,
            width=220,
            height=45
        )

        # Mevcut DNS ayarları bölümü
        self.current_dns_label = ft.Markdown(
            self._('label_loading'),
            selectable=True,
            extension_set=ft.MarkdownExtensionSet.GITHUB_WEB,
            on_tap_link=lambda e: self.page.launch_url(e.data) # Linkleri açmak için
        )

        # İşlemler düğmeleri
        self.btn_speed_test = ft.ElevatedButton(
            text=self._('button_speed_test'),
            on_click=self.run_all_dns_speed_test,
            expand=True
        )
        self.btn_flush_dns = ft.ElevatedButton(
            text=self._('button_flush_cache'),
            on_click=self.flush_dns_cache,
            expand=True
        )
        self.btn_restore_dhcp = ft.ElevatedButton(
            text=self._('button_restore_dhcp'),
            on_click=self.restore_dhcp_dns,
            expand=True
        )
        self.btn_add_custom_dns = ft.ElevatedButton(
            text=self._('button_add_custom'),
            on_click=self.add_custom_dns_provider,
            expand=True
        )
        self.btn_gaming_mode = ft.ElevatedButton(
            text=self._('button_gaming_mode'),
            on_click=self.activate_gaming_mode,
            expand=True
        )
        self.btn_toggle_theme = ft.ElevatedButton(
            text=self._('button_toggle_theme_dark') if self.current_theme == ft.ThemeMode.LIGHT else self._('button_toggle_theme_light'),
            on_click=self.toggle_theme,
            expand=True
        )
        self.btn_backup_settings = ft.ElevatedButton(
            text=self._('button_backup_settings'),
            on_click=self.backup_settings,
            expand=True
        )
        self.btn_restore_settings = ft.ElevatedButton(
            text=self._('button_restore_settings'),
            on_click=self.restore_settings,
            expand=True
        )

        self.progress_bar = ft.ProgressBar(width=400, value=0, visible=False)
        self.progress_bar_text = ft.Text("")
        
        self.admin_status_text = ft.Text(self._('label_admin_status_checking'))

        # KOD TASARIM PROBLEMİ ÇÖZÜMÜ: UI referanslarının kırılganlığı giderildi.
        # Group başlıklarına ve diğer Text kontrollerine 'key' atandı.
        self.search_filter_group_title = ft.Text(self._('group_search_filter'), size=18, weight=ft.FontWeight.BOLD, key="search_filter_group_title")
        self.current_dns_group_title = ft.Text(self._('group_current_dns'), size=18, weight=ft.FontWeight.BOLD, key="current_dns_group_title")
        self.actions_group_title = ft.Text(self._('group_actions'), size=18, weight=ft.FontWeight.BOLD, key="actions_group_title")
        self.dns_leak_test_label = ft.Text(self._('label_dns_leak_test'), selectable=True, text_align=ft.TextAlign.CENTER, key="dns_leak_test_label")
        self.language_selection_label = ft.Text("Dil Seçimi:", size=16, key="language_selection_label")


        self.tab_dns_list_content = ft.Column(
            [
                ft.Container(
                    content=ft.Column([
                        self.search_filter_group_title, # Doğrudan referans kullanıldı
                        ft.Row([self.search_input]),
                        ft.Row([self.ad_block_checkbox])
                    ], spacing=10),
                    padding=ft.padding.all(20),
                    margin=ft.margin.only(bottom=15),
                    border_radius=ft.border_radius.all(10),
                    bgcolor=ft.Colors.with_opacity(0.05, ft.Colors.PRIMARY_CONTAINER if self.page.theme_mode == ft.ThemeMode.LIGHT else ft.Colors.PRIMARY)
                ),
                self.dns_card_grid_view,
                ft.Row([self.btn_apply_dns], alignment=ft.MainAxisAlignment.CENTER)
            ],
            expand=True,
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH
        )
        
        self.tab_settings_actions_content = ft.Column(
            [
                ft.Row([
                    self.language_selection_label, # Doğrudan referans kullanıldı
                    self.language_dropdown
                ]),
                ft.Container(
                    content=ft.Column([
                        self.current_dns_group_title, # Doğrudan referans kullanıldı
                        self.current_dns_label
                    ], spacing=10),
                    padding=ft.padding.all(20),
                    margin=ft.margin.only(bottom=15),
                    border_radius=ft.border_radius.all(10),
                    bgcolor=ft.Colors.with_opacity(0.05, ft.Colors.PRIMARY_CONTAINER if self.page.theme_mode == ft.ThemeMode.LIGHT else ft.Colors.PRIMARY)
                ),
                ft.Container(
                    content=ft.Column([
                        self.actions_group_title, # Doğrudan referans kullanıldı
                        self.btn_speed_test,
                        self.btn_flush_dns,
                        self.btn_restore_dhcp,
                        self.btn_add_custom_dns,
                        self.btn_gaming_mode,
                        self.btn_toggle_theme,
                        self.btn_backup_settings,
                        self.btn_restore_settings,
                        ft.Row([self.progress_bar, self.progress_bar_text], alignment=ft.MainAxisAlignment.CENTER)
                    ], spacing=10),
                    padding=ft.padding.all(20),
                    margin=ft.margin.only(bottom=15),
                    border_radius=ft.border_radius.all(10),
                    bgcolor=ft.Colors.with_opacity(0.05, ft.Colors.PRIMARY_CONTAINER if self.page.theme_mode == ft.ThemeMode.LIGHT else ft.Colors.PRIMARY)
                ),
                self.dns_leak_test_label, # Doğrudan referans kullanıldı
                self.admin_status_text
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            expand=True,
            scroll=ft.ScrollMode.ADAPTIVE # İçerik taşarsa kaydırır
        )

        self.tabs_control = ft.Tabs(
            selected_index=0,
            animation_duration=300,
            tabs=[
                ft.Tab(text=self._('tab_dns_list'), content=self.tab_dns_list_content),
                ft.Tab(text=self._('tab_settings_actions'), content=self.tab_settings_actions_content),
            ],
            expand=True,
            on_change=lambda e: self.page.update()
        )
        self.page.add(self.tabs_control)
        # init_ui sonunda page.update() çağrısı kaldırıldı, on_page_connect içinde yeterli.
        # self.page.update()

    # Asenkron çağrı için sarmalayıcı (on_change handler'larda kullanılacak)
    async def filter_dns_cards_async(self, e):
        await self.filter_dns_cards()

    async def update_ui_texts(self):
        """Uygulamanın tüm UI metinlerini mevcut dile göre günceller."""
        lang = self.current_lang
        self.page.title = self._('window_title')
        
        # Sekme başlıklarını güncelle (doğrudan self.tabs_control üzerinden)
        self.tabs_control.tabs[0].text = self._('tab_dns_list')
        self.tabs_control.tabs[1].text = self._('tab_settings_actions')

        # Ana ekrandaki kontrolleri güncelle (doğrudan referanslarla)
        self.search_input.label = self._('placeholder_search')
        self.ad_block_checkbox.label = self._('checkbox_ad_block')
        self.btn_apply_dns.text = self._('button_apply_dns')

        # KOD TASARIM PROBLEMİ ÇÖZÜMÜ: Key'lerle erişilen group başlıkları güncellendi
        self.search_filter_group_title.value = self._('group_search_filter')
        self.current_dns_group_title.value = self._('group_current_dns')
        self.actions_group_title.value = self._('group_actions')
        
        # Diğer butonlar ve etiketler
        self.btn_speed_test.text = self._('button_speed_test')
        self.btn_flush_dns.text = self._('button_flush_cache')
        self.btn_restore_dhcp.text = self._('button_restore_dhcp')
        self.btn_add_custom_dns.text = self._('button_add_custom')
        self.btn_gaming_mode.text = self._('button_gaming_mode')
        self.btn_toggle_theme.text = self._('button_toggle_theme_light') if self.current_theme == ft.ThemeMode.DARK else self._('button_toggle_theme_dark')
        self.btn_backup_settings.text = self._('button_backup_settings')
        self.btn_restore_settings.text = self._('button_restore_settings')
        
        # DNS Sızıntı Testi etiketi
        self.dns_leak_test_label.value = self._('label_dns_leak_test')
        self.language_selection_label.value = "Dil Seçimi:" # Bu metin çeviriye eklenmemişti, şimdilik sabit
        
        self.page.update()
        
        # Tüm DNS kartlarını yeni metinlerle yeniden oluşturmak için çağır
        await self.populate_dns_cards()
        
        # Sadece populate_dns_cards içinde update() çağrısı yeterli olmalıydı, tekrar çağrı kaldırıldı.
        # self.page.update()


    async def change_language(self, e):
        """Kullanıcı dil seçeneğini değiştirdiğinde çalışır."""
        selected_lang = e.control.value
        if self.current_lang != selected_lang:
            self.current_lang = selected_lang
            self._ = lambda key: TRANSLATIONS[self.current_lang][key] # KÜÇÜK SORUN DÜZELTİLDİ: Çeviri yardımcı fonksiyonu güncellendi
            await self.update_ui_texts()
            await self.update_current_dns_info() # Dil değiştikçe mevcut DNS bilgisini de güncelle
            self.page.update()

    def toggle_theme(self, e):
        """Temayı aydınlık ve karanlık arasında değiştirir."""
        if self.page.theme_mode == ft.ThemeMode.LIGHT:
            self.page.theme_mode = ft.ThemeMode.DARK
        else:
            self.page.theme_mode = ft.ThemeMode.LIGHT
        # KÜÇÜK SORUN DÜZELTİLDİ: Tema butonu metni doğru şekilde dinamikleştirildi
        self.btn_toggle_theme.text = self._('button_toggle_theme_dark') if self.page.theme_mode == ft.ThemeMode.LIGHT else self._('button_toggle_theme_light')
        self.page.update()

    async def check_admin_status(self):
        """Yönetici yetkisini kontrol eder ve etiketi günceller."""
        lang = self.current_lang
        if is_admin():
            self.admin_status_text.value = self._('label_admin_status_granted')
            self.admin_status_text.color = ft.Colors.GREEN_500
        else:
            self.admin_status_text.value = self._('label_admin_status_required')
            self.admin_status_text.color = ft.Colors.RED_500
        self.page.update()

    async def update_current_dns_info(self):
        """Mevcut DNS ayarlarını alır ve görüntüler."""
        lang = self.current_lang
        self.current_dns_data = get_current_dns_settings(self.current_lang)
        info_text = ""
        if not self.current_dns_data or "Error" in self.current_dns_data:
            info_text = self._('label_loading') + "<br>"
            if "Error" in self.current_dns_data:
                info_text = self.current_dns_data["Error"] + "<br>"
            info_text += self._('msg_platform_not_supported_dns_mod_text')
        else:
            for adapter, dns_list in self.current_dns_data.items():
                info_text += f"<b>{adapter}</b>:<br>"
                if dns_list:
                    for dns_ip in dns_list:
                        info_text += f"  - {dns_ip}<br>"
                else:
                    info_text += self._('label_automatic_dhcp')
        self.current_dns_label.value = info_text
        self.page.update()

        self.network_interfaces = get_network_interfaces()
        if not self.network_interfaces and platform.system() == "Windows":
             await show_alert(self.page, self._('msg_no_network_adapters'), self._('msg_no_network_adapters'))

    async def get_filtered_dns_providers(self):
        """Arama metnine ve filtreleme seçeneklerine göre DNS sağlayıcılarını filtreler."""
        all_providers = DNS_PROVIDERS + self.custom_dns_providers
        search_text = self.search_input.value.strip().lower()
        show_ad_blockers = self.ad_block_checkbox.value

        filtered_providers = []
        for provider in all_providers:
            name_match = search_text in provider['name'].lower()
            ad_block_match = True
            if show_ad_blockers and not provider.get('ad_blocking', False):
                ad_block_match = False
            
            if name_match and ad_block_match:
                filtered_providers.append(provider)
        return filtered_providers

    async def populate_dns_cards(self):
        """DNS kartlarını oluşturur ve UI'ya ekler."""
        self.dns_card_grid_view.controls.clear()
        self.dns_cards = {}

        filtered_providers = await self.get_filtered_dns_providers()

        for dns_data in filtered_providers:
            # Kart için basit bir container oluşturun
            card_content = ft.Column(
                [
                    ft.Text(dns_data['name'], size=16, weight=ft.FontWeight.BOLD),
                    ft.Text(self._('label_ad_blocking_enabled') if dns_data.get('ad_blocking') else " "),
                    ft.Text(f"{self._('label_ipv4')} {', '.join(dns_data['ipv4'])}" if dns_data.get('ipv4') else f"{self._('label_ipv4')} {self._('label_dnssec_no')}"),
                    ft.Text(f"{self._('label_ipv6')} {', '.join(dns_data['ipv6'])}" if dns_data.get('ipv6') else f"{self._('label_ipv6')} {self._('label_dnssec_no')}"),
                    ft.Text(f"{self._('label_doh')} {dns_data['doh_url'].replace('https://', '').replace('/dns-query', '').split('/')[0]}..." if dns_data.get('doh_url') else f"{self._('label_doh')} {self._('label_dnssec_no')}", tooltip=dns_data.get('doh_url')),
                    ft.Text(f"{self._('label_dot')} {dns_data['dot_url'].replace('tls://', '').split('/')[0]}..." if dns_data.get('dot_url') else f"{self._('label_dot')} {self._('label_dnssec_no')}", tooltip=dns_data.get('dot_url')),
                    ft.Text(f"{self._('label_dnssec')} {self._('label_dnssec_yes') if dns_data.get('dnssec_enabled') else self._('label_dnssec_no')}" if dns_data.get('dnssec_enabled') is not None else f"{self._('label_dnssec')} {self._('label_dnssec_unknown')}"),
                    ft.Text(self._('label_ping_measuring'), key=f"ping_{dns_data['name']}")
                ],
                spacing=5,
                horizontal_alignment=ft.CrossAxisAlignment.START,
                expand=True
            )

            card_container = ft.Container(
                content=card_content,
                padding=15,
                alignment=ft.alignment.top_left,
                border_radius=ft.border_radius.all(12),
                # Seçili durum için koşullu arka plan rengi
                bgcolor=ft.Colors.SURFACE_VARIANT if self.page.theme_mode == ft.ThemeMode.LIGHT else ft.Colors.BLUE_GREY_900,
                # KRİTİK HATA DÜZELTİLDİ: asyncio.run yerine page.run_task kullanıldı
                on_click=lambda e, data=dns_data: self.page.run_task(self.on_dns_card_selected(data)),
                width=300, # Izgarada tekdüzelik için sabit genişlik
                height=200, # Izgarada tekdüzelik için sabit yükseklik
                ink=True # Tıklama anında görsel geri bildirim
            )
            self.dns_card_grid_view.controls.append(card_container)
            self.dns_cards[dns_data['name']] = {"container": card_container, "data": dns_data, "ping_value": None}
            
            # Ping görevlerini başlat
            if dns_data.get('ipv4'):
                await self.start_ping_for_card(dns_data['name'], dns_data['ipv4'][0], ip_version=4)
            elif dns_data.get('ipv6'):
                await self.start_ping_for_card(dns_data['name'], dns_data['ipv6'][0], ip_version=6)
            else:
                self.dns_cards[dns_data['name']]["ping_value"] = float('inf')
                ping_label = card_container.content.controls[-1]
                ping_label.value = self._('label_ping_na')
                ping_label.color = ft.Colors.GREY_500
        
        self.page.update()

    async def on_dns_card_selected(self, dns_data):
        """Bir DNS kartı seçildiğinde çalışır."""
        # KOD TASARIM PROBLEMİ ÇÖZÜMÜ: Aynı isimdeki DNS sağlayıcıları için çakışma durumunda dikkat.
        # Şu anki mantık, aynı isimdeki son kartı günceller. Eğer farklı kartlar olması gerekiyorsa,
        # 'dns_cards' yapısı benzersiz ID'ler kullanacak şekilde yeniden tasarlanmalıdır.
        self.selected_dns = dns_data
        for name, card_info in self.dns_cards.items():
            if name == dns_data['name']:
                card_info["container"].border = ft.border.all(3, ft.Colors.BLUE_ACCENT_700)
                if self.page.theme_mode == ft.ThemeMode.LIGHT:
                    card_info["container"].bgcolor = ft.Colors.BLUE_100
                else:
                    card_info["container"].bgcolor = ft.Colors.PURPLE_900 # Seçim için daha koyu bir mor
            else:
                card_info["container"].border = None
                if self.page.theme_mode == ft.ThemeMode.LIGHT:
                    card_info["container"].bgcolor = ft.Colors.SURFACE_VARIANT
                else:
                    card_info["container"].bgcolor = ft.Colors.BLUE_GREY_900
        self.btn_apply_dns.disabled = False
        self.page.update()

    async def start_ping_for_card(self, dns_name, ip_address, ip_version):
        """Tek bir DNS kartı için ping işlemini başlatır."""
        task = asyncio.create_task(run_ping(ip_address, ip_version))
        # KRİTİK HATA DÜZELTİLDİ: asyncio.run yerine page.run_task kullanıldı
        task.add_done_callback(lambda t: self.page.run_task(self.handle_ping_result(dns_name, t.result())))
        self.ping_tasks.append(task)


    async def handle_ping_result(self, dns_name, result):
        """Ping sonucunu işler ve UI'yı günceller."""
        ping_time, error_message = result
        if dns_name in self.dns_cards:
            card_info = self.dns_cards[dns_name]
            card_info["ping_value"] = ping_time
            ping_label = card_info["container"].content.controls[-1] # Son kontrol ping etiketi olmalı

            if ping_time >= 0 and ping_time != float('inf'):
                ping_label.value = f"Ping: **{int(ping_time)} ms**"
                ping_label.color = ft.Colors.BLUE_ACCENT_700
            elif error_message:
                ping_label.value = f"Ping: Hata ({error_message})"
                ping_label.color = ft.Colors.RED_500
            else:
                ping_label.value = self._('label_ping_na')
                ping_label.color = ft.Colors.GREY_500
            
            self.page.update()
            # Ping test sonuçları için de kaydet
            self.ping_results_for_speed_test.append({
                "name": dns_name,
                "ping": ping_time,
                "error": error_message
            })
            await self.task_completed() # İşlemi tamamlandı olarak işaretle


    async def apply_selected_dns(self):
        """Seçilen DNS ayarlarını sisteme uygular."""
        lang = self.current_lang
        if not self.selected_dns:
            await show_alert(self.page, self._('msg_no_dns_selected_title'), self._('msg_no_dns_selected_text'))
            return

        if not is_admin():
            await show_alert(self.page, self._('msg_admin_priv_required_title'), self._('msg_admin_priv_required_text'))
            return

        if platform.system() != "Windows":
            await show_alert(self.page, self._('msg_platform_not_supported_title'), self._('msg_platform_not_supported_dns_mod_text'))
            return

        ipv4_addresses = self.selected_dns.get('ipv4')
        ipv6_addresses = self.selected_dns.get('ipv6')
        doh_url = self.selected_dns.get('doh_url')
        dot_url = self.selected_dns.get('dot_url')

        if not ipv4_addresses and not ipv6_addresses and not doh_url and not dot_url:
            await show_alert(self.page, self._('msg_invalid_dns_title'), self._('msg_invalid_dns_text'))
            return

        confirmation_text = self._('msg_confirm_dns_change').format(name=self.selected_dns['name'])
        if ipv4_addresses:
            confirmation_text += f"{self._('label_ipv4')} {', '.join(ipv4_addresses)}<br>"
        if ipv6_addresses:
            confirmation_text += f"{self._('label_ipv6')} {', '.join(ipv6_addresses)}<br>"
        if doh_url:
            confirmation_text += f"{self._('label_doh')} {doh_url}<br>"
        if dot_url:
            confirmation_text += f"{self._('label_dot')} {dot_url}<br>"

        reply = await show_confirm_dialog(self.page, self._('msg_confirm_dns_change'), confirmation_text)

        if reply:
            if doh_url or dot_url:
                await show_alert(self.page, "DoH/DoT Bilgilendirme", self._('msg_doh_dot_info').format(name=self.selected_dns['name']))
                if not ipv4_addresses and not ipv6_addresses:
                    await self.update_current_dns_info()
                    return

            success_adapters = []
            failed_adapters = []
            
            for adapter in self.network_interfaces:
                try:
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
                await show_alert(self.page, self._('msg_dns_apply_success'), self._('msg_dns_apply_success').format(adapters=', '.join(success_adapters)))
            if failed_adapters:
                await show_alert(self.page, self._('msg_dns_apply_partial_error'), self._('msg_dns_apply_partial_error').format(adapters='<br>'.join(failed_adapters)), alert_type="error")
            if not success_adapters and not failed_adapters:
                 await show_alert(self.page, self._('msg_dns_apply_no_change'), self._('msg_dns_apply_no_change'))

            await self.update_current_dns_info()

    async def run_all_dns_speed_test(self):
        """Tüm DNS sağlayıcıları için hız testi başlatır."""
        lang = self.current_lang
        if not is_admin():
            await show_alert(self.page, self._('msg_admin_priv_required_title'), self._('msg_admin_priv_required_text'))
            return

        if platform.system() != "Windows":
            await show_alert(self.page, self._('msg_platform_not_supported_title'), self._('msg_platform_not_supported_speed_test_text'))
            return

        providers_to_test = await self.get_filtered_dns_providers()
        if not providers_to_test:
            await show_alert(self.page, self._('msg_speed_test_no_providers'), self._('msg_speed_test_no_providers'))
            self.btn_speed_test.disabled = False
            self.btn_gaming_mode.disabled = False
            self.page.update()
            return

        self.btn_speed_test.disabled = True
        self.btn_gaming_mode.disabled = True
        self.progress_bar.value = 0
        self.progress_bar.visible = True
        self.progress_bar_text.value = "0%"
        self.page.update()
        
        self.ping_results_for_speed_test = []
        self.completed_tasks = 0

        # Mevcut ping görevlerini iptal et
        for task in self.ping_tasks:
            task.cancel()
        await asyncio.gather(*self.ping_tasks, return_exceptions=True)
        self.ping_tasks = []

        # UI'daki ping etiketlerini sıfırla
        for dns_data, card_info in self.dns_cards.items():
            ping_label = card_info["container"].content.controls[-1]
            ping_label.value = self._('label_ping_measuring')
            ping_label.color = ft.Colors.PRIMARY
            card_info["ping_value"] = None
        self.page.update()

        total_tasks_count = len(providers_to_test)
        self.progress_bar.max = total_tasks_count
        self.progress_bar.value = 0
        self.progress_bar.visible = True
        self.progress_bar_text.value = f"0 / {total_tasks_count}"
        self.page.update()


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
                task = asyncio.create_task(run_ping(ip_to_ping, ip_version))
                # KRİTİK HATA DÜZELTİLDİ: asyncio.run yerine page.run_task kullanıldı
                task.add_done_callback(lambda t, dn=dns_data['name']: self.page.run_task(self.handle_speed_test_result(dn, t.result())))
                self.ping_tasks.append(task)
            else:
                await self.handle_speed_test_result(dns_data['name'], (float('inf'), self._('label_ping_na')))


    async def handle_speed_test_result(self, dns_name, result):
        """Hız testi ping sonuçlarını işler ve UI'yı günceller."""
        ping_time, error_message = result

        # DNS kartındaki ping etiketini güncelle
        if dns_name in self.dns_cards:
            card_info = self.dns_cards[dns_name]
            card_info["ping_value"] = ping_time
            ping_label = card_info["container"].content.controls[-1]

            if ping_time >= 0 and ping_time != float('inf'):
                ping_label.value = f"Ping: **{int(ping_time)} ms**"
                ping_label.color = ft.Colors.BLUE_ACCENT_700
            elif error_message:
                ping_label.value = f"Ping: Hata ({error_message})"
                ping_label.color = ft.Colors.RED_500
            else:
                ping_label.value = self._('label_ping_na')
                ping_label.color = ft.Colors.GREY_500
            self.page.update()
        
        self.ping_results_for_speed_test.append({
            "name": dns_name,
            "ping": ping_time,
            "error": error_message
        })
        await self.task_completed() # İşlemi tamamlandı olarak işaretle


    async def task_completed(self):
        """Tamamlanan görev sayacını günceller ve tüm görevler bittiğinde sonuçları işler."""
        self.completed_tasks += 1
        self.progress_bar.value = self.completed_tasks
        self.progress_bar_text.value = f"{self.completed_tasks} / {self.progress_bar.max}"
        self.page.update()

        if self.progress_bar.max > 0 and self.completed_tasks >= self.progress_bar.max:
            self.btn_speed_test.disabled = False
            self.btn_gaming_mode.disabled = False
            self.progress_bar.visible = False
            self.progress_bar_text.value = ""
            self.page.update()
            await self.show_speed_test_results()

    async def show_speed_test_results(self):
        """Sıralanmış hız testi sonuçlarını görüntüler."""
        lang = self.current_lang
        sorted_results = sorted(self.ping_results_for_speed_test, key=lambda x: x['ping'] if x['ping'] >= 0 else float('inf'))

        result_message = f"**{self._('msg_speed_test_results_title')}**\n\n"
        if not sorted_results:
            result_message += self._('msg_speed_test_results_no_test')
        else:
            for i, res in enumerate(sorted_results):
                if res['ping'] >= 0 and res['ping'] != float('inf'):
                    result_message += f"{i+1}. {res['name']}: **{int(res['ping'])} ms**\n"
                else:
                    error_text = res['error'] if res['error'] else self._('label_ping_failed_generic')
                    result_message += f"{i+1}. {res['name']}: {self._('label_ping_na')} veya Hata ({error_text})\n"

        if hasattr(self, '_apply_fastest_after_speed_test') and self._apply_fastest_after_speed_test:
            self._apply_fastest_after_speed_test = False
            if sorted_results and sorted_results[0]['ping'] != float('inf'):
                fastest_dns_name = sorted_results[0]['name']
                fastest_dns_data = None
                for provider in DNS_PROVIDERS + self.custom_dns_providers:
                    if provider['name'] == fastest_dns_name:
                        fastest_dns_data = provider
                        break
                
                if fastest_dns_data:
                    self.selected_dns = fastest_dns_data
                    await self.on_dns_card_selected(fastest_dns_data) # UI'da kartı seç
                    await self.apply_selected_dns()
                    await show_alert(self.page, self._('msg_gaming_mode_active'),
                                     self._('msg_gaming_mode_active').format(name=fastest_dns_name))
                else:
                    await show_alert(self.page, self._('msg_gaming_mode_error'), self._('msg_gaming_mode_error'))
            else:
                await show_alert(self.page, self._('msg_gaming_mode_error'), self._('msg_gaming_mode_no_results'))
        else:
            await show_alert(self.page, self._('msg_speed_test_results_title'), result_message)

    async def activate_gaming_mode(self):
        """Oyun Modunu etkinleştirir: En hızlı DNS'i bulur ve uygular."""
        lang = self.current_lang
        if not is_admin():
            await show_alert(self.page, self._('msg_admin_priv_required_title'), self._('msg_admin_priv_required_text'))
            return
        
        await show_alert(self.page, self._('button_gaming_mode'), self._('msg_gaming_mode_activating'))
        
        self._apply_fastest_after_speed_test = True
        await self.run_all_dns_speed_test()

    async def flush_dns_cache(self):
        """DNS önbelleğini temizler."""
        lang = self.current_lang
        if not is_admin():
            await show_alert(self.page, self._('msg_admin_priv_required_title'), self._('msg_admin_priv_required_text'))
            return

        if platform.system() != "Windows":
            await show_alert(self.page, self._('msg_platform_not_supported_title'), self._('msg_platform_not_supported_flush_text'))
            return

        try:
            subprocess.run(["ipconfig", "/flushdns"], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            await show_alert(self.page, self._('msg_flush_success'), self._('msg_flush_success'))
        except subprocess.CalledProcessError as e:
            await show_alert(self.page, self._('msg_flush_error'), self._('msg_flush_error').format(error=e.stderr.strip() if e.stderr else 'Bilinmeyen hata'), alert_type="error")
        except FileNotFoundError:
            await show_alert(self.page, self._('msg_ipconfig_not_found'), self._('msg_ipconfig_not_found'), alert_type="error")
        except Exception as e:
            await show_alert(self.page, self._('msg_settings_load_error_unexpected'), self._('msg_settings_load_error_unexpected').format(error=e), alert_type="error")

    async def restore_dhcp_dns(self):
        """DNS ayarlarını otomatik (DHCP) olarak geri yükler."""
        lang = self.current_lang
        if not is_admin():
            await show_alert(self.page, self._('msg_admin_priv_required_title'), self._('msg_admin_priv_required_text'))
            return

        if platform.system() != "Windows":
            await show_alert(self.page, self._('msg_platform_not_supported_title'), self._('msg_platform_not_supported_dhcp_text'))
            return

        reply = await show_confirm_dialog(self.page, self._('button_restore_dhcp'), self._('msg_dhcp_confirm'))

        if reply:
            success_adapters = []
            failed_adapters = []
            for adapter in self.network_interfaces:
                try:
                    subprocess.run(["netsh", "interface", "ipv4", "set", "dnsservers", adapter, "dhcp"], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    subprocess.run(["netsh", "interface", "ipv6", "set", "dnsservers", adapter, "dhcp"], check=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    success_adapters.append(adapter)
                except subprocess.CalledProcessError as e:
                    failed_adapters.append(f"{adapter} ({e.stderr.strip() if e.stderr else 'Bilinmeyen hata'})")
                except Exception as e:
                    failed_adapters.append(f"{adapter} (Genel Hata: {e})")
            
            if success_adapters:
                await show_alert(self.page, self._('msg_dhcp_success'), self._('msg_dhcp_success').format(adapters=', '.join(success_adapters)))
            if failed_adapters:
                await show_alert(self.page, self._('msg_dhcp_partial_error'), self._('msg_dhcp_partial_error').format(adapters='<br>'.join(failed_adapters)), alert_type="error")
            if not success_adapters and not failed_adapters:
                await show_alert(self.page, self._('msg_dhcp_no_revert'), self._('msg_dhcp_no_revert'))
            
            await self.update_current_dns_info()

    async def add_custom_dns_provider(self):
        """Kullanıcının özel bir DNS sağlayıcısı eklemesine olanak tanır (IPv4, IPv6, DoH, DoT)."""
        lang = self.current_lang
        name = await get_text_input(self.page, self._('button_add_custom'), self._('input_custom_dns_name'))
        if not name or not name.strip():
            return

        ipv4_str = await get_text_input(self.page, self._('button_add_custom'), self._('input_ipv4_addresses'))
        ipv6_str = await get_text_input(self.page, self._('button_add_custom'), self._('input_ipv6_addresses'))
        doh_url = await get_text_input(self.page, self._('button_add_custom'), self._('input_doh_url'))
        dot_url = await get_text_input(self.page, self._('button_add_custom'), self._('input_dot_url'))
        
        ipv4_list = [ip.strip() for ip in ipv4_str.split(',') if ip.strip()] if ipv4_str else []
        ipv6_list = [ip_v6.strip() for ip_v6 in ipv6_str.split(',') if ip_v6.strip()] if ipv6_str else []

        valid_ipv4s = []
        for ip in ipv4_list:
            if IPV4_PATTERN.match(ip):
                valid_ipv4s.append(ip)
            else:
                await show_alert(self.page, self._('msg_invalid_ipv4'), self._('msg_invalid_ipv4').format(ip=ip), alert_type="warning")
        
        valid_ipv6s = []
        for ip in ipv6_list:
            if IPV6_PATTERN.match(ip):
                valid_ipv6s.append(ip)
            else:
                await show_alert(self.page, self._('msg_invalid_ipv6'), self._('msg_invalid_ipv6').format(ip=ip), alert_type="warning")

        if not valid_ipv4s and not valid_ipv6s and not (doh_url and doh_url.strip()) and not (dot_url and dot_url.strip()):
            await show_alert(self.page, self._('msg_invalid_input_title'), self._('msg_invalid_input_no_data'))
            return

        new_provider = {
            "name": name.strip(),
            "ipv4": valid_ipv4s if valid_ipv4s else None,
            "ipv6": valid_ipv6s if valid_ipv6s else None,
            "doh_url": doh_url.strip() if doh_url and doh_url.strip() else None,
            "dot_url": dot_url.strip() if dot_url and dot_url.strip() else None,
            "ad_blocking": False,
            "dnssec_enabled": False
        }
        
        self.custom_dns_providers.append(new_provider)
        await self.populate_dns_cards()
        self.save_settings()
        await show_alert(self.page, self._('msg_custom_dns_added_success'),
                                self._('msg_custom_dns_added_success').format(name=name.strip()))

    def load_settings(self):
        """Ayarları (özel DNS sağlayıcıları) bir dosyadan yükler."""
        lang = self.current_lang
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if "custom_dns_providers" in data and isinstance(data["custom_dns_providers"], list):
                        self.custom_dns_providers = data["custom_dns_providers"]
            except json.JSONDecodeError:
                # KRİTİK HATA DÜZELTİLDİ: asyncio.run yerine asyncio.ensure_future kullanıldı
                asyncio.ensure_future(show_alert(self.page, self._('msg_settings_load_error_decode'), self._('msg_settings_load_error_decode').format(file=self.settings_file), alert_type="error"))
            except IOError as e:
                asyncio.ensure_future(show_alert(self.page, self._('msg_settings_load_error_io'), self._('msg_settings_load_error_io').format(error=e), alert_type="error"))
            except Exception as e:
                asyncio.ensure_future(show_alert(self.page, self._('msg_settings_load_error_unexpected'), self._('msg_settings_load_error_unexpected').format(error=e), alert_type="error"))

    def save_settings(self):
        """Ayarları (özel DNS sağlayıcıları) bir dosyaya kaydeder."""
        lang = self.current_lang
        try:
            with open(self.settings_file, 'w', encoding='utf-8') as f:
                json.dump({"custom_dns_providers": self.custom_dns_providers}, f, indent=4)
        except IOError as e:
            # KRİTİK HATA DÜZELTİLDİ: asyncio.run yerine asyncio.ensure_future kullanıldı
            asyncio.ensure_future(show_alert(self.page, self._('msg_settings_save_error_io'), self._('msg_settings_save_error_io').format(error=e), alert_type="error"))
        except Exception as e:
            asyncio.ensure_future(show_alert(self.page, self._('msg_settings_save_error_unexpected'), self._('msg_settings_save_error_unexpected').format(error=e), alert_type="error"))

    async def backup_settings(self):
        """Mevcut ayarları ve özel DNS'leri bir dosyaya yedekler."""
        lang = self.current_lang
        file_name = await self.page.get_directory_path("dns_manager_backup.json")
        if file_name:
            try:
                backup_data = {"custom_dns_providers": self.custom_dns_providers}
                with open(file_name, 'w', encoding='utf-8') as f:
                    json.dump(backup_data, f, indent=4)
                await show_alert(self.page, self._('msg_backup_success'), self._('msg_backup_success').format(file_name=os.path.basename(file_name)))
            except IOError as e:
                await show_alert(self.page, self._('msg_backup_error'), self._('msg_backup_error').format(error=e), alert_type="error")
            except Exception as e:
                await show_alert(self.page, self._('msg_backup_error_unexpected'), self._('msg_backup_error_unexpected').format(error=e), alert_type="error")

    async def restore_settings(self):
        """Daha önce yedeklenmiş ayarları ve özel DNS'leri bir dosyadan geri yükler."""
        lang = self.current_lang
        file_name = await self.page.get_file_path()
        if file_name:
            try:
                with open(file_name, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if "custom_dns_providers" in data and isinstance(data["custom_dns_providers"], list):
                        self.custom_dns_providers = data["custom_dns_providers"]
                        await self.populate_dns_cards()
                        self.save_settings()
                        await show_alert(self.page, self._('msg_restore_success'), self._('msg_restore_success').format(file_name=os.path.basename(file_name)))
                    else:
                        await show_alert(self.page, self._('msg_restore_invalid_file'), self._('msg_restore_invalid_file'), alert_type="warning")
            except json.JSONDecodeError:
                await show_alert(self.page, self._('msg_restore_error_decode'), self._('msg_restore_error_decode').format(file=file_name), alert_type="error")
            except IOError as e:
                await show_alert(self.page, self._('msg_restore_error_io'), self._('msg_restore_error_io').format(error=e), alert_type="error")
            except Exception as e:
                await show_alert(self.page, self._('msg_restore_error_unexpected'), self._('msg_restore_error_unexpected').format(error=e), alert_type="error")

# --- Main Flet Function ---
async def main(page: ft.Page):
    app = DNSManagerApp(page)
    # İlk update çağrısı on_page_connect içinde yapıldığı için burada kaldırıldı
    # await app.page.update_async() # Kaldırıldı

if __name__ == "__main__":
    ft.app(target=main) # Flet uygulamasını başlatan satır eklendi
