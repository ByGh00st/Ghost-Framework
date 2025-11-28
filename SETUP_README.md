# 🚀 Advanced Cyber Security Framework v3.0 - Kurulum Kılavuzu

## 📋 Genel Bakış

Bu framework, profesyonel siber güvenlik araçlarını tek bir arayüzde birleştiren gelişmiş bir sistemdir. Modüler yapısı sayesinde kolayca genişletilebilir ve özelleştirilebilir.

## 🛠️ Kurulum Gereksinimleri

### Sistem Gereksinimleri
- **Python 3.8+** (3.9+ önerilir)
- **İşletim Sistemi**: Windows 10/11, Linux (Kali, Ubuntu, Debian), macOS 10.15+
- **RAM**: Minimum 2GB, Önerilen 4GB+
- **Disk Alanı**: Minimum 500MB

### Python Paketleri
Framework otomatik olarak gerekli paketleri kuracaktır:
- `rich` - Gelişmiş terminal arayüzü
- `readchar` - Klavye kontrolü
- Diğer gerekli paketler

## 🚀 Kurulum Adımları

### 1. Framework'ü İndirin
```bash
# GitHub'dan klonlayın
git clone https://github.com/your-repo/Advanced-Cyber-Security-Framework-v3.0.git
cd Advanced-Cyber-Security-Framework-v3.0

# Veya ZIP olarak indirip açın
```

### 2. Setup Sistemini Çalıştırın
```bash
# Windows
python setup.py

# Linux/macOS
python3 setup.py
```

### 3. Setup Menüsünden Seçim Yapın

Setup sistemi size şu seçenekleri sunar:

#### 🌐 İşletim Sistemi Seçimi
- **Windows**: CMD ve PowerShell desteği
- **Linux**: Terminal emülatör desteği (xfce4-terminal, gnome-terminal, konsole)
- **macOS**: Terminal.app desteği
- **Auto-Detect**: Otomatik algılama

#### 🔍 Modül Kontrolü
- Mevcut modülleri kontrol eder
- Eksik modülleri otomatik indirir
- Modül durumlarını raporlar

#### 📦 Bağımlılık Kurulumu
- Python paketlerini kontrol eder
- Eksik paketleri pip ile kurar
- Gereksinimleri doğrular

#### 🔐 İzin Kontrolü
- Dosya yazma izinlerini kontrol eder
- Gerekli izinleri doğrular
- Güvenlik kontrollerini yapar

#### 🧪 Test Çalıştırma
- Framework'ü test eder
- Temel fonksiyonları doğrular
- Konfigürasyon sistemini test eder

#### 💾 Konfigürasyon Kaydet
- Tüm ayarları kaydeder
- Setup'ı tamamlar
- Framework'ü kullanıma hazır hale getirir

### 4. Framework'ü Çalıştırın
```bash
# Windows
python "TUI Framework.py"

# Linux/macOS
python3 "TUI Framework.py"
```

## 🎮 Kullanım

### Ana Kontroller
- **↑/↓ Ok Tuşları**: Modüller arasında geçiş
- **Enter**: Seçili modülü çalıştır
- **C**: Konfigürasyon değiştir (setup.py'ye yönlendirir)
- **Q**: Çıkış

### Modüller
- **HONEY**: Chimera Honeypot v3.2
- **SCAN**: Network Scanner & Port Analysis
- **CRYPT**: Cryptography Tools & Hash Generator
- **LOG**: Log Analyzer & Event Monitor
- **EXPLOIT**: MSFvenom Payload Generator
- **WIFI**: WiFi Attack Suite
- **C2**: Command & Control Panel (LOCKED)

## ⚙️ Konfigürasyon

### Konfigürasyon Dosyası
Setup tamamlandıktan sonra `framework_config.json` dosyası oluşturulur:

```json
{
  "os_type": "Linux",
  "setup_complete": true,
  "os_selection": true,
  "module_check": true,
  "dependencies": true,
  "permissions": true,
  "test_run": true,
  "modules": {
    "honey": true,
    "scan": true,
    "crypt": true,
    "log": true,
    "exploit": true,
    "wifi": true
  }
}
```

### Konfigürasyon Değiştirme
Ayarları değiştirmek için:
```bash
python setup.py
```

## 🔧 Sorun Giderme

### Setup Sırasında Hata
1. Python sürümünü kontrol edin (3.8+)
2. İnternet bağlantısını kontrol edin
3. Gerekli izinleri kontrol edin
4. Hata mesajlarını okuyun

### Framework Çalışmıyor
1. Setup'ın tamamlandığından emin olun
2. `framework_config.json` dosyasının varlığını kontrol edin
3. Python paketlerinin kurulu olduğunu kontrol edin
4. Terminal/CMD'yi yönetici olarak çalıştırın

### Modül Hataları
1. Modül dosyalarının varlığını kontrol edin
2. Gerekli bağımlılıkları kontrol edin
3. İşletim sistemi uyumluluğunu kontrol edin

## 📁 Dosya Yapısı

```
Advanced Cyber Security Framework v3.0/
├── setup.py                 # Kurulum sistemi
├── TUI Framework.py         # Ana framework
├── requirements.txt         # Python bağımlılıkları
├── framework_config.json    # Konfigürasyon (setup sonrası)
├── modules/                 # Modül klasörü
│   ├── honey/              # Honeypot modülü
│   ├── scan/               # Scanner modülü
│   ├── crypt/              # Crypto modülü
│   ├── log/                # Log analyzer modülü
│   ├── exploit/            # Exploit generator modülü
│   └── wifi/               # WiFi attack modülü
├── chimera_ftp_root/       # FTP honeypot dosyaları
├── chimera_ssh_root/       # SSH honeypot dosyaları
├── siem_events/            # SIEM event dosyaları
└── pcap_logs/              # PCAP log dosyaları
```

## 🚨 Güvenlik Uyarıları

⚠️ **ÖNEMLİ**: Bu framework gerçek siber güvenlik araçları içerir!

- Sadece **yasal test ortamlarında** kullanın
- **Üretim sistemlerinde** kullanmayın
- **İzinsiz testler** yapmayın
- **Yerel ağınızda** test edin
- Gerekli **yasal izinleri** alın

## 📞 Destek

### Hata Bildirimi
- GitHub Issues kullanın
- Detaylı hata mesajları ekleyin
- Sistem bilgilerini paylaşın

### Katkıda Bulunma
- Pull Request gönderin
- Kod standartlarına uyun
- Test ekleyin

## 📄 Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.

## 🙏 Teşekkürler

- **ImLock/ByGhost** - Framework geliştiricisi
- **Rich** - Terminal arayüz kütüphanesi
- **Python Community** - Açık kaynak desteği

---

**Not**: Bu framework eğitim ve yasal test amaçlıdır. Kötüye kullanımdan kullanıcı sorumludur.
