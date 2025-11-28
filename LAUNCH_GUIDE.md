# 🚀 Advanced Cyber Security Framework - Otomatik Başlatma Rehberi

## 📋 Genel Bakış

Bu rehber, **Advanced Cyber Security Framework v3.0**'ı farklı işletim sistemlerinde nasıl otomatik olarak başlatacağınızı açıklar. Tüm scriptler otomatik olarak gerekli bağımlılıkları kontrol eder ve kurar.

## 🖥️ İşletim Sistemi Seçenekleri

### 🪟 Windows

#### Seçenek 1: Batch Script (run.bat) - Önerilen
```cmd
# Çift tıklayın veya komut satırında çalıştırın:
run.bat
```

#### Seçenek 2: PowerShell Script (run.ps1)
```powershell
# PowerShell'de çalıştırın:
.\run.ps1
```

**Not:** PowerShell script çalıştırma politikası engelliyorsa:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 🐧 Linux

#### Bash Script (run.sh)
```bash
# Terminal'de çalıştırın:
./run.sh

# Eğer çalıştırma izni yoksa:
chmod +x run.sh
./run.sh
```

### 🍎 macOS

#### Bash Script (run.sh)
```bash
# Terminal'de çalıştırın:
./run.sh

# Eğer çalıştırma izni yoksa:
chmod +x run.sh
./run.sh
```

## 🔧 Otomatik Özellikler

### ✅ Python Kontrolü
- Python 3.7+ varlığını kontrol eder
- Eksikse otomatik kurulum talimatları verir
- Sürüm uyumluluğunu doğrular

### ✅ pip Kontrolü
- pip paket yöneticisinin varlığını kontrol eder
- Eksikse otomatik kurulum yapar
- Güncellemeleri kontrol eder

### ✅ Bağımlılık Yönetimi
- `requirements.txt` dosyasını okur
- Tüm Python paketlerini otomatik kurar
- Eksik paketleri tespit eder ve kurar

### ✅ Sistem Bağımlılıkları (Linux/macOS)
- Nmap, Wireshark, Aircrack-ng gibi sistem araçlarını kurar
- İşletim sistemine göre uygun paket yöneticisini kullanır

## 📋 Menü Seçenekleri

Tüm scriptler aşağıdaki seçenekleri sunar:

### 1. 🚀 TUI Framework (Ana Arayüz)
- İnteraktif modül seçimi
- Tüm modüller tek yerden erişim
- Modern siberpunk arayüz
- Klavye kontrolleri:
  - ↑/↓ Ok tuşları: Modül geçişi
  - Enter: Seçili modülü çalıştır
  - Q: Çıkış
  - Ctrl+C: Acil çıkış

### 2. 🍯 Direkt Honeypot Başlat
- Chimera v3.2 honeypot
- Tüm servisler aktif:
  - 🌐 Web Server: http://localhost:8080
  - 🔐 SSH Server: localhost:2222
  - 📁 FTP Server: localhost:2121
  - 💾 SMB Server: localhost:14445
  - 📧 SMTP Server: localhost:2525
  - 🗄️ Redis Server: localhost:16379
  - 🔍 Elasticsearch: localhost:9209

### 3. 🔧 Gereksinimleri Yeniden Kur
- Tüm Python paketlerini günceller
- Eksik paketleri kurar
- pip'i günceller

### 4. 🛠️ Sistem Bağımlılıklarını Kur (Linux/macOS)
- Nmap, Wireshark, Aircrack-ng kurar
- Sistem araçlarını yükler

### 5. ❌ Çıkış
- Güvenli çıkış

## 🎨 Renkli Arayüz

Tüm scriptler modern, renkli terminal arayüzü sunar:
- 🔵 Cyan: Başlıklar ve çerçeveler
- 🟢 Yeşil: Başarı mesajları
- 🟡 Sarı: Uyarılar ve bilgiler
- 🔴 Kırmızı: Hatalar
- 🟣 Magenta: Özel işlemler
- ⚪ Beyaz: Normal metin

## ⚠️ Önemli Notlar

### Güvenlik
- Framework'ü sadece test ortamlarında kullanın
- Honeypot modülünü dikkatli kullanın
- Gerçek sistemlerde kullanmadan önce güvenlik testleri yapın

### Sistem Gereksinimleri
- **Python 3.7+** gerekli
- **İnternet bağlantısı** (ilk kurulum için)
- **Yönetici/root izinleri** (bazı modüller için)
- **ANSI escape code** destekli terminal

### Hata Durumları
- Python bulunamazsa: Otomatik kurulum talimatları
- pip bulunamazsa: Otomatik kurulum
- Bağımlılık hatası: İnternet bağlantısını kontrol edin
- Dosya bulunamazsa: Doğru dizinde olduğunuzdan emin olun

## 🔄 Güncelleme

Framework'ü güncellemek için:
1. Yeni sürümü indirin
2. Eski dosyaları yedekleyin
3. Yeni dosyaları kopyalayın
4. Script'i çalıştırın (otomatik güncelleme)

## 📞 Destek

Sorun yaşarsanız:
1. Hata mesajını not edin
2. İşletim sisteminizi belirtin
3. Python sürümünüzü kontrol edin
4. İnternet bağlantınızı test edin

## 🎯 Hızlı Başlangıç

### Windows
```cmd
# Çift tıklayın:
run.bat
```

### Linux/macOS
```bash
# Terminal'de:
./run.sh
```

**Bu kadar!** Script otomatik olarak her şeyi halledecek. 🚀
