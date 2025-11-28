<img width="1200" height="475" alt="NetGraph Analyzer System Banner" src="https://i.hizliresim.com/q3l40dn.png" />
# 🌐 TUI framework - Cybersecurity Framework
# 🌐 TUI framework - Siber Güvenlik Framework'ü

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-green.svg)](https://github.com/your-repo)
[![License](https://img.shields.io/badge/License-Educational-red.svg)](LICENSE)

---

## 🇹🇷 Türkçe Açıklama

**TUI framework**, gelişmiş siber güvenlik araçları ve gerçek zamanlı ağ izleme yeteneklerine sahip modüler bir framework'tür. Her modül kendi interaktif TUI arayüzüne sahiptir ve modern siberpunk estetiği ile tasarlanmıştır.

### 🚀 Özellikler

- **🍯 Chimera Honeypot v3.2**: Çok aşamalı aldatma sistemi
       - **🔍 Network Scanner**: Nmap entegrasyonu ile port tarama
       - **🔐 Cryptography Tools**: Hash üretimi ve şifre kırma
       - **📊 Log Analyzer**: Gerçek zamanlı log analizi ve PCAP analizi
       - **💣 Exploit Generator**: MSFvenom ile payload üretimi
       - **📡 WiFi Attack Suite**: Otomatik WiFi tarama ve deauth saldırıları
       - **🛡️ Real-time Network Monitoring**: tshark ile ağ trafiği yakalama
       - **🎨 Modern TUI**: Rich kütüphanesi ile neon siberpunk arayüzü

---

## 🇺🇸 English Description

**TUI framework** is an advanced cybersecurity framework with modular architecture and real-time network monitoring capabilities. Each module has its own interactive TUI interface designed with modern cyberpunk aesthetics.

### 🚀 Features

       - **🍯 Chimera Honeypot v3.2**: Multi-stage deception system
       - **🔍 Network Scanner**: Port scanning with nmap integration
       - **🔐 Cryptography Tools**: Hash generation and password cracking
       - **📊 Log Analyzer**: Real-time log analysis and PCAP analysis
       - **💣 Exploit Generator**: Payload generation with MSFvenom
       - **📡 WiFi Attack Suite**: Automatic WiFi scanning and deauth attacks
       - **🛡️ Real-time Network Monitoring**: Network traffic capture with tshark
       - **🎨 Modern TUI**: Neon cyberpunk interface with Rich library

---

## 📁 Project Structure / Proje Yapısı

```
TUI framework/
├── TUI framework.py          # Main TUI launcher / Ana TUI başlatıcı
├── run.bat                   # Windows launcher / Windows başlatıcı
├── run.sh                    # Linux/Mac launcher / Linux/Mac başlatıcı
├── requirements.txt          # Python dependencies / Python bağımlılıkları
├── README.md                # This file / Bu dosya
└── modules/                 # Module directory / Modül dizini
    ├── __init__.py          # Package marker / Paket işaretleyici
    ├── honey/               # Honeypot module / Honeypot modülü
    │   ├── __init__.py      # Package marker / Paket işaretleyici
    │   └── honeypot.py      # Chimera Honeypot v3.2
    ├── scan/                # Network scanning module / Ağ tarama modülü
    │   ├── __init__.py      # Package marker / Paket işaretleyici
    │   └── scan_tui.py      # Network scanner TUI
    ├── crypt/               # Cryptography module / Kriptografi modülü
    │   ├── __init__.py      # Package marker / Paket işaretleyici
    │   └── crypt_tui.py     # Crypto tools TUI
    ├── log/                 # Log analysis module / Log analiz modülü
    │   ├── __init__.py      # Package marker / Paket işaretleyici
    │   ├── log_tui.py       # Log analyzer TUI
    │   ├── logscan.py       # Real-time network monitor
    │   └── sample_log.txt   # Sample log file / Örnek log dosyası
    ├── exploit/             # Exploit module / Exploit modülü
    │   ├── __init__.py      # Package marker / Paket işaretleyici
    │   └── exploit_tui.py   # MSFvenom payload generator TUI
    └── wifi/                # WiFi attack module / WiFi saldırı modülü
        ├── __init__.py      # Package marker / Paket işaretleyici
        └── wifi_tui.py      # WiFi attack suite TUI
```

---

## 🚀 Quick Start / Hızlı Başlangıç

### Windows
```bash
# Install dependencies / Bağımlılıkları yükle
pip install -r requirements.txt

# Run main framework / Ana framework'ü çalıştır
python "TUI framework.py"

# Or use batch file / Veya batch dosyasını kullan
run.bat
```

### Linux/Mac
```bash
# Install dependencies / Bağımlılıkları yükle
pip3 install -r requirements.txt

# Run main framework / Ana framework'ü çalıştır
python3 "TUI framework.py"

# Or use shell script / Veya shell script'i kullan
./run.sh
```

---

## 🔧 Modules / Modüller

### 🍯 HONEY - Chimera Honeypot v3.2
- **Location / Konum**: `modules/honey/honeypot.py`
- **Features / Özellikler**:
  - Multi-stage deception with terminal replays
  - PCAP-like logs and SIEM webhook support
  - SMB realism with NTLM-like bait
  - Web, FTP, SSH, SMB, SMTP, Redis, ES services
  - Rate limiting and tarpit functionality

### 🔍 SCAN - Network Scanner
- **Location / Konum**: `modules/scan/scan_tui.py`
- **Features / Özellikler**:
  - Quick port scanning (no nmap required)
  - Nmap integration with multiple scan types
  - Service detection and banner grabbing
  - Basic, Medium, Aggressive, Stealth modes

### 🔐 CRYPT - Cryptography Tools
- **Location / Konum**: `modules/crypt/crypt_tui.py`
- **Features / Özellikler**:
  - Hash generation (MD5, SHA1, SHA256, etc.)
  - Password cracking utilities
  - Random key generation
  - Dictionary attack capabilities

### 📊 LOG - Log Analyzer & Network Monitor
- **Location / Konum**: `modules/log/`
- **Features / Özellikler**:
  - **log_tui.py**: Advanced log analysis TUI
  - **logscan.py**: Real-time network traffic capture
  - Pattern detection and anomaly analysis
  - PCAP file analysis with tshark
  - Wireshark integration
  - Threat detection (DoS, Brute Force, ARP Spoof, etc.)

### 💣 EXPLOIT - MSFvenom Payload Generator
- **Location / Konum**: `modules/exploit/exploit_tui.py`
- **Features / Özellikler**:
  - **Standard Payloads**: APK, EXE, PHP, Python, ELF, WAR
  - **Advanced Payloads**: HTA, VBS, JSP, ASP, DLL, SO, JAR, PS1, BAT, SH, PL, RB
  - **Interactive Sub-menu**: Expandable "EXTRA" section with pagination
  - **Auto IP detection** and manual configuration
  - **Auto port selection** (4444) and manual port input
  - **Payload encoding** and customization
  - **Cross-platform support** with MSFvenom integration
  - **Dynamic UI**: Responsive sidebar sizing and visual frames

### 📡 WIFI - WiFi Attack Suite
- **Location / Konum**: `modules/wifi/wifi_tui.py`
- **Features / Özellikler**:
  - **Automatic WiFi scanning** with Aircrack-ng integration
  - **Arrow key navigation** for network selection
  - **Continuous deauth attacks** with time control (30s - 1 hour)
  - **Monitor mode management** (start/stop)
  - **Real-time attack status** monitoring
  - **Cross-platform support** (Linux with Aircrack-ng)
  - **Threading-based attacks** for non-blocking operation
  - **Auto cleanup** and safe exit procedures

---

## 🛡️ Real-Time Network Monitoring / Gerçek Zamanlı Ağ İzleme

The LOG module includes advanced network monitoring capabilities:

### Network Capture Features / Ağ Yakalama Özellikleri:
- **Real-time traffic capture** using tshark
- **Automatic threat detection**:
  - Port scanning detection
  - Brute force attack detection
  - DoS attack indicators
  - ARP spoofing detection
  - SQL injection attempts
  - XSS attack patterns
  - Directory traversal attempts

### Output Files / Çıktı Dosyaları:
- `traffic.pcapng` - Captured network traffic
- `scan_results.log` - Analysis results
- `network_stats.json` - Statistics
- `security_alerts.log` - Security alerts

---

## 🎮 Usage / Kullanım

1. **Launch Main Framework / Ana Framework'ü Başlat**:
   ```bash
   python "TUI framework.py"
   ```

2. **Navigate Modules / Modüller Arasında Gezin**:
   - Use ↑/↓ arrow keys to select modules
   - Press ENTER to launch selected module
   - Press Q to exit

3. **Real-Time Monitoring / Gerçek Zamanlı İzleme**:
   - Select LOG module
   - Choose "Start Network Capture"
   - Select network interface
   - Set capture duration
   - Use other modules while monitoring
   - Stop capture and analyze results

4. **Exploit Generation / Exploit Üretimi**:
   - Select EXPLOIT module
   - Choose standard payloads (APK, EXE, PHP, etc.)
   - Or select "Advanced Payloads" for extra options
   - Use A/D keys to navigate between pages
   - Use arrow keys to select specific payloads
   - Configure IP, port, and encoding options
   - Generate payloads with MSFvenom

5. **WiFi Attack Suite / WiFi Saldırı Paketi**:
   - Select WIFI module
   - Choose interface and enable monitor mode
   - Select "Auto Scan & Attack" for automatic operation
   - Or use "Manual Network Select" for specific targeting
   - Use arrow keys to select target networks
   - Set attack duration (30s - 1 hour)
   - Monitor attack status in real-time
   - Stop attacks safely when done

---

## 📋 Requirements / Gereksinimler

### Core Dependencies / Temel Bağımlılıklar:
```
rich>=13.0.0
readchar>=4.0.0
cryptography>=41.0.0
```

### Optional Dependencies / Opsiyonel Bağımlılıklar:
- **Wireshark/tshark**: For network capture and PCAP analysis
- **nmap**: For advanced network scanning
- **Metasploit Framework**: For payload generation (MSFvenom)
- **Aircrack-ng**: For WiFi attack suite (Linux only)

### Installation / Kurulum:
```bash
# Windows
# Download Wireshark from wireshark.org

# Linux
sudo apt install wireshark tshark nmap aircrack-ng

# Mac
brew install wireshark nmap
# Note: Aircrack-ng not available on macOS via Homebrew
```

---

## 🔒 Security Features / Güvenlik Özellikleri

### Threat Detection Patterns / Tehdit Tespit Desenleri:
- **Port Scan**: nmap, probe, syn, fin, rst
- **Brute Force**: failed login attempts
- **DoS Attack**: flood, connection limit, rate-limit
- **Suspicious IP**: blocked, banned, malicious
- **ARP Spoof**: arp, duplicate, spoof, poison
- **SQL Injection**: union, select, insert, delete
- **XSS Attack**: script, javascript, alert
- **Directory Traversal**: ../, ..\\, %2e%2e

### Anomaly Detection / Anomali Tespiti:
- High packet rate detection
- Suspicious IP behavior
- Failed authentication patterns
- Network attack indicators

---

## ⚠️ Disclaimer / Sorumluluk Reddi

**🇹🇷 Türkçe:**
Bu framework eğitim ve yetkili güvenlik testleri amaçlı tasarlanmıştır. Kullanıcılar, uygulanabilir yasalar ve düzenlemelere uygunluğu sağlamaktan sorumludur. Sadece sahip olduğunuz sistemlerde veya açık izniniz olan sistemlerde test edin.

**🇺🇸 English:**
This framework is designed for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. Use only on systems you own or have explicit permission to test.

---

## 🤝 Contributing / Katkıda Bulunma

Feel free to contribute by:
- Adding new modules
- Improving existing functionality
- Enhancing threat detection patterns
- Optimizing performance

---

## 📄 License / Lisans

<p align="center">
  <h2>⚠️ GÜVENLİK NOTU & YASAL UYARI / SECURITY NOTE & DISCLAIMER ⚠️</h2>
</p>

> ### 🇹🇷 Türkçe
> **Güvenlik Notu:** Bu projenin kaynak kodları, güvenlik ve gizlilik ilkeleri gereği bu repoda **paylaşılmamaktadır**. Projelerim hakkında daha fazla bilgi almak ve benimle iletişime geçmek için resmi web sitemi ziyaret edebilirsiniz: **[byghost.tr](https://byghost.tr)**
>
> ---
>
> **Yasal Uyarı:** Bu framework, yalnızca **eğitim ve yetkili güvenlik testleri** amacıyla tasarlanmıştır. Bu araçların kullanımından doğacak tüm yasal sorumluluk kullanıcıya aittir. Yalnızca sahibi olduğunuz veya test etmek için **açık izniniz** olan sistemlerde kullanın. Yasa dışı faaliyetler kesinlikle desteklenmemektedir.

> ### 🇺🇸 English
> **Security Note:** For security and privacy reasons, the source code for this project **is not included** in this repository. For more information about my projects and to get in touch, please visit my official website: **[byghost.tr](https://byghost.tr)**
>
> ---
>
> **Disclaimer:** This framework is designed for **educational and authorized security testing purposes only**. The user is solely responsible for all legal compliance when using these tools. Use it only on systems you own or have **explicit permission** to test. Illegal activities are strictly not supported.
---
---

**🌐 TUI framework - Advanced Cybersecurity Framework**
**🌐 TUI framework - Gelişmiş Siber Güvenlik Framework'ü**
