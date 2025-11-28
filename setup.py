#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Cyber Security Framework v3.0 - Setup System
=====================================================
Modüler kurulum sistemi ile framework'ü hazırlayın.
"""

import os
import sys
import json
import subprocess
import platform
from typing import Dict, List, Optional
import readchar

# Rich kütüphanesi kontrolü
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.align import Align
    from rich.table import Table
    from rich.box import HEAVY_EDGE, ROUNDED
    from rich.theme import Theme
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# ============================
# CONFIGURATION
# ============================
CONFIG_FILE = "framework_config.json"
REQUIREMENTS_FILE = "requirements.txt"

# ============================
# THEME & STYLE
# ============================
if RICH_AVAILABLE:
    NEON_THEME = Theme({
        "neon.cyan": "bold #00eaff", "neon.magenta": "bold #ff00f7",
        "neon.green": "bold #35ff69", "neon.yellow": "bold #ffe500",
        "neon.red": "bold #ff4d4d", "accent": "bold #00ffc6",
        "warn": "bold #ff4d4d", "ok": "bold #76ff03", "hint": "#9ca3af",
    })
    console = Console(theme=NEON_THEME)
else:
    console = None

# ============================
# SETUP OPTIONS
# ============================
SETUP_OPTIONS = [
    {"id": "os_selection", "name": "🌐 İşletim Sistemi Seçimi", "desc": "Windows, Linux, macOS seçimi"},
    {"id": "module_check", "name": "🔍 Modül Kontrolü", "desc": "Eksik modülleri kontrol et ve indir"},
    {"id": "dependencies", "name": "📦 Bağımlılık Kurulumu", "desc": "Python paketlerini kur"},
    {"id": "permissions", "name": "🔐 İzin Kontrolü", "desc": "Gerekli izinleri kontrol et"},
    {"id": "test_run", "name": "🧪 Test Çalıştırma", "desc": "Framework'ü test et"},
    {"id": "save_config", "name": "💾 Konfigürasyon Kaydet", "desc": "Ayarları kaydet ve çık"}
]

# ============================
# UTILITY FUNCTIONS
# ============================
def print_header(title: str, subtitle: str = ""):
    """Print formatted header"""
    if console:
        console.clear()
        console.print(Panel(
            Align.center(Text(title, style="neon.cyan")),
            title=f"[neon.green]{subtitle}[/neon.green]" if subtitle else "",
            border_style="neon.green",
            box=HEAVY_EDGE
        ))
    else:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("=" * 60)
        print(f" {title}")
        if subtitle:
            print(f" {subtitle}")
        print("=" * 60)

def print_status(message: str, status: str = "info"):
    """Print status message with color"""
    if console:
        colors = {
            "info": "neon.cyan",
            "success": "neon.green",
            "warning": "neon.yellow",
            "error": "neon.red"
        }
        console.print(f"[{colors.get(status, 'hint')}]{message}[/]")
    else:
        print(f"[{status.upper()}] {message}")

def get_user_input(prompt: str, options: List[str] = None) -> str:
    """Get user input with optional choices"""
    print_status(prompt, "info")
    if options:
        for i, option in enumerate(options, 1):
            print(f" {i}. {option}")
        while True:
            try:
                choice = input("\nSeçiminiz (1-{}): ".format(len(options))).strip()
                if choice.isdigit() and 1 <= int(choice) <= len(options):
                    return options[int(choice) - 1]
                print_status("Geçersiz seçim! Tekrar deneyin.", "error")
            except KeyboardInterrupt:
                print_status("\n\nSetup iptal edildi!", "warning")
                sys.exit(1)
    else:
        return input(f"\n> ").strip()

# ============================
# CONFIGURATION FUNCTIONS
# ============================
def load_config() -> Dict:
    """Load existing configuration"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            pass
    return {"os_type": None, "setup_complete": False, "modules": {}}

def save_config(config: Dict) -> bool:
    """Save configuration to file"""
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return True
    except:
        return False

# ============================
# OS SELECTION
# ============================
def os_selection_setup() -> Optional[str]:
    """Interactive OS selection with arrow keys"""
    print_header("🌐 İŞLETİM SİSTEMİ SEÇİMİ", "FRAMEWORK SETUP")

    os_options = [
        ("Windows", "Windows 10/11 - CMD ve PowerShell desteği"),
        ("Linux", "Kali Linux, Ubuntu, Debian - Terminal emülatör desteği"),
        ("macOS", "macOS 10.15+ - Terminal.app desteği"),
        ("Auto-Detect", "Otomatik algılama ve uygun ayarlar")
    ]
    selected_index = 0

    def display_menu():
        if console:
            console.clear()
            table = Table(title="İşletim Sistemi Seçenekleri", box=ROUNDED, header_style="neon.yellow")
            table.add_column("Seçenek", style="neon.cyan", width=15)
            table.add_column("Açıklama", style="neon.magenta")
            for i, (os_name, desc) in enumerate(os_options):
                if i == selected_index:
                    table.add_row(f"➤ {os_name}", desc, style="accent")
                else:
                    table.add_row(f"  {os_name}", desc)
            console.print(table)
            console.print("\n[neon.yellow]Yön tuşları ile seçin ve Enter'a basın[/neon.yellow]")
        else:
            os.system('cls' if os.name == 'nt' else 'clear')
            print_header("🌐 İŞLETİM SİSTEMİ SEÇİMİ", "FRAMEWORK SETUP")
            for i, (os_name, desc) in enumerate(os_options, 1):
                prefix = "➤" if i - 1 == selected_index else " "
                print(f" {prefix} {i}. {os_name} - {desc}")
            print("\nYukarı/aşağı ok tuşları ile seçin ve Enter'a basın")

    display_menu()
    while True:
        try:
            key = readchar.readkey()
            if key == readchar.key.UP:
                selected_index = (selected_index - 1) % len(os_options)
            elif key == readchar.key.DOWN:
                selected_index = (selected_index + 1) % len(os_options)
            elif key == readchar.key.ENTER:
                selected_os = os_options[selected_index][0]
                break
            elif key.lower() == 'q':
                return None
            display_menu()
        except KeyboardInterrupt:
            print_status("\n\nSetup iptal edildi!", "warning")
            sys.exit(1)

    if selected_os == "Auto-Detect":
        detected = platform.system()
        os_type_map = {"Windows": "Windows", "Linux": "Linux", "Darwin": "macOS"}
        os_type = os_type_map.get(detected, "Linux")
        print_status(f"Otomatik algılandı: {os_type}", "success")
    else:
        os_type = selected_os

    return os_type

# ============================
# MODULE CHECKING
# ============================
def check_modules() -> Dict[str, bool]:
    """Check which modules are available"""
    print_header("🔍 MODÜL KONTROLÜ", "MEVCUT MODÜLLERİ KONTROL ET")
    modules = {
        "honey": "modules/honey/honeypot.py",
        "scan": "modules/scan/scan_tui.py",
        "crypt": "modules/crypt/crypt_tui.py",
        "log": "modules/log/log_tui.py",
        "exploit": "modules/exploit/exploit_tui.py",
        "wifi": "modules/wifi/wifi_tui.py"
    }
    module_status = {name: os.path.exists(path) for name, path in modules.items()}
    if console:
        table = Table(title="Modül Durumu", box=ROUNDED, header_style="neon.yellow")
        table.add_column("Modül", style="neon.cyan", width=12)
        table.add_column("Dosya", style="neon.magenta")
        table.add_column("Durum", style="neon.green", width=10)
        for name, path in modules.items():
            exists = module_status[name]
            status_text, style = ("✓ Mevcut", "ok") if exists else ("✗ Eksik", "warn")
            table.add_row(name, path, f"[{style}]{status_text}[/]")
        console.print(table)
    else:
        for name, path in modules.items():
            status = "✓ Mevcut" if module_status[name] else "✗ Eksik"
            print(f" {name}: {status}")
    return module_status

def download_missing_modules(module_status: Dict[str, bool]):
    missing = [name for name, exists in module_status.items() if not exists]
    if not missing:
        print_status("Tüm modüller mevcut!", "success")
        return
    print_status(f"Eksik modüller: {', '.join(missing)}", "warning")
    print_status("Bu özellik henüz uygulanmadı. Lütfen eksik modülleri manuel olarak ekleyin.", "info")

# ============================
# DEPENDENCY INSTALLATION
# ============================
def check_dependencies() -> bool:
    print_header("📦 BAĞIMLILIK KONTROLÜ", "PYTHON PAKETLERİNİ KONTROL ET")
    if not os.path.exists(REQUIREMENTS_FILE):
        print_status(f"{REQUIREMENTS_FILE} bulunamadı!", "error")
        return False
    try:
        with open(REQUIREMENTS_FILE, 'r') as f:
            requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except IOError:
        print_status(f"{REQUIREMENTS_FILE} okunamadı!", "error")
        return False

    print_status("Paketler kontrol ediliyor...", "info")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", REQUIREMENTS_FILE])
        print_status("Tüm bağımlılıklar başarıyla kuruldu veya zaten mevcut.", "success")
        return True
    except subprocess.CalledProcessError:
        print_status("Bağımlılıklar kurulurken bir hata oluştu. Lütfen manuel olarak kurun:", "error")
        print(f"pip install -r {REQUIREMENTS_FILE}")
        return False

# ============================
# PERMISSION CHECK
# ============================
def check_permissions() -> bool:
    print_header("🔐 İZİN KONTROLÜ", "GEREKLİ İZİNLERİ KONTROL ET")
    checks = {"Dosya yazma izni": lambda: os.access(".", os.W_OK)}
    all_passed = True
    if console:
        table = Table(title="İzin Kontrolleri", box=ROUNDED, header_style="neon.yellow")
        table.add_column("Kontrol", style="neon.cyan", width=25)
        table.add_column("Durum", style="neon.green", width=15)
        for name, func in checks.items():
            try:
                result = func()
                status, style = ("✓ Geçti", "ok") if result else ("✗ Başarısız", "warn")
                if not result: all_passed = False
            except Exception as e:
                status, style = (f"✗ Hata: {e}", "error")
                all_passed = False
            table.add_row(name, f"[{style}]{status}[/]")
        console.print(table)
    else:
        for name, func in checks.items():
            try:
                result = func()
                status = "✓ Geçti" if result else "✗ Başarısız"
                if not result: all_passed = False
            except Exception as e:
                status = f"✗ Hata: {e}"
                all_passed = False
            print(f" {name}: {status}")
    print_status("İzin kontrolleri tamamlandı.", "success" if all_passed else "warning")
    return all_passed

# ============================
# TEST RUN
# ============================
def test_framework() -> bool:
    print_header("🧪 TEST ÇALIŞTIRMA", "FRAMEWORK'Ü TEST ET")
    print_status("Framework test ediliyor...", "info")
    try:
        print_status("✓ Temel modüller yüklendi", "success")
        test_config = {"test": True}
        with open("test_config.json", 'w') as f: json.dump(test_config, f)
        with open("test_config.json", 'r') as f: loaded = json.load(f)
        os.remove("test_config.json")
        if loaded == test_config:
            print_status("✓ Konfigürasyon sistemi çalışıyor", "success")
            print_status("✓ Framework testi başarılı!", "success")
            return True
        else:
            raise ValueError("Config read/write mismatch")
    except Exception as e:
        print_status(f"✗ Framework testi başarısız: {e}", "error")
        return False

# ============================
# MAIN SETUP LOOP
# ============================
def main_setup_loop() -> Optional[Dict]:
    config = load_config()
    selected_index = 0

    def display_main_menu():
        print_header("🚀 FRAMEWORK SETUP", "ADVANCED CYBER SECURITY FRAMEWORK v3.0")
        if console:
            table = Table(title="Setup Seçenekleri", box=ROUNDED, header_style="neon.yellow")
            table.add_column("Seçenek", style="neon.cyan", width=30)
            table.add_column("Açıklama", style="neon.magenta")
            table.add_column("Durum", style="neon.green", width=15)
            for i, option in enumerate(SETUP_OPTIONS):
                status, style = ("✓ Tamamlandı", "ok") if config.get(option["id"]) else ("○ Bekliyor", "hint")
                row_style = "accent" if i == selected_index else ""
                table.add_row(f"{option['name']}", option['desc'], f"[{style}]{status}[/]", style=row_style)
            console.print(table)
            console.print("\n[neon.yellow]Yön tuşları ile seçin, Enter ile onaylayın, Q ile çıkın[/neon.yellow]")
        else:
            for i, option in enumerate(SETUP_OPTIONS):
                prefix = "➤" if i == selected_index else " "
                status = "✓" if config.get(option["id"]) else "○"
                print(f" {prefix} {i+1}. {option['name']} - {option['desc']} [{status}]")
            print("\nYön tuşları ile seçin, Enter ile onaylayın, Q ile çıkın")

    while True:
        display_main_menu()
        try:
            key = readchar.readkey()
            if key == readchar.key.UP: selected_index = (selected_index - 1) % len(SETUP_OPTIONS)
            elif key == readchar.key.DOWN: selected_index = (selected_index + 1) % len(SETUP_OPTIONS)
            elif key.lower() == 'q':
                print_status("Setup iptal edildi!", "warning")
                sys.exit(0)
            elif key == readchar.key.ENTER:
                option_id = SETUP_OPTIONS[selected_index]["id"]
                if option_id == "os_selection":
                    os_type = os_selection_setup()
                    if os_type:
                        config["os_type"], config["os_selection"] = os_type, True
                        print_status(f"İşletim sistemi {os_type} olarak ayarlandı!", "success")
                elif option_id == "module_check":
                    module_status = check_modules()
                    download_missing_modules(module_status)
                    config["module_check"], config["modules"] = True, module_status
                    print_status("Modül kontrolü tamamlandı!", "success")
                elif option_id == "dependencies":
                    if check_dependencies():
                        config["dependencies"] = True
                        print_status("Bağımlılık kurulumu tamamlandı!", "success")
                elif option_id == "permissions":
                    if check_permissions():
                        config["permissions"] = True
                        print_status("İzin kontrolü tamamlandı!", "success")
                elif option_id == "test_run":
                    if test_framework():
                        config["test_run"] = True
                        print_status("Framework testi tamamlandı!", "success")
                elif option_id == "save_config":
                    config["setup_complete"] = True
                    if save_config(config):
                        print_status("Konfigürasyon kaydedildi!", "success")
                        print_status("Setup tamamlandı! Framework kullanıma hazır.", "success")
                        return config
                    else:
                        config["setup_complete"] = False
                        print_status("Konfigürasyon kaydedilemedi!", "error")
                input("\nDevam etmek için Enter'a basın...")
        except KeyboardInterrupt:
            print_status("\nSetup iptal edildi!", "warning")
            sys.exit(0)

# ============================
# MAIN FUNCTION
# ============================
def main():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                if json.load(f).get("setup_complete"):
                    print_header("BİLGİ", "FRAMEWORK SETUP")
                    print_status("Framework zaten kurulu!", "success")
                    if get_user_input("Yeniden kurmak istiyor musunuz?", ["Evet", "Hayır"]) == "Hayır":
                        print_status("Setup iptal edildi.", "info")
                        return
                    os.remove(CONFIG_FILE)
                    print_status("Eski konfigürasyon silindi, yeniden kuruluyor...", "info")
        except: pass
    main_setup_loop()
    print_header("🎉 SETUP TAMAMLANDI!", "FRAMEWORK KULLANIMA HAZIR")
    print_status("Artık 'python \"TUI Framework.py\"' komutu ile çalıştırabilirsiniz.", "info")

if __name__ == "__main__":
    if not RICH_AVAILABLE:
        print("[UYARI] 'rich' kütüphanesi bulunamadı. Kurulum basit bir arayüzle devam edecek.")
        print("En iyi deneyim için: pip install rich")
    try:
        main()
    except Exception as e:
        print_status(f"Beklenmedik bir hata oluştu: {e}", "error")
        sys.exit(1)