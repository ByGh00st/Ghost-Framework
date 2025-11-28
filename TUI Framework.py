#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cyberpunk Rich TUI Framework — ImLock/ByGhost 
=======================================================
İnteraktif, modern siberpunk estetiğinde, mükemmel hizalamaya takıntılı
ve tamamen framework gibi bir Rich tabanlı arayüz.

📋 PROJE AÇIKLAMASI:
Bu dosya, klavye kontrolü ile etkileşimli bir terminal arayüzü sağlar.
Kullanıcı yukarı/aşağı ok tuşları ile modüller arasında geçiş yapabilir.

🎮 KONTROLLER:
- ↑/↓ Ok tuşları: Modül geçişi
- Enter: Seçili modülü çalıştır (executable dosya)
- Q: Çıkış
- Ctrl+C: Acil çıkış

🏗️ TEKNİK ÖZELLİKLER:
- readchar kütüphanesi ile düşük seviye klavye kontrolü
- Rich Layout sistemi ile modüler arayüz tasarımı
- Neon renk paleti ile siberpunk estetiği
- Gradient metin efektleri
- ASCII art bannerlar
- Executable dosya entegrasyonu

⚠️ ÖNEMLİ NOT:
Bu artık gerçek araçlar çalıştırır. Dikkatli kullanın!

"""

from __future__ import annotations
import os
import subprocess
import sys
import platform
import json
from typing import Dict, List

from rich.console import Console, RenderableType
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.table import Table
from rich.rule import Rule
from rich.box import ROUNDED, HEAVY, HEAVY_EDGE
from rich.theme import Theme
import readchar

# ============================
# THEME & STYLE DEFINITIONS
# ============================
NEON_THEME = Theme({
    "neon.cyan": "bold #00eaff", "neon.magenta": "bold #ff00f7",
    "neon.green": "bold #35ff69", "neon.yellow": "bold #ffe500",
    "neon.red": "bold #ff4d4d",
    "dim.gray": "#6b7280", "accent": "bold #00ffc6", "warn": "bold #ff4d4d",
    "ok": "bold #76ff03", "hint": "#9ca3af",
})
console = Console(theme=NEON_THEME)

# ============================
# CONFIGURATION SYSTEM
# ============================
CONFIG_FILE = "framework_config.json"

def load_config():
    """Load configuration from file"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                return config
        except:
            pass
    
    # No config found - redirect to setup
    return None

def check_setup():
    """Check if setup is complete, if not redirect to setup.py"""
    config = load_config()
    
    if not config or not config.get("setup_complete"):
        console.clear()
        console.print(Panel(
            Align.center(Text("⚠️  SETUP GEREKLİ", style="neon.yellow")),
            title="[neon.red]FRAMEWORK KURULMAMIŞ[/neon.red]",
            border_style="neon.red",
            box=HEAVY_EDGE
        ))
        
        console.print("\n[neon.yellow]Framework henüz kurulmamış![/neon.yellow]")
        console.print("[neon.cyan]Önce setup.py dosyasını çalıştırmanız gerekiyor.[/neon.cyan]")
        console.print("\n[neon.green]Kurulum için:[/neon.green]")
        console.print(" python setup.py")
        console.print("\n[neon.green]Kurulum tamamlandıktan sonra:[/neon.green]")
        console.print(" python TUI Framework.py")
        
        input("\n[neon.yellow]Çıkmak için Enter'a basın...[/neon.yellow]")
        sys.exit(1)
    
    return config["os_type"]

def change_config():
    """Redirect to setup.py for configuration changes"""
    console.clear()
    console.print(Panel(
        Align.center(Text("⚙️  AYAR DEĞİŞTİRME", style="neon.yellow")),
        title="[neon.green]CONFIGURATION[/neon.green]",
        border_style="neon.green",
        box=HEAVY_EDGE
    ))
    
    console.print("\n[neon.yellow]Ayarları değiştirmek için setup.py çalıştırın:[/neon.yellow]")
    console.print(" python setup.py")
    console.print("\n[neon.cyan]Bu size tüm konfigürasyon seçeneklerini sunacak.[/neon.cyan]")
    
    input("\n[neon.yellow]Ana menüye dönmek için Enter'a basın...[/neon.yellow]")
    return None

# ============================
# ASCII BANNERS & MODULES
# ============================
BANNERS: Dict[str, str] = {
    "HONEY": r""" 
__________      .__        __   
\______   \____ |__| _____/  |_ 
 |     ___/  _ \|  |/    \   __\
 |    |  (  <_> )  |   |  \  |  
 |____|   \____/|__|___|  /__|  
                         \/    
""", 
    "SCAN": r"""  
 _________                     
 /   _____/ ____ _____    ____  
 \_____  \_/ ___\\__  \  /    \ 
 /        \  \___ / __ \|   |  \
/_______  /\___  >____  /___|  /
        \/     \/     \/     \/ """, 
    "CRYPT": r"""   
 _________                _____ 
\_   ___ \_____   __ ___/ ____\
/    \  \/\__  \ |  |  \   __\ 
\     \____/ __ \|  |  /|  |   
 \______  (____  /____/ |__|   
        \/     \/                   """, 
    "LOG": r""" 
 __      __.__          
/  \    /  \  |   ____  
\   \/\/   /  | _/ __ \ 
 \        /|  |_\  ___/ 
  \__/\  / |____/\___  >
       \/            \/ """,
    "EXPLOIT": r""" 
___________              .__         .__  __   
\_   _____/__  _________ |  |   ____ |__|/  |_ 
 |    __)_\  \/  /\____ \|  |  /  _ \|  \   __\
 |        \>    < |  |_> >  |_(  <_> )  ||  |  
/_______  /__/\_ \|   __/|____/\____/|__||__|  
        \/      \/|__| """,
         "WIFI": r""" 
  __      __.__      .__       .__    
 /  \    /  \__|____ |__|____  |  |   
 \   \/\/   /  \__  \|  \__  \ |  |   
  \        /|  |/ __ \|  |/ __ \|  |__ 
   \__/\  / |__(____  /__(____  /____/ 
        \/          \/        \/      """,
}

MODULES = [
    {"key": "HONEY", "desc": "Chimera Honeypot v3.2 - Advanced Deception", "status": "READY", "executable": "modules/honey/honeypot.py"},
    {"key": "SCAN", "desc": "Network Scanner & Port Analysis", "status": "READY", "executable": "modules/scan/scan_tui.py"},
    {"key": "CRYPT", "desc": "Cryptography Tools & Hash Generator", "status": "READY", "executable": "modules/crypt/crypt_tui.py"},
    {"key": "LOG", "desc": "Log Analyzer & Event Monitor", "status": "READY", "executable": "modules/log/log_tui.py"},
    {"key": "EXPLOIT", "desc": "MSFvenom Payload Generator", "status": "READY", "executable": "modules/exploit/exploit_tui.py"},
    {"key": "WIFI", "desc": "WiFi Attack Suite - Auto Deauth & Scanning", "status": "READY", "executable": "modules/wifi/wifi_tui.py"}   
]

# ============================
# RENDER HELPERS
# ============================
def gradient_text(text: str, colors: List[str]) -> Text:
    t = Text()
    if not colors: return Text(text)
    if len(colors) == 1: return Text(text, style=colors[0])
    def lerp(a: int, b: int, t: float) -> int: return int(a + (b - a) * t)
    
    color_segments = len(colors) - 1
    segment_length = len(text) / color_segments if color_segments > 0 else len(text)
    
    for i, char in enumerate(text):
        segment = int(i / segment_length) if segment_length > 0 else 0
        if segment >= color_segments: segment = color_segments - 1
        progress = (i % segment_length) / segment_length if segment_length > 0 else 0
        c1, c2 = colors[segment], colors[segment+1]
        r1, g1, b1 = int(c1[1:3],16), int(c1[3:5],16), int(c1[5:7],16)
        r2, g2, b2 = int(c2[1:3],16), int(c2[3:5],16), int(c2[5:7],16)
        r, g, b = lerp(r1, r2, progress), lerp(g1, g2, progress), lerp(b1, b2, progress)
        t.append(char, style=f"bold #{r:02x}{g:02x}{b:02x}")
    return t

def banner_panel(key: str) -> Panel:
    title = gradient_text(f" // {key} // ", ["#00eaff", "#ff00f7", "#00ffc6"])
    return Panel(Align.center(Text.from_ansi(BANNERS.get(key, "").strip("\n")), vertical="middle"), title=title, border_style="neon.magenta", box=HEAVY_EDGE, padding=(1, 3))

def module_table() -> Table:
    table = Table(expand=True, box=ROUNDED, show_header=True, header_style="neon.yellow", pad_edge=False)
    table.add_column("MODUL", justify="center", style="neon.cyan", width=12)
    table.add_column("AÇIKLAMA", style="neon.magenta")
    table.add_column("DURUM", justify="center", width=10)
    
    for m in MODULES:
        s_style = {"OK": "ok", "IDLE": "hint", "LOCKED": "warn", "READY": "neon.green"}.get(m["status"], "dim.gray")
        table.add_row(m["key"], m["desc"], f"[{s_style}]{m['status']}[/]")
    
    return table

def sidebar_active(index: int) -> Panel:
    lines = [Text(f" {'➤' if i == index else '·'} {m['key']}", style="accent" if i == index else "dim.gray") for i, m in enumerate(MODULES)]
    lines.append(Text(""))  # Boş satır
    lines.append(Text(""))  # Boş satır
    body = Align.left(Text("\n").join(lines))
    return Panel(body, title="[neon.cyan]MODÜLLER[/]", border_style="neon.cyan", box=HEAVY)

def center_stage(active_key: str) -> RenderableType:
    if active_key == "HONEY":
        t = Text.assemble(
            ("Chimera Hardened v3.2", "neon.green"), ("\n",),
            ("• Multi-stage deception with terminal replays", "hint"), ("\n",),
            ("• PCAP-like logs and SIEM webhook support", "hint"), ("\n",),
            ("• SMB realism with NTLM-like bait", "hint"), ("\n",),
            ("• Web, FTP, SSH, SMB, SMTP, Redis, ES services", "hint"), ("\n",),
            ("• Rate limiting and tarpit functionality", "hint"), ("\n",),
            ("\n",), ("Press ENTER to launch honeypot", "accent"), ("\n",),
            ("⚠️  This will start real honeypot services!", "warn")
        )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("CHIMERA HONEYPOT", ["#35ff69", "#00eaff"]), border_style="neon.green", box=HEAVY, expand=True)
    
    elif active_key == "SCAN":
        t = Text.assemble(
            ("Network Scanner & Port Analysis", "neon.cyan"), ("\n",),
            ("• Quick port scanning (no nmap required)", "hint"), ("\n",),
            ("• Nmap integration with multiple scan types", "hint"), ("\n",),
            ("• Service detection and banner grabbing", "hint"), ("\n",),
            ("• Cross-platform support", "hint"), ("\n",),
            ("• Basic, Medium, Aggressive, Stealth modes", "hint"), ("\n",),
            ("\n",), ("Press ENTER to launch scanner", "accent"), ("\n",),
            ("🔍 Network scanning tool", "hint")
        )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("NETWORK SCANNER", ["#00eaff", "#35ff69"]), border_style="neon.cyan", box=HEAVY, expand=True)
    
    elif active_key == "CRYPT":
        t = Text.assemble(
            ("Cryptography Tools & Hash Generator", "neon.magenta"), ("\n",),
            ("• Hash generation (MD5, SHA1, SHA256, etc.)", "hint"), ("\n",),
            ("• Password cracking utilities", "hint"), ("\n",),
            ("• Random key generation", "hint"), ("\n",),
            ("• Secure password generation", "hint"), ("\n",),
            ("• Dictionary attack capabilities", "hint"), ("\n",),
            ("\n",), ("Press ENTER to launch crypto tools", "accent"), ("\n",),
            ("🔐 Cryptographic utilities", "hint")
        )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("CRYPTOGRAPHY TOOLS", ["#ff00f7", "#ffe500"]), border_style="neon.magenta", box=HEAVY, expand=True)
    
    elif active_key == "LOG":
        t = Text.assemble(
            ("Advanced Log Analyzer & PCAP Analysis", "neon.yellow"), ("\n",),
            ("• Load and analyze log files", "hint"), ("\n",),
            ("• Search and filter log entries", "hint"), ("\n",),
            ("• Pattern detection and analysis", "hint"), ("\n",),
            ("• PCAP file analysis with tshark", "hint"), ("\n",),
            ("• Wireshark integration", "hint"), ("\n",),
            ("\n",), ("Press ENTER to launch log analyzer", "accent"), ("\n",),
            ("📊 Advanced log analysis and network forensics", "hint")
        )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("LOG ANALYZER", ["#ffe500", "#00eaff"]), border_style="neon.yellow", box=HEAVY, expand=True)
    
    elif active_key == "EXPLOIT":
        t = Text.assemble(
            ("MSFvenom Payload Generator", "neon.red"), ("\n",),
            ("• APK, EXE, PHP, Python payload generation", "hint"), ("\n",),
            ("• EXTRA: HTA, VBS, JSP, DLL, SO, JAR, PS1", "hint"), ("\n",),
            ("• Auto IP detection and manual configuration", "hint"), ("\n",),
            ("• Payload encoding and customization", "hint"), ("\n",),
            ("• Advanced evasion techniques", "hint"), ("\n",),
            ("• Cross-platform payload support", "hint"), ("\n",),
            ("\n",), ("Press ENTER to launch exploit generator", "accent"), ("\n",),
            ("💣 Advanced payload generation with MSFvenom", "hint")
        )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("EXPLOIT GENERATOR", ["#ff4d4d", "#ffe500"]), border_style="neon.red", box=HEAVY, expand=True)
    
    elif active_key == "WIFI":
        t = Text.assemble(
            ("WiFi Attack Suite - Auto Deauth & Scanning", "neon.magenta"), ("\n",),
            ("• Automatic WiFi network scanning", "hint"), ("\n",),
            ("• Arrow key navigation for network selection", "hint"), ("\n",),
            ("• Continuous deauth attacks with time control", "hint"), ("\n",),
            ("• Aircrack-ng integration", "hint"), ("\n",),
            ("• Monitor mode management", "hint"), ("\n",),
            ("• Cross-platform support (Linux)", "hint"), ("\n",),
            ("\n",), ("Press ENTER to launch WiFi attack suite", "accent"), ("\n",),
            ("📡 Advanced WiFi penetration testing", "hint")
        )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("WIFI ATTACK SUITE", ["#ff00f7", "#00eaff"]), border_style="neon.magenta", box=HEAVY, expand=True)
    
   
# ============================
# MODULE LAUNCHER
# ============================
# MODULE LAUNCHER
# ============================
def launch_module(module_key: str, executable: str, os_type: str):
    """Launch the selected module executable in a new terminal window."""
    
    executable_path = os.path.abspath(executable)
    if not os.path.exists(executable_path):
        console.print(f"[red]Hata: Çalıştırılacak dosya bulunamadı: {executable_path}[/red]")
        return False
    
    current_dir = os.getcwd()
    
    try:
        if os_type == "Windows":
            # Windows: Yeni bir cmd penceresinde başlat
            command = f'start "Running {module_key}" cmd /k "\"{sys.executable}\" \"{executable_path}\""'
            subprocess.run(command, shell=True, check=True)
            console.print(f"[green]✓ {module_key} yeni bir Windows terminalinde başlatıldı![/green]")
            
        elif os_type == "Linux":
            # Linux: Yaygın terminal emülatörlerini dene
            # Kali Linux için xfce4-terminal ve diğerleri eklendi.
            run_command = f"cd \"{current_dir}\" && python3 \"{executable_path}\"; echo -e '\\nİşlem tamamlandı...'; exec bash"
            
            terminal_commands = [
                # Kali/XFCE, Mint/XFCE için
                ["xfce4-terminal", "--title", module_key, "--command", f"bash -c '{run_command}'"],
                # GNOME için
                ["gnome-terminal", "--title", module_key, "--", "bash", "-c", run_command],
                # KDE için
                ["konsole", "-e", f"bash -c '{run_command}'"],
                # Diğer yaygın terminaller
                ["tilix", "-t", module_key, "-e", f"bash -c '{run_command}'"],
                ["xterm", "-T", module_key, "-e", f"bash -c '{run_command}'"],
                ["kitty", "--title", module_key, "bash", "-c", run_command]
            ]
            
            launched = False
            for cmd in terminal_commands:
                try:
                    subprocess.Popen(cmd)
                    console.print(f"[green]✓ {module_key} yeni bir {cmd[0]} terminalinde başlatıldı![/green]")
                    launched = True
                    break
                except FileNotFoundError:
                    continue
                except Exception as e:
                    console.print(f"[warn]'{cmd[0]}' başlatılamadı: {e}[/warn]")

            if not launched:
                console.print(f"[yellow]Desteklenen bir terminal bulunamadı, doğrudan mevcut terminalde çalıştırılıyor...[/yellow]")
                subprocess.Popen([sys.executable, executable_path])
            
        elif os_type == "macOS":
            # macOS: Terminal.app kullanarak yeni bir pencere aç
            command = f'tell app "Terminal" to do script "cd {current_dir} && python3 {executable_path}"'
            subprocess.Popen(["osascript", "-e", command])
            console.print(f"[green]✓ {module_key} yeni bir macOS terminalinde başlatıldı![/green]")
            
        else:
            # Fallback: Auto-detect
            system = platform.system()
            console.print(f"[yellow]OS tipi belirlenemedi, otomatik algılanıyor: {system}[/yellow]")
            
            if system == "Windows":
                command = f'start "Running {module_key}" cmd /k "\"{sys.executable}\" \"{executable_path}\""'
                subprocess.run(command, shell=True, check=True)
                console.print(f"[green]✓ {module_key} yeni bir Windows terminalinde başlatıldı![/green]")
            elif system == "Linux":
                subprocess.Popen([sys.executable, executable_path])
                console.print(f"[green]✓ {module_key} mevcut Linux terminalde başlatıldı![/green]")
            elif system == "Darwin":
                command = f'tell app "Terminal" to do script "cd {current_dir} && python3 {executable_path}"'
                subprocess.Popen(["osascript", "-e", command])
                console.print(f"[green]✓ {module_key} yeni bir macOS terminalinde başlatıldı![/green]")
            else:
                subprocess.Popen([sys.executable, executable_path])
                console.print(f"[green]✓ {module_key} mevcut terminalde başlatıldı![/green]")
            
        return True
        
    except Exception as e:
        console.print(f"[red]Hata: {module_key} başlatılırken bir sorun oluştu: {e}[/red]")
        return False

# ============================
# ANA İNTERAKTİF DÖNGÜ
# ============================
def main():
    # Setup kontrolü - OS seçimi
    os_type = check_setup()
    
    active_index = 0
    
    while True:
        # 1. Her seferinde ekranı temizle
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # 2. Mevcut duruma göre tüm arayüzü oluştur
        layout = Layout(name="root")
        layout.split(Layout(name="header", size=11), Layout(name="body", ratio=1))
        layout["body"].split_row(Layout(name="sidebar", size=24), Layout(name="stage", ratio=1))
        
        active_key = MODULES[active_index]["key"]
        byghost ="""
__________         ________.__                    __   
\______   \___.__./  _____|/  |__   ____  _______/  |_ 
 |    |  _<   |  /   \  ___|  |  \ /  _ \/  ___/\   __|
 |    |   |\___  \    \_\  \   Y  (  <_> )___ \  |  |  
 |______  |/ ____|\______  /___|  |\____/____  > |__|  
        \/ \/            \/     \/           \/        
        """
        # Header'ı doldur
        header_content = Panel(Align.center(gradient_text(f"{byghost}", ["#00eaff", "#ff00f7"]), vertical="middle"), subtitle=Text("Commander Framework • Ghost Exploit", style="hint"), border_style="accent", box=HEAVY_EDGE, padding=(1, 2))
        banner = banner_panel(active_key)
        
        # OS bilgisi ekle
        
        header_layout = Layout()
        header_layout.split_row(Layout(header_content, ratio=4), Layout(banner, ratio=2))
        layout["header"].update(header_layout)

        # Sidebar'ı doldur
        layout["sidebar"].update(sidebar_active(active_index))

        # Ana sahneyi ve modül tablosunu doldur
        stage = Layout()
        
        # --- DEĞİŞİKLİK BURADA BAŞLIYOR ---
        # 1. Modül sayısına göre tablo yüksekliğini dinamik olarak hesapla.
        #    Her modül için 1 satır + Başlık için 1 satır + Üst/Alt kenarlıklar için 2 satır = len(MODULES) + 3
        table_height = len(MODULES) + 3
        
        # 2. `stage.split` metodunda sabit `size=9` yerine bu dinamik yüksekliği kullan.
        stage.split(
            Layout(Rule(style="dim.gray"), size=1), 
            Layout(center_stage(active_key), ratio=1), 
            Layout(Rule(style="dim.gray"), size=1), 
            Layout(module_table(), size=table_height)
        )
        # --- DEĞİŞİKLİK BURADA BİTİYOR ---
        
        layout["stage"].update(stage)

        # 3. Oluşturulan arayüzü ekrana bas
        console.print(layout)        
        try:
            # Readchar ile direkt tuş kontrolü
            key = readchar.readkey()
            
            if key == readchar.key.UP:  # Yukarı ok
                active_index = (active_index - 1) % len(MODULES)
            elif key == readchar.key.DOWN:  # Aşağı ok
                active_index = (active_index + 1) % len(MODULES)
            elif key == readchar.key.ENTER:  # Enter - seçili modülü çalıştır
                selected_module = MODULES[active_index]
                
                # Check if the module is locked
                if selected_module.get("status") == "LOCKED":
                    console.print(f"\n[bold warn]Module '{selected_module['key']}' is LOCKED and cannot be launched.[/bold warn]")
                    input("\nPress Enter to continue...")
                    continue  # Launching işlemini atla
                
                console.print(f"\n[bold cyan]Launching {selected_module['key']}...[/bold cyan]")
                if launch_module(selected_module['key'], selected_module['executable'], os_type):
                    console.print(f"[green]✓ {selected_module['key']} successfully launched![/green]")
                    console.print("[yellow]Check the new terminal window/tab for output.[/yellow]")
                else:
                    console.print(f"[red]✗ Failed to launch {selected_module['key']}![/red]")
                input("\nPress Enter to continue...")
            elif key.lower() == 'c':  # C ile config değiştir
                new_os_type = change_config()
                if new_os_type:
                    os_type = new_os_type
                    console.print(f"\n[green]✓ İşletim sistemi {os_type} olarak güncellendi![/green]")
                input("\nPress Enter to continue...")
            elif key.lower() == 'q':  # Q ile çıkış
                break
            # Diğer tuşlar için hiçbir şey yapma
            
        except KeyboardInterrupt:
            break
        except EOFError:
            break

    # Program biterken çıkış mesajı
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print(Panel(Align.center(Text("EXIT", style="warn")), border_style="warn", box=HEAVY))

if __name__ == "__main__":
    main()