#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 Rich TUI Mock Framework — ImLock/ByGhost 
=======================================================
İnteraktif, modern siberpunk estetiğinde, mükemmel hizalamaya takıntılı
ve tamamen framework gibi bir Rich tabanlı arayüz.

📋 PROJE AÇIKLAMASI:
Bu dosya, klavye kontrolü ile etkileşimli bir terminal arayüzü sağlar.
Kullanıcı yukarı/aşağı ok tuşları ile modüller arasında geçiş yapabilir.

🎮 KONTROLLER:
- ↑/↓ Ok tuşları: Modül geçişi
- Enter: Seçim (şu an sadece gezinme)
- Q: Çıkış
- Ctrl+C: Acil çıkış

🏗️ TEKNİK ÖZELLİKLER:
- readchar kütüphanesi ile düşük seviye klavye kontrolü
- Rich Layout sistemi ile modüler arayüz tasarımı
- Neon renk paleti ile siberpunk estetiği
- Gradient metin efektleri
- ASCII art bannerlar

⚠️ ÖNEMLİ NOT:
Bu bir demo projesidir. Gerçek siber güvenlik işlemleri yapmaz.
Sadece görsel ve estetik amaçlıdır.

"""

from __future__ import annotations
import time
import random
import os
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
    "dim.gray": "#6b7280", "accent": "bold #00ffc6", "warn": "bold #ff4d4d",
    "ok": "bold #76ff03", "hint": "#9ca3af",
})
console = Console(theme=NEON_THEME)

# ============================
# ASCII BANNERS & MODULES (Değişiklik yok)
# ============================
BANNERS: Dict[str, str] = {
    "CORE": r""" 
 ____  __.                   
|    |/ _|____ ___.__. ______
|      <_/ __ <   |  |/  ___/
|    |  \  ___/\___  |\___ \ 
|____|__ \___  > ____/____  >
        \/   \/\/         \/
   """, "SCAN": r"""  
 _________                     
 /   _____/ ____ _____    ____  
 \_____  \_/ ___\\__  \  /    \ 
 /        \  \___ / __ \|   |  \
/_______  /\___  >____  /___|  /
        \/     \/     \/     \/ """, "EXPLOIT": r""" 
 __      __       ____  ___
/  \    /  \______\   \/  /
\   \/\/   /\____ \\     / 
 \        / |  |_> >     \ 
  \__/\  /  |   __/___/\  \
       \/   |__|        \_/        """, "CRYPT": r"""   
 _________                _____ 
\_   ___ \_____   __ ___/ ____\
/    \  \/\__  \ |  |  \   __\ 
\     \____/ __ \|  |  /|  |   
 \______  (____  /____/ |__|   
        \/     \/                   """, "LOG": r""" 
 __      __.__          
/  \    /  \  |   ____  
\   \/\/   /  | _/ __ \ 
 \        /|  |_\  ___/ 
  \__/\  / |____/\___  >
       \/            \/ """,
}
MODULES = [
    {"key": "CORE", "desc": "Kernel, config ve sahte servisler", "status": "OK"},
    {"key": "SCAN", "desc": "Ağ tarama ve yüzey analizi", "status": "IDLE"},
    {"key": "EXPLOIT", "desc": "Payload upload ", "status": "LOCKED"},
    {"key": "CRYPT", "desc": "Şifreleme/çözme vitrin fonksiyonları", "status": "OK"},
    {"key": "LOG", "desc": "Taklit log akışı ve uyarılar", "status": "OK"},
]
# ============================
# RENDER HELPERS (Değişiklik yok)
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
    table.add_column("AÇIKLAMA"); table.add_column("DURUM", justify="center", width=10)
    for m in MODULES:
        s_style = {"OK": "ok", "IDLE": "hint", "LOCKED": "warn"}.get(m["status"], "dim.gray")
        table.add_row(m["key"], m["desc"], f"[{s_style}]{m['status']}[/]")
    return table

def sidebar_active(index: int) -> Panel:
    lines = [Text(f" {'➤' if i == index else '·'} {m['key']}", style="accent" if i == index else "dim.gray") for i, m in enumerate(MODULES)]
    body = Align.left(Text("\n").join(lines))
    return Panel(body, title="[neon.cyan]MODÜLLER[/]", border_style="neon.cyan", box=HEAVY)

def center_stage(active_key: str) -> RenderableType:
    if active_key == "SCAN":
        s_bar = "".join("Nmap Scan > nmap -v -Ss -T5  10.1.1.0/24")
        return Panel(Align.center(Text(s_bar, style="neon.green"), vertical="middle"), title=gradient_text("SURFACE SWEEP", ["#35ff69", "#00eaff"]), border_style="neon.green", box=HEAVY, expand=True)
    if active_key == "EXPLOIT":
        t = Table(expand=True, box=ROUNDED, header_style="neon.magenta")
        t.add_column("PAYLOAD", style="neon.magenta", width=16); t.add_column("VEKTÖR"); t.add_column("SİMÜLASYON", justify="center", width=12)
        sample = [("ICE-NEEDLE", "HTTP/2 Rapid Reset (mock)", "ARMING"), ("NIGHT-FALL", "SMB Ghost (mock)", "STAGED"), ("GLASS-DAGGER", "RADIUS blast (mock)", "LOCKED")]
        for n, v, s in sample: t.add_row(n, v, f"[{'warn' if s == 'LOCKED' else 'ok'}]{s}[/]")
        return Panel(t, title=gradient_text("EXPLOIT LAB", ["#ff00f7", "#ffe500"]))
    if active_key == "CRYPT":
        body = Text.assemble(("Key ", "hint"), (str(random.randint(2,16)), "neon.yellow"), (" :: ",), ("".join(random.choice("0123456789abcdef") for _ in range(64)), "accent"))
        return Panel(Align.center(body, vertical="middle"), title=gradient_text("CRYPTOGRAPHY SANDBOX", ["#00ffc6", "#ff00f7"]), expand=True)
    if active_key == "LOG":
        log = Table.grid(padding=(0,1))
        log.add_column(ratio=1)
        for _ in range(console.height // 4 if console.height > 4 else 1):
            log.add_row(Text(f"[{random.choice(['OK','INFO','WARN'])}] {random.choice(['phantom event','kernel heartbeat','auth attempt'])} id={random.randint(1000,9999)}", style=random.choice(["ok","hint","warn"])))
        return Panel(log, title=gradient_text("EVENT LOG", ["#ffe500", "#00eaff"]))
    # CORE (default)
    t = Text.assemble(("Config: ", "hint"), ("/etc/ghost/core.toml\n", "accent"), ("Services: ", "hint"), ("daemon(mock)=active\n", "ok"), ("Web: ", "hint"), ("byghost.tr.", "warn"))
    return Panel(Align.center(t, vertical="middle"), title=gradient_text("CORE KERNEL", ["#00eaff", "#35ff69"]), expand=True)

# ============================
# ANA İNTERAKTİF DÖNGÜ (READCHAR SIDEBAR)
# ============================
def main():
    active_index = 0  # Direkt index kullan
    
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
        header_layout = Layout()
        header_layout.split_row(Layout(header_content, ratio=2), Layout(banner, ratio=1))
        layout["header"].update(header_layout)

        # Sidebar'ı doldur
        layout["sidebar"].update(sidebar_active(active_index))

        # Ana sahneyi ve modül tablosunu doldur
        stage = Layout()
        stage.split(Layout(Rule(style="dim.gray"), size=1), Layout(center_stage(active_key), ratio=1), Layout(Rule(style="dim.gray"), size=1), Layout(module_table(), size=9))
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
            elif key == readchar.key.ENTER:  # Enter - seçim yapma, sadece gezin
                pass
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
