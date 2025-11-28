#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Scanner TUI - The Complete Vision (v8.0 FINAL)
========================================================
This is the definitive build, rectifying the previous misinterpretation.
The results screen now correctly displays BOTH the Host Information panel
AND the detailed Open Ports table below it, all within a single, clean
interface. All aesthetic distractions have been removed. This is the
tool as it was always meant to be.
"""
import threading
import socket
import subprocess
from typing import List, Dict, Any
from enum import Enum, auto
import time

from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.box import SQUARE

import readchar
import xml.etree.ElementTree as ET

# --- Enums for State Management ---
class AppState(Enum):
    MAIN_MENU = auto()
    GETTING_INPUT = auto()
    SCANNING = auto()
    SHOWING_RESULTS = auto()

# --- Aesthetics & Constants ---
CYAN = "bold cyan"
GREEN = "bold #35ff69"
YELLOW = "bold #ffe500"
RED = "bold #ff4d4d"
HINT = "grey50"
BORDER_COLOR = "dim cyan"
SELECTION = "bold #35ff69"
CONSOLE = Console()

# --- Network Scanning Logic (Corrected to return full port list) ---
class NetworkScanner:
    def nmap_scan(self, target: str, scan_type: str) -> Dict[str, Any]:
        nmap_args = ['nmap', '-oX', '-']
        scan_configs = {'basic': ['-sS', '-T4', '--top-ports', '1000'], 'medium': ['-sS', '-sV', '-T4', '--top-ports', '1000'], 'aggressive': ['-A', '-T4'], 'stealth': ['-sS', '-T2', '--top-ports', '100']}
        nmap_args.extend(scan_configs.get(scan_type, []))
        nmap_args.append(target)
        try:
            result = subprocess.run(nmap_args, capture_output=True, text=True, timeout=600)
            if result.returncode == 0 and result.stdout: return self._parse_nmap_xml(result.stdout)
            else: return {'error': f"Nmap error: {result.stderr or 'Permission denied (try sudo)'}"}
        except subprocess.TimeoutExpired: return {'error': 'Nmap scan timed out (10 minutes).'}
        except Exception as e: return {'error': f"An unexpected error occurred: {e}"}

    def _parse_nmap_xml(self, xml_output: str) -> Dict[str, Any]:
        try:
            root = ET.fromstring(xml_output)
            host = root.find('.//host')
            if host is None: return {'ports': []} # No host found
            
            host_info = {}
            status = host.find('status'); host_info['status'] = status.get('state', 'unknown') if status is not None else 'unknown'
            addr = host.find("address[@addrtype='ipv4']"); host_info['ip'] = addr.get('addr') if addr is not None else 'N/A'
            mac_addr = host.find("address[@addrtype='mac']")
            if mac_addr is not None:
                host_info['mac'] = mac_addr.get('addr')
                host_info['mac_vendor'] = mac_addr.get('vendor', 'Unknown')
            os_match = host.find("os/osmatch")
            if os_match is not None: host_info['os'] = os_match.get('name', 'Detection failed')

            # DÜZELTME: Port listesini tam olarak topla
            open_ports = []
            for port in host.findall('.//port'):
                state_element = port.find('state')
                if state_element is not None and state_element.get('state') == 'open':
                    port_id, protocol = port.get('portid'), port.get('protocol')
                    service = port.find('service')
                    service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                    service_product = service.get('product', '') if service is not None else ''
                    service_version = service.get('version', '') if service is not None else ''
                    open_ports.append({'port': f"{port_id}/{protocol}", 'state': 'open', 'service': service_name, 'version': f"{service_product} {service_version}".strip()})
            
            return {'host_info': host_info, 'ports': open_ports}
        except ET.ParseError: return {'error': 'Failed to parse Nmap XML output.'}

# --- Main Application Class ---
class App:
    def __init__(self):
        self.scanner = NetworkScanner()
        self.app_state = { "state": AppState.MAIN_MENU, "menu_index": 0, "input_buffer": "", "target": "", "results": {} }
        self.running = True
        self.layout = self._create_layout()

    def _create_layout(self) -> Layout:
        layout = Layout()
        layout.split(
            Layout(self._create_header_panel(), name="header", size=12),
            Layout(name="body", ratio=1)
        )
        layout["body"].split_row(
            Layout(name="sidebar", size=40),
            Layout(name="main", ratio=1)
        )
        return layout

    def _create_header_panel(self) -> Panel:
            banner_art = r"""
    ███████╗ █████╗ ██████╗ █████╗ ███████╗ █████╗
    ██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗
    ███████╗███████║██║  ███╗███████║███████╗███████║
    ╚════██║██╔══██║██║   ██║██╔══██║╚════██║██╔══██║
    ███████║██║  ██║╚██████╔╝██║  ██║███████║██║  ██║
    ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    """
            quote = "There are no secrets in the dark, only undiscovered truths."

            # Assemble the banner and the quote into a single renderable object
            header_content = Text.assemble(
                (banner_art, "bold #03a9f4"),
                "\n",  # Add a newline for spacing
                (quote, RED)
            )

            return Panel(
                Align.center(header_content),
                border_style=BORDER_COLOR,
                title="NETWORK SCANNER",
                title_align="center"
            )
    def _generate_renderable(self) -> Layout:
        self.layout["sidebar"].update(self._create_sidebar_panel())
        self.layout["main"].update(self._create_main_panel())
        return self.layout

    def _create_sidebar_panel(self) -> Panel:
        options = ["Nmap Basic", "Nmap Medium", "Nmap Aggressive", "Nmap Stealth", "Exit"]
        active_index = self.app_state["menu_index"]
        option_texts = [ Text(f" > {opt}" if i == active_index else f"   {opt}", style=SELECTION if i == active_index else HINT) for i, opt in enumerate(options) ]
        return Panel(Text("\n").join(option_texts), title="OPTIONS", border_style=BORDER_COLOR)

    def _create_main_panel(self) -> Panel:
        state = self.app_state["state"]
        content, title, border_style = Text(""), "", BORDER_COLOR

        if state == AppState.MAIN_MENU:
            content = Align.center(Text.assemble(("Select a scan type to begin.", HINT)), vertical="middle")
        elif state == AppState.GETTING_INPUT:
            title = "TARGET INPUT"; border_style = YELLOW
            content = Align.center(Text.assemble(("Enter Target IP / Hostname", YELLOW), ("\n\n> ", HINT), (self.app_state["input_buffer"], GREEN), ("█", "blink white")), vertical="middle")
        elif state == AppState.SCANNING:
            title = "SCANNING"; border_style = GREEN
            content = Align.center(Text.assemble(("Scan in progress...", YELLOW), ("\n\nTarget: ", HINT), (self.app_state["target"], CYAN)), vertical="middle")
        elif state == AppState.SHOWING_RESULTS:
            results = self.app_state["results"]
            if 'error' in results:
                title = "ERROR"; border_style = RED
                content = Align.center(Text(results.get('error', "An unknown error occurred."), style=GREEN), vertical="middle")
            else:
                title = "HOST REPORT"; border_style = GREEN
                
                # DÜZELTME: Rapor ve Portlar için dikey layout
                report_layout = Layout()
                report_layout.split(Layout(name="info", size=7), Layout(name="ports", ratio=1))
                
                info = results.get('host_info', {})
                info_table = Table.grid(padding=(0, 2))
                info_table.add_column(style=YELLOW); info_table.add_column()
                if info.get('ip'): info_table.add_row("IP Address:", Text(info.get('ip', 'N/A'), style=CYAN))
                if info.get('mac'): info_table.add_row("MAC Address:", Text(f"{info.get('mac')} ({info.get('mac_vendor', 'N/A')})", style=CYAN))
                if info.get('os'): info_table.add_row("Operating System:", Text(info.get('os'), style=CYAN))
                report_layout["info"].update(Panel(info_table, title="Host_Information", border_style=HINT, title_align="right"))
                
                ports = results.get('ports', [])
                ports_table = Table(box=SQUARE, border_style=HINT, expand=True)
                ports_table.add_column("Port", style=YELLOW); ports_table.add_column("State", style=GREEN); ports_table.add_column("Service", style=CYAN); ports_table.add_column("Version", style=HINT)
                if not ports:
                    ports_table.add_row(Text("No open ports found.", style=HINT, justify="center"))
                else:
                    for res in ports: ports_table.add_row(str(res.get('port')), res.get('state', '').upper(), res.get('service'), res.get('version'))
                report_layout["ports"].update(ports_table)
                content = report_layout
        
        return Panel(content, title=title, border_style=border_style)

    def run(self):
        input_thread = threading.Thread(target=self._input_loop, daemon=True); input_thread.start()
        with Live(self._generate_renderable(), screen=True, transient=True, refresh_per_second=20) as live:
            while self.running:
                live.update(self._generate_renderable()); time.sleep(0.05)

    def _input_loop(self):
        menu_count = 5 # Menüden Quick Scan kaldırıldı
        while self.running:
            try: key = readchar.readkey(); self._handle_key(key, menu_count)
            except KeyboardInterrupt: self.running = False; break
    
    def _handle_key(self, key: str, menu_count: int):
        if key.lower() == 'q': self.running = False; return
        if key.lower() == 'b' and self.app_state["state"] == AppState.SHOWING_RESULTS: self.app_state["state"] = AppState.MAIN_MENU; return
        
        current_state = self.app_state["state"]
        if current_state in [AppState.MAIN_MENU, AppState.SHOWING_RESULTS]:
            if key == readchar.key.UP: self.app_state["menu_index"] = (self.app_state["menu_index"] - 1) % menu_count
            elif key == readchar.key.DOWN: self.app_state["menu_index"] = (self.app_state["menu_index"] + 1) % menu_count
            elif key == readchar.key.ENTER:
                if self.app_state["menu_index"] == (menu_count - 1): self.running = False; return # Exit
                self.app_state["state"] = AppState.GETTING_INPUT; self.app_state["input_buffer"] = ""
        elif current_state == AppState.GETTING_INPUT:
            if key == readchar.key.ENTER:
                if self.app_state["input_buffer"]:
                    self.app_state["target"] = self.app_state["input_buffer"]; self.app_state["state"] = AppState.SCANNING
                    threading.Thread(target=self._scan_worker, daemon=True).start()
            elif key == readchar.key.BACKSPACE: self.app_state["input_buffer"] = self.app_state["input_buffer"][:-1]
            elif key == readchar.key.ESC: self.app_state["state"] = AppState.MAIN_MENU
            elif len(key) == 1 and key.isprintable(): self.app_state["input_buffer"] += key

    def _scan_worker(self):
        scan_types = {0: 'basic', 1: 'medium', 2: 'aggressive', 3: 'stealth'}
        scan_type = scan_types[self.app_state["menu_index"]]
        target = self.app_state["target"]
        results = self.scanner.nmap_scan(target, scan_type)
        self.app_state["results"] = results
        self.app_state["state"] = AppState.SHOWING_RESULTS

if __name__ == "__main__":
    try: app = App(); app.run()
    except Exception: CONSOLE.print_exception(show_locals=True)
    finally: CONSOLE.print(f"[{GREEN}]Scanner terminated. Goodbye![/{GREEN}]")
