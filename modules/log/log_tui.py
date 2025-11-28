#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Log Analyzer & PCAP Analysis TUI
=========================================
Real log analysis with file reading, searching, filtering, PCAP analysis, and pattern detection.
Includes anomaly detection for DoS, Brute-Force, and PCAP analysis for ARP Spoofing.
"""

import os
import sys
import time
import subprocess
import platform
import re
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from collections import defaultdict, Counter
from rich.console import Console, RenderableType
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.table import Table
from rich.box import ROUNDED, HEAVY, HEAVY_EDGE
from rich.theme import Theme
import readchar

# Theme
NEON_THEME = Theme({
    "neon.magenta": "bold #ff00f7",
    "neon.green": "bold #35ff69",
    "neon.yellow": "bold #ffe500",
    "neon.red": "bold #ff4d4d",
    "neon.cyan": "bold #00eaff",
    "accent": "bold #00ffc6",
    "hint": "#9ca3af",
})

console = Console(theme=NEON_THEME)

class LogAnalyzer:
    def __init__(self):
        self.selected_module = self.load_selected_module()
        self.current_file = ""
        self.log_lines = []
        self.filtered_lines = []
        self.search_results = []
        self.pcap_analysis = {}
        self.network_monitor = None
        self.patterns = {
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'url': r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?',
            'timestamp': r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
            'error': r'(?i)(error|fail|exception|critical|fatal)',
            'warning': r'(?i)(warn|warning|alert)',
            'success': r'(?i)(success|ok|passed|completed)',
            'ssh_attempt': r'(?i)(ssh|sshd).*(failed|accepted|rejected)',
            'http_request': r'(?i)(get|post|put|delete)\s+[^\s]+',
            'port_scan': r'(?i)(port|scan|nmap|probe)',
            # New patterns for specific attack indicators in logs
            'potential_dos_indicator': r'(?i)(flood|connection limit|rate-limit)',
            'potential_arp_spoof_indicator': r'(?i)(arp spoof|duplicate mac address)',
        }
        self.stats = defaultdict(int)
        self.wireshark_installed = self.check_wireshark()
        
        # Initialize network monitor
        self.init_network_monitor()

    def load_selected_module(self) -> str:
        """Load selected module from file"""
        try:
            if os.path.exists("selected_module.txt"):
                with open("selected_module.txt", "r") as f:
                    module = f.read().strip()
                    return module if module else "None"
        except:
            pass
        return "None"

    def check_wireshark(self) -> bool:
        """Check if Wireshark and tshark are installed"""
        try:
            if platform.system() == "Windows":
                possible_paths = [
                    r"C:\Program Files\Wireshark\Wireshark.exe",
                    r"C:\Program Files (x86)\Wireshark\Wireshark.exe"
                ]
                return any(os.path.exists(path) for path in possible_paths)
            else:
                result = subprocess.run(['which', 'wireshark'], capture_output=True, text=True)
                tshark_result = subprocess.run(['which', 'tshark'], capture_output=True, text=True)
                return result.returncode == 0 and tshark_result.returncode == 0
        except:
            return False

    def load_log_file(self, filepath: str) -> str:
        """Load and parse log file"""
        try:
            if not os.path.exists(filepath):
                return "File not found"

            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                self.log_lines = [line.strip() for line in f if line.strip()]

            self.current_file = filepath
            self.filtered_lines = self.log_lines.copy()
            self.analyze_patterns()
            return f"Loaded {len(self.log_lines)} lines from {filepath}"

        except Exception as e:
            return f"Error reading file: {e}"

    def analyze_patterns(self):
        """Analyze log patterns, extract statistics, and detect anomalies."""
        self.stats.clear()
        
        ip_counter = Counter()
        failed_ssh_counter = Counter()
        ip_pattern = re.compile(self.patterns['ip_address'])
        
        for line in self.log_lines:
            # Count pattern matches
            for pattern_name, pattern in self.patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    self.stats[pattern_name] += 1
            
            # Count by log level
            if re.search(r'(?i)error|fail|exception|critical|fatal', line):
                self.stats['error_level'] += 1
            elif re.search(r'(?i)warn|warning|alert', line):
                self.stats['warning_level'] += 1
            elif re.search(r'(?i)info|information', line):
                self.stats['info_level'] += 1
            elif re.search(r'(?i)debug', line):
                self.stats['debug_level'] += 1
            
            # Anomaly Detection Logic: count events per IP
            ip_match = ip_pattern.search(line)
            if ip_match:
                ip = ip_match.group(0)
                ip_counter[ip] += 1
                
                # Check for failed SSH attempts from this IP
                if re.search(r'(?i)(ssh|sshd).*failed', line):
                    failed_ssh_counter[ip] += 1

        # Analyze collected data for anomalies
        DOS_THRESHOLD = 150 # High number of requests from a single IP
        BRUTE_FORCE_THRESHOLD = 10 # High number of failed logins from a single IP

        potential_dos_sources = [ip for ip, count in ip_counter.items() if count > DOS_THRESHOLD]
        if potential_dos_sources:
            self.stats['potential_dos_sources'] = len(potential_dos_sources)

        potential_brute_force_sources = [ip for ip, count in failed_ssh_counter.items() if count > BRUTE_FORCE_THRESHOLD]
        if potential_brute_force_sources:
            self.stats['potential_brute_force_sources'] = len(potential_brute_force_sources)

    def search_logs(self, search_term: str, case_sensitive: bool = False) -> List[str]:
        """Search logs for specific terms"""
        results = []
        flags = 0 if case_sensitive else re.IGNORECASE

        for i, line in enumerate(self.log_lines, 1):
            if re.search(search_term, line, flags):
                results.append(f"Line {i}: {line}")

        self.search_results = results
        return results

    def filter_logs(self, filter_type: str, value: str = "") -> List[str]:
        """Filter logs by various criteria"""
        if filter_type == "error":
            self.filtered_lines = [line for line in self.log_lines if re.search(r'(?i)error|fail|exception|critical|fatal', line)]
        elif filter_type == "warning":
            self.filtered_lines = [line for line in self.log_lines if re.search(r'(?i)warn|warning|alert', line)]
        elif filter_type == "ip":
            self.filtered_lines = [line for line in self.log_lines if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)]
        elif filter_type == "timestamp":
            self.filtered_lines = [line for line in self.log_lines if re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', line)]
        elif filter_type == "custom":
            if value:
                self.filtered_lines = [line for line in self.log_lines if value.lower() in line.lower()]
        elif filter_type == "clear":
            self.filtered_lines = self.log_lines.copy()

        return self.filtered_lines

    def analyze_pcap(self, pcap_file: str) -> Dict:
        """Analyze PCAP file using tshark for general stats and specific attacks."""
        if not os.path.exists(pcap_file):
            return {"error": "PCAP file not found"}

        try:
            # Check if tshark is available
            if platform.system() == "Windows":
                tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
                if not os.path.exists(tshark_path):
                    return {"error": "tshark not found. Install Wireshark with CLI tools."}
            else:
                result = subprocess.run(['which', 'tshark'], capture_output=True, text=True)
                if result.returncode != 0:
                    return {"error": "tshark not found. Install Wireshark with CLI tools."}
                tshark_path = "tshark"

            # Basic PCAP statistics
            stats_cmd = [tshark_path, "-r", pcap_file, "-q", "-z", "io,stat,0"]
            stats_result = subprocess.run(stats_cmd, capture_output=True, text=True, timeout=60)

            # Protocol statistics
            proto_cmd = [tshark_path, "-r", pcap_file, "-q", "-z", "io,phs"]
            proto_result = subprocess.run(proto_cmd, capture_output=True, text=True, timeout=60)

            # Top talkers
            talkers_cmd = [tshark_path, "-r", pcap_file, "-q", "-z", "conv,ip"]
            talkers_result = subprocess.run(talkers_cmd, capture_output=True, text=True, timeout=60)

            # --- NEW ADVANCED ANALYSIS ---
            # ARP Spoofing Detection
            arp_cmd = [tshark_path, "-r", pcap_file, "-Y", "arp.duplicate-address-detected", "-T", "fields", "-e", "frame.time", "-e", "arp.src.hw_mac", "-e", "arp.src.proto_ipv4"]
            arp_result = subprocess.run(arp_cmd, capture_output=True, text=True, timeout=60)

            # SYN Flood / Potential DoS Detection (counts half-open connections)
            syn_flood_cmd = [tshark_path, "-r", pcap_file, "-q", "-z", "conv,tcp,tcp.flags.syn==1&&tcp.flags.ack==0"]
            syn_flood_result = subprocess.run(syn_flood_cmd, capture_output=True, text=True, timeout=60)
            
            return {
                "file": pcap_file,
                "stats": stats_result.stdout,
                "protocols": proto_result.stdout,
                "talkers": talkers_result.stdout,
                "arp_spoofing": arp_result.stdout.strip() or "No duplicate ARP packets detected.",
                "syn_flood_analysis": syn_flood_result.stdout.strip() or "No SYN-only conversations found."
            }
        
        except subprocess.TimeoutExpired:
            return {"error": f"PCAP analysis timed out on {os.path.basename(pcap_file)}. File may be too large."}
        except Exception as e:
            return {"error": f"PCAP analysis failed: {e}"}

    def launch_wireshark(self, pcap_file: str = None):
        """Launch Wireshark with optional PCAP file"""
        try:
            if platform.system() == "Windows":
                wireshark_path = r"C:\Program Files\Wireshark\Wireshark.exe"
                if not os.path.exists(wireshark_path):
                    wireshark_path = r"C:\Program Files (x86)\Wireshark\Wireshark.exe"
                cmd = [wireshark_path]
                if pcap_file and os.path.exists(pcap_file):
                    cmd.append(pcap_file)
            else:
                cmd = ['wireshark']
                if pcap_file and os.path.exists(pcap_file):
                    cmd.append(pcap_file)

            subprocess.Popen(cmd)
            return True
        except Exception as e:
            console.print(f"[neon.red]Error launching Wireshark: {e}[/neon.red]")
            return False
    
    def init_network_monitor(self):
        """Initialize network monitor from logscan.py"""
        try:
            # Import NetworkMonitor from logscan.py using relative import
            from .logscan import NetworkMonitor
            self.network_monitor = NetworkMonitor()
            return True
        except ImportError:
            # Fallback for when running from different directory
            try:
                import sys
                import os
                # Add the project root to path
                project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                if project_root not in sys.path:
                    sys.path.insert(0, project_root)
                from modules.log.logscan import NetworkMonitor
                self.network_monitor = NetworkMonitor()
                return True
            except Exception as e:
                console.print(f"[neon.yellow]Network monitor not available: {e}[/neon.yellow]")
                return False
        except Exception as e:
            console.print(f"[neon.yellow]Network monitor not available: {e}[/neon.yellow]")
            return False
    
    def start_network_capture(self, interface: str = None, duration: int = 300) -> bool:
        """Start real-time network capture"""
        if not self.network_monitor:
            console.print("[neon.red]Network monitor not initialized![/neon.red]")
            return False
        
        try:
            return self.network_monitor.start_capture(interface, duration)
        except Exception as e:
            console.print(f"[neon.red]Error starting capture: {e}[/neon.red]")
            return False
    
    def stop_network_capture(self) -> bool:
        """Stop network capture"""
        if not self.network_monitor:
            return False
        
        try:
            return self.network_monitor.stop_capture()
        except Exception as e:
            console.print(f"[neon.red]Error stopping capture: {e}[/neon.red]")
            return False
    
    def get_network_interfaces(self) -> List[str]:
        """Get available network interfaces"""
        if not self.network_monitor:
            return []
        
        try:
            return self.network_monitor.interface_list
        except:
            return []
    
    def is_capturing(self) -> bool:
        """Check if network capture is running"""
        if not self.network_monitor:
            return False
        
        try:
            return self.network_monitor.is_capturing
        except:
            return False
    
    def auto_load_network_logs(self):
        """Auto-load network logs if they exist"""
        network_files = ["scan_results.log", "security_alerts.log", "network_stats.json"]
        loaded_files = []
        
        for filename in network_files:
            if os.path.exists(filename):
                try:
                    if filename.endswith('.log'):
                        result = self.load_log_file(filename)
                        if "Loaded" in result:
                            loaded_files.append(filename)
                    elif filename.endswith('.json'):
                        # Load JSON stats
                        with open(filename, 'r') as f:
                            stats_data = json.load(f)
                            console.print(f"[neon.green]Loaded network stats: {filename}[/neon.green]")
                            loaded_files.append(filename)
                except Exception as e:
                    console.print(f"[neon.yellow]Error loading {filename}: {e}[/neon.yellow]")
        
        if loaded_files:
            console.print(f"[neon.cyan]Auto-loaded network files: {', '.join(loaded_files)}[/neon.cyan]")
            return True
        
        return False

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

def create_layout() -> Layout:
    layout = Layout(name="root")
    layout.split(Layout(name="header", size=8), Layout(name="body", ratio=1))
    layout["body"].split_row(Layout(name="sidebar", size=30), Layout(name="main", ratio=1))
    return layout

def create_header() -> Panel:
    banner = r"""
 __      __.__  .__  .__   
/  \    /  \__| |  | |  |  
\   \/\/   /  | |  | |  |  
 \        /|  |_|  |_|  |__
  \__/\  / |____/____/____/
       \/                  
        
        Developer > ByGhost
        WebSite   > byghost.tr """
    
    title = gradient_text("LOG & PCAP ANALYZER", ["#ff00f7", "#ffe500"])
    return Panel(
        Align.center(Text.from_ansi(banner.strip("\n")), vertical="middle"),
        title=title,
        border_style="neon.magenta",
        box=HEAVY_EDGE
    )

def create_sidebar(active_index: int) -> Panel:
    options = [
        "Load Log File",
        "Search Logs",
        "Filter Logs",
        "Pattern Analysis",
        "PCAP Analysis",
        "Start Network Capture",
        "Stop Network Capture",
        "Launch Wireshark",
        "View Selected Module",
        "Exit"
    ]
    
    lines = []
    for i, option in enumerate(options):
        if i == active_index:
            lines.append(Text(f" ➤ {option}", style="accent"))
        else:
            lines.append(Text(f"   {option}", style="hint"))
    
    body = Align.left(Text("\n").join(lines))
    return Panel(body, title="[neon.magenta]OPTIONS[/]", border_style="neon.magenta", box=HEAVY)

def create_main_content(analyzer: LogAnalyzer, content_type: str = "welcome") -> RenderableType:
    if content_type == "welcome":
        t = Text.assemble(
            ("Advanced Log Analyzer & PCAP Analysis", "neon.magenta"), ("\n\n",),
            ("• Load and analyze log files", "hint"), ("\n",),
            ("• Search and filter log entries", "hint"), ("\n",),
            ("• Anomaly and pattern detection", "hint"), ("\n",),
            ("• PCAP file analysis for network attacks", "neon.yellow"), ("\n",),
            ("• Wireshark integration", "hint"), ("\n\n",),
            ("Select an option from the sidebar", "accent"), ("\n",),
            ("Use ↑/↓ to navigate, Enter to select", "hint")
        )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("WELCOME", ["#ff00f7", "#ffe500"]), border_style="neon.magenta", box=HEAVY, expand=True)
    
    elif content_type == "load_file":
        t = Text.assemble(
            ("Load Log File", "neon.cyan"), ("\n\n",),
            ("Current File: ", "hint"), (analyzer.current_file or "None", "accent"), ("\n",),
            ("Lines Loaded: ", "hint"), (str(len(analyzer.log_lines)), "accent"), ("\n\n",),
            ("Enter file path to load:", "hint"), ("\n",),
            ("(e.g., /var/log/auth.log, access.log)", "hint"), ("\n\n",),
            ("Press Enter to input file path", "accent"), ("\n",),
            ("Press Q to go back", "hint")
        )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("LOAD FILE", ["#00eaff", "#ff00f7"]), border_style="neon.cyan", box=HEAVY, expand=True)
    
    elif content_type == "search":
        t = Text.assemble(
            ("Search Logs", "neon.yellow"), ("\n\n",),
            ("Search Results: ", "hint"), (str(len(analyzer.search_results)), "accent"), ("\n",),
            ("Current File: ", "hint"), (analyzer.current_file or "None", "accent"), ("\n\n",),
            ("Enter search term:", "hint"), ("\n",),
            ("(supports regex patterns)", "hint"), ("\n\n",),
            ("Press Enter to search", "accent"), ("\n",),
            ("Press Q to go back", "hint")
        )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("SEARCH", ["#ffe500", "#ff00f7"]), border_style="neon.yellow", box=HEAVY, expand=True)
    
    elif content_type == "filter":
        t = Text.assemble(
            ("Filter Logs", "neon.green"), ("\n\n",),
            ("Filtered Lines: ", "hint"), (str(len(analyzer.filtered_lines)), "accent"), ("\n",),
            ("Total Lines: ", "hint"), (str(len(analyzer.log_lines)), "accent"), ("\n\n",),
            ("Filter Options:", "hint"), ("\n",),
            ("1. Error messages", "hint"), ("\n",),
            ("2. Warning messages", "hint"), ("\n",),
            ("3. IP addresses", "hint"), ("\n",),
            ("4. Timestamps", "hint"), ("\n",),
            ("5. Custom filter", "hint"), ("\n",),
            ("6. Clear filters", "hint"), ("\n\n",),
            ("Press Enter to select filter", "accent"), ("\n",),
            ("Press Q to go back", "hint")
        )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("FILTER", ["#35ff69", "#ff00f7"]), border_style="neon.green", box=HEAVY, expand=True)
    
    elif content_type == "patterns":
        if not analyzer.stats:
            t = Text.assemble(
                ("Pattern Analysis", "neon.magenta"), ("\n\n",),
                ("No patterns analyzed yet.", "hint"), ("\n\n",),
                ("Load a log file first to analyze patterns.", "hint"), ("\n\n",),
                ("Press Enter to go back", "hint")
            )
            return Panel(Align.center(t, vertical="middle"), title=gradient_text("PATTERNS", ["#ff00f7", "#ffe500"]), border_style="neon.magenta", box=HEAVY, expand=True)
        
        # Create pattern analysis table
        table = Table(box=ROUNDED)
        table.add_column("Pattern / Anomaly", style="neon.magenta", justify="center")
        table.add_column("Count / Sources", style="neon.green", justify="center")
        
        for pattern, count in sorted(analyzer.stats.items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                table.add_row(pattern.replace("_", " ").upper(), str(count))
        
        return Panel(table, title=gradient_text("PATTERN & ANOMALY ANALYSIS", ["#ff00f7", "#ffe500"]), border_style="neon.magenta", box=HEAVY, expand=True)
    
    elif content_type == "pcap":
        t = Text.assemble(
            ("PCAP Analysis", "neon.cyan"), ("\n\n",),
            ("Wireshark/tshark: ", "hint"), ("✓ Available" if analyzer.wireshark_installed else "✗ Not found", "accent"), ("\n\n",),
            ("Enter PCAP file path:", "hint"), ("\n",),
            ("(e.g., capture.pcap, traffic.pcapng)", "hint"), ("\n\n",),
            ("Press Enter to analyze PCAP", "accent"), ("\n",),
            ("Press Q to go back", "hint")
        )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("PCAP ANALYSIS", ["#00eaff", "#ff00f7"]), border_style="neon.cyan", box=HEAVY, expand=True)
    
    elif content_type == "start_capture":
        interfaces = analyzer.get_network_interfaces()
        if interfaces:
            t = Text.assemble(
                ("Start Network Capture", "neon.green"), ("\n\n",),
                ("Available Interfaces:", "hint"), ("\n",),
            )
            for i, interface in enumerate(interfaces[:5], 1):
                t.append(f"{i}. {interface}\n", "accent")
            
            if len(interfaces) > 5:
                t.append(f"... and {len(interfaces) - 5} more\n", "hint")
            
            t.append(Text.assemble(
                ("\n",),
                ("Enter interface number or name", "hint"), ("\n",),
                ("Duration: 300 seconds (5 minutes)", "hint"), ("\n\n",),
                ("Press Enter to start capture", "accent"), ("\n",),
                ("Press Q to go back", "hint")
            ))
        else:
            t = Text.assemble(
                ("Start Network Capture", "neon.green"), ("\n\n",),
                ("✗ No network interfaces found", "neon.red"), ("\n",),
                ("Please check your network configuration", "hint"), ("\n\n",),
                ("Press Q to go back", "hint")
            )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("START CAPTURE", ["#35ff69", "#ff00f7"]), border_style="neon.green", box=HEAVY, expand=True)
    
    elif content_type == "stop_capture":
        if analyzer.is_capturing():
            t = Text.assemble(
                ("Stop Network Capture", "neon.red"), ("\n\n",),
                ("⚠️  Capture is currently running", "neon.yellow"), ("\n",),
                ("Interface: ", "hint"), (analyzer.network_monitor.interface if analyzer.network_monitor else "Unknown", "accent"), ("\n",),
                ("Output: traffic.pcapng", "hint"), ("\n\n",),
                ("Press Enter to stop capture", "accent"), ("\n",),
                ("Press Q to go back", "hint")
            )
        else:
            t = Text.assemble(
                ("Stop Network Capture", "neon.red"), ("\n\n",),
                ("✓ No capture currently running", "neon.green"), ("\n\n",),
                ("Press Q to go back", "hint")
            )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("STOP CAPTURE", ["#ff4d4d", "#ff00f7"]), border_style="neon.red", box=HEAVY, expand=True)
    
    elif content_type == "wireshark":
        if analyzer.wireshark_installed:
            t = Text.assemble(
                ("Wireshark Integration", "neon.cyan"), ("\n\n",),
                ("✓ Wireshark is installed", "neon.green"), ("\n",),
                ("Click Enter to launch Wireshark", "hint"), ("\n\n",),
                ("Wireshark will open in a new window", "hint"), ("\n",),
                ("for network packet analysis.", "hint"), ("\n\n",),
                ("Press Enter to launch", "accent"), ("\n",),
                ("Press Q to go back", "hint")
            )
        else:
            t = Text.assemble(
                ("Wireshark Integration", "neon.cyan"), ("\n\n",),
                ("✗ Wireshark not found", "neon.red"), ("\n",),
                ("Please install Wireshark first:", "hint"), ("\n\n",),
                ("Windows: Download from wireshark.org", "hint"), ("\n",),
                ("Linux: sudo apt install wireshark tshark", "hint"), ("\n",),
                ("Mac: brew install wireshark", "hint"), ("\n\n",),
                ("Press Q to go back", "hint")
            )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("WIRESHARK", ["#00eaff", "#ff00f7"]), border_style="neon.cyan", box=HEAVY, expand=True)
    
    elif content_type == "selected_module":
        t = Text.assemble(
            ("Selected Module from Main TUI", "neon.yellow"), ("\n\n",),
            ("Current Selection: ", "hint"), (analyzer.selected_module, "accent"), ("\n\n",),
            ("This shows which module was selected", "hint"), ("\n",),
            ("in the main TUI framework.", "hint"), ("\n\n",),
            ("Press Enter to go back", "hint")
        )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("SELECTED MODULE", ["#ffe500", "#ff00f7"]), border_style="neon.yellow", box=HEAVY, expand=True)
    
    elif content_type == "search_results":
        if not analyzer.search_results:
            t = Text.assemble(
                ("Search Results", "neon.yellow"), ("\n\n",),
                ("No search results found.", "hint"), ("\n\n",),
                ("Press Enter to go back", "hint")
            )
            return Panel(Align.center(t, vertical="middle"), title=gradient_text("SEARCH RESULTS", ["#ffe500", "#ff00f7"]), border_style="neon.yellow", box=HEAVY, expand=True)
        
        # Create search results table
        table = Table(box=ROUNDED)
        table.add_column("Result", style="neon.green")
        
        for result in analyzer.search_results[:20]:  # Show first 20 results
            table.add_row(result)
        
        if len(analyzer.search_results) > 20:
            table.add_row(f"... and {len(analyzer.search_results) - 20} more results")
        
        return Panel(table, title=gradient_text("SEARCH RESULTS", ["#ffe500", "#ff00f7"]), border_style="neon.yellow", box=HEAVY, expand=True)
    
    elif content_type == "filtered_results":
        if not analyzer.filtered_lines:
            t = Text.assemble(
                ("Filtered Results", "neon.green"), ("\n\n",),
                ("No filtered results to show.", "hint"), ("\n\n",),
                ("Press Enter to go back", "hint")
            )
            return Panel(Align.center(t, vertical="middle"), title=gradient_text("FILTERED RESULTS", ["#35ff69", "#ff00f7"]), border_style="neon.green", box=HEAVY, expand=True)
        
        # Create filtered results table
        table = Table(box=ROUNDED)
        table.add_column("Line", style="neon.green")
        
        for line in analyzer.filtered_lines[:20]:  # Show first 20 results
            table.add_row(line[:80] + "..." if len(line) > 80 else line)
        
        if len(analyzer.filtered_lines) > 20:
            table.add_row(f"... and {len(analyzer.filtered_lines) - 20} more lines")
        
        return Panel(table, title=gradient_text("FILTERED RESULTS", ["#35ff69", "#ff00f7"]), border_style="neon.green", box=HEAVY, expand=True)
    
    elif content_type == "pcap_results":
        if not hasattr(analyzer, 'pcap_analysis') or not analyzer.pcap_analysis:
            t = Text.assemble(
                ("PCAP Analysis Results", "neon.cyan"), ("\n\n",),
                ("No PCAP analysis results available.", "hint"), ("\n\n",),
                ("Press Enter to go back", "hint")
            )
            return Panel(Align.center(t, vertical="middle"), title=gradient_text("PCAP RESULTS", ["#00eaff", "#ff00f7"]), border_style="neon.cyan", box=HEAVY, expand=True)
        
        # Display PCAP analysis results
        pcap_data = analyzer.pcap_analysis
        if "error" in pcap_data:
            t = Text.assemble(
                ("PCAP Analysis Error", "neon.red"), ("\n\n",),
                (pcap_data["error"], "hint"), ("\n\n",),
                ("Press Enter to go back", "hint")
            )
            return Panel(Align.center(t, vertical="middle"), title=gradient_text("PCAP ERROR", ["#ff4d4d", "#ff00f7"]), border_style="neon.red", box=HEAVY, expand=True)
        
        # Show PCAP statistics
        t = Text.assemble(
            ("PCAP Analysis Results", "neon.cyan"), ("\n\n",),
            ("File: ", "hint"), (pcap_data.get("file", "Unknown"), "accent"), ("\n\n",),
            ("Analysis completed successfully!", "neon.green"), ("\n",),
            ("Check terminal output for detailed results.", "hint"), ("\n\n",),
            ("Press Enter to go back", "hint")
        )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("PCAP RESULTS", ["#00eaff", "#ff00f7"]), border_style="neon.cyan", box=HEAVY, expand=True)

def main():
    analyzer = LogAnalyzer()
    active_index = 0
    content_type = "welcome"
    
    # Auto-load network logs if they exist
    analyzer.auto_load_network_logs()
    
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        
        layout = create_layout()
        
        # Header
        layout["header"].update(create_header())
        
        # Sidebar
        layout["sidebar"].update(create_sidebar(active_index))
        
        # Main content
        layout["main"].update(create_main_content(analyzer, content_type))
        
        console.print(layout)
        
        try:
            key = readchar.readkey()
            
            if key == readchar.key.UP:
                active_index = (active_index - 1) % 10
            elif key == readchar.key.DOWN:
                active_index = (active_index + 1) % 10
            elif key == readchar.key.ENTER:
                if active_index == 0:  # Load Log File
                    content_type = "load_file"
                    while True:
                        os.system('cls' if os.name == 'nt' else 'clear')
                        layout = create_layout()
                        layout["header"].update(create_header())
                        layout["sidebar"].update(create_sidebar(active_index))
                        layout["main"].update(create_main_content(analyzer, content_type))
                        console.print(layout)
                        
                        filepath = input("Enter log file path (or 'q' to go back): ").strip()
                        if filepath.lower() == 'q':
                            content_type = "welcome"
                            break
                        elif filepath:
                            result = analyzer.load_log_file(filepath)
                            console.print(f"[neon.green]✓ {result}[/neon.green]")
                            input("Press Enter to continue...")
                            content_type = "welcome"
                            break
                
                elif active_index == 1:  # Search Logs
                    if not analyzer.log_lines:
                        console.print("[neon.red]No log file loaded! Load a file first.[/neon.red]")
                        input("Press Enter to continue...")
                        continue
                    
                    content_type = "search"
                    while True:
                        os.system('cls' if os.name == 'nt' else 'clear')
                        layout = create_layout()
                        layout["header"].update(create_header())
                        layout["sidebar"].update(create_sidebar(active_index))
                        layout["main"].update(create_main_content(analyzer, content_type))
                        console.print(layout)
                        
                        search_term = input("Enter search term (or 'q' to go back): ").strip()
                        if search_term.lower() == 'q':
                            content_type = "welcome"
                            break
                        elif search_term:
                            results = analyzer.search_logs(search_term)
                            console.print(f"[neon.green]✓ Found {len(results)} results[/neon.green]")
                            input("Press Enter to view results...")
                            content_type = "search_results"
                            break
                
                elif active_index == 2:  # Filter Logs
                    if not analyzer.log_lines:
                        console.print("[neon.red]No log file loaded! Load a file first.[/neon.red]")
                        input("Press Enter to continue...")
                        continue
                    
                    content_type = "filter"
                    os.system('cls' if os.name == 'nt' else 'clear')
                    layout = create_layout()
                    layout["header"].update(create_header())
                    layout["sidebar"].update(create_sidebar(active_index))
                    layout["main"].update(create_main_content(analyzer, content_type))
                    console.print(layout)
                    
                    choice = input("\nSelect option (1-6) or 'q' to go back: ").strip()
                    
                    if choice.lower() == 'q':
                        content_type = "welcome"
                        continue

                    if choice == "1":
                        analyzer.filter_logs("error")
                        console.print(f"[neon.green]✓ Filtered to {len(analyzer.filtered_lines)} error lines[/neon.green]")
                    elif choice == "2":
                        analyzer.filter_logs("warning")
                        console.print(f"[neon.green]✓ Filtered to {len(analyzer.filtered_lines)} warning lines[/neon.green]")
                    elif choice == "3":
                        analyzer.filter_logs("ip")
                        console.print(f"[neon.green]✓ Filtered to {len(analyzer.filtered_lines)} lines with IPs[/neon.green]")
                    elif choice == "4":
                        analyzer.filter_logs("timestamp")
                        console.print(f"[neon.green]✓ Filtered to {len(analyzer.filtered_lines)} lines with timestamps[/neon.green]")
                    elif choice == "5":
                        custom_value = input("Enter custom filter term: ").strip()
                        if custom_value:
                            analyzer.filter_logs("custom", custom_value)
                            console.print(f"[neon.green]✓ Filtered to {len(analyzer.filtered_lines)} lines[/neon.green]")
                    elif choice == "6":
                        analyzer.filter_logs("clear")
                        console.print("[neon.green]✓ Filters cleared[/neon.green]")
                    else:
                        console.print("[neon.red]Invalid choice![/neon.red]")
                        input("Press Enter to continue...")
                        continue
                    
                    input("Press Enter to view results...")
                    content_type = "filtered_results"
                
                elif active_index == 3:  # Pattern Analysis
                    if not analyzer.log_lines:
                        console.print("[neon.red]No log file loaded! Load a file first.[/neon.red]")
                        input("Press Enter to continue...")
                        continue
                    
                    content_type = "patterns"
                
                elif active_index == 4:  # PCAP Analysis
                    content_type = "pcap"
                    while True:
                        os.system('cls' if os.name == 'nt' else 'clear')
                        layout = create_layout()
                        layout["header"].update(create_header())
                        layout["sidebar"].update(create_sidebar(active_index))
                        layout["main"].update(create_main_content(analyzer, content_type))
                        console.print(layout)
                        
                        pcap_file = input("Enter PCAP file path (or 'q' to go back): ").strip()
                        if pcap_file.lower() == 'q':
                            content_type = "welcome"
                            break
                        elif pcap_file:
                            console.print("[neon.yellow]Analyzing PCAP file... This may take a moment.[/neon.yellow]")
                            analyzer.pcap_analysis = analyzer.analyze_pcap(pcap_file)
                            
                            os.system('cls' if os.name == 'nt' else 'clear')
                            if "error" not in analyzer.pcap_analysis:
                                console.print("[neon.green]✓ PCAP analysis completed![/neon.green]")
                                # Print analysis results to terminal
                                print("\n" + "="*50)
                                print("PCAP ANALYSIS RESULTS")
                                print("="*50)
                                print(analyzer.pcap_analysis.get("stats", "No stats available"))
                                print("\n" + "="*50)
                                print("PROTOCOL STATISTICS")
                                print("="*50)
                                print(analyzer.pcap_analysis.get("protocols", "No protocol stats available"))
                                print("\n" + "="*50)
                                print("TOP TALKERS (IP CONVERSATIONS)")
                                print("="*50)
                                print(analyzer.pcap_analysis.get("talkers", "No talker stats available"))
                                print("\n" + "="*50)
                                print("POTENTIAL ARP SPOOFING")
                                print("="*50)
                                print(analyzer.pcap_analysis.get("arp_spoofing", "Analysis not run or no results."))
                                print("\n" + "="*50)
                                print("POTENTIAL SYN FLOOD (TCP HALF-OPEN)")
                                print("="*50)
                                print(analyzer.pcap_analysis.get("syn_flood_analysis", "Analysis not run or no results."))
                            else:
                                console.print(f"[neon.red]✗ {analyzer.pcap_analysis['error']}[/neon.red]")
                            
                            input("\nPress Enter to return to the TUI...")
                            content_type = "pcap_results"
                            break
                
                elif active_index == 5:  # Start Network Capture
                    content_type = "start_capture"
                    while True:
                        os.system('cls' if os.name == 'nt' else 'clear')
                        layout = create_layout()
                        layout["header"].update(create_header())
                        layout["sidebar"].update(create_sidebar(active_index))
                        layout["main"].update(create_main_content(analyzer, content_type))
                        console.print(layout)
                        
                        interfaces = analyzer.get_network_interfaces()
                        if interfaces:
                            interface_input = input("Enter interface (number or name, or 'q' to go back): ").strip()
                            if interface_input.lower() == 'q':
                                content_type = "welcome"
                                break
                            
                            # Handle interface selection
                            if interface_input.isdigit():
                                idx = int(interface_input) - 1
                                if 0 <= idx < len(interfaces):
                                    interface = interfaces[idx]
                                else:
                                    console.print("[neon.red]Invalid interface number![/neon.red]")
                                    input("Press Enter to continue...")
                                    continue
                            else:
                                interface = interface_input
                            
                            duration = input("Enter duration in seconds [300]: ").strip()
                            duration = int(duration) if duration.isdigit() else 300
                            
                            console.print(f"[neon.yellow]Starting capture on {interface} for {duration} seconds...[/neon.yellow]")
                            if analyzer.start_network_capture(interface, duration):
                                console.print("[neon.green]✓ Network capture started![/neon.green]")
                                console.print("[neon.cyan]Capture will run in background. Use 'Stop Network Capture' to stop.[/neon.cyan]")
                            else:
                                console.print("[neon.red]✗ Failed to start capture[/neon.red]")
                            
                            input("Press Enter to continue...")
                            content_type = "welcome"
                            break
                        else:
                            console.print("[neon.red]No network interfaces available![/neon.red]")
                            input("Press Enter to continue...")
                            content_type = "welcome"
                            break
                
                elif active_index == 6:  # Stop Network Capture
                    content_type = "stop_capture"
                    while True:
                        os.system('cls' if os.name == 'nt' else 'clear')
                        layout = create_layout()
                        layout["header"].update(create_header())
                        layout["sidebar"].update(create_sidebar(active_index))
                        layout["main"].update(create_main_content(analyzer, content_type))
                        console.print(layout)
                        
                        if analyzer.is_capturing():
                            stop_input = input("Stop capture? (y/n, or 'q' to go back): ").strip().lower()
                            if stop_input == 'q':
                                content_type = "welcome"
                                break
                            elif stop_input == 'y':
                                console.print("[neon.yellow]Stopping capture...[/neon.yellow]")
                                if analyzer.stop_network_capture():
                                    console.print("[neon.green]✓ Capture stopped![/neon.green]")
                                    console.print("[neon.cyan]Files saved: traffic.pcapng, scan_results.log[/neon.cyan]")
                                else:
                                    console.print("[neon.red]✗ Failed to stop capture[/neon.red]")
                                
                                input("Press Enter to continue...")
                                content_type = "welcome"
                                break
                        else:
                            input("Press Enter to continue...")
                            content_type = "welcome"
                            break
                
                elif active_index == 7:  # Launch Wireshark
                    content_type = "wireshark"
                    while True:
                        os.system('cls' if os.name == 'nt' else 'clear')
                        layout = create_layout()
                        layout["header"].update(create_header())
                        layout["sidebar"].update(create_sidebar(active_index))
                        layout["main"].update(create_main_content(analyzer, content_type))
                        console.print(layout)
                        
                        if analyzer.wireshark_installed:
                            pcap_file = input("Enter PCAP file path (optional, or 'q' to go back): ").strip()
                            if pcap_file.lower() == 'q':
                                break
                            console.print("[neon.yellow]Launching Wireshark...[/neon.yellow]")
                            if analyzer.launch_wireshark(pcap_file if pcap_file else None):
                                console.print("[neon.green]✓ Wireshark launched![/neon.green]")
                            else:
                                console.print("[neon.red]✗ Failed to launch Wireshark[/neon.red]")
                        else:
                            console.print("[neon.red]Wireshark not installed![/neon.red]")
                        
                        input("Press Enter to continue...")
                        content_type = "welcome"
                        break
                
                elif active_index == 8:  # View Selected Module
                    content_type = "selected_module"
                
                elif active_index == 9:  # Exit
                    break
            
            elif key.lower() == 'q':
                if content_type != "welcome":
                    content_type = "welcome"
                else:
                    break
                    
        except KeyboardInterrupt:
            break
        except EOFError:
            break

    os.system('cls' if os.name == 'nt' else 'clear')
    console.print("[neon.green]Goodbye![/neon.green]")

if __name__ == "__main__":
    main()