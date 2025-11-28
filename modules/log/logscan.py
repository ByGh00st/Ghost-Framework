#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Real-Time Network Traffic Capture & Analysis
===========================================
Background network monitoring with tshark integration.
Automatically captures traffic during scans and saves to PCAP files.
"""

import os
import sys
import time
import subprocess
import platform
import threading
import signal
import json
from datetime import datetime
from typing import Dict, List, Optional
from collections import defaultdict, Counter
import re

class NetworkMonitor:
    def __init__(self):
        self.is_capturing = False
        self.capture_process = None
        self.interface = None
        self.output_file = "traffic.pcapng"
        self.log_file = "scan_results.log"
        self.stats_file = "network_stats.json"
        self.alert_file = "security_alerts.log"
        self.patterns = {
            'port_scan': r'(?i)(port|scan|nmap|probe|syn|fin|rst)',
            'brute_force': r'(?i)(failed|invalid|wrong|incorrect).*(password|login|auth)',
            'dos_attack': r'(?i)(flood|connection limit|rate-limit|timeout)',
            'suspicious_ip': r'(?i)(blocked|banned|suspicious|malicious)',
            'arp_spoof': r'(?i)(arp|duplicate|spoof|poison)',
            'sql_injection': r'(?i)(union|select|insert|delete|drop|exec)',
            'xss_attack': r'(?i)(script|javascript|alert|onload|onerror)',
            'directory_traversal': r'(?i)(\.\./|\.\.\\|%2e%2e)',
        }
        self.stats = defaultdict(int)
        self.alerts = []
        self.interface_list = self.get_network_interfaces()
        
    def get_network_interfaces(self) -> List[str]:
        """Get available network interfaces"""
        interfaces = []
        try:
            if platform.system() == "Windows":
                # Windows: Use netsh to get interfaces
                result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Enabled' in line and ('Ethernet' in line or 'Wi-Fi' in line):
                            parts = line.split()
                            if len(parts) >= 4:
                                interfaces.append(parts[-1])
            else:
                # Linux/Mac: Use ifconfig or ip
                try:
                    result = subprocess.run(['ip', 'link', 'show'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if 'state UP' in line:
                                match = re.search(r'\d+:\s+(\w+):', line)
                                if match:
                                    interfaces.append(match.group(1))
                except:
                    # Fallback to ifconfig
                    result = subprocess.run(['ifconfig'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if 'flags=' in line:
                                match = re.search(r'^(\w+):', line)
                                if match:
                                    interfaces.append(match.group(1))
        except Exception as e:
            print(f"Error getting interfaces: {e}")
        
        return interfaces if interfaces else ['eth0', 'wlan0', 'Wi-Fi', 'Ethernet']
    
    def check_tshark(self) -> bool:
        """Check if tshark is available"""
        try:
            if platform.system() == "Windows":
                tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
                if not os.path.exists(tshark_path):
                    tshark_path = r"C:\Program Files (x86)\Wireshark\tshark.exe"
                return os.path.exists(tshark_path)
            else:
                result = subprocess.run(['which', 'tshark'], 
                                      capture_output=True, text=True, timeout=5)
                return result.returncode == 0
        except:
            return False
    
    def start_capture(self, interface: str = None, duration: int = 300) -> bool:
        """Start network traffic capture"""
        if not self.check_tshark():
            print("❌ tshark not found! Install Wireshark with CLI tools.")
            return False
        
        if self.is_capturing:
            print("⚠️  Capture already running!")
            return False
        
        # Select interface
        if not interface:
            if self.interface_list:
                interface = self.interface_list[0]
                print(f"📡 Using interface: {interface}")
            else:
                print("❌ No network interfaces found!")
                return False
        
        try:
            # Prepare tshark command
            if platform.system() == "Windows":
                tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
                if not os.path.exists(tshark_path):
                    tshark_path = r"C:\Program Files (x86)\Wireshark\tshark.exe"
            else:
                tshark_path = "tshark"
            
            # Build capture command
            cmd = [
                tshark_path,
                "-i", interface,
                "-w", self.output_file,
                "-q",  # Quiet mode
                "-b", f"duration:{duration}",  # Ring buffer
                "-b", "files:1",  # Keep only 1 file
                "-f", "not port 22 and not port 23",  # Filter out SSH/Telnet
            ]
            
            print(f"🚀 Starting capture on {interface}...")
            print(f"📁 Output: {self.output_file}")
            print(f"⏱️  Duration: {duration} seconds")
            
            # Start capture process
            self.capture_process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.is_capturing = True
            self.interface = interface
            
            # Start monitoring thread
            monitor_thread = threading.Thread(target=self.monitor_capture, args=(duration,))
            monitor_thread.daemon = True
            monitor_thread.start()
            
            print("✅ Capture started successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Error starting capture: {e}")
            return False
    
    def stop_capture(self) -> bool:
        """Stop network traffic capture"""
        if not self.is_capturing or not self.capture_process:
            print("⚠️  No capture running!")
            return False
        
        try:
            print("🛑 Stopping capture...")
            self.capture_process.terminate()
            
            # Wait for process to end
            try:
                self.capture_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.capture_process.kill()
            
            self.is_capturing = False
            self.capture_process = None
            
            print("✅ Capture stopped!")
            return True
            
        except Exception as e:
            print(f"❌ Error stopping capture: {e}")
            return False
    
    def monitor_capture(self, duration: int):
        """Monitor capture process and analyze traffic"""
        start_time = time.time()
        
        while self.is_capturing and (time.time() - start_time) < duration:
            try:
                # Check if process is still running
                if self.capture_process and self.capture_process.poll() is not None:
                    break
                
                # Analyze current traffic (if PCAP file exists)
                if os.path.exists(self.output_file):
                    self.analyze_current_traffic()
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                print(f"⚠️  Monitor error: {e}")
                break
        
        # Final analysis
        if os.path.exists(self.output_file):
            self.analyze_final_traffic()
        
        self.is_capturing = False
    
    def analyze_current_traffic(self):
        """Analyze current traffic for threats"""
        try:
            if not os.path.exists(self.output_file):
                return
            
            # Use tshark to get current statistics
            if platform.system() == "Windows":
                tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
                if not os.path.exists(tshark_path):
                    tshark_path = r"C:\Program Files (x86)\Wireshark\tshark.exe"
            else:
                tshark_path = "tshark"
            
            # Get packet count
            cmd = [tshark_path, "-r", self.output_file, "-q", "-z", "io,stat,0"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Parse statistics
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'packets' in line.lower():
                        match = re.search(r'(\d+)\s+packets', line)
                        if match:
                            packet_count = int(match.group(1))
                            self.stats['total_packets'] = packet_count
                            
                            # Alert if high packet rate
                            if packet_count > 1000:
                                self.create_alert("HIGH_TRAFFIC", f"High packet count: {packet_count}")
            
            # Check for suspicious patterns
            self.detect_threats()
            
        except Exception as e:
            print(f"⚠️  Analysis error: {e}")
    
    def analyze_final_traffic(self):
        """Perform final analysis of captured traffic"""
        try:
            if not os.path.exists(self.output_file):
                return
            
            print("🔍 Performing final traffic analysis...")
            
            # Get detailed statistics
            if platform.system() == "Windows":
                tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
                if not os.path.exists(tshark_path):
                    tshark_path = r"C:\Program Files (x86)\Wireshark\tshark.exe"
            else:
                tshark_path = "tshark"
            
            # Protocol statistics
            cmd = [tshark_path, "-r", self.output_file, "-q", "-z", "io,phs"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # Save protocol stats
                with open(self.log_file, 'w') as f:
                    f.write("=== NETWORK TRAFFIC ANALYSIS ===\n")
                    f.write(f"Capture Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Interface: {self.interface}\n")
                    f.write(f"File: {self.output_file}\n\n")
                    f.write("PROTOCOL STATISTICS:\n")
                    f.write(result.stdout)
                    f.write("\n\nSECURITY ALERTS:\n")
                    for alert in self.alerts:
                        f.write(f"- {alert}\n")
            
            # Save statistics
            stats_data = {
                'timestamp': datetime.now().isoformat(),
                'interface': self.interface,
                'file': self.output_file,
                'stats': dict(self.stats),
                'alerts': self.alerts
            }
            
            with open(self.stats_file, 'w') as f:
                json.dump(stats_data, f, indent=2)
            
            print("✅ Final analysis completed!")
            print(f"📄 Results saved to: {self.log_file}")
            print(f"📊 Statistics saved to: {self.stats_file}")
            
        except Exception as e:
            print(f"❌ Final analysis error: {e}")
    
    def detect_threats(self):
        """Detect security threats in traffic"""
        try:
            if not os.path.exists(self.output_file):
                return
            
            # Use tshark to extract packet information
            if platform.system() == "Windows":
                tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
                if not os.path.exists(tshark_path):
                    tshark_path = r"C:\Program Files (x86)\Wireshark\tshark.exe"
            else:
                tshark_path = "tshark"
            
            # Extract packet details
            cmd = [
                tshark_path, "-r", self.output_file,
                "-T", "fields",
                "-e", "frame.time",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "tcp.port",
                "-e", "http.request.method",
                "-e", "http.request.uri"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.strip():
                        # Check for suspicious patterns
                        for threat_type, pattern in self.patterns.items():
                            if re.search(pattern, line, re.IGNORECASE):
                                self.stats[threat_type] += 1
                                self.create_alert(threat_type.upper(), line[:100])
            
        except Exception as e:
            print(f"⚠️  Threat detection error: {e}")
    
    def create_alert(self, alert_type: str, message: str):
        """Create security alert"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        alert = f"[{timestamp}] {alert_type}: {message}"
        
        if alert not in self.alerts:
            self.alerts.append(alert)
            
            # Save to alert file
            with open(self.alert_file, 'a') as f:
                f.write(alert + '\n')
            
            print(f"🚨 ALERT: {alert_type} - {message[:50]}...")

def main():
    """Main function for standalone operation"""
    monitor = NetworkMonitor()
    
    print("🌐 Network Traffic Monitor")
    print("=" * 40)
    
    # Check tshark
    if not monitor.check_tshark():
        print("❌ tshark not found! Please install Wireshark with CLI tools.")
        print("Windows: Download from wireshark.org")
        print("Linux: sudo apt install wireshark tshark")
        print("Mac: brew install wireshark")
        return
    
    # Show available interfaces
    print(f"📡 Available interfaces: {', '.join(monitor.interface_list)}")
    
    # Start capture
    duration = int(input("Enter capture duration (seconds) [300]: ") or "300")
    interface = input(f"Enter interface [{monitor.interface_list[0] if monitor.interface_list else 'eth0'}]: ") or None
    
    if monitor.start_capture(interface, duration):
        print(f"⏳ Capturing for {duration} seconds... Press Ctrl+C to stop early.")
        
        try:
            while monitor.is_capturing:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Interrupted by user")
            monitor.stop_capture()
    
    print("✅ Monitoring completed!")

if __name__ == "__main__":
    main()
