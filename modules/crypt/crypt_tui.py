#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cryptography Tools TUI - Hash Generator & Cracker
=================================================
Interactive TUI for cryptography tools and hash operations.

Features:
- Hash generation (MD5, SHA1, SHA256, etc.)
- Password cracking utilities
- Encryption/Decryption tools
- Random key generation

"""

import os
import sys
import time
import hashlib
import secrets
import base64
from typing import List, Dict, Optional
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

class CryptoTool:
    def __init__(self):
        self.password = ""
        self.hash_results = {}
        self.hash_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
            'blake2b': hashlib.blake2b,
            'sha3_256': hashlib.sha3_256,
        }
        
    def generate_hash(self, text: str, algorithm: str = 'sha256') -> str:
        """Generate hash of text using specified algorithm"""
        if algorithm.lower() not in self.hash_algorithms:
            return f"Unknown algorithm: {algorithm}"
            
        hash_func = self.hash_algorithms[algorithm.lower()]
        return hash_func(text.encode()).hexdigest()
    
    def generate_all_hashes(self, text: str) -> Dict[str, str]:
        """Generate hashes using all available algorithms"""
        results = {}
        for algo in self.hash_algorithms.keys():
            results[algo] = self.generate_hash(text, algo)
        return results
    
    def crack_hash(self, hash_value: str, wordlist_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """Simple hash cracking (dictionary attack) reading line by line."""
        hash_value = hash_value.lower().strip()
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for word in f:
                    word = word.strip()
                    if not word:
                        continue
                    if self.generate_hash(word, algorithm) == hash_value:
                        return word
        except FileNotFoundError:
            return "FileNotFound"  # Special value to indicate file not found
        except Exception as e:
            return f"Error: {str(e)}"
        return None
    
    def generate_random_key(self, length: int = 32) -> str:
        """Generate random key/string"""
        return secrets.token_hex(length)
    
    def generate_password(self, length: int = 16, include_symbols: bool = True) -> str:
        """Generate secure password"""
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        if include_symbols:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        return ''.join(secrets.choice(chars) for _ in range(length))

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
 _________                _____ 
\_   ___ \_____   __ ___/ ____\
/    \  \/\__  \ |  |  \   __\ 
\     \____/ __ \|  |  /|  |   
 \______  (____  /____/ |__|   
        \/     \/            
        Developer > ByGhost
        WebSite   > byghost.tr       """
    
    title = gradient_text("CRYPTOGRAPHY TOOLS", ["#ff00f7", "#ffe500"])
    return Panel(
        Align.center(Text.from_ansi(banner.strip("\n")), vertical="middle"),
        title=title,
        border_style="neon.magenta",
        box=HEAVY_EDGE
    )

def create_sidebar(active_index: int) -> Panel:
    options = [
        "Generate Hash",
        "Generate All Hashes",
        "Crack Hash",
        "Generate Key",
        "Generate Password",
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

def create_main_content(crypto: CryptoTool, content_type: str = "welcome") -> RenderableType:
    if content_type == "welcome":
        t = Text.assemble(
            ("Cryptography Tools & Hash Generator", "neon.magenta"), ("\n\n",),
            ("• Hash generation (MD5, SHA1, SHA256, etc.)", "hint"), ("\n",),
            ("• Password cracking utilities", "hint"), ("\n",),
            ("• Random key generation", "hint"), ("\n",),
            ("• Secure password generation", "hint"), ("\n\n",),
            ("Select an option from the sidebar", "accent"), ("\n",),
            ("Use ↑/↓ to navigate, Enter to select", "hint")
        )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("WELCOME", ["#ff00f7", "#ffe500"]), border_style="neon.magenta", box=HEAVY, expand=True)
    
    elif content_type == "password_input":
        t = Text.assemble(
            ("Enter Password/Text", "neon.yellow"), ("\n\n",),
            ("Password: ", "hint"), (crypto.password or "Not set", "accent"), ("\n\n",),
            ("Press Enter to set password", "hint"), ("\n",),
            ("Press Q to go back", "hint")
        )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("PASSWORD", ["#ffe500", "#ff00f7"]), border_style="neon.yellow", box=HEAVY, expand=True)
    
    elif content_type == "hash_results":
        if not crypto.hash_results:
            t = Text.assemble(
                ("No Results", "neon.red"), ("\n\n",),
                ("No hash results available.", "hint")
            )
            return Panel(Align.center(t, vertical="middle"), title=gradient_text("RESULTS", ["#ff4d4d", "#ff00f7"]), border_style="neon.red", box=HEAVY, expand=True)
        
        # Create results table
        table = Table(box=ROUNDED)
        table.add_column("Algorithm", style="neon.magenta", justify="center")
        table.add_column("Hash", style="neon.green")
        
        for algo, hash_value in crypto.hash_results.items():
            table.add_row(algo.upper(), hash_value)
        
        return Panel(table, title=gradient_text("HASH RESULTS", ["#35ff69", "#ff00f7"]), border_style="neon.green", box=HEAVY, expand=True)
    
    elif content_type == "crack_input":
        t = Text.assemble(
            ("Hash Cracking", "neon.yellow"), ("\n\n",),
            ("Enter hash to crack: ", "hint"), ("[Input required]", "accent"), ("\n",),
            ("Algorithm: ", "hint"), ("[Select algorithm]", "accent"), ("\n\n",),
            ("Press Enter to start cracking", "hint"), ("\n",),
            ("Press Q to go back", "hint")
        )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("CRACK HASH", ["#ffe500", "#ff00f7"]), border_style="neon.yellow", box=HEAVY, expand=True)
    
    elif content_type == "key_generation":
        t = Text.assemble(
            ("Key Generation", "neon.cyan"), ("\n\n",),
            ("Length: ", "hint"), ("[Enter length]", "accent"), ("\n",),
            ("Type: ", "hint"), ("[Random Key / Password]", "accent"), ("\n\n",),
            ("Press Enter to generate", "hint"), ("\n",),
            ("Press Q to go back", "hint")
        )
        return Panel(Align.center(t, vertical="middle"), title=gradient_text("KEY GENERATION", ["#00eaff", "#ff00f7"]), border_style="neon.cyan", box=HEAVY, expand=True)

def main():
    crypto = CryptoTool()
    active_index = 0
    content_type = "welcome"
    
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        
        layout = create_layout()
        
        # Header
        layout["header"].update(create_header())
        
        # Sidebar
        layout["sidebar"].update(create_sidebar(active_index))
        
        # Main content
        layout["main"].update(create_main_content(crypto, content_type))
        
        console.print(layout)
        
        try:
            key = readchar.readkey()
            
            if key == readchar.key.UP:
                active_index = (active_index - 1) % 6
            elif key == readchar.key.DOWN:
                active_index = (active_index + 1) % 6
            elif key == readchar.key.ENTER:
                if active_index == 0:  # Generate Hash
                    content_type = "password_input"
                    while True:
                        os.system('cls' if os.name == 'nt' else 'clear')
                        layout = create_layout()
                        layout["header"].update(create_header())
                        layout["sidebar"].update(create_sidebar(active_index))
                        layout["main"].update(create_main_content(crypto, content_type))
                        console.print(layout)
                        
                        text_input = input("Enter text to hash: ").strip()
                        if text_input:
                            crypto.password = text_input
                            algo_input = input("Enter algorithm (md5/sha1/sha256/sha512/blake2b/sha3_256) [sha256]: ").strip() or 'sha256'
                            
                            # Check if algorithm is valid
                            if algo_input.lower() not in crypto.hash_algorithms:
                                console.print(f"[neon.red]Invalid algorithm: {algo_input}[/neon.red]")
                                console.print("[neon.cyan]Available algorithms: md5, sha1, sha256, sha512, blake2b, sha3_256[/neon.cyan]")
                                input("Press Enter to continue...")
                                continue
                            
                            hash_result = crypto.generate_hash(text_input, algo_input)
                            crypto.hash_results = {algo_input: hash_result}
                            
                            console.print(f"[neon.green]✓ Hash generated successfully![/neon.green]")
                            console.print(f"[neon.cyan]Text: {text_input}[/neon.cyan]")
                            console.print(f"[neon.cyan]Algorithm: {algo_input.upper()}[/neon.cyan]")
                            console.print(f"[neon.yellow]Hash: {hash_result}[/neon.yellow]")
                            
                            input("Press Enter to continue...")
                            content_type = "hash_results"
                            break
                        elif password_input.lower() == 'q':
                            content_type = "welcome"
                            break
                
                elif active_index == 1:  # Generate All Hashes
                    content_type = "password_input"
                    while True:
                        os.system('cls' if os.name == 'nt' else 'clear')
                        layout = create_layout()
                        layout["header"].update(create_header())
                        layout["sidebar"].update(create_sidebar(active_index))
                        layout["main"].update(create_main_content(crypto, content_type))
                        console.print(layout)
                        
                        password_input = input("Enter password/text: ").strip()
                        if password_input:
                            crypto.password = password_input
                            crypto.hash_results = crypto.generate_all_hashes(password_input)
                            
                            console.print(f"[neon.green]✓ All hashes generated successfully![/neon.green]")
                            console.print(f"[neon.cyan]Generated {len(crypto.hash_results)} different hash types[/neon.cyan]")
                            
                            input("Press Enter to continue...")
                            content_type = "hash_results"
                            break
                        elif password_input.lower() == 'q':
                            content_type = "welcome"
                            break
                
                elif active_index == 2:  # Crack Hash
                    content_type = "crack_input"
                    while True:
                        os.system('cls' if os.name == 'nt' else 'clear')
                        layout = create_layout()
                        layout["header"].update(create_header())
                        layout["sidebar"].update(create_sidebar(active_index))
                        layout["main"].update(create_main_content(crypto, content_type))
                        console.print(layout)
                        
                        hash_input = input("Enter hash: ").strip()
                        if hash_input:
                            algo_input = input("Enter algorithm (md5/sha1/sha256/sha512/blake2b/sha3_256) [sha256]: ").strip() or 'sha256'
                            
                            console.print("\n[neon.cyan]Choose method:[/neon.cyan]")
                            console.print("1. Enter password to test")
                            console.print("2. Auto attack with wordlist file")
                            
                            method = input("\nSelect method (1/2): ").strip()
                            
                            if method == "1":
                                # Enter password to test
                                password_input = input("Enter password: ").strip()
                                if password_input:
                                    generated_hash = crypto.generate_hash(password_input, algo_input)
                                    console.print(f"[neon.cyan]Password: {password_input}[/neon.cyan]")
                                    console.print(f"[neon.cyan]Algorithm: {algo_input.upper()}[/neon.cyan]")
                                    console.print(f"[neon.yellow]Generated Hash: {generated_hash}[/neon.yellow]")
                                    
                                    # Check if it matches the input hash
                                    if generated_hash.lower() == hash_input.lower():
                                        console.print(f"[neon.green]✓ MATCH! Password is correct![/neon.green]")
                                        crypto.hash_results = {"MATCH": f"Password: {password_input} | Hash: {generated_hash}"}
                                    else:
                                        console.print(f"[neon.red]✗ NO MATCH! Password is incorrect![/neon.red]")
                                        crypto.hash_results = {"NO_MATCH": f"Generated: {generated_hash} | Input: {hash_input}"}
                                    
                                    input("Press Enter to continue...")
                                    content_type = "hash_results"
                                    break
                                else:
                                    console.print("[neon.red]No password entered![/neon.red]")
                                    input("Press Enter to continue...")
                                    continue
                            
                            elif method == "2":
                                # Auto attack with wordlist file
                                wordlist_path = input("Enter wordlist file path (e.g., wordlist.txt): ").strip()
                                if not wordlist_path:
                                    console.print("[neon.red]No file path entered![/neon.red]")
                                    input("Press Enter to continue...")
                                    continue
                                
                                console.print(f"[neon.yellow]Starting auto attack on {wordlist_path}...[/neon.yellow]")
                                
                                result = crypto.crack_hash(hash_input, wordlist_path, algo_input)
                                
                                if result == "FileNotFound":
                                    console.print(f"[neon.red]File not found: {wordlist_path}[/neon.red]")
                                    input("Press Enter to continue...")
                                    continue
                                elif result and result.startswith("Error:"):
                                    console.print(f"[neon.red]{result}[/neon.red]")
                                    input("Press Enter to continue...")
                                    continue
                                elif result:
                                    crypto.hash_results = {"CRACKED": f"Password found: {result}"}
                                    console.print(f"[neon.green]✓ Hash cracked! Password: {result}[/neon.green]")
                                else:
                                    crypto.hash_results = {"FAILED": f"Hash not found in {wordlist_path}"}
                                    console.print("[neon.red]✗ Hash not cracked with wordlist[/neon.red]")
                                
                                input("Press Enter to continue...")
                                content_type = "hash_results"
                                break
                            

                        elif hash_input.lower() == 'q':
                            content_type = "welcome"
                            break
                
                elif active_index == 3:  # Generate Key
                    content_type = "key_generation"
                    while True:
                        os.system('cls' if os.name == 'nt' else 'clear')
                        layout = create_layout()
                        layout["header"].update(create_header())
                        layout["sidebar"].update(create_sidebar(active_index))
                        layout["main"].update(create_main_content(crypto, content_type))
                        console.print(layout)
                        
                        length_input = input("Enter key length [32]: ").strip() or '32'
                        try:
                            length = int(length_input)
                            key = crypto.generate_random_key(length)
                            crypto.hash_results = {"RANDOM_KEY": key}
                            content_type = "hash_results"
                            break
                        except ValueError:
                            console.print("[neon.red]Invalid length![/neon.red]")
                            input("Press Enter to continue...")
                        except length_input.lower() == 'q':
                            content_type = "welcome"
                            break
                
                elif active_index == 4:  # Generate Password
                    content_type = "key_generation"
                    while True:
                        os.system('cls' if os.name == 'nt' else 'clear')
                        layout = create_layout()
                        layout["header"].update(create_header())
                        layout["sidebar"].update(create_sidebar(active_index))
                        layout["main"].update(create_main_content(crypto, content_type))
                        console.print(layout)
                        
                        length_input = input("Enter password length [16]: ").strip() or '16'
                        symbols_input = input("Include symbols? (y/n) [y]: ").strip().lower() != 'n'
                        
                        try:
                            length = int(length_input)
                            password = crypto.generate_password(length, symbols_input)
                            crypto.hash_results = {"SECURE_PASSWORD": password}
                            content_type = "hash_results"
                            break
                        except ValueError:
                            console.print("[neon.red]Invalid length![/neon.red]")
                            input("Press Enter to continue...")
                        except length_input.lower() == 'q':
                            content_type = "welcome"
                            break
                
                elif active_index == 5:  # Exit
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

    console.print("[neon.green]Goodbye![/neon.green]")

if __name__ == "__main__":
    main()
