# SHADOWNET v2.0

```python
  /$$$$$$  /$$   /$$  /$$$$$$  /$$$$$$$   /$$$$$$  /$$      /$$ /$$   /$$ /$$$$$$$$ /$$$$$$$$
 /$$__  $$| $$  | $$ /$$__  $$| $$__  $$ /$$__  $$| $$  /$ | $$| $$$ | $$| $$_____/|__  $$__/
| $$  \__/| $$  | $$| $$  \ $$| $$  \ $$| $$  \ $$| $$ /$$$| $$| $$$$| $$| $$         | $$   
|  $$$$$$ | $$$$$$$$| $$$$$$$$| $$  | $$| $$  | $$| $$/$$ $$ $$| $$ $$ $$| $$$$$      | $$   
 \____  $$| $$__  $$| $$__  $$| $$  | $$| $$  | $$| $$$$_  $$$$| $$  $$$$| $$__/      | $$   
 /$$  \ $$| $$  | $$| $$  | $$| $$  | $$| $$  | $$| $$$/ \  $$$| $$\  $$$| $$         | $$   
|  $$$$$$/| $$  | $$| $$  | $$| $$$$$$$/|  $$$$$$/| $$/   \  $$| $$ \  $$| $$$$$$$$   | $$   
 \______/ |__/  |__/|__/  |__/|_______/  \______/ |__/     \__/|__/  \__/|________/   |__/   
                                          
```


SHADOWNET is an advanced network security testing toolkit designed for authorized penetration testing and security research.

New in this version:
- OS detection and guided dependency installation (Linux/macOS; guidance for Windows)
- Built-in helpers to enable/disable monitor mode on Linux
- Windows monitor mode support via Npcap WlanHelper (where supported by adapter)



## CORE MODULES

<details>
  <summary> Click to View All Core Modules</summary>

### 01 - NETWORK RECONNAISSANCE
- Target network discovery  
- Host enumeration  
- Service identification  

### 02 - HIDDEN SSID DISCOVERY
- Advanced wireless network scanning  
- Hidden access point detection  
- SSID correlation analysis  

### 03 - ACCESS POINT ANALYSIS
- Wireless interface management  
- Monitor mode configuration  
- Detailed network information  

### 04 - DEAUTH OPERATIONS
- Deauthentication attacks  
- Client disconnection  
- Network disruption testing  

### 05 - WIRELESS BRUTEFORCE
- WPA/WPA2 password cracking  
- Dictionary-based attacks  
- Handshake analysis  

### 06 - HANDSHAKE CAPTURE
- WPA handshake collection  
- Targeted packet capture  
- Authentication monitoring  

### 07 - DICTIONARY ATTACK
- Custom wordlist selection  
- Password list management  
- Automated cracking  

### 08 - SYSTEM INFILTRATION
- Port scanning  
- Service enumeration  
- Vulnerability assessment  

### 09 - WORDLIST MANAGEMENT
- View and analyze wordlists  
- Create custom wordlists  
- Merge multiple wordlists  
- Download popular wordlists  

### 10 - FILE OPERATIONS
- Capture file analysis  
- Format conversion  
- Handshake verification  

### 11 - WIRELESS AUTO-AUDIT (WIFITE-LIKE)
- PMKID capture via hcxdumptool
- Handshake capture via airodump-ng with optional deauth
- Automated conversion to 22000 hash format
- Optional cracking with aircrack-ng/wordlist

</details>

## INSTALLATION

```bash
git clone https://github.com/0nsec/ShadowNet
cd ShadowNet
sudo chmod +x setup.sh
sudo ./setup.sh
```

## USAGE

### Main Interface
```bash
sudo python3 scan.py
```

### Legacy Mode
```bash
sudo python3 scan.py --legacy
```

### System Setup and Monitor Mode

- Use menu [00] System Setup & OS Detection to:
  - Detect OS and package manager
  - Install/verify dependencies (Linux/macOS)
  - Enable/disable monitor mode on Linux
  - List Windows adapters and enable monitor mode via Npcap WlanHelper

Windows notes:
- Install Npcap with "Support raw 802.11 traffic (and monitor mode)"
- Use WlanHelper.exe to toggle monitor mode: `WlanHelper.exe <adapter> mode monitor`
- Not all adapters/drivers support monitor mode on Windows.

## REQUIREMENTS

- Linux or Windows (limited features on Windows)
- Root privileges
- aircrack-ng suite
- nmap
- wireless-tools
- hcxdumptool, hcxpcapngtool (for PMKID workflow)
- reaver/bully (optional, WPS)
- hashcat (optional)
- Python 3.x
- scapy
- netifaces
 - On Windows: Npcap with raw 802.11 support (for monitor mode)

## WORDLIST SUPPORT

The tool now supports multiple wordlist options:

- **Default wordlist**: Built-in password list (`list.txt`)
- **Custom wordlists**: Specify your own wordlist file path
- **Generated wordlists**: Create custom wordlists with patterns
- **Popular wordlists**: Download rockyou.txt, common passwords, etc.
- **Wordlist management**: View, merge, and analyze wordlists

## LEGAL DISCLAIMER

THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY. Users are responsible for complying with local laws and obtaining proper authorization before testing any networks. The developers are not responsible for misuse.

## FEATURES

- Interactive menu-driven interface
- Multiple scanning techniques
- Advanced packet analysis
- Custom wordlist generation
- Automated attack modules
- Professional reporting
- Animated-themed UI

## SUPPORT

For issues and updates, visit the official repository or contact the 0nsec development team.

REMEMBER: WITH GREAT POWER COMES GREAT RESPONSIBILITY


```python
██████╗ ███╗   ██╗███████╗███████╗ ██████╗
██╔═████╗████╗  ██║██╔════╝██╔════╝██╔════╝
██║██╔██║██╔██╗ ██║███████╗█████╗  ██║     
████╔╝██║██║╚██╗██║╚════██║██╔══╝  ██║     
╚██████╔╝██║ ╚████║███████║███████╗╚██████╗
 ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝  
```
