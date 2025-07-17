# Hidden Networks Scanner

A powerful Python tool for discovering and displaying hidden wireless networks along with their SSID and BSSID information.

## Features

- **Multi-method scanning**: Uses iwlist, nmcli, and optional passive monitoring
- **Hidden network detection**: Automatically identifies networks with hidden SSIDs
- **Comprehensive information**: Displays BSSID, SSID, channel, signal strength, and security
- **Passive monitoring**: Optional monitor mode for advanced detection
- **Export functionality**: Save results to JSON format
- **Interface selection**: Automatic detection or manual interface specification
- **Root privilege detection**: Ensures proper permissions for wireless scanning

## Requirements

### System Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install wireless-tools iw network-manager

# CentOS/RHEL/Fedora
sudo yum install wireless-tools iw NetworkManager
# or
sudo dnf install wireless-tools iw NetworkManager

# Arch Linux
sudo pacman -S wireless_tools iw networkmanager
```

### Python Requirements

- Python 3.6+
- Standard library modules (no additional pip packages required)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/0nsec/hidden-networks.git
cd hidden-networks
```

2. Make the script executable:
```bash
chmod +x scan.py
```

## Usage

### Basic Usage

```bash

sudo python3 scan.py

sudo ./scan.py
```

### Advanced Options

```bash

sudo python3 scan.py -i wlan0


sudo python3 scan.py -t 60

sudo python3 scan.py -p


sudo python3 scan.py -o scan_results.json

sudo python3 scan.py -v

sudo python3 scan.py -i wlan0 -t 45 -p -o results.json -v
```

### Command Line Arguments

- `-i, --interface`: Specify wireless interface to use
- `-t, --timeout`: Scan timeout in seconds (default: 30)
- `-p, --passive`: Enable passive monitoring mode
- `-o, --output`: Output file for results in JSON format
- `-v, --verbose`: Enable verbose output for debugging

## Output Format

The tool provides detailed information about discovered networks:

### Hidden Networks Section
```
HIDDEN NETWORKS DETECTED:
================================================================================
BSSID              SSID                 Channel  Signal   Security  
--------------------------------------------------------------------------------
aa:bb:cc:dd:ee:ff  <hidden>            6        -45      WPA2      
11:22:33:44:55:66  <hidden>            11       -67      WPA       
```

### All Networks Section
```
ALL NETWORKS:
================================================================================
BSSID              SSID                     Channel  Signal   Security   Hidden  
----------------------------------------------------------------------------------
aa:bb:cc:dd:ee:ff  <hidden>                6        -45      WPA2       Yes     
11:22:33:44:55:66  MyNetwork               11       -67      WPA2       No      
```

## Technical Details

### Scanning Methods

1. **iwlist scan**: Traditional wireless scanning using iwlist command
2. **nmcli**: NetworkManager's command-line interface for network discovery
3. **Passive monitoring**: Optional tcpdump-based beacon frame capture

### Hidden Network Detection

Networks are identified as hidden when:
- SSID is empty or contains only whitespace
- SSID is explicitly marked as `<hidden>`
- SSID field is empty quotes `""`

### Security Information

The tool detects and displays:
- **WPA2**: IEEE 802.11i/WPA2 networks
- **WPA**: WPA Version 1 networks
- **WEP**: Legacy WEP encryption
- **Open**: Unencrypted networks

## Troubleshooting

### Common Issues

1. **"Missing required tools" error**:
   - Install wireless-tools and NetworkManager packages
   - Ensure iwlist, iw, and nmcli are in PATH

2. **"This tool requires root privileges" error**:
   - Run with sudo: `sudo python3 scan.py`

3. **"No wireless interfaces found" error**:
   - Check if wireless adapter is connected
   - Verify wireless drivers are loaded
   - Use `iw dev` to list available interfaces

4. **Monitor mode failures**:
   - Not all wireless adapters support monitor mode
   - Try without `-p` option for basic scanning
   - Check if adapter supports monitor mode: `iw list`

### Debug Mode

Use `-v` flag for verbose output to diagnose issues:
```bash
sudo python3 scan.py -v
```

## Export Format

JSON export includes:
- Scan timestamp
- Total networks count
- Hidden networks count
- Complete network details
- Separate hidden networks array

Example JSON structure:
```json
{
  "scan_time": "2025-07-17T10:30:00",
  "total_networks": 15,
  "hidden_networks_count": 3,
  "networks": [...],
  "hidden_networks": [...]
}
```

## Security Considerations

- **Root privileges required**: Wireless scanning requires elevated permissions
- **Legal compliance**: Ensure compliance with local laws regarding wireless scanning
- **Network policies**: Respect organizational network policies
- **Ethical use**: Use only for authorized security testing and research

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors are not responsible for any misuse of this tool.

## Support

For issues, questions, or contributions, please visit the GitHub repository or create an issue.