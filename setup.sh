#!/bin/bash

set -e

echo "SHADOWNET SETUP SCRIPT"
echo "======================"

if [[ $EUID -ne 0 ]]; then
   echo "THIS SCRIPT MUST BE RUN AS ROOT" 
   echo "USE: sudo ./setup.sh"
   exit 1
fi

detect_os() {
    OS="$(uname -s)"
    DISTRO_ID=""
    if [[ "$OS" == "Linux" && -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO_ID="${ID:-}"
    fi
    echo "$OS|$DISTRO_ID"
}

install_linux_deps() {
    local pm=""
    if command -v apt >/dev/null 2>&1; then pm=apt; fi
    if command -v dnf >/dev/null 2>&1; then pm=dnf; fi
    if command -v yum >/dev/null 2>&1; then pm=yum; fi
    if command -v pacman >/dev/null 2>&1; then pm=pacman; fi

    echo "[*] Detected package manager: ${pm:-unknown}"
    case "$pm" in
        apt)
            apt update -y
            # Install build dependencies for hcxtools
            apt install -y build-essential git libcurl4-openssl-dev libssl-dev zlib1g-dev libpcap-dev
            # Install other wireless tools
            apt install -y wireless-tools iw network-manager tcpdump aircrack-ng nmap net-tools python3 python3-pip python3-venv reaver bully hashcat
            ;;
        dnf)
            # Install build dependencies for hcxtools
            dnf install -y gcc make git curl-devel openssl-devel zlib-devel libpcap-devel
            # Install other tools
            dnf install -y wireless-tools iw NetworkManager tcpdump aircrack-ng nmap net-tools python3 python3-pip reaver hashcat
            ;;
        yum)
            # Install build dependencies for hcxtools
            yum install -y gcc make git curl-devel openssl-devel zlib-devel libpcap-devel
            # Install other tools
            yum install -y wireless-tools iw NetworkManager tcpdump aircrack-ng nmap net-tools python3 python3-pip reaver hashcat
            ;;
        pacman)
            pacman -Sy --noconfirm
            # Install build dependencies for hcxtools
            pacman -S --noconfirm base-devel git curl openssl zlib libpcap
            # Install other tools
            pacman -S --noconfirm wireless_tools iw networkmanager tcpdump aircrack-ng nmap net-tools python python-pip reaver hashcat
            ;;
        *)
            echo "[!] Unsupported or unknown Linux package manager. Install deps manually: wireless-tools iw network-manager tcpdump aircrack-ng nmap"
            ;;
    esac
}

install_hcxtools() {
    echo "[*] Installing hcxtools from source..."
    
    # Create temporary directory for compilation
    TEMP_DIR="/tmp/hcxtools_build"
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"
    
    # Clone the repository
    if git clone https://github.com/ZerBea/hcxtools.git; then
        cd hcxtools
        
        # Compile and install
        if make && make install; then
            echo "[+] hcxtools installed successfully"
            
            # Update library cache
            ldconfig
            
            # Add /usr/local/bin to PATH if not already there
            if ! echo "$PATH" | grep -q "/usr/local/bin"; then
                echo 'export PATH="/usr/local/bin:$PATH"' >> /etc/environment
                export PATH="/usr/local/bin:$PATH"
            fi
            
            # Clean up
            cd /
            rm -rf "$TEMP_DIR"
            
            return 0
        else
            echo "[!] Failed to compile hcxtools"
            cd /
            rm -rf "$TEMP_DIR"
            return 1
        fi
    else
        echo "[!] Failed to clone hcxtools repository"
        cd /
        rm -rf "$TEMP_DIR"
        return 1
    fi
}

os_line=$(detect_os)
os_name=${os_line%%|*}
distro_id=${os_line##*|}

echo "Detected OS: $os_name | Distro: ${distro_id:-unknown}"

case "$os_name" in
    Linux)
        install_linux_deps
        install_hcxtools
        ;;
    Darwin)
        if command -v brew >/dev/null 2>&1; then
            brew update
            brew install aircrack-ng nmap tcpdump
            echo "[i] hcxtools not available via brew. Install manually from https://github.com/ZerBea/hcxtools"
        else
            echo "[!] Homebrew not found. Install from https://brew.sh or install deps manually."
        fi
        ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT|Windows)
        echo "[i] On Windows, install Npcap (with raw 802.11 support), Wireshark (optional), and aircrack-ng (optional)."
        echo "[i] hcxtools may need to be compiled manually or use Windows binaries if available."
        ;;
    *)
        echo "[!] Unsupported OS: $os_name"
        ;;
esac

echo "[*] SETTING PERMISSIONS..."
chmod +x scan.py

echo "[*] CREATING WORDLIST..."
if [ ! -f "list.txt" ]; then
    cat > list.txt << 'EOF'
password
123456
admin
root
toor
pass
12345678
qwerty
123456789
letmein
EOF
    echo "[+] Default wordlist created at list.txt"
else
    echo "[*] WORDLIST ALREADY EXISTS"
fi

echo ""
echo "SHADOWNET SETUP COMPLETE"
echo "========================"
echo "RUN WITH: sudo python3 scan.py"
echo "LEGACY MODE: sudo python3 scan.py --legacy"
echo ""

echo "Installing Python dependencies..."
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

if [ ! -d ".venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
fi

echo "Making scan.py executable..."
chmod +x scan.py


echo "Checking Python version..."
python3 --version


echo "Verifying tool installation..."
tools=("iwlist" "iw" "nmcli" "tcpdump")
for tool in "${tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "✓ $tool is installed"
    else
        echo "✗ $tool is not installed"
    fi
done

echo "Checking optional tools..."
optional_tools=("aircrack-ng" "airodump-ng" "hcxdumptool" "hcxpcapngtool" "hcxpsktool")
for tool in "${optional_tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "✓ $tool is installed (optional)"
    else
        echo "○ $tool is not installed (optional)"
    fi
done

echo ""
echo "[+] Enhanced setup completed successfully!"
echo ""
echo "Enhanced Features:"
echo "  ✓ Scapy-based 802.11 frame analysis"
echo "  ✓ Probe request monitoring"
echo "  ✓ Advanced hidden SSID detection"
echo "  ✓ Vendor identification"
echo "  ✓ Security analysis"
echo "  ✓ hcxtools suite for WPA/WPA2 capture and conversion"
echo ""
echo "hcxtools Commands:"
echo "  hcxdumptool   - Capture WPA/WPA2 handshakes"
echo "  hcxpcapngtool - Convert captures to hashcat format"
echo "  hcxpsktool    - PSK recovery and analysis"
echo ""
echo "Usage Examples:"
echo "  sudo ./scan.py                           # Basic enhanced scan"
echo "  sudo ./scan.py -i wlan0 -p               # Passive scan with probe requests"
echo "  sudo ./scan.py --probe-ssids home office # Probe specific SSIDs"
echo "  sudo ./scan.py -v -o results.json        # Verbose with JSON export"
echo ""
echo "hcxtools Usage Examples:"
echo "  sudo hcxdumptool -i wlan0 -o capture.pcapng --enable_status=15"
echo "  hcxpcapngtool -o hash.hc22000 -E essidlist capture.pcapng"
echo ""
echo "IMPORTANT: Root privileges are required for wireless scanning"
echo "WARNING: Use deauth features responsibly and only on authorized networks"
