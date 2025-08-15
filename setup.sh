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
            apt install -y wireless-tools iw network-manager tcpdump aircrack-ng nmap net-tools python3 python3-pip python3-venv
            ;;
        dnf)
            dnf install -y wireless-tools iw NetworkManager tcpdump aircrack-ng nmap net-tools python3 python3-pip
            ;;
        yum)
            yum install -y wireless-tools iw NetworkManager tcpdump aircrack-ng nmap net-tools python3 python3-pip
            ;;
        pacman)
            pacman -Sy --noconfirm
            pacman -S --noconfirm wireless_tools iw networkmanager tcpdump aircrack-ng nmap net-tools python python-pip
            ;;
        *)
            echo "[!] Unsupported or unknown Linux package manager. Install deps manually: wireless-tools iw network-manager tcpdump aircrack-ng nmap"
            ;;
    esac
}

os_line=$(detect_os)
os_name=${os_line%%|*}
distro_id=${os_line##*|}

echo "Detected OS: $os_name | Distro: ${distro_id:-unknown}"

case "$os_name" in
    Linux)
        install_linux_deps
        ;;
    Darwin)
        if command -v brew >/dev/null 2>&1; then
            brew update
            brew install aircrack-ng nmap tcpdump
        else
            echo "[!] Homebrew not found. Install from https://brew.sh or install deps manually."
        fi
        ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT|Windows)
        echo "[i] On Windows, install Npcap (with raw 802.11 support), Wireshark (optional), and aircrack-ng (optional)."
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
optional_tools=("aircrack-ng" "airodump-ng")
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
echo ""
echo "Usage Examples:"
echo "  sudo ./scan.py                           # Basic enhanced scan"
echo "  sudo ./scan.py -i wlan0 -p               # Passive scan with probe requests"
echo "  sudo ./scan.py --probe-ssids home office # Probe specific SSIDs"
echo "  sudo ./scan.py -v -o results.json        # Verbose with JSON export"
echo ""
echo "IMPORTANT: Root privileges are required for wireless scanning"
echo "WARNING: Use deauth features responsibly and only on authorized networks"
