#!/bin/bash
echo "Hidden Networks Scanner Setup"
echo "============================="

if [[ $EUID -eq 0 ]]; then
   echo "Please do not run this setup script as root"
   echo "The script will prompt for sudo when needed"
   exit 1
fi

if [[ -f /etc/debian_version ]]; then
    OS="debian"
elif [[ -f /etc/redhat-release ]]; then
    OS="redhat"
elif [[ -f /etc/arch-release ]]; then
    OS="arch"
else
    echo "Unsupported operating system"
    exit 1
fi

echo "Detected OS: $OS"

echo "Installing system dependencies..."

case $OS in
    debian)
        sudo apt-get update
        sudo apt-get install -y wireless-tools iw network-manager python3 python3-pip python3-venv tcpdump
        sudo apt-get install -y aircrack-ng
        ;;
    redhat)
        if command -v dnf &> /dev/null; then
            sudo dnf install -y wireless-tools iw NetworkManager python3 python3-pip tcpdump
            sudo dnf install -y aircrack-ng
        else
            sudo yum install -y wireless-tools iw NetworkManager python3 python3-pip tcpdump
            sudo yum install -y aircrack-ng
        fi
        ;;
    arch)
        sudo pacman -S --needed wireless_tools iw networkmanager python python-pip tcpdump
        sudo pacman -S --needed aircrack-ng
        ;;
esac

if [ ! -d ".venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate

echo "Installing Python dependencies..."
pip install --upgrade pip
pip install scapy>=2.4.5 netifaces>=0.11.0


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
        exit 1
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
