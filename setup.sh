#!/bin/bash

# Hidden Networks Scanner Setup Script
# This script installs system dependencies and sets up the tool

echo "Hidden Networks Scanner Setup"
echo "============================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "Please do not run this setup script as root"
   echo "The script will prompt for sudo when needed"
   exit 1
fi

# Detect OS
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

# Install system dependencies
echo "Installing system dependencies..."

case $OS in
    debian)
        sudo apt-get update
        sudo apt-get install -y wireless-tools iw network-manager python3
        ;;
    redhat)
        if command -v dnf &> /dev/null; then
            sudo dnf install -y wireless-tools iw NetworkManager python3
        else
            sudo yum install -y wireless-tools iw NetworkManager python3
        fi
        ;;
    arch)
        sudo pacman -S --needed wireless_tools iw networkmanager python
        ;;
esac


echo "Making scan.py executable..."
chmod +x scan.py


echo "Checking Python version..."
python3 --version


echo "Verifying tool installation..."
tools=("iwlist" "iw" "nmcli")
for tool in "${tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo "✓ $tool is installed"
    else
        echo "✗ $tool is not installed"
        exit 1
    fi
done

echo ""
echo "[+] Setup completed successfully!"
echo ""
echo "Usage:"
echo "  sudo ./scan.py                    # Basic scan"
echo "  sudo ./scan.py -i wlan0           # Scan specific interface"
echo "  sudo ./scan.py -p                 # Enable passive monitoring"
echo "  sudo ./scan.py -o results.json    # Export results"
echo ""
echo "Note: Root privileges are required for wireless scanning"
