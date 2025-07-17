#!/usr/bin/env python3

import subprocess
import sys
import time
import argparse
import json
import re
import threading
from collections import defaultdict
from datetime import datetime
import os


class HiddenNetworkScanner:
    def __init__(self, interface=None, timeout=30, passive_scan=False):
        self.interface = interface
        self.timeout = timeout
        self.passive_scan = passive_scan
        self.networks = defaultdict(dict)
        self.hidden_networks = []
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
        
        for cell in cells[1:]:  # Skip first empty element
            network = {}
            lines = cell.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # BSSID
                if 'Address:' in line:
                    network['bssid'] = line.split('Address: ')[1].strip()
                
                # SSID
                elif 'ESSID:' in line:
                    essid = line.split('ESSID:')[1].strip().strip('"')
                    network['ssid'] = essid if essid else '<hidden>'
                
                # Channel
                elif 'Channel:' in line:
                    network['channel'] = line.split('Channel:')[1].strip()
                
                # Signal strength
                elif 'Signal level=' in line:
                    signal_match = re.search(r'Signal level=(-?\d+)', line)
                    if signal_match:
                        network['signal'] = int(signal_match.group(1))
                
                # Encryption
                elif 'Encryption key:' in line:
                    network['encryption'] = 'on' in line.lower()
                
                # Security protocols
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
    
    def scan_networks(self):
        """Main network scanning function"""
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
            
            # Regular scan with iwlist
            networks = self.scan_with_iwlist(interface)
            all_networks.extend(networks)
            
            # If passive scan is enabled, try monitor mode
            if self.passive_scan:
                original_mode = True
                if self.set_monitor_mode(interface):
                    passive_networks = self.passive_monitor_scan(interface, self.timeout)
                    all_networks.extend(passive_networks)
                    self.restore_managed_mode(interface)
        
        # Also try nmcli scan
        nmcli_networks = self.scan_with_nmcli()
        all_networks.extend(nmcli_networks)
        
        # Remove duplicates and identify hidden networks
        unique_networks = {}
        for network in all_networks:
            bssid = network.get('bssid', '')
            if bssid and bssid not in unique_networks:
                unique_networks[bssid] = network
                
                # Check if network is hidden
                ssid = network.get('ssid', '')
                if not ssid or ssid == '<hidden>' or ssid == '""' or len(ssid.strip()) == 0:
                    network['hidden'] = True
                    self.hidden_networks.append(network)
                else:
                    network['hidden'] = False
        
        return list(unique_networks.values())
    
    def display_results(self, networks):
        """Display scan results"""
        print(f"\n{'='*80}")
        print("HIDDEN NETWORKS SCAN RESULTS")
        print(f"{'='*80}")
        print(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total networks found: {len(networks)}")
        print(f"Hidden networks: {len(self.hidden_networks)}")
        
        if self.hidden_networks:
            print(f"\n{'='*80}")
            print("HIDDEN NETWORKS DETECTED:")
            print(f"{'='*80}")
            print(f"{'BSSID':<18} {'SSID':<20} {'Channel':<8} {'Signal':<8} {'Security':<10}")
            print("-" * 80)
            
            for network in self.hidden_networks:
                bssid = network.get('bssid', 'Unknown')
                ssid = network.get('ssid', '<hidden>')
                channel = network.get('channel', 'Unknown')
                signal = network.get('signal', 0)
                security = network.get('security', 'Unknown')
                
                print(f"{bssid:<18} {ssid:<20} {channel:<8} {signal:<8} {security:<10}")
        
        print(f"\n{'='*80}")
        print("ALL NETWORKS:")
        print(f"{'='*80}")
        print(f"{'BSSID':<18} {'SSID':<25} {'Channel':<8} {'Signal':<8} {'Security':<10} {'Hidden':<8}")
        print("-" * 90)
        
        for network in sorted(networks, key=lambda x: x.get('signal', 0), reverse=True):
            bssid = network.get('bssid', 'Unknown')
            ssid = network.get('ssid', '<hidden>')
            channel = network.get('channel', 'Unknown')
            signal = network.get('signal', 0)
            security = network.get('security', 'Unknown')
            hidden = 'Yes' if network.get('hidden', False) else 'No'
            
            print(f"{bssid:<18} {ssid:<25} {channel:<8} {signal:<8} {security:<10} {hidden:<8}")
    
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
        description='Hidden Networks Scanner - Discover and display hidden wireless networks'
    )
    parser.add_argument('-i', '--interface', help='Wireless interface to use')
    parser.add_argument('-t', '--timeout', type=int, default=30, 
                       help='Scan timeout in seconds (default: 30)')
    parser.add_argument('-p', '--passive', action='store_true',
                       help='Enable passive monitoring (requires monitor mode support)')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("This tool requires root privileges. Please run with sudo.")
        sys.exit(1)
    
    print("Hidden Networks Scanner")
    print("=" * 50)
    
    scanner = HiddenNetworkScanner(
        interface=args.interface,
        timeout=args.timeout,
        passive_scan=args.passive
    )
    
    try:
        networks = scanner.scan_networks()
        scanner.display_results(networks)
        
        if args.output:
            scanner.export_results(networks, args.output)
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"Error during scan: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()

