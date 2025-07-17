#!/usr/bin/env python3
"""
Enhanced Hidden Networks Scanner with Scapy
Advanced techniques for discovering hidden SSIDs using 802.11 frame analysis
"""

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

# Enhanced imports for Scapy-based analysis
try:
    from scapy.all import *
    from scapy.layers.dot11 import *
    import netifaces
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: Scapy not available. Some advanced features will be disabled.")
    SCAPY_AVAILABLE = False


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
        
        # Signal handling for graceful shutdown
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
    
    def get_mac_vendor(self, mac):
        """Get MAC address vendor information"""
        try:
            # Simple vendor identification based on OUI
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
        
        # Get additional information
        channel = int(ord(pkt[Dot11Elt:3].info))
        signal_strength = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else 0
        
        # Check for hidden network
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
        
        # Extract SSID from probe request
        if pkt.haslayer(Dot11Elt):
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            if ssid:
                self.probe_requests[client_mac].add(ssid)
                
                # Check if this SSID corresponds to a hidden network
                for bssid, network in self.networks.items():
                    if network.get('hidden', False):
                        # Try to correlate with hidden network
                        self.correlate_probe_with_hidden(client_mac, ssid, bssid)
    
    def process_probe_response(self, pkt):
        """Process probe response frames"""
        if not pkt.haslayer(Dot11ProbeResp):
            return
            
        bssid = pkt[Dot11].addr3
        ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
        
        # Update network information if we have a match
        if bssid in self.networks:
            if self.networks[bssid].get('hidden', False) and ssid:
                self.networks[bssid]['ssid'] = ssid
                self.networks[bssid]['hidden'] = False
                print(f"Hidden network revealed: {bssid} -> {ssid}")
    
    def correlate_probe_with_hidden(self, client_mac, ssid, bssid):
        """Correlate probe requests with hidden networks"""
        # Add client to network
        self.clients[bssid].add(client_mac)
        
        # If we have a hidden network and a client probing for an SSID,
        # there's a chance they're related
        if bssid in self.networks and self.networks[bssid].get('hidden', False):
            confidence = self.calculate_correlation_confidence(client_mac, ssid, bssid)
            if confidence > 0.7:  # High confidence threshold
                self.networks[bssid]['probable_ssid'] = ssid
                self.networks[bssid]['confidence'] = confidence
                print(f"Probable SSID for {bssid}: {ssid} (confidence: {confidence:.2f})")
    
    def calculate_correlation_confidence(self, client_mac, ssid, bssid):
        """Calculate confidence level for SSID correlation"""
        # Simple confidence calculation based on multiple factors
        confidence = 0.5  # Base confidence
        
        # Increase confidence if client is seen multiple times
        if len(self.clients[bssid]) > 1:
            confidence += 0.2
            
        # Increase confidence if SSID appears in multiple probe requests
        probe_count = sum(1 for probes in self.probe_requests.values() if ssid in probes)
        if probe_count > 1:
            confidence += 0.1
            
        return min(confidence, 1.0)
    
    def parse_security_info(self, pkt):
        """Parse security information from beacon/probe response"""
        security_info = {'security': 'Open', 'encryption': False}
        
        if pkt.haslayer(Dot11Elt):
            # Check for WPA/WPA2
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 48:  # RSN (WPA2)
                    security_info['security'] = 'WPA2'
                    security_info['encryption'] = True
                elif elt.ID == 221:  # WPA
                    if elt.info.startswith(b'\x00\x50\xf2\x01'):
                        security_info['security'] = 'WPA'
                        security_info['encryption'] = True
                
                elt = elt.payload if hasattr(elt, 'payload') else None
        
        # Check for WEP
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
                # Process different frame types
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
            
        # Common SSIDs to probe for
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
                # Create probe request packet
                probe_req = (
                    RadioTap() /
                    Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", 
                          addr2=RandMAC(), addr3="ff:ff:ff:ff:ff:ff") /
                    Dot11ProbeReq() /
                    Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
                )
                
                # Send the packet
                sendp(probe_req, iface=interface, verbose=False)
                time.sleep(0.1)  # Small delay between probes
                
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
        
        # If no specific client, use broadcast
        if not client_mac:
            client_mac = "ff:ff:ff:ff:ff:ff"
            
        try:
            # Create deauth packet
            deauth = (
                RadioTap() /
                Dot11(addr1=client_mac, addr2=target_bssid, addr3=target_bssid) /
                Dot11Deauth(reason=7)
            )
            
            # Send deauth packets
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
        
        # Start packet capture in a separate thread
        def capture_packets():
            try:
                sniff(iface=interface, prn=self.packet_handler, 
                      timeout=duration, store=0)
            except Exception as e:
                print(f"Error during packet capture: {e}")
        
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.daemon = True
        capture_thread.start()
        
        # Send probe requests in parallel
        if self.passive_scan:
            probe_thread = threading.Thread(
                target=self.send_probe_requests, 
                args=(interface,)
            )
            probe_thread.daemon = True
            probe_thread.start()
        
        # Wait for scanning to complete
        time.sleep(duration)
        self.scanning = False
        
        # Wait for threads to complete
        capture_thread.join(timeout=2)
        
        return list(self.networks.values())
    
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

