#!/usr/bin/env python3
"""
Advanced Hidden Networks Scanner Examples
Demonstrates various usage patterns and advanced features
"""

import os
import sys
import json
import time
from datetime import datetime

# Add the current directory to the path so we can import scan
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scan import HiddenNetworkScanner


def example_basic_scan():
    """Basic scanning example"""
    print("Example 1: Basic Hidden Networks Scan")
    print("=" * 50)
    
    scanner = HiddenNetworkScanner()
    networks = scanner.scan_networks()
    scanner.display_results(networks)
    
    return networks


def example_interface_specific_scan():
    """Scan specific interface"""
    print("\nExample 2: Interface-Specific Scan")
    print("=" * 50)
    
    # Get available interfaces
    scanner = HiddenNetworkScanner()
    interfaces = scanner.get_wireless_interfaces()
    
    if interfaces:
        print(f"Available interfaces: {', '.join(interfaces)}")
        interface = interfaces[0]  # Use first available interface
        
        scanner = HiddenNetworkScanner(interface=interface)
        networks = scanner.scan_networks()
        scanner.display_results(networks)
        
        return networks
    else:
        print("No wireless interfaces found")
        return []


def example_passive_monitoring():
    """Passive monitoring example"""
    print("\nExample 3: Passive Monitoring Scan")
    print("=" * 50)
    
    scanner = HiddenNetworkScanner(passive_scan=True, timeout=20)
    networks = scanner.scan_networks()
    scanner.display_results(networks)
    
    return networks


def example_json_export():
    """Export results to JSON"""
    print("\nExample 4: JSON Export")
    print("=" * 50)
    
    scanner = HiddenNetworkScanner()
    networks = scanner.scan_networks()
    
    # Export to timestamped file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"hidden_networks_scan_{timestamp}.json"
    
    scanner.export_results(networks, filename)
    
    # Display file contents
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            data = json.load(f)
        
        print(f"\nExported data preview:")
        print(f"Scan time: {data['scan_time']}")
        print(f"Total networks: {data['total_networks']}")
        print(f"Hidden networks: {data['hidden_networks_count']}")
        
        if data['hidden_networks']:
            print("\nHidden networks found:")
            for network in data['hidden_networks']:
                print(f"  BSSID: {network['bssid']}, Signal: {network.get('signal', 'Unknown')}")
    
    return networks


def example_continuous_monitoring():
    """Continuous monitoring example"""
    print("\nExample 5: Continuous Monitoring")
    print("=" * 50)
    
    scanner = HiddenNetworkScanner(timeout=15)
    
    print("Starting continuous monitoring (press Ctrl+C to stop)...")
    scan_count = 0
    
    try:
        while True:
            scan_count += 1
            print(f"\nScan #{scan_count} at {datetime.now().strftime('%H:%M:%S')}")
            print("-" * 30)
            
            networks = scanner.scan_networks()
            
            # Only show hidden networks for continuous monitoring
            if scanner.hidden_networks:
                print(f"Hidden networks detected: {len(scanner.hidden_networks)}")
                for network in scanner.hidden_networks:
                    print(f"  {network['bssid']} - Signal: {network.get('signal', 'Unknown')}")
            else:
                print("No hidden networks detected")
            
            print("Waiting 30 seconds before next scan...")
            time.sleep(30)
            
    except KeyboardInterrupt:
        print(f"\nContinuous monitoring stopped after {scan_count} scans")


def example_network_analysis():
    """Analyze network patterns"""
    print("\nExample 6: Network Analysis")
    print("=" * 50)
    
    scanner = HiddenNetworkScanner()
    networks = scanner.scan_networks()
    
    if not networks:
        print("No networks found for analysis")
        return
    
    # Analysis
    total_networks = len(networks)
    hidden_count = len(scanner.hidden_networks)
    visible_count = total_networks - hidden_count
    
    # Security analysis
    security_stats = {}
    channel_stats = {}
    signal_ranges = {'Strong': 0, 'Medium': 0, 'Weak': 0}
    
    for network in networks:
        # Security statistics
        security = network.get('security', 'Unknown')
        security_stats[security] = security_stats.get(security, 0) + 1
        
        # Channel statistics
        channel = network.get('channel', 'Unknown')
        channel_stats[channel] = channel_stats.get(channel, 0) + 1
        
        # Signal strength categories
        signal = network.get('signal', 0)
        if signal > -50:
            signal_ranges['Strong'] += 1
        elif signal > -70:
            signal_ranges['Medium'] += 1
        else:
            signal_ranges['Weak'] += 1
    
    # Display analysis
    print(f"Network Analysis Results:")
    print(f"  Total networks: {total_networks}")
    print(f"  Visible networks: {visible_count}")
    print(f"  Hidden networks: {hidden_count}")
    print(f"  Hidden percentage: {(hidden_count/total_networks)*100:.1f}%")
    
    print(f"\nSecurity Distribution:")
    for security, count in sorted(security_stats.items()):
        print(f"  {security}: {count} ({(count/total_networks)*100:.1f}%)")
    
    print(f"\nChannel Distribution:")
    for channel, count in sorted(channel_stats.items()):
        print(f"  Channel {channel}: {count} networks")
    
    print(f"\nSignal Strength Distribution:")
    for strength, count in signal_ranges.items():
        print(f"  {strength}: {count} networks")


def main():
    """Run all examples"""
    print("Hidden Networks Scanner - Advanced Examples")
    print("=" * 60)
    
    # Check if running as root
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run with sudo.")
        sys.exit(1)
    
    examples = [
        example_basic_scan,
        example_interface_specific_scan,
        example_json_export,
        example_network_analysis,
        # Uncomment these for interactive examples
        # example_passive_monitoring,
        # example_continuous_monitoring,
    ]
    
    for i, example in enumerate(examples, 1):
        try:
            example()
            if i < len(examples):
                input(f"\nPress Enter to continue to next example...")
        except KeyboardInterrupt:
            print("\nExample interrupted by user")
            break
        except Exception as e:
            print(f"Error in example {i}: {e}")
            continue
    
    print("\nAll examples completed!")


if __name__ == "__main__":
    main()
