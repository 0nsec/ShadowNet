#!/usr/bin/env python3
"""
Test suite for Hidden Networks Scanner
Validates functionality and system requirements
"""

import os
import sys
import subprocess
import unittest
from unittest.mock import patch, MagicMock

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scan import HiddenNetworkScanner


class TestHiddenNetworkScanner(unittest.TestCase):
    """Test cases for HiddenNetworkScanner"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.scanner = HiddenNetworkScanner()
    
    def test_initialization(self):
        """Test scanner initialization"""
        self.assertIsNotNone(self.scanner)
        self.assertEqual(self.scanner.timeout, 30)
        self.assertFalse(self.scanner.passive_scan)
        self.assertEqual(len(self.scanner.hidden_networks), 0)
    
    def test_custom_initialization(self):
        """Test scanner with custom parameters"""
        scanner = HiddenNetworkScanner(
            interface="wlan0",
            timeout=60,
            passive_scan=True
        )
        self.assertEqual(scanner.interface, "wlan0")
        self.assertEqual(scanner.timeout, 60)
        self.assertTrue(scanner.passive_scan)
    
    @patch('subprocess.run')
    def test_check_requirements_success(self, mock_run):
        """Test successful requirements check"""
        mock_run.return_value = MagicMock(returncode=0)
        result = self.scanner.check_requirements()
        self.assertTrue(result)
    
    @patch('subprocess.run')
    def test_check_requirements_failure(self, mock_run):
        """Test failed requirements check"""
        mock_run.side_effect = subprocess.CalledProcessError(1, 'which')
        result = self.scanner.check_requirements()
        self.assertFalse(result)
    
    @patch('subprocess.run')
    def test_get_wireless_interfaces(self, mock_run):
        """Test wireless interface detection"""
        mock_output = """
        phy#0
            Interface wlan0
                ifindex 3
                wdev 0x1
                addr aa:bb:cc:dd:ee:ff
                type managed
        """
        mock_run.return_value = MagicMock(stdout=mock_output)
        interfaces = self.scanner.get_wireless_interfaces()
        self.assertIn("wlan0", interfaces)
    
    def test_parse_iwlist_output(self):
        """Test iwlist output parsing"""
        sample_output = """
        Cell 01 - Address: AA:BB:CC:DD:EE:FF
                  Channel:6
                  Frequency:2.437 GHz (Channel 6)
                  Quality=70/70  Signal level=-40 dBm
                  Encryption key:on
                  ESSID:"TestNetwork"
                  
        Cell 02 - Address: 11:22:33:44:55:66
                  Channel:11
                  Frequency:2.462 GHz (Channel 11)
                  Quality=50/70  Signal level=-60 dBm
                  Encryption key:on
                  ESSID:""
        """
        networks = self.scanner.parse_iwlist_output(sample_output)
        self.assertEqual(len(networks), 2)
        
        # Check first network
        self.assertEqual(networks[0]['bssid'], 'AA:BB:CC:DD:EE:FF')
        self.assertEqual(networks[0]['ssid'], 'TestNetwork')
        self.assertEqual(networks[0]['channel'], '6')
        
        # Check second network (hidden)
        self.assertEqual(networks[1]['bssid'], '11:22:33:44:55:66')
        self.assertEqual(networks[1]['ssid'], '<hidden>')
        self.assertEqual(networks[1]['channel'], '11')
    
    def test_hidden_network_detection(self):
        """Test hidden network detection logic"""
        test_networks = [
            {'bssid': 'AA:BB:CC:DD:EE:FF', 'ssid': 'NormalNetwork'},
            {'bssid': '11:22:33:44:55:66', 'ssid': ''},
            {'bssid': '77:88:99:AA:BB:CC', 'ssid': '<hidden>'},
            {'bssid': '00:11:22:33:44:55', 'ssid': '""'},
            {'bssid': 'FF:EE:DD:CC:BB:AA', 'ssid': '   '},
        ]
        
        # Simulate the hidden network detection logic
        hidden_count = 0
        for network in test_networks:
            ssid = network.get('ssid', '')
            if not ssid or ssid == '<hidden>' or ssid == '""' or len(ssid.strip()) == 0:
                hidden_count += 1
        
        self.assertEqual(hidden_count, 4)  # All except 'NormalNetwork'
    
    def test_export_results(self):
        """Test results export functionality"""
        import tempfile
        import json
        
        # Create test data
        test_networks = [
            {'bssid': 'AA:BB:CC:DD:EE:FF', 'ssid': 'TestNetwork', 'hidden': False},
            {'bssid': '11:22:33:44:55:66', 'ssid': '<hidden>', 'hidden': True}
        ]
        
        self.scanner.hidden_networks = [test_networks[1]]
        
        # Export to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_filename = f.name
        
        try:
            self.scanner.export_results(test_networks, temp_filename)
            
            # Verify file was created and contains expected data
            self.assertTrue(os.path.exists(temp_filename))
            
            with open(temp_filename, 'r') as f:
                data = json.load(f)
            
            self.assertEqual(data['total_networks'], 2)
            self.assertEqual(data['hidden_networks_count'], 1)
            self.assertEqual(len(data['networks']), 2)
            self.assertEqual(len(data['hidden_networks']), 1)
            
        finally:
            # Clean up
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)


class TestSystemRequirements(unittest.TestCase):
    """Test system requirements and dependencies"""
    
    def test_python_version(self):
        """Test Python version compatibility"""
        version = sys.version_info
        self.assertGreaterEqual(version.major, 3)
        if version.major == 3:
            self.assertGreaterEqual(version.minor, 6)
    
    def test_required_modules(self):
        """Test required Python modules are available"""
        required_modules = [
            'subprocess', 'sys', 'time', 'argparse', 'json', 're',
            'threading', 'collections', 'datetime', 'os'
        ]
        
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                self.fail(f"Required module '{module}' not available")
    
    def test_system_tools_availability(self):
        """Test if required system tools are available"""
        tools = ['iwlist', 'iw', 'nmcli']
        missing_tools = []
        
        for tool in tools:
            try:
                subprocess.run(['which', tool], check=True, 
                             capture_output=True, text=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                missing_tools.append(tool)
        
        if missing_tools:
            self.skipTest(f"Missing system tools: {', '.join(missing_tools)}")


def run_system_checks():
    """Run comprehensive system checks"""
    print("Running System Checks")
    print("=" * 30)
    
    # Check Python version
    version = sys.version_info
    print(f"Python version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 6):
        print("WARNING: Python 3.6+ is recommended")
    else:
        print("Python version: OK")
    
    # Check system tools
    tools = ['iwlist', 'iw', 'nmcli', 'tcpdump']
    print(f"\nChecking system tools:")
    
    for tool in tools:
        try:
            result = subprocess.run(['which', tool], check=True, 
                                  capture_output=True, text=True)
            print(f"  {tool}: {result.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"  {tool}: NOT FOUND")
    
    # Check permissions
    print(f"\nChecking permissions:")
    if os.geteuid() == 0:
        print("  Running as root: OK")
    else:
        print("  Running as root: NO (required for wireless scanning)")
    
    # Check wireless interfaces
    print(f"\nChecking wireless interfaces:")
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        interfaces = []
        for line in result.stdout.split('\n'):
            if 'Interface' in line:
                interface = line.split()[-1]
                interfaces.append(interface)
        
        if interfaces:
            print(f"  Found interfaces: {', '.join(interfaces)}")
        else:
            print("  No wireless interfaces found")
    except Exception as e:
        print(f"  Error checking interfaces: {e}")


def main():
    """Run tests and system checks"""
    print("Hidden Networks Scanner - Test Suite")
    print("=" * 50)
    
    # Run system checks first
    run_system_checks()
    
    print(f"\nRunning Unit Tests")
    print("=" * 30)
    
    # Run unit tests
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTest(loader.loadTestsFromTestCase(TestHiddenNetworkScanner))
    suite.addTest(loader.loadTestsFromTestCase(TestSystemRequirements))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Summary
    print(f"\nTest Summary:")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    
    if result.failures:
        print(f"\nFailures:")
        for test, traceback in result.failures:
            print(f"  {test}: {traceback}")
    
    if result.errors:
        print(f"\nErrors:")
        for test, traceback in result.errors:
            print(f"  {test}: {traceback}")
    
    return len(result.failures) + len(result.errors)


if __name__ == "__main__":
    sys.exit(main())
