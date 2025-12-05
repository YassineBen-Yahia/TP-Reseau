#!/usr/bin/env python3
"""
Complete IPv4/IPv6 Fragmentation Demo - No Root Required
This version creates and analyzes fragments without actually sending them
"""

from scapy.all import *
import sys


class FragmentationTester:
    def __init__(self, target_ip, interface="eth0"):
        self.target_ip = target_ip
        self.interface = interface
        self.results = []
        
    def test_ipv4_fragmentation(self, payload_sizes=[1500, 3000, 5000]):
        """
        Test IPv4 fragmentation with different payload sizes
        MTU = 1500 bytes (standard)
        """
        print("\n=== Testing IPv4 Fragmentation ===")
        
        for size in payload_sizes:
            print(f"\nCreating IPv4 packet with payload size: {size} bytes")
            
            # Create payload
            payload = Raw(load="A" * size)
            
            # Create IP packet
            pkt = IP(dst=self.target_ip)/ICMP()/payload
            
            print(f"  Original packet size: {len(pkt)} bytes")
            
            # Fragment the packet (MTU=1500, fragsize=1480 for 20-byte header)
            frags = fragment(pkt, fragsize=1480)
            print(f"  Packet fragmented into {len(frags)} fragments")
            
            # Analyze fragments
            for i, frag in enumerate(frags, 1):
                if IP in frag:
                    ip_layer = frag[IP]
                    print(f"    Fragment {i}:")
                    print(f"      - ID: {ip_layer.id}")
                    print(f"      - Flags: MF={int(ip_layer.flags.MF)}, DF={int(ip_layer.flags.DF)}")
                    print(f"      - Fragment Offset: {ip_layer.frag} (= {ip_layer.frag * 8} bytes)")
                    print(f"      - Total Length: {ip_layer.len} bytes")
                    print(f"      - More Fragments: {'Yes' if ip_layer.flags.MF else 'No'}")
            
            self.results.append({
                'protocol': 'IPv4',
                'size': size,
                'fragments': len(frags),
                'packets': frags
            })
    
    def test_ipv6_fragmentation(self, payload_sizes=[1500, 3000, 5000]):
        """
        Test IPv6 fragmentation with different payload sizes
        Minimum MTU = 1280 bytes
        """
        print("\n=== Testing IPv6 Fragmentation ===")
        
        for size in payload_sizes:
            print(f"\nCreating IPv6 packet with payload size: {size} bytes")
            
            # Create payload
            payload = Raw(load="B" * size)
            
            # Create IPv6 packet
            pkt = IPv6(dst=self.target_ip)/ICMPv6EchoRequest()/payload
            
            print(f"  Original packet size: {len(pkt)} bytes")
            
            # Fragment the packet (fragSize=1280 for minimum MTU)
            frags = fragment6(pkt, fragSize=1280)
            print(f"  Packet fragmented into {len(frags)} fragments")
            
            # Analyze fragments
            for i, frag in enumerate(frags, 1):
                if IPv6 in frag:
                    print(f"    Fragment {i}:")
                    print(f"      - Next Header: {frag[IPv6].nh}")
                    print(f"      - Payload Length: {frag[IPv6].plen}")
                    
                    if IPv6ExtHdrFragment in frag:
                        frag_hdr = frag[IPv6ExtHdrFragment]
                        print(f"      - Fragment ID: 0x{frag_hdr.id:08x}")
                        print(f"      - Fragment Offset: {frag_hdr.offset} (= {frag_hdr.offset * 8} bytes)")
                        print(f"      - More Fragments: {'Yes' if frag_hdr.m else 'No'}")
            
            self.results.append({
                'protocol': 'IPv6',
                'size': size,
                'fragments': len(frags),
                'packets': frags
            })
    
    def generate_report(self):
        """Generate a summary report of the tests"""
        print("\n" + "="*60)
        print("FRAGMENTATION TEST SUMMARY")
        print("="*60)
        
        print("\nProtocol | Payload Size | Number of Fragments")
        print("-" * 60)
        
        for result in self.results:
            print(f"{result['protocol']:8} | {result['size']:12} | {result['fragments']}")
        
        print("\n" + "="*60)
    
    def compare_protocols(self):
        """Compare IPv4 and IPv6 fragmentation behavior"""
        print("\n=== Protocol Comparison ===")
        print("\nIPv4 Fragmentation:")
        print("  - Can be done by routers")
        print("  - Uses 13-bit fragment offset (8-byte units)")
        print("  - 16-bit Identification field in main header")
        print("  - DF (Don't Fragment) flag available")
        print("  - Header size: 20 bytes (minimum)")
        
        print("\nIPv6 Fragmentation:")
        print("  - Only source node can fragment")
        print("  - Uses Fragment Extension Header (8 bytes)")
        print("  - 32-bit Identification field")
        print("  - Minimum MTU: 1280 bytes")
        print("  - Base header size: 40 bytes")
        print("  - More efficient reassembly (only at destination)")
    
    def export_pcap(self, filename="fragments.pcap"):
        """Export all fragments to a PCAP file"""
        all_packets = []
        for result in self.results:
            all_packets.extend(result['packets'])
        
        if all_packets:
            wrpcap(filename, all_packets)
            print(f"\n✓ Exported {len(all_packets)} packets to {filename}")
            print(f"  You can analyze this file with Wireshark")
        else:
            print("\n✗ No packets to export")


def main():
    """Main function - no root/admin required"""
    print("="*60)
    print("IPv4/IPv6 FRAGMENTATION DEMO")
    print("(Analysis mode - no packets sent, no root required)")
    print("="*60)
    
    # IPv4 test
    print("\n### Testing IPv4 ###")
    tester_v4 = FragmentationTester("192.168.1.100")
    tester_v4.test_ipv4_fragmentation([1400, 3000, 5000])
    
    # IPv6 test
    print("\n### Testing IPv6 ###")
    tester_v6 = FragmentationTester("2001:db8::1")
    tester_v6.test_ipv6_fragmentation([1400, 3000, 5000])
    
    # Reports
    print("\n### IPv4 Results ###")
    tester_v4.generate_report()
    
    print("\n### IPv6 Results ###")
    tester_v6.generate_report()
    
    # Comparison
    tester_v4.compare_protocols()
    
    # Export to PCAP
    tester_v4.export_pcap("ipv4_fragments.pcap")
    tester_v6.export_pcap("ipv6_fragments.pcap")
    
    print("\n✓ Demo complete!")


if __name__ == "__main__":
    try:
        from scapy.all import *
        main()
    except ImportError:
        print("Error: Scapy is not installed")
        print("Install with: pip install scapy")
        sys.exit(1)
