#!/usr/bin/env python3
"""
Fragmentation Visualizer
Creates visual comparisons and charts for IPv4/IPv6 fragmentation analysis
"""

from scapy.all import *
import json
from typing import List, Dict, Tuple


class FragmentationVisualizer:
    """Visualize and compare fragmentation between IPv4 and IPv6"""
    
    def __init__(self):
        self.ipv4_data = []
        self.ipv6_data = []
    
    def analyze_fragmentation(self, protocol: str, target_ip: str, 
                             payload_sizes: List[int], mtu: int = 1500) -> List[Dict]:
        """Analyze fragmentation for given protocol and payload sizes"""
        
        results = []
        
        for size in payload_sizes:
            if protocol.lower() == 'ipv4':
                # Create IPv4 packet
                payload = Raw(load="X" * size)
                pkt = IP(dst=target_ip)/ICMP()/payload
                
                # Fragment
                fragsize = mtu - 20  # Account for IP header
                frags = fragment(pkt, fragsize=fragsize)
                
                # Analyze
                total_overhead = 0
                for frag in frags:
                    if IP in frag:
                        total_overhead += 20  # IP header size
                
                result = {
                    'payload_size': size,
                    'fragments': len(frags),
                    'header_overhead': total_overhead,
                    'total_size': total_overhead + size,
                    'efficiency': (size / (total_overhead + size)) * 100,
                    'avg_fragment_size': (total_overhead + size) / len(frags),
                    'packets': frags
                }
                
            else:  # IPv6
                # Create IPv6 packet
                payload = Raw(load="Y" * size)
                pkt = IPv6(dst=target_ip)/ICMPv6EchoRequest()/payload
                
                # Fragment
                fragsize = mtu - 48  # 40 base + 8 fragment header
                frags = fragment6(pkt, fragSize=fragsize)
                
                # Analyze
                total_overhead = 0
                for frag in frags:
                    if IPv6 in frag:
                        total_overhead += 40  # Base header
                        if IPv6ExtHdrFragment in frag:
                            total_overhead += 8  # Fragment header
                
                result = {
                    'payload_size': size,
                    'fragments': len(frags),
                    'header_overhead': total_overhead,
                    'total_size': total_overhead + size,
                    'efficiency': (size / (total_overhead + size)) * 100,
                    'avg_fragment_size': (total_overhead + size) / len(frags),
                    'packets': frags
                }
            
            results.append(result)
        
        return results
    
    def compare_protocols(self, payload_sizes: List[int] = [1000, 2000, 3000, 5000, 8000]):
        """Compare IPv4 and IPv6 fragmentation across different payload sizes"""
        
        print("\n" + "="*90)
        print("FRAGMENTATION COMPARISON: IPv4 vs IPv6")
        print("="*90 + "\n")
        
        # Analyze both protocols
        self.ipv4_data = self.analyze_fragmentation('ipv4', '192.168.1.100', payload_sizes)
        self.ipv6_data = self.analyze_fragmentation('ipv6', '2001:db8::1', payload_sizes)
        
        # Print comparison table
        print(f"{'Payload':<10} | {'Protocol':<8} | {'Frags':<6} | {'Overhead':<10} | {'Total':<10} | {'Efficiency':<12}")
        print("-" * 90)
        
        for i, size in enumerate(payload_sizes):
            ipv4 = self.ipv4_data[i]
            ipv6 = self.ipv6_data[i]
            
            print(f"{size:<10} | {'IPv4':<8} | {ipv4['fragments']:<6} | {ipv4['header_overhead']:<10} | {ipv4['total_size']:<10} | {ipv4['efficiency']:<12.2f}%")
            print(f"{'':<10} | {'IPv6':<8} | {ipv6['fragments']:<6} | {ipv6['header_overhead']:<10} | {ipv6['total_size']:<10} | {ipv6['efficiency']:<12.2f}%")
            
            # Calculate difference
            overhead_diff = ipv6['header_overhead'] - ipv4['header_overhead']
            eff_diff = ipv4['efficiency'] - ipv6['efficiency']
            
            print(f"{'':<10} | {'Diff':<8} | {ipv6['fragments']-ipv4['fragments']:<6} | {overhead_diff:+10} | {ipv6['total_size']-ipv4['total_size']:+10} | {-eff_diff:+12.2f}%")
            print("-" * 90)
        
        return self.ipv4_data, self.ipv6_data
    
    def generate_ascii_chart(self, payload_sizes: List[int] = None):
        """Generate ASCII chart comparing fragment counts"""
        
        if not self.ipv4_data or not self.ipv6_data:
            self.compare_protocols(payload_sizes or [1000, 2000, 3000, 5000, 8000])
        
        print("\n" + "="*90)
        print("FRAGMENT COUNT COMPARISON")
        print("="*90 + "\n")
        
        max_frags = max(
            max(d['fragments'] for d in self.ipv4_data),
            max(d['fragments'] for d in self.ipv6_data)
        )
        
        for i, (ipv4, ipv6) in enumerate(zip(self.ipv4_data, self.ipv6_data)):
            payload = ipv4['payload_size']
            
            # Calculate bar lengths (scale to 40 chars max)
            ipv4_bar_len = int((ipv4['fragments'] / max_frags) * 40)
            ipv6_bar_len = int((ipv6['fragments'] / max_frags) * 40)
            
            print(f"Payload: {payload:>5} bytes")
            print(f"  IPv4 [{ipv4['fragments']:2}]: {'█' * ipv4_bar_len}")
            print(f"  IPv6 [{ipv6['fragments']:2}]: {'█' * ipv6_bar_len}")
            print()
    
    def generate_efficiency_chart(self):
        """Generate ASCII chart comparing efficiency"""
        
        if not self.ipv4_data or not self.ipv6_data:
            return
        
        print("\n" + "="*90)
        print("EFFICIENCY COMPARISON (%)")
        print("="*90 + "\n")
        
        for i, (ipv4, ipv6) in enumerate(zip(self.ipv4_data, self.ipv6_data)):
            payload = ipv4['payload_size']
            
            # Calculate bar lengths (scale to 50 chars = 100%)
            ipv4_bar_len = int((ipv4['efficiency'] / 100) * 50)
            ipv6_bar_len = int((ipv6['efficiency'] / 100) * 50)
            
            print(f"Payload: {payload:>5} bytes")
            print(f"  IPv4 [{ipv4['efficiency']:5.2f}%]: {'█' * ipv4_bar_len}")
            print(f"  IPv6 [{ipv6['efficiency']:5.2f}%]: {'█' * ipv6_bar_len}")
            print()
    
    def show_detailed_breakdown(self, payload_size: int):
        """Show detailed breakdown for a specific payload size"""
        
        print("\n" + "="*90)
        print(f"DETAILED BREAKDOWN: {payload_size} bytes payload")
        print("="*90 + "\n")
        
        # Find matching data
        ipv4 = next((d for d in self.ipv4_data if d['payload_size'] == payload_size), None)
        ipv6 = next((d for d in self.ipv6_data if d['payload_size'] == payload_size), None)
        
        if not ipv4 or not ipv6:
            print("Data not available. Run compare_protocols first.")
            return
        
        # IPv4 breakdown
        print("IPv4 Fragmentation:")
        print(f"  Total Fragments: {ipv4['fragments']}")
        print(f"  Header per Fragment: 20 bytes")
        print(f"  Total Header Overhead: {ipv4['header_overhead']} bytes")
        print(f"  Payload Size: {payload_size} bytes")
        print(f"  Total Transmitted: {ipv4['total_size']} bytes")
        print(f"  Efficiency: {ipv4['efficiency']:.2f}%")
        print(f"  Average Fragment Size: {ipv4['avg_fragment_size']:.2f} bytes")
        
        print("\n" + "-"*90 + "\n")
        
        # IPv6 breakdown
        print("IPv6 Fragmentation:")
        print(f"  Total Fragments: {ipv6['fragments']}")
        print(f"  Base Header per Fragment: 40 bytes")
        print(f"  Fragment Header per Fragment: 8 bytes")
        print(f"  Total Header per Fragment: 48 bytes")
        print(f"  Total Header Overhead: {ipv6['header_overhead']} bytes")
        print(f"  Payload Size: {payload_size} bytes")
        print(f"  Total Transmitted: {ipv6['total_size']} bytes")
        print(f"  Efficiency: {ipv6['efficiency']:.2f}%")
        print(f"  Average Fragment Size: {ipv6['avg_fragment_size']:.2f} bytes")
        
        print("\n" + "-"*90 + "\n")
        
        # Comparison
        print("Comparison:")
        print(f"  Fragment Count Difference: {ipv6['fragments'] - ipv4['fragments']}")
        print(f"  Overhead Difference: {ipv6['header_overhead'] - ipv4['header_overhead']} bytes (IPv6 has more)")
        print(f"  Total Size Difference: {ipv6['total_size'] - ipv4['total_size']} bytes")
        print(f"  Efficiency Difference: {ipv4['efficiency'] - ipv6['efficiency']:.2f}% (IPv4 is more efficient)")
    
    def export_comparison_json(self, filename: str = "fragmentation_comparison.json"):
        """Export comparison data to JSON"""
        
        data = {
            'ipv4': [
                {k: v for k, v in d.items() if k != 'packets'}
                for d in self.ipv4_data
            ],
            'ipv6': [
                {k: v for k, v in d.items() if k != 'packets'}
                for d in self.ipv6_data
            ]
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\n✓ Exported comparison data to {filename}")
    
    def export_pcap(self, filename_ipv4: str = "ipv4_comparison.pcap",
                   filename_ipv6: str = "ipv6_comparison.pcap"):
        """Export packets to PCAP files"""
        
        # IPv4
        ipv4_packets = []
        for data in self.ipv4_data:
            ipv4_packets.extend(data['packets'])
        
        if ipv4_packets:
            wrpcap(filename_ipv4, ipv4_packets)
            print(f"✓ Exported {len(ipv4_packets)} IPv4 packets to {filename_ipv4}")
        
        # IPv6
        ipv6_packets = []
        for data in self.ipv6_data:
            ipv6_packets.extend(data['packets'])
        
        if ipv6_packets:
            wrpcap(filename_ipv6, ipv6_packets)
            print(f"✓ Exported {len(ipv6_packets)} IPv6 packets to {filename_ipv6}")


def main():
    """Main demonstration"""
    
    print("\n" + "="*90)
    print("FRAGMENTATION VISUALIZER")
    print("(No root/admin required)")
    print("="*90)
    
    viz = FragmentationVisualizer()
    
    # Compare protocols
    payload_sizes = [1000, 2000, 3000, 5000, 8000]
    viz.compare_protocols(payload_sizes)
    
    # Generate charts
    viz.generate_ascii_chart()
    viz.generate_efficiency_chart()
    
    # Detailed breakdown for 3000 bytes
    viz.show_detailed_breakdown(3000)
    
    # Export data
    viz.export_comparison_json()
    viz.export_pcap()
    
    print("\n" + "="*90)
    print("✓ Visualization Complete!")
    print("="*90)


if __name__ == "__main__":
    try:
        from scapy.all import *
        main()
    except ImportError:
        print("Error: Scapy is not installed")
        print("Install with: pip install scapy")
        import sys
        sys.exit(1)
