#!/usr/bin/env python3
"""
Analyseur de captures PCAP pour démontrer la fragmentation IPv4 vs IPv6
Analyse les fichiers .pcapng capturés depuis GNS3
"""

from scapy.all import *
import os
from collections import defaultdict
from typing import Dict, List, Tuple
import json

class FragmentationAnalyzer:
    """Analyse les captures de paquets pour la fragmentation"""
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.packets = []
        self.ipv4_fragments = defaultdict(list)
        self.ipv6_fragments = defaultdict(list)
        self.icmp_messages = []
        
    def load_capture(self):
        """Charge le fichier PCAP"""
        try:
            print(f"📂 Chargement de {self.pcap_file}...")
            self.packets = rdpcap(self.pcap_file)
            print(f"✅ {len(self.packets)} paquets chargés\n")
            return True
        except FileNotFoundError:
            print(f"❌ Fichier non trouvé: {self.pcap_file}")
            return False
        except Exception as e:
            print(f"❌ Erreur: {e}")
            return False
    
    def analyze_ipv4_fragmentation(self):
        """Analyse la fragmentation IPv4"""
        print("="*70)
        print("ANALYSE IPv4")
        print("="*70)
        
        total_ipv4 = 0
        fragmented_packets = 0
        fragment_groups = defaultdict(list)
        
        for pkt in self.packets:
            if IP in pkt:
                total_ipv4 += 1
                ip_layer = pkt[IP]
                
                # Récupère les flags et l'offset
                flags = ip_layer.flags
                frag_offset = ip_layer.frag
                packet_id = ip_layer.id
                
                # Détecte si c'est un fragment
                is_fragment = (frag_offset > 0) or (flags & 0x1)  # MF flag
                
                if is_fragment:
                    fragmented_packets += 1
                    fragment_groups[packet_id].append({
                        'offset': frag_offset * 8,
                        'size': len(ip_layer.payload),
                        'mf_flag': bool(flags & 0x1),
                        'df_flag': bool(flags & 0x2),
                        'total_length': ip_layer.len
                    })
        
        print(f"\n📊 Statistiques IPv4:")
        print(f"   • Total paquets IPv4: {total_ipv4}")
        print(f"   • Paquets fragmentés: {fragmented_packets}")
        print(f"   • Groupes de fragments: {len(fragment_groups)}")
        
        if fragment_groups:
            print(f"\n📦 Détails des fragments IPv4:")
            for packet_id, fragments in fragment_groups.items():
                print(f"\n   ID de paquet: {packet_id}")
                print(f"   Nombre de fragments: {len(fragments)}")
                
                for i, frag in enumerate(sorted(fragments, key=lambda x: x['offset']), 1):
                    mf = "Oui" if frag['mf_flag'] else "Non"
                    print(f"      Fragment {i}: Offset={frag['offset']}, "
                          f"Taille={frag['size']}B, More Fragments={mf}")
                
                # Calcule la taille totale reconstituée
                total_data = sum(f['size'] for f in fragments)
                print(f"   → Taille totale des données: {total_data} octets")
        
        return len(fragment_groups)
    
    def analyze_ipv6_fragmentation(self):
        """Analyse la fragmentation IPv6"""
        print("\n" + "="*70)
        print("ANALYSE IPv6")
        print("="*70)
        
        total_ipv6 = 0
        fragmented_packets = 0
        fragment_groups = defaultdict(list)
        
        for pkt in self.packets:
            if IPv6 in pkt:
                total_ipv6 += 1
                
                # Cherche l'en-tête d'extension Fragment (type 44)
                if IPv6ExtHdrFragment in pkt:
                    fragmented_packets += 1
                    frag_layer = pkt[IPv6ExtHdrFragment]
                    
                    fragment_groups[frag_layer.id].append({
                        'offset': frag_layer.offset * 8,
                        'size': len(pkt[IPv6].payload) - 8,  # -8 pour l'en-tête fragment
                        'm_flag': frag_layer.m,
                        'identification': frag_layer.id
                    })
        
        print(f"\n📊 Statistiques IPv6:")
        print(f"   • Total paquets IPv6: {total_ipv6}")
        print(f"   • Paquets avec en-tête Fragment: {fragmented_packets}")
        print(f"   • Groupes de fragments: {len(fragment_groups)}")
        
        if fragment_groups:
            print(f"\n📦 Détails des fragments IPv6:")
            for frag_id, fragments in fragment_groups.items():
                print(f"\n   ID de fragment: {frag_id}")
                print(f"   Nombre de fragments: {len(fragments)}")
                
                for i, frag in enumerate(sorted(fragments, key=lambda x: x['offset']), 1):
                    m_flag = "Oui" if frag['m_flag'] else "Non"
                    print(f"      Fragment {i}: Offset={frag['offset']}, "
                          f"Taille={frag['size']}B, More Fragments={m_flag}")
                
                total_data = sum(f['size'] for f in fragments)
                print(f"   → Taille totale des données: {total_data} octets")
        
        return len(fragment_groups)
    
    def analyze_icmp_messages(self):
        """Analyse les messages ICMP/ICMPv6 liés à la fragmentation"""
        print("\n" + "="*70)
        print("MESSAGES ICMP/ICMPv6")
        print("="*70)
        
        icmpv4_frag_needed = 0
        icmpv6_packet_too_big = 0
        
        for pkt in self.packets:
            # ICMP Fragmentation Needed (Type 3, Code 4)
            if ICMP in pkt:
                icmp = pkt[ICMP]
                if icmp.type == 3 and icmp.code == 4:
                    icmpv4_frag_needed += 1
                    if hasattr(icmp, 'nexthopmtu'):
                        mtu = icmp.nexthopmtu
                    else:
                        mtu = "Non spécifié"
                    print(f"\n   🔵 IPv4 - Fragmentation Needed")
                    print(f"      Source: {pkt[IP].src}")
                    print(f"      MTU suggéré: {mtu}")
            
            # ICMPv6 Packet Too Big (Type 2)
            if ICMPv6PacketTooBig in pkt:
                icmpv6_packet_too_big += 1
                icmpv6 = pkt[ICMPv6PacketTooBig]
                print(f"\n   🟣 IPv6 - Packet Too Big")
                print(f"      Source: {pkt[IPv6].src}")
                print(f"      MTU: {icmpv6.mtu} octets")
        
        print(f"\n📊 Résumé ICMP:")
        print(f"   • ICMPv4 Fragmentation Needed: {icmpv4_frag_needed}")
        print(f"   • ICMPv6 Packet Too Big: {icmpv6_packet_too_big}")
    
    def generate_statistics(self) -> Dict:
        """Génère des statistiques complètes"""
        stats = {
            'file': self.pcap_file,
            'total_packets': len(self.packets),
            'ipv4': {
                'total': 0,
                'fragmented': 0,
                'fragment_groups': 0
            },
            'ipv6': {
                'total': 0,
                'fragmented': 0,
                'fragment_groups': 0
            },
            'icmp': {
                'fragmentation_needed': 0,
                'packet_too_big': 0
            }
        }
        
        for pkt in self.packets:
            if IP in pkt:
                stats['ipv4']['total'] += 1
                if pkt[IP].frag > 0 or (pkt[IP].flags & 0x1):
                    stats['ipv4']['fragmented'] += 1
            
            if IPv6 in pkt:
                stats['ipv6']['total'] += 1
                if IPv6ExtHdrFragment in pkt:
                    stats['ipv6']['fragmented'] += 1
            
            if ICMP in pkt and pkt[ICMP].type == 3 and pkt[ICMP].code == 4:
                stats['icmp']['fragmentation_needed'] += 1
            
            if ICMPv6PacketTooBig in pkt:
                stats['icmp']['packet_too_big'] += 1
        
        return stats
    
    def run_full_analysis(self):
        """Exécute l'analyse complète"""
        if not self.load_capture():
            return None
        
        ipv4_groups = self.analyze_ipv4_fragmentation()
        ipv6_groups = self.analyze_ipv6_fragmentation()
        self.analyze_icmp_messages()
        
        return self.generate_statistics()


def compare_captures(capture_files: List[str]):
    """Compare plusieurs captures"""
    print("\n" + "="*70)
    print("COMPARAISON DE CAPTURES MULTIPLES")
    print("="*70)
    
    all_stats = []
    
    for pcap_file in capture_files:
        if os.path.exists(pcap_file):
            print(f"\n{'='*70}")
            print(f"Analyse: {os.path.basename(pcap_file)}")
            print(f"{'='*70}")
            
            analyzer = FragmentationAnalyzer(pcap_file)
            stats = analyzer.run_full_analysis()
            if stats:
                all_stats.append(stats)
    
    # Tableau comparatif
    if all_stats:
        print("\n" + "="*70)
        print("TABLEAU COMPARATIF")
        print("="*70)
        print(f"\n{'Fichier':<30} {'IPv4 Frag':<12} {'IPv6 Frag':<12} {'ICMP Msg':<12}")
        print("-" * 70)
        
        for stat in all_stats:
            filename = os.path.basename(stat['file'])
            ipv4_frag = stat['ipv4']['fragmented']
            ipv6_frag = stat['ipv6']['fragmented']
            icmp_total = stat['icmp']['fragmentation_needed'] + stat['icmp']['packet_too_big']
            
            print(f"{filename:<30} {ipv4_frag:<12} {ipv6_frag:<12} {icmp_total:<12}")


def main():
    """Fonction principale"""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║     ANALYSEUR DE FRAGMENTATION IPv4/IPv6 - CAPTURES GNS3        ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    # Exemple 1: Analyse d'un seul fichier
    print("📌 EXEMPLE 1: Analyse d'une seule capture")
    print("-" * 70)
    
    # Remplacez par le chemin de votre fichier PCAP
    pcap_file = "ipv4_comparison.pcap"
    
    if os.path.exists(pcap_file):
        analyzer = FragmentationAnalyzer(pcap_file)
        analyzer.run_full_analysis()
    else:
        print(f"⚠️  Fichier exemple non trouvé: {pcap_file}")
        print("\n💡 Pour utiliser ce script:")
        print("   1. Placez vos fichiers .pcap dans le même dossier")
        print("   2. Modifiez la variable 'pcap_file' avec votre nom de fichier")
        print("   3. Ou utilisez l'exemple 2 ci-dessous pour comparer plusieurs fichiers")
    
    # Exemple 2: Comparaison de plusieurs captures
    print("\n\n📌 EXEMPLE 2: Comparaison de plusieurs captures")
    print("-" * 70)
    
    captures = [
        "ipv4_comparison.pcap",
        "ipv6_comparison.pcap",
        
    ]
    
    # Vérifie quels fichiers existent
    existing_captures = [f for f in captures if os.path.exists(f)]
    
    if existing_captures:
        compare_captures(existing_captures)
    else:
        print("⚠️  Aucun fichier de capture trouvé")
        print("\n📋 Structure recommandée:")
        print("   projet/")
        print("   ├── analyse_captures.py  (ce script)")
        print("   └── captures/")
        print("       ├── ipv4_mtu_1500.pcap")
        print("       ├── ipv4_mtu_1000.pcap")
        print("       ├── ipv6_mtu_1500.pcap")
        print("       └── ipv6_mtu_1280.pcap")
    
 
   


if __name__ == "__main__":
    main()