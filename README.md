# 🌐 Fragmentation IPv4 vs IPv6

Analyse comparative des mécanismes de fragmentation entre IPv4 et IPv6 avec démonstrations pratiques.

##  Démarrage Rapide

```bash
# Installation
pip install scapy

# Exécution du notebook principal
jupyter notebook main.ipynb
```

##  Structure

```
├── Exemple_dutilisation.ipynb           # Notebook principal avec tests
├── Code/
│   ├── fragmentation_complete.py        # Tests de fragmentation
│   ├── fragmentation_visualizer.py      # Visualisations et comparaisons
│   └── pcap_analyzer.py                 # Analyse de fichiers PCAP
└── gns3-lab/                            # Laboratoire GNS3 pratique
    ├── readme.md                        # Guide détaillé du lab
    └── captures/                        # Captures PCAP réelles
```

##  Fonctionnalités

-  **Démonstration sans privilèges root** - utilise Scapy pour créer des paquets
-  **Comparaisons visuelles** - graphiques ASCII, tableaux, métriques d'efficacité
-  **Analyse PCAP** - inspection détaillée des captures réseau
-  **Lab GNS3** - topologie réelle avec MTU réduit pour tests

##  Différences Clés

| Aspect              | IPv4                          | IPv6                        |
|---------------------|-------------------------------|----------------------------|
| **Fragmentation**   | Routeurs intermédiaires       | Source uniquement          |
| **En-tête**         | 20 bytes                      | 40 bytes + 8 (fragment)    |
| **MTU Discovery**   | Optionnel (DF flag)           | Obligatoire                |
| **Message ICMP**    | Type 3 Code 4                 | Type 2 "Packet Too Big"    |
| **MTU minimum**     | 68 bytes                      | 1280 bytes                 |

##  Utilisation

### Exemple 1 : Comparaison de protocoles
```python
from Code.fragmentation_visualizer import FragmentationVisualizer

viz = FragmentationVisualizer()
viz.compare_protocols(payload_sizes=[1000, 2000, 3000, 5000])
viz.generate_ascii_chart()
viz.export_pcap()
```

### Exemple 2 : Analyse PCAP
```python
from Code.pcap_analyzer import FragmentationAnalyzer

analyzer = FragmentationAnalyzer("capture.pcap")
analyzer.run_full_analysis()
```

## 🧪 Laboratoire GNS3

Le dossier `gns3-lab/` contient une topologie complète avec :
- 2 routeurs Cisco (R1, R2)
- MTU réduit à 1300 sur R2 (goulot d'étranglement)
- Scripts de test automatisés
- Filtres Wireshark prêts à l'emploi

Voir `gns3-lab/readme.md` pour le guide détaillé.

## 📦 Exports

Les scripts génèrent automatiquement :
- `fragmentation_comparison.json` - Données comparatives
- `ipv4_comparison.pcap` - Fragments IPv4
- `ipv6_comparison.pcap` - Fragments IPv6

##  Résultats Clés

**Efficacité (payload 3000 bytes, MTU 1300) :**
- IPv4 : 98.04% (60 bytes overhead)
- IPv6 : 95.42% (144 bytes overhead)

**IPv4** est plus efficace mais **IPv6** est plus robuste avec PMTUD obligatoire.


