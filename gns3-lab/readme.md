# Laboratoire GNS3 : Fragmentation IPv4 vs IPv6

## Objectif du Laboratoire

Ce laboratoire démontre de manière pratique les **différences fondamentales** entre les mécanismes de fragmentation IPv4 et IPv6 à travers une topologie réseau contrôlée dans GNS3. Il permet d'observer en temps réel :

- 🔹 La **fragmentation par routeur** (IPv4) vs **fragmentation par source** (IPv6)
- 🔹 Le mécanisme de **Path MTU Discovery** (PMTUD) en IPv6
- 🔹 L'impact du **Don't Fragment (DF) flag** en IPv4
- 🔹 Les messages **ICMPv6 "Packet Too Big"** pour la découverte dynamique du MTU
- 🔹 Les différences d'**overhead** et d'**efficacité** entre les deux protocoles

---

## Prérequis

### Logiciels Requis
- **GNS3** installé et configuré (version 2.2+)
- **Images Cisco IOS** c3745 ou équivalent
- **2 machines virtuelles Linux** (Ubuntu 20.04+ / Fedora 34+ recommandés)
- **Wireshark** pour l'analyse des captures PCAP
- **Python 3.8+** avec Scapy (pour les scripts d'analyse)



###  Points Clés de la Topologie
- **Goulot d'étranglement MTU** : Le lien R1-R2 (F0/0) a un MTU réduit à **1300 bytes**
- **But** : Forcer la fragmentation et observer les différences de comportement IPv4/IPv6
- **Chemin MTU** : 1500 → **1300** → 1500 (crée un "bottleneck" au milieu)

---

##  Configuration MTU Spécifique

### Tableau des Valeurs MTU Configurées

| Équipement  | Interface        | MTU              | Rôle                          |
|-------------|------------------|------------------|-------------------------------|
| Linux VM    | enp0s3           | 1500 (défaut)    | Source des paquets            |
| R1          | FastEthernet0/0  | 1500 (défaut)    | Lien vers source              |
| R1          | FastEthernet1/0  | 1500 (défaut)    | Lien sortant vers R2          |
| R2          | FastEthernet0/0  | **1300**       | **Goulot d'étranglement**     |
| R2          | FastEthernet0/1  | 1500 (défaut)    | Lien vers destination         |

### Commandes de Configuration MTU


#### Vérification des MTU sur Tous les Routeurs

```cisco
! Sur R1
R1# show interfaces | include MTU
  MTU 1500 bytes, BW 100000 Kbit/sec
  MTU 1500 bytes, BW 100000 Kbit/sec

! Sur R2
R2# show interfaces | include MTU
  MTU 1300 bytes, BW 100000 Kbit/sec  ← Goulot confirmé
  MTU 1500 bytes, BW 100000 Kbit/sec
```

---

##  Méthodologie de Test

### Test 1 : Vérification de Connectivité de Base

**Objectif** : Valider que tous les équipements communiquent correctement avant les tests de fragmentation.

```bash
# Depuis Linux VM

# Test IPv4 - Connectivité vers R1
ping -c 4 10.0.0.1
#  Attendu : 4 paquets reçus, 0% perte

# Test IPv6 - Connectivité vers R1
ping6 -c 4 2001:db8:1::1
#  Attendu : 4 paquets reçus, 0% perte

# Test IPv4 - Connectivité vers R2 (à travers R1)
ping -c 4 10.0.12.2
#  Attendu : 4 paquets reçus, 0% perte

# Test IPv6 - Connectivité vers R2 (à travers R1)
ping6 -c 4 2001:db8:12::2
#  Attendu : 4 paquets reçus, 0% perte
```

### Test 2 : Fragmentation IPv4 (Routeur Intermédiaire)

**Principe** : En IPv4, les routeurs intermédiaires **peuvent fragmenter** les paquets si nécessaire.

#### Test 2.1 : Fragmentation Automatique (DF=0)

```bash
# Envoi d'un paquet de 1400 bytes (> MTU 1300 de R2)
# Sans le flag DF, R2 peut fragmenter
ping -c 3 -s 1400 192.168.1.2

#  Résultat attendu :
# - Linux envoie 1 paquet de 1400 bytes
# - R1 transmet sans modification (MTU=1500)
# - R2 fragmente en 2 paquets (MTU=1300)
# - Destination reçoit et réassemble
#  Succès : 3 paquets reçus
```


### Test 3 : Fragmentation IPv6 (Source Uniquement)

**Principe** : En IPv6, **seule la source** peut fragmenter. Les routeurs envoient des messages ICMPv6 "Packet Too Big".

#### Test 3.1 : Fragmentation par la Source

```bash
# Envoi d'un paquet de 2000 bytes (> MTU 1500 local)
# Linux fragmente AVANT d'envoyer
ping6 -c 3 -s 2000 2001:db8:1::1

#  Résultat attendu :
# - Linux détecte 2000 > 1500 (MTU local)
# - Linux fragmente en 2 fragments + en-tête extension
# - R1 reçoit 2 fragments et transmet
#  Succès : 3 paquets reçus
```

#### Test 3.2 : Path MTU Discovery Automatique

```bash
# Vider le cache PMTU pour forcer la redécouverte
sudo ip -6 route flush cache

# Envoi d'un paquet de 1400 bytes vers R2
ping6 -c 5 -s 1400 2001:db8:12::2 -v

```



### Test 4 : Comparaison MTU Minimum

**IPv6 a un MTU minimum de 1280 bytes** (vs 68 pour IPv4).

```bash
# Test avec le MTU minimum IPv6
# 1232 = 1280 - 40 (IPv6 header) - 8 (ICMPv6 header)
ping6 -c 3 -s 1232 2001:db8:12::2
#  Doit fonctionner sans problème

# Test avec une valeur légèrement supérieure
ping6 -c 3 -s 1240 2001:db8:12::2
#  Peut nécessiter fragmentation selon le PMTU découvert

# Comparaison IPv4 - MTU minimum 68 bytes
ping -c 3 -s 40 10.0.12.2
#  Fonctionne (bien en dessous du minimum)
```

---

##  Capture et Analyse avec Wireshark

### Points de Capture Stratégiques

| Point de Capture | Emplacement       | Observations Attendues                                    |
|------------------|-------------------|----------------------------------------------------------|
| **Capture 1**    | Lien Linux → R1   | Paquets originaux, fragmentation ipv4            |
| **Capture 2**    | Lien R1 → R2      |Ddécouverte MTU         |
| **Capture 3**    | Lien R2 → Dest    | Fragments IPv4 créés par R2, fragments IPv6 de la source |

