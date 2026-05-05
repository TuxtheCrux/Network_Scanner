# Network_Scanner

# 🔍 Network Scanner

Ein kommandozeilenbasiertes Netzwerk-Tool in Python zum Erkennen von Geräten, Scannen von Ports und Analysieren von Live-Traffic im lokalen Netzwerk.

---

## Features

- **ARP-Scan** – Findet alle aktiven Geräte im lokalen Netzwerk und zeigt ihre IP- und MAC-Adresse an.
- **Portscan** – Prüft welche TCP-Ports eines bestimmten Geräts offen sind (bekannte Ports oder alle 65535).
- **Selfscan** – Zeigt die eigenen lauschenden Ports; optional mit Live-Traffic-Anzeige.

---

## Voraussetzungen

- Python 3.10+
- Root-/Administrator-Rechte (für Raw Sockets)
- Linux empfohlen

### Abhängigkeiten installieren

```bash
pip install scapy psutil
```

---

## Installation

```bash
git clone <repo-url>
cd network_scanner
python -m venv .venv
source .venv/bin/activate
pip install scapy psutil
```

---

## Verwendung

Da das Tool Raw Sockets verwendet, sind Root-Rechte erforderlich. Da `sudo` die virtuelle Umgebung nicht automatisch erkennt, muss das Python der venv explizit angegeben werden:

```bash
sudo .venv/bin/python3 network_scanner.py <subcommand>
```

### ARP-Scan

Findet alle aktiven Geräte im lokalen Netzwerk automatisch über alle Netzwerkinterfaces.

```bash
sudo .venv/bin/python3 network_scanner.py arp
```

Beispielausgabe:
```
IP: 192.168.1.1   | MAC: aa:bb:cc:dd:ee:ff
IP: 192.168.1.42  | MAC: 11:22:33:44:55:66
```

### Portscan

Scannt die TCP-Ports eines bestimmten Geräts via SYN-Scan.

```bash
# Bekannte Ports 1-1024 scannen (Standard)
sudo .venv/bin/python3 network_scanner.py portscan 192.168.1.1

# Alle 65535 Ports scannen
sudo .venv/bin/python3 network_scanner.py portscan --all 192.168.1.1
```

Beispielausgabe:
```
Port offen: 22
Port offen: 80
Port offen: 443
```

### Selfscan

Zeigt die eigenen lauschenden Ports ohne Pakete zu senden.

```bash
# Nur lauschende Ports anzeigen
sudo .venv/bin/python3 network_scanner.py selfscan

# Lauschende Ports + Live-Traffic
sudo .venv/bin/python3 network_scanner.py selfscan -l
```

Beispielausgabe mit `-l`:
```
Pakettyp   | Source-IP       | Destination-IP  | Flags/Sport/Type | DPort/Code
TCP        | 192.168.1.42    | 151.101.1.91    | PA               | 443
UDP        | 192.168.1.42    | 8.8.8.8         | 54321            | 53
ICMP       | 192.168.1.1     | 192.168.1.42    | 8                | 0
```

---

## Technischer Überblick

Das Tool nutzt **Scapy** um Pakete direkt auf Layer 2 und 3 des OSI-Modells zu bauen und zu senden. Der ARP-Scan sendet Ethernet-Broadcasts um Geräte im Netz zu finden. Der Portscan nutzt TCP SYN-Pakete – ein `SYN-ACK` als Antwort bedeutet offener Port. Der Selfscan liest Verbindungsinformationen direkt aus dem Betriebssystem via `psutil`, ohne Pakete zu senden.

---

## Rechtlicher Hinweis

Dieses Tool darf **ausschließlich auf eigenen Geräten und Netzwerken** oder mit ausdrücklicher Genehmigung des Netzwerkeigentümers verwendet werden. Das Scannen fremder Netzwerke ist in vielen Ländern strafbar.

---

## Geplante Erweiterungen

- IPv6 NDP-Scan (Neighbor Discovery Protocol als ARP-Äquivalent)
- UDP-Portscan
- JSON-Export der Ergebnisse
- Service-Detection (Diensterkennung hinter offenen Ports)
