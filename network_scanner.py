import argparse
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, sniff, sr
from scapy.layers.inet import IP, TCP, ICMP, UDP
import psutil
import ipaddress
import socket


def main():
    parser = argparse.ArgumentParser(
        description="Scan the network for devices,\n"
        + "open ports or check the traffic of your own device"
    )
    subparsers = parser.add_subparsers()
    arp_parser = subparsers.add_parser("arp", help="Scan for devices on network")
    arp_parser.set_defaults(func=device_scan)
    portscan_parser = subparsers.add_parser(
        "portscan", help="Scan the open ports of a device via ip"
    )
    portscan_parser.add_argument("--allp", action="store_true")
    portscan_parser.add_argument("ip", type=ipaddress.ip_address, help="ipv4 or ipv6")
    portscan_parser.set_defaults(func=portscan)
    selfscan_parser = subparsers.add_parser(
        "selfscan", help="Selfscan the ports of your own device"
    )
    selfscan_parser.add_argument("-l", action="store_true")
    selfscan_parser.set_defaults(func=selfscan)
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return
    args.func(args)


def device_scan(_):
    ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    for interface, addresses in psutil.net_if_addrs().items():
        if interface != "lo":
            for addr in addresses:
                if addr.address is not None and addr.netmask is not None:
                    if addr.family == socket.AF_INET:
                        ip_address = ipaddress.IPv4Network(
                            addr.address + "/" + addr.netmask, strict=False
                        )
                        arp_request = ARP(pdst=ip_address)
                        packet = ethernet_frame / arp_request
                        answered = srp(packet, timeout=2, verbose=False)
                        for devices in answered[0]:
                            print(
                                "IP: "
                                + devices[1][ARP].psrc
                                + " | MAC: "
                                + devices[1][ARP].hwsrc
                            )


def portscan(args):
    packets = [
        IP(dst=args.ip)
        / TCP(
            dport=list(range(1, 65536)) if args.allp else list(range(1, 1025)),
            flags="S",
        )
    ]
    answered, _ = sr(packets, timeout=2, verbose=False)
    for send, recieved in answered:
        if recieved[TCP].flags == "SA":
            print("Ports offen: " + str(send[TCP].dport))


def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
    else:
        src = "N/A"
        dst = "N/A"
    if TCP in packet:
        typ = "TCP"
        flags = packet[TCP].flags
        dport = packet[TCP].dport
        print(f"{typ:<10} | {src:<10} | {dst:<10} | {flags:<10} | {dport:<10}")
    elif UDP in packet:
        typ = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        print(f"{typ:<10} | {src:<10} | {dst:<10} | {sport:<10} | {dport:<10}")

    elif ICMP in packet:
        typ = "ICMP"
        icmp_type = packet[ICMP].type
        code = packet[ICMP].code
        print(f"{typ:<10} | {src:<10} | {dst:<10} | {icmp_type:<10} | {code:<10}")


def selfscan(args):
    connections = psutil.net_connections()
    for connection in connections:
        if connection.status == "LISTEN" and connection.laddr:
            print(connection.laddr.port)
    if args.l:
        print(
            f"{'Packettyp':<10} | {'Source-IP':<10} | {'Destination-IP':<10} | {'flags/sport/type':<10} | {'dport/code':<10}"
        )
        sniff(prn=packet_callback)
