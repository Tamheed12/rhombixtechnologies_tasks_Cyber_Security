# Network Sniffer

import socket
import struct
import time
import argparse
import os
import sys

# ===================== Helper Functions =====================

def format_mac(mac):
    return ':'.join(f'{b:02x}' for b in mac)

def ipv4(addr):
    return '.'.join(map(str, addr))

def get_interfaces():
    return os.listdir('/sys/class/net/')

# ===================== Argument Parser =====================

parser = argparse.ArgumentParser(description="Advanced Python Network Sniffer")
parser.add_argument("-i", "--interface", help="Network interface (eth0, wlan0)")
parser.add_argument("-p", "--protocol", choices=["tcp", "udp", "icmp", "all"], default="all")
parser.add_argument("--port", type=int, help="Filter by port")
args = parser.parse_args()

if not args.interface:
    print("Available interfaces:", ", ".join(get_interfaces()))
    sys.exit("❌ Please specify an interface using -i")

# ===================== Raw Socket =====================

try:
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    sniffer.bind((args.interface, 0))
except PermissionError:
    sys.exit("❌ Run as root: sudo python3 sniffer.py")

print(f"\n📡 Sniffing on {args.interface} | Protocol: {args.protocol.upper()}\n")

packet_count = 0

# ===================== Sniffing Loop =====================

try:
    while True:
        raw_data, addr = sniffer.recvfrom(65535)
        packet_count += 1
        timestamp = time.strftime("%H:%M:%S")

        # -------- Ethernet --------
        dest_mac, src_mac, eth_proto = struct.unpack('!6s6sH', raw_data[:14])

        if eth_proto != 0x0800:
            continue

        # -------- IP --------
        ip_header = raw_data[14:34]
        version_ihl, tos, length, ident, flags, ttl, proto, checksum, src, dst = \
            struct.unpack('!BBHHHBBH4s4s', ip_header)

        ihl = (version_ihl & 15) * 4
        src_ip = ipv4(src)
        dst_ip = ipv4(dst)

        # -------- ICMP --------
        if proto == 1 and args.protocol in ("icmp", "all"):
            icmp_type, code, checksum = struct.unpack('!BBH', raw_data[14+ihl:14+ihl+4])
            print(f"[{timestamp}] #{packet_count} ICMP {src_ip} → {dst_ip} | Type {icmp_type}")

        # -------- TCP --------
        elif proto == 6 and args.protocol in ("tcp", "all"):
            tcp_start = 14 + ihl
            tcp_header = raw_data[tcp_start:tcp_start+20]
            src_port, dst_port, seq, ack, offset_flags, win, checksum, urg = \
                struct.unpack('!HHLLHHHH', tcp_header)

            if args.port and args.port not in (src_port, dst_port):
                continue

            flags = {
                "FIN": offset_flags & 0x01,
                "SYN": offset_flags & 0x02,
                "RST": offset_flags & 0x04,
                "PSH": offset_flags & 0x08,
                "ACK": offset_flags & 0x10,
                "URG": offset_flags & 0x20,
            }

            flag_str = ",".join(k for k,v in flags.items() if v)

            print(f"[{timestamp}] #{packet_count} TCP {src_ip}:{src_port} → {dst_ip}:{dst_port} [{flag_str}]")

        # -------- UDP --------
        elif proto == 17 and args.protocol in ("udp", "all"):
            udp_start = 14 + ihl
            src_port, dst_port, length, checksum = \
                struct.unpack('!HHHH', raw_data[udp_start:udp_start+8])

            if args.port and args.port not in (src_port, dst_port):
                continue

            print(f"[{timestamp}] #{packet_count} UDP {src_ip}:{src_port} → {dst_ip}:{dst_port}")

except KeyboardInterrupt:
    print(f"\n🛑 Stopped. Total packets captured: {packet_count}")



# it is work on Wln0 and also eth0 show the tcp and udp
#let run the code

#currently i have no ethernet so it donot show any think
# you can spacify it by saying the TCP or UDP
# and also tell the port http 80 and hpps 447



# Thank you for watching it . T
# This is Tamheed Tariq Project