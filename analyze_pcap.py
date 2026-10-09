#!/usr/bin/env python3
"""Summarise a Wireshark capture. Usage: python3 analyze_pcap.py capture.pcap"""
import csv
import sys
from collections import Counter

from scapy.all import (ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, IPv6, Raw,
                       rdpcap)


def classify(pkt):
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(IPv6) and pkt[IPv6].nh == 58:
        return "ICMPv6"
    if pkt.haslayer(TCP):
        ports = {pkt[TCP].sport, pkt[TCP].dport}
        if 53 in ports:
            return "DNS"
        if 80 in ports:
            return "HTTP"
        if 443 in ports:
            return "TLS/HTTPS"
        return "TCP (other)"
    if pkt.haslayer(UDP):
        ports = {pkt[UDP].sport, pkt[UDP].dport}
        if 53 in ports or pkt.haslayer(DNS):
            return "DNS"
        if 5353 in ports:
            return "mDNS"
        if ports & {67, 68}:
            return "DHCP"
        if 123 in ports:
            return "NTP"
        if 1900 in ports:
            return "SSDP"
        if 443 in ports:
            return "QUIC"
        return "UDP (other)"
    return "Other"


def main(path):
    packets = rdpcap(path)
    total = len(packets)
    if total == 0:
        sys.exit("No packets found in capture.")

    proto_count, proto_bytes = Counter(), Counter()
    ip_pairs, dns_queries, http_hosts = Counter(), Counter(), Counter()
    tcp_flags = Counter()

    for pkt in packets:
        label = classify(pkt)
        proto_count[label] += 1
        proto_bytes[label] += len(pkt)

        if pkt.haslayer(IP):
            ip_pairs[(pkt[IP].src, pkt[IP].dst)] += 1

        if pkt.haslayer(DNSQR) and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            dns_queries[pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")] += 1

        if pkt.haslayer(TCP):
            flags = str(pkt[TCP].flags)
            if flags == "S":
                tcp_flags["SYN"] += 1
            elif flags == "SA":
                tcp_flags["SYN-ACK"] += 1
            elif "F" in flags:
                tcp_flags["FIN"] += 1
            elif "R" in flags:
                tcp_flags["RST"] += 1

        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and 80 in {pkt[TCP].sport, pkt[TCP].dport}:
            data = bytes(pkt[Raw].load)
            if data.startswith((b"GET ", b"POST ", b"HEAD ")):
                for line in data.split(b"\r\n"):
                    if line.lower().startswith(b"host:"):
                        http_hosts[line[5:].strip().decode(errors="ignore")] += 1

    rows = [(p, c, round(100 * c / total, 2), proto_bytes[p])
            for p, c in proto_count.most_common()]

    print(f"File: {path}\nTotal packets: {total}\n")
    print(f"{'Protocol':<14}{'Packets':>9}{'%':>8}{'Bytes':>12}")
    for p, c, pct, b in rows:
        print(f"{p:<14}{c:>9}{pct:>8}{b:>12}")

    with open("protocol_summary.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["protocol", "packets", "percent", "bytes"])
        w.writerows(rows)

    with open("analysis_output.md", "w") as f:
        f.write(f"# Analysis output for `{path}`\n\n")
        f.write(f"**Total packets:** {total}\n\n")
        f.write("## Protocol distribution\n\n| Protocol | Packets | % | Bytes |\n|---|---|---|---|\n")
        for p, c, pct, b in rows:
            f.write(f"| {p} | {c} | {pct} | {b} |\n")
        f.write("\n## Top 5 conversations (IP src -> dst)\n\n")
        for (s, d), c in ip_pairs.most_common(5):
            f.write(f"- {s} -> {d}: {c} packets\n")
        f.write("\n## Top DNS queries\n\n")
        for q, c in dns_queries.most_common(10):
            f.write(f"- {q} ({c})\n")
        if http_hosts:
            f.write("\n## HTTP hosts requested (plain-text port 80)\n\n")
            for h, c in http_hosts.most_common(10):
                f.write(f"- {h} ({c})\n")
        if tcp_flags:
            f.write("\n## TCP handshake / teardown counts\n\n")
            for k, v in tcp_flags.items():
                f.write(f"- {k}: {v}\n")

    print("\nWrote protocol_summary.csv and analysis_output.md")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 analyze_pcap.py capture.pcap")
    main(sys.argv[1])
