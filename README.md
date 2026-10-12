# Capture and Analyze Network Traffic (Kali Linux Terminal)

## Objective
Capture live packets and identify basic protocols using tshark on Kali Linux.

## Tools
tshark, capinfos, ping, nslookup, curl, Python 3 + Scapy

## Steps
1. Installed tools: `sudo apt install -y wireshark tshark tcpdump python3-scapy`
2. Found interface: `ip route | grep default` (eth0)
3. Captured 60 s: `sudo tshark -i eth0 -a duration:60 -F pcap -w /tmp/capture.pcap`, then moved it into the project folder.
4. Generated traffic: ping, nslookup, curl (HTTP and HTTPS).
5. Verified: `capinfos capture.pcap` (129 packets, about 55 s).
6. Filtered by protocol with `tshark -r capture.pcap -Y "<filter>"` (dns, arp, http, icmp, icmpv6, tcp).
7. Identified protocols: ARP, HTTP, DNS, ICMPv6, ICMP.
8. Exported capture as capture.pcap.
9. Summarised with `python3 analyze_pcap.py capture.pcap`.

## Files
- capture.pcap - packet capture
- analyze_pcap.py - protocol summary script
- protocol_summary.csv, analysis_output.md - script output
- outputs/ - filter and packet-detail outputs
- screenshots/ - terminal screenshots
- REPORT.md - findings

## Protocols identified
| Protocol | Packets |
|---|---|
| ARP | 24 |
| HTTP | 18 |
| ICMPv6 | 12 |
| DNS | 12 |
| ICMP | 1 |

Total packets: 129.
