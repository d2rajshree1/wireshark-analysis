# Task 5 – Network Traffic Capture and Analysis Report

**Platform:** Kali Linux (terminal) | **Tool:** tshark | **Date:** 9 October 2026

## 1. Capture details
| Item | Value |
|---|---|
| Interface | eth0 |
| Command | `sudo tshark -i eth0 -a duration:60 -F pcap -w /tmp/capture.pcap` |
| Duration | about 55 seconds |
| Total packets | 129 (11,711 bytes) |
| Local host IP | 192.168.29.217 |
| Traffic generated | ping google.com, nslookup example.com, curl http://neverssl.com, curl https://example.com |
| Capture file | capture.pcap |

## 2. Protocol hierarchy (tshark -z io,phs)
| Layer | Protocol | Frames | % of 129 |
|---|---|---|---|
| Link | ARP | 24 | 18.6% |
| Network | IPv4 | 43 | 33.3% |
| Network | IPv6 | 62 | 48.1% |
| Network | ICMPv6 | 53 | 41.1% |
| Network | IGMP | 20 | 15.5% |
| Network | ICMP | 1 | 0.8% |
| Transport | TCP | 18 | 14.0% |
| Transport | UDP | 13 | 10.1% |
| Application | DNS | 12 | 9.3% |

## 3. Protocols identified
1. **ARP** (filter `arp`, 24 frames): maps IP addresses to MAC addresses on the local network.
2. **DNS** (filter `dns`, 12 frames): name resolution, 6 queries and 6 responses.
3. **ICMPv6** (filter `icmpv6`, 53 frames): IPv6 neighbour and router discovery.
4. **IGMP** (filter `igmp`, 20 frames): multicast group membership messages.
5. **TCP** (filter `tcp`, 18 frames): connection setup and teardown for the curl requests on port 80.
6. **ICMP** (filter `icmp`, 1 frame): one packet from the ping test.

## 4. Packet detail
DNS queries from 192.168.29.217: google.com (frames 19, 20), example.com (frames 51, 53), neverssl.com (frames 55, 56). Each name was queried twice, typical of separate IPv4 and IPv6 record lookups.

TCP carried 18 frames (9 over IPv4, 9 over IPv6). tshark showed no HTTP layer, so no HTTP request was decoded. Only 1 ICMP frame appeared where `ping -c 5` should produce 10, so the ping likely did not complete normally.

## 5. Findings
- ARP, DNS, TCP, ICMP, ICMPv6 and IGMP were all present, covering link, network, transport and application layers.
- IPv6 (62 frames) outweighed IPv4 (43), mostly from ICMPv6 background traffic.
- DNS lookups happened before the connections, so name resolution comes first.
- Much of the capture is system housekeeping (ARP, IGMP, ICMPv6), so filters are needed to isolate traffic.
- No TLS traffic was captured, so the https request did not appear on port 443.
- One ICMP packet where 10 were expected shows how a capture reveals a failing or filtered ping.

## 6. Conclusion
I captured 129 live packets with tshark on Kali Linux, filtered them by protocol, and identified ARP, DNS, TCP, ICMP, ICMPv6 and IGMP. The exercise showed how the TCP/IP layers fit together and how packet captures help with network troubleshooting.

## 7. Files
capture.pcap, analyze_pcap.py, protocol_summary.csv, analysis_output.md, outputs/, screenshots/, README.md
