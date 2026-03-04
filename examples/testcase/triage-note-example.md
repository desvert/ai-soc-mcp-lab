Triage Note — case001.pcap                                                                                                                                                            
                                                                                                                                                                                        
  PCAP: /evidence/soc/cases/testcase/raw/case001.pcap                                                                                                                                   
  Capture period: 2020-09-18 ~21:59 – ~22:05 UTC (approx. 15,738 seconds captured, ~4.4 hours)
  DNS queries: 2,950 rows | A-record rows: 1,177 | HTTP host rows: 248

  ---
  Summary of Network Activity

  A Windows Active Directory environment (domain C137.local, DC CITADEL-DC01 at 10.42.85.10) with at least one workstation (DESKTOP-SDN1RPT, 10.42.85.115). The traffic contains:

  1. Routine Windows telemetry and certificate validation (OCSP) from 10.42.85.115.
  2. Heavy RDP scanning/probing from external IP 194.61.24.102 against 10.42.85.10:3389 — 293 rapid short-lived TCP sessions in the conversation tail alone.
  3. Repeated WPAD proxy-discovery queries (192 total) and ISATAP queries (52 total).
  4. Suspicious DNS resolution pattern: 10.90.90.90 appears as the most-resolved A-record answer (338 times), far above any other IP.

  ---
  Notable DNS Queries

  ┌───────────────────────────────────────────────────────────────────┬──────────────────┬───────────────────────────────────────────────────────────────────────┐
  │                               Query                               │      Count       │                                 Notes                                 │
  ├───────────────────────────────────────────────────────────────────┼──────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ wpad                                                              │ 192              │ Unqualified WPAD probe — very high; no NXDOMAIN visible in sample     │
  ├───────────────────────────────────────────────────────────────────┼──────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ settings-win.data.microsoft.com                                   │ 90               │ Windows telemetry                                                     │
  ├───────────────────────────────────────────────────────────────────┼──────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ wpad.C137.local                                                   │ 60               │ Domain-qualified WPAD — answered NXDOMAIN in sample                   │
  ├───────────────────────────────────────────────────────────────────┼──────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ v10.events.data.microsoft.com                                     │ 58               │ Windows telemetry                                                     │
  ├───────────────────────────────────────────────────────────────────┼──────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ isatap                                                            │ 52               │ IPv6 ISATAP transition                                                │
  ├───────────────────────────────────────────────────────────────────┼──────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ _ldap._tcp.Default-First-Site-Name._sites.CITADEL-DC01.C137.local │ 26               │ DC locator (normal AD)                                                │
  ├───────────────────────────────────────────────────────────────────┼──────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ xioorhri.C137.local                                               │ (seen in sample) │ Random-looking short hostname in corporate domain — NXDOMAIN returned │
  └───────────────────────────────────────────────────────────────────┴──────────────────┴───────────────────────────────────────────────────────────────────────┘

  The xioorhri.C137.local query is anomalous: it is a random 8-character alphabetic name that does not match any known host in the environment. It appeared at 21:59:39 UTC, at the very
   start of the capture window.

  ---
  Notable HTTP Hosts

  ┌────────────────────────────────┬───────┬──────────────────────────────────────────────────────────────────────────────────────────────┐
  │              Host              │ Count │                                            Notes                                             │
  ├────────────────────────────────┼───────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
  │ ocsp.digicert.com              │ 77    │ Certificate revocation — routine                                                             │
  ├────────────────────────────────┼───────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
  │ 239.255.255.250:1900           │ 21    │ SSDP/UPnP multicast — routine                                                                │
  ├────────────────────────────────┼───────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
  │ go.microsoft.com               │ 13    │ Windows redirects — routine                                                                  │
  ├────────────────────────────────┼───────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
  │ dmd.metaservices.microsoft.com │ 12    │ Device metadata — routine                                                                    │
  ├────────────────────────────────┼───────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
  │ 194.61.24.102                  │ 5     │ Raw IP as HTTP Host header — unusual; implies a client explicitly contacted this external IP │
  ├────────────────────────────────┼───────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
  │ o.ss2.us                       │ 2     │ Symantec OCSP service, but HTTP traffic resolved/directed to internal IP 10.90.90.90         │
  ├────────────────────────────────┼───────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
  │ vignette2.wikia.nocookie.net   │ 2     │ Fandom/wiki content (Rick and Morty images)                                                  │
  └────────────────────────────────┴───────┴──────────────────────────────────────────────────────────────────────────────────────────────┘

  HTTP sample rows show 10.42.85.115 browsed Rick and Morty fan content (i.cdn.turner.com, img04.deviantart.net, vignette1/2.wikia.nocookie.net) around 22:01:00 UTC.

  The o.ss2.us OCSP requests were directed to 10.90.90.90 — an internal address — rather than the real Symantec OCSP service. This is structurally unusual.

  ---
  Notable IP Conversations

  All 295 of the final 300 conversation-tail entries involve 194.61.24.102 as the initiator:

  ┌───────────────────────────────────────────┬───────┬───────────────────────┬──────────────┐
  │              Session pattern              │ Count │ Avg bytes (sent/recv) │ Avg duration │
  ├───────────────────────────────────────────┼───────┼───────────────────────┼──────────────┤
  │ 194.61.24.102:HighPort → 10.42.85.10:3389 │ 293   │ 134 / 723 bytes       │ ~0.002 s     │
  ├───────────────────────────────────────────┼───────┼───────────────────────┼──────────────┤
  │ 194.61.24.102 → 10.42.85.10:80            │ 1     │ —                     │ —            │
  ├───────────────────────────────────────────┼───────┼───────────────────────┼──────────────┤
  │ 194.61.24.102 → 10.42.85.10:443           │ 1     │ —                     │ —            │
  └───────────────────────────────────────────┴───────┴───────────────────────┴──────────────┘

  Each RDP session: 2 packets sent, 3 packets received, ~857 bytes total, ~2 ms. This byte profile (134 B → 723 B response) is consistent with an RDP X.224 Connection Request → Server
  Confirm exchange — i.e., a connection was negotiated to the RDP layer but no further authentication completed. Source ports increment sequentially (39458, 39460, 39462 … 39476+),
  indicating automated tooling.

  Other internal conversations:
  - 10.42.85.115:50623/50624 → 104.111.89.205:443 — likely Akamai CDN (TLS)
  - 10.42.85.115:50626 → 72.21.81.240:80 — likely Microsoft
  - 52.230.222.68:443 → 10.42.85.115:49809 — inbound TLS from Azure IP (259 bytes, could be push notification)

  ---
  Suspicious Indicators

  1. 194.61.24.102 — 293 sequential rapid RDP sessions to 10.42.85.10:3389
  — Sequential source ports, ~2 ms duration, automated pattern — textbook RDP scanning or credential brute-force tooling.
  2. 194.61.24.102 as HTTP Host header (×5)
  — At least 5 HTTP requests used this IP as the Host value, implying an internal host made outbound HTTP contact directly to this external IP.
  3. 10.90.90.90 as top A-record answer (338 responses)
  — An internal RFC-1918 address appearing as the resolution answer for a large number of queries (far exceeding any other A-record). o.ss2.us (Symantec OCSP) was directed there in
  HTTP traffic. This IP may be intercepting or hijacking DNS responses.
  4. xioorhri.C137.local DNS query at capture start
  — Random-looking hostname with no meaning, queried internally. Returned NXDOMAIN.
  5. WPAD — 192 unqualified queries
  — High volume of WPAD lookups. If an attacker can respond to these (WPAD poisoning via NBNS/LLMNR), they can MITM all proxy-aware traffic.

  ---
  Hypotheses (speculative — requires validation)

  H1 [HIGH CONFIDENCE]: External RDP scan/brute-force in progress
  194.61.24.102 ran an automated RDP connection tool against 10.42.85.10:3389. The sequential port increments and consistent 2 ms session durations match tools like Hydra, Medusa, or a
   custom scanner performing RDP negotiation probes. Target is the domain controller's (or a server's) RDP port.

  H2 [MEDIUM CONFIDENCE]: Possible prior compromise of 10.42.85.115 or C2 beaconing
  The HTTP Host: 194.61.24.102 entries (×5) suggest 10.42.85.115 (the workstation) reached out to the attacker IP over HTTP. If confirmed, this could indicate a reverse-shell callback
  or dropper checking in — though it could also be a browser artifact if the user visited a page that included that IP.

  H3 [MEDIUM CONFIDENCE]: DNS sinkhole or intercepting device at 10.90.90.90
  The volume (338 A-record responses) and routing of o.ss2.us OCSP traffic to an internal IP suggests 10.90.90.90 is either a legitimate corporate DNS sinkhole/proxy or has been placed
   there by an attacker to intercept or redirect traffic. Verify whether this IP is a known asset (e.g., Palo Alto DNS sinkhole, Blue Coat proxy).

  H4 [LOW-MEDIUM CONFIDENCE]: Early-stage reconnaissance or lateral movement by malware on 10.42.85.115
  The xioorhri.C137.local DNS query (random-looking, at capture start) combined with the WPAD flood could indicate an enumerating payload on the workstation probing the network before
  escalating. Random short-name DNS queries are a known pattern in malware enumeration and DGA fallback behavior.

  ---
  Suggested Next Investigation Steps

  1. Pivot on 194.61.24.102
    - WHOIS / threat-intel lookup (VirusTotal, Shodan, AbuseIPDB).
    - Extract all full packet detail for 194.61.24.102 sessions with pcap_extract_fields using ip.addr == 194.61.24.102.
    - Check whether any RDP sessions completed (full auth exchange) by looking for rdp protocol fields or TLS ClientHello packets in those sessions.
  2. Confirm or rule out outbound HTTP to 194.61.24.102
    - Filter http.host == "194.61.24.102" and capture ip.src, ip.dst, http.request.uri to see which internal host initiated contact, what URI was requested, and the direction.
  3. Investigate 10.90.90.90
    - Determine if this is a known asset (check DHCP/IPAM, firewall configs).
    - Enumerate all distinct domain names that resolved to it via pcap_extract_fields with dns.a == "10.90.90.90" and field dns.qry.name.
    - If unknown, treat as potential rogue/compromised DNS forwarder.
  4. Examine xioorhri.C137.local query source
    - Use pcap_extract_fields to find what process/host generated this query and whether similar random-name queries appear elsewhere in the capture.
  5. WPAD exposure check
    - Determine if any host responded to wpad or wpad.C137.local queries (check for positive DNS A responses or NBNS/LLMNR responses to wpad).
    - If no internal WPAD server exists, this traffic is a WPAD poisoning attack surface.
  6. Run Suricata alerts (suricata_alerts) against this case to surface any signature matches on the 194.61.24.102 RDP sessions, DNS anomalies, or HTTP beaconing.
  7. Extract TLS SNI fields for traffic from/to 10.42.85.115 to enumerate all HTTPS destinations — the current view only shows HTTP plaintext hosts and OCSP; encrypted sessions may
  reveal additional C2 or exfil infrastructure.
