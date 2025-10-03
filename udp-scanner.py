#!/usr/bin/env python3
from scapy.all import IP, UDP, sr1, ICMP, DNS, DNSQR
import argparse
import time

def scan_udp_port(target_ip, port, timeout=2.0, retries=3):
    """
    Send UDP probe(s) to `target_ip:port`. Retries configured to reduce false positives.
    Returns:
      - "UDP Port {port}: Open (UDP service replied)"
      - "UDP Port {port}: Open|Filtered"
      - "UDP Port {port}: ICMP type={type} code={code}"
      - None  (meaning: closed -- ICMP Port Unreachable observed; don't print)
    """
    probe_pkt = None
    # service-specific payloads
    if port == 53:
        # craft a minimal DNS query (Scapy will build correct UDP/DNS).
        probe_pkt = IP(dst=target_ip)/UDP(dport=port)/DNS(rd=1,qd=DNSQR(qname="www.google.com"))
    else:
        # small generic UDP payload
        probe_pkt = IP(dst=target_ip)/UDP(dport=port)/b"\x00"

    for attempt in range(1, retries + 1):
        resp = sr1(probe_pkt, timeout=timeout, verbose=0)
        if resp is None:
            # no response for this attempt — retry (unless last attempt)
            if attempt < retries:
                # small jitter/backoff to allow ICMPs to arrive and to avoid rate-limiting
                time.sleep(0.1 * attempt)
                continue
            else:
                return f"UDP Port {port}: Open|Filtered"
        # got a response: determine type
        if resp.haslayer(UDP):
            # UDP service replied (open)
            return f"UDP Port {port}: Open (UDP service replied)"
        elif resp.haslayer(ICMP):
            icmp_type = resp.getlayer(ICMP).type
            icmp_code = resp.getlayer(ICMP).code
            # ICMP Port Unreachable indicates closed
            if icmp_type == 3 and icmp_code == 3:
                return None  # closed -> consistent with original behaviour (do not print)
            else:
                return f"UDP Port {port}: ICMP type={icmp_type} code={icmp_code}"
        else:
            # Received some other response — treat conservatively as ambiguous/open|filtered
            return f"UDP Port {port}: Open|Filtered (unexpected reply type)"
    # fallback
    return f"UDP Port {port}: Open|Filtered"

def positive_int_min5(value: str) -> int:
    ivalue = int(value)
    if ivalue < 5:
        raise argparse.ArgumentTypeError("batch-size must be at least 5")
    return ivalue

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UDP Port Scanner using Scapy and ICMP (improved to reduce false positives)")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--start-port", type=int, default=1, help="Start port")
    parser.add_argument("--end-port", type=int, default=100, help="End port")
    parser.add_argument("--batch-size", type=positive_int_min5, default=50,
                        help="Number of ports to scan per batch (min 5)")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="Timeout in seconds for each port probe (float allowed)")
    parser.add_argument("--retries", type=int, default=3,
                        help="Number of probe retries per port to reduce false positives")
    args = parser.parse_args()

    print(f"Starting UDP scan on {args.target} from port {args.start_port} to {args.end_port}")
    print(f"Batch size: {args.batch_size}, Timeout: {args.timeout}s, Retries: {args.retries}")
    start_time = time.time()

    open_udp = 0
    filtered_udp = 0
    closed_udp = 0

    ports = list(range(args.start_port, args.end_port + 1))
    for i in range(0, len(ports), args.batch_size):
        batch = ports[i:i + args.batch_size]
        for port in batch:
            result = scan_udp_port(args.target, port, timeout=args.timeout, retries=args.retries)
            if result:
                print(result)
                if "Open (UDP service replied)" in result:
                    open_udp += 1
                elif "Open|Filtered" in result:
                    filtered_udp += 1
            else:
                closed_udp += 1

    elapsed = time.time() - start_time
    print("\n--- Scan Summary ---")
    print(f"Open UDP ports: {open_udp}")
    print(f"Open|Filtered UDP ports: {filtered_udp}")
    print(f"Closed UDP ports (ICMP replies): {closed_udp}")
    print(f"Scan finished in {elapsed:.2f} seconds.")
