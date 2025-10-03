#!/usr/bin/env python3
import argparse, time, threading, sys, random
from typing import Optional, List, Set
from scapy.all import IP, TCP, ARP, AsyncSniffer, send, conf

conf.verb = 0
try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

# ---------- helpers ----------
def paced(rate):
    period = 1.0 / max(1, rate)
    nxt = time.monotonic()
    while True:
        now = time.monotonic()
        if now < nxt:
            time.sleep(nxt - now)
        yield
        nxt += period

def arp_claim_loop(ips: List[str], stop_evt: threading.Event, period=6):
    def burst():
        for ip in ips:
            send(ARP(op=2, psrc=ip, pdst=ip, hwdst="ff:ff:ff:ff:ff:ff"), count=3, inter=0.25, verbose=0)
    while not stop_evt.is_set():
        burst()
        stop_evt.wait(period)

def print_rate(prefix, done, total, t0):
    elapsed = max(1e-6, time.monotonic() - t0)
    rate = done / elapsed
    eta = (total - done) / rate if rate > 0 else float("inf")
    print(f"{prefix} {done}/{total}  rate={rate:.1f}/s  eta={eta:.1f}s", flush=True)

# ---------- FIN sweep ----------
def fin_sweep(target, ports, helpers, fin_src_port, fin_per_helper, tail_wait, iface=None):
    if iface: conf.iface = iface
    closed: Set[int] = set()
    seen: Set[int] = set()
    lock = threading.Lock()
    bpf = f"tcp and src host {target} and tcp dst port {fin_src_port} and tcp[13] & 0x04 != 0"
    def on(pkt):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP): return
        dport = int(pkt[TCP].sport)
        with lock:
            if dport in seen: return
            seen.add(dport); closed.add(dport)

    sniffer = AsyncSniffer(filter=bpf, prn=on, store=False, iface=iface); sniffer.start(); time.sleep(0.05)

    stop_arp = threading.Event()
    if helpers:
        threading.Thread(target=arp_claim_loop, args=(helpers, stop_arp, 6), daemon=True).start()
        time.sleep(0.5)

    work = ports[:]; random.shuffle(work)
    helpers_list = helpers or ["single"]
    tokens = {h: paced(fin_per_helper) for h in helpers_list}
    idx = 0; sent = 0; total = len(work); t0 = time.monotonic()

    try:
        while work:
            h = helpers_list[idx % len(helpers_list)]; idx += 1
            next(tokens[h])
            dport = work.pop()
            ip = IP(dst=target)
            if helpers: ip.src = h
            send(ip/TCP(sport=fin_src_port, dport=dport, flags="F"), verbose=0) #first sends tcp packets with only FIN flag set
            sent += 1
            if sent % 2000 == 0: print_rate("[FIN] sent", sent, total, t0)
        if tail_wait > 0: time.sleep(tail_wait)
    finally:
        try: sniffer.stop()
        except: pass
        stop_arp.set()

    candidates = set(ports) - closed
    print(f"[FIN] done: closed={len(closed)}, candidates(open|filtered)={len(candidates)}, time={time.monotonic()-t0:.1f}s")
    return closed, candidates
# ---------- SYN verify (with helpers too) ----------
def syn_verify(target, candidates, helpers, syn_src_port, syn_per_helper, tail_wait, iface=None, max_seconds=None):
    if iface: conf.iface = iface
    opens: Set[int] = set()
    seen: Set[int] = set()
    lock = threading.Lock()

    bpf = f"tcp and src host {target} and tcp dst port {syn_src_port} and tcp[13] & 0x12 == 0x12"
    def on(pkt):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP): return
        tcp = pkt[TCP]; dport = int(tcp.sport)
        with lock:
            if dport in seen: return
            seen.add(dport); opens.add(dport)
        # polite RST
        try:
            send(IP(dst=target)/TCP(sport=syn_src_port, dport=dport, flags="R",
                                    seq=tcp.ack, ack=tcp.seq+1), verbose=0)
        except: pass

    sniffer = AsyncSniffer(filter=bpf, prn=on, store=False, iface=iface); sniffer.start(); time.sleep(0.05)

    cand = list(candidates); random.shuffle(cand)
    helpers_list = helpers or ["single"]
    tokens = {h: paced(syn_per_helper) for h in helpers_list}
    idx = 0; sent = 0; total = len(cand); t0 = time.monotonic()

    try:
        for dport in cand:
            if max_seconds and (time.monotonic()-t0) > max_seconds:
                print("[SYN] stopping due to --max-seconds", flush=True); break
            h = helpers_list[idx % len(helpers_list)]; idx += 1
            next(tokens[h])
            ip = IP(dst=target)
            if helpers: ip.src = h
            send(ip/TCP(sport=syn_src_port, dport=dport, flags="S"), verbose=0)
            sent += 1
            if sent % 1000 == 0: print_rate("[SYN] sent", sent, total, t0)
        if tail_wait > 0: time.sleep(tail_wait)
    finally:
        try: sniffer.stop()
        except: pass

    print(f"[SYN] verify done: open={len(opens)}, time={time.monotonic()-t0:.1f}s")
    return opens

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description="FIN sweep + helper-accelerated SYN verify (single node, <300s)")
    ap.add_argument("target")
    ap.add_argument("--start-port", type=int, default=1)
    ap.add_argument("--end-port", type=int, default=65535)
    ap.add_argument("--iface", default=None)
    ap.add_argument("--tail-wait", type=float, default=3.0)
    ap.add_argument("--max-seconds", type=float, default=None, help="optional cap for SYN verify runtime")
    ap.add_argument("--helpers", type=str, default="")

    # FIN
    ap.add_argument("--fin-src-port", type=int, default=40000)
    ap.add_argument("--fin-per-helper", type=int, default=25)
    # SYN
    ap.add_argument("--syn-src-port", type=int, default=40001)
    ap.add_argument("--syn-per-helper", type=int, default=8, help="keep <=10 per helper (per-IP limiter)")
    ap.add_argument("--skip-verify", action="store_true")
    args = ap.parse_args()

    helpers = [h.strip() for h in args.helpers.split(",") if h.strip()]
    ports = list(range(args.start_port, args.end_port+1))

    print(f"Range {args.start_port}-{args.end_port} | ports={len(ports)}")
    print(f"Helpers: {len(helpers)} | FIN/helper={args.fin_per_helper} | SYN/helper={args.syn_per_helper}")
    print(f"FIN src={args.fin_src_port} | SYN src={args.syn_src_port} | iface={args.iface or '(auto)'}\n)

    closed, candidates = fin_sweep(
        target=args.target, ports=ports, helpers=helpers,
        fin_src_port=args.fin_src_port, fin_per_helper=args.fin_per_helper,
        tail_wait=args.tail_wait, iface=args.iface
    )
    if args.skip_verify:
        print("\n--- FIN-only Summary ---")
        print(f"Closed: {len(closed)} | Open|Filtered (candidates): {len(candidates)}")
        return
    opens = syn_verify(
        target=args.target, candidates=candidates, helpers=helpers,
        syn_src_port=args.syn_src_port, syn_per_helper=args.syn_per_helper,
        tail_wait=args.tail_wait, iface=args.iface, max_seconds=args.max_seconds
    )

    print("\n--- FINAL SUMMARY ---")
    print(f"Ports scanned: {len(ports)}")
    print(f"Open: {len(opens)}")
    print(f"Closed: {len(closed)}")
    print(f"Filtered/No response after verify: {len(candidates - opens)}")
    if opens:
        print("Open port list:", ", ".join(str(p) for p in sorted(opens)))

if _name_ == "_main_":
    main()
