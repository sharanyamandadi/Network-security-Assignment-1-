#!/usr/bin/env python3
# server.py — simple async TCP test server (use to expose known-open ports)
import argparse, asyncio

async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        writer.write(b"hello\r\n")
        await writer.drain()
    except Exception:
        pass
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

async def main():
    ap = argparse.ArgumentParser(description="Tiny TCP server for testing scanners.")
    ap.add_argument("--ports", default="9999", help="Comma-separated list of ports to listen on (default 9999)")
    ap.add_argument("--host", default="0.0.0.0", help="Bind address (default 0.0.0.0)")
    args = ap.parse_args()

    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    servers = []
    for p in ports:
        srv = await asyncio.start_server(handle, args.host, p)
        servers.append(srv)
        sock = next(iter(srv.sockets), None)
        bind = sock.getsockname() if sock else (args.host, p)
        print(f"[listening] {bind}")

    try:
        await asyncio.gather(*[s.serve_forever() for s in servers])
    except asyncio.CancelledError:
        pass

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
