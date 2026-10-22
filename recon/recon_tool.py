#!/usr/bin/env python3
"""
Attack-surface recon tool — FOR AUTHORIZED TESTING ONLY.
Use only on targets you own or have written permission to test.

Phases:
  1. Subdomain enumeration (crt.sh certificate transparency)
  2. Live host check (HTTP/HTTPS)
  3. Port scan (common ports, pure sockets, no exploit payloads)
  4. Banner grab + HTTP header/tech fingerprinting
  5. Consolidated report (JSON + console)

Usage: python recon_tool.py example.com [-o report.json] [--ports 1-1000] [--threads 50]
"""
import argparse, concurrent.futures, json, socket, ssl, sys, time
import urllib.request, urllib.error

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
                1433, 1521, 2049, 3000, 3306, 3389, 5432, 5900, 6379, 8000,
                8080, 8443, 9200, 27017]


def banner(msg):
    print(f"\n=== {msg} ===")


def get_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "recon-tool"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.load(r)
    except Exception as e:
        print(f"[warn] crt.sh lookup failed: {e}")
        return {domain}
    subs = {domain}
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lstrip("*.").lower()
            if name.endswith(domain):
                subs.add(name)
    return subs


def check_live(host):
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}", headers={"User-Agent": "recon-tool"})
            with urllib.request.urlopen(req, timeout=6) as r:
                return {
                    "scheme": scheme,
                    "status": r.status,
                    "server": r.headers.get("Server", "unknown"),
                    "headers": dict(r.headers),
                }
        except urllib.error.HTTPError as e:
            return {"scheme": scheme, "status": e.code, "server": e.headers.get("Server", "unknown") if e.headers else "unknown"}
        except Exception:
            continue
    return None


def scan_port(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            svc = guess_banner(s, port)
            return port, svc
    except Exception:
        return None


def guess_banner(sock, port):
    try:
        sock.settimeout(1.0)
        if port in (80, 8080, 8000):
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(256)
        return data.decode(errors="ignore").split("\r\n")[0].strip() or f"open:{port}"
    except Exception:
        return f"open:{port}"


def parse_port_range(spec):
    if "-" in spec:
        lo, hi = map(int, spec.split("-"))
        return list(range(lo, hi + 1))
    return COMMON_PORTS


def missing_security_headers(headers):
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    checks = ["strict-transport-security", "content-security-policy",
              "x-frame-options", "x-content-type-options"]
    return [c for c in checks if c not in headers]


def main():
    ap = argparse.ArgumentParser(description="Authorized recon only.")
    ap.add_argument("domain")
    ap.add_argument("-o", "--output", default="recon_report.json")
    ap.add_argument("--ports", default="common", help="'common' or e.g. 1-1000")
    ap.add_argument("--threads", type=int, default=50)
    ap.add_argument("--max-hosts", type=int, default=15, help="cap live-check/port-scan to top N subdomains")
    args = ap.parse_args()

    print("AUTHORIZED TESTING ONLY. Confirm you have written permission before continuing.")
    confirm = input(f"Type the domain '{args.domain}' to confirm authorization: ").strip()
    if confirm != args.domain:
        print("Confirmation mismatch. Aborting.")
        sys.exit(1)

    report = {"target": args.domain, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "hosts": {}}

    banner("Subdomain enumeration (crt.sh)")
    subs = sorted(get_subdomains(args.domain))
    print(f"Found {len(subs)} subdomains")
    for s in subs[:50]:
        print(" ", s)

    targets = subs[:args.max_hosts]
    ports = COMMON_PORTS if args.ports == "common" else parse_port_range(args.ports)

    banner("Live host check")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        live_results = dict(zip(targets, ex.map(check_live, targets)))

    for host, info in live_results.items():
        if info:
            report["hosts"].setdefault(host, {})["http"] = info
            missing = missing_security_headers(info.get("headers"))
            report["hosts"][host]["missing_security_headers"] = missing
            print(f"  {host:<35} {info['scheme']:<6} {info['status']} server={info.get('server')}")

    banner(f"Port scan ({len(ports)} ports x {len(targets)} hosts)")
    for host in targets:
        open_ports = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            futures = [ex.submit(scan_port, host, p) for p in ports]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    open_ports[res[0]] = res[1]
        if open_ports:
            report["hosts"].setdefault(host, {})["open_ports"] = open_ports
            print(f"  {host}: {open_ports}")

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    banner("Summary")
    print(f"Full report saved to {args.output}")
    print("Review 'missing_security_headers' and 'open_ports' per host for findings.")
    print("This tool does NOT exploit anything — use findings to guide manual, authorized testing.")


if __name__ == "__main__":
    main()
