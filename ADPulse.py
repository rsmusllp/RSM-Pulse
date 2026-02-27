#!/usr/bin/env python3
"""
AD Security Scanner - Entry Point
Usage:
    python -m ad_scanner --domain corp.local --user admin --password P@ssw0rd
    python -m ad_scanner --domain corp.local --user admin --password P@ssw0rd --dc-ip 10.0.0.1
    python -m ad_scanner --domain corp.local --user admin --password P@ssw0rd --report all
"""
import argparse, sys, datetime
from pathlib import Path
from connector import ADConnector, resolve_dc
from checks import run_all_checks
from models import ScanResult
from report import print_report, export_json, export_html

def main():
    parser = argparse.ArgumentParser(description="Open-Source Active Directory Security Scanner")
    parser.add_argument("--domain",     required=True, help="Target AD domain (e.g. corp.local)")
    parser.add_argument("--user",       required=True, help="Username")
    parser.add_argument("--password",   required=True, help="Password")
    parser.add_argument("--dc-ip",      help="Domain Controller IP (auto-resolved if omitted)")
    parser.add_argument("--report",     choices=["console","json","html","all"], default="all")
    parser.add_argument("--output-dir", default=".", help="Parent directory for the Reports folder (default: current directory)")
    parser.add_argument("--no-color",   action="store_true", help="Disable color output")
    args = parser.parse_args()

    try:
        from colorama import init as cinit
        cinit(autoreset=True, strip=args.no_color)
    except ImportError:
        pass

    print("╔═══════════════════════════════════════════╗")
    print("║ ADPulse Active Directory Security Scanner ║")
    print("║                version 1.0                ║")
    print("║                by TheMayor                ║")
    print("╚═══════════════════════════════════════════╝\n")

    dc_ip = args.dc_ip or resolve_dc(args.domain)
    if not dc_ip:
        print("[!] Could not resolve DC. Use --dc-ip.")
        sys.exit(1)
    print(f"[+] Domain Controller : {dc_ip}")

    ad = ADConnector(dc_ip, args.domain, args.user, args.password)
    if not ad.connect():
        sys.exit(1)
    print(f"[+] LDAP bind successful\n")

    findings, stats = run_all_checks(ad)

    result = ScanResult(
        domain=args.domain,
        scan_time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        dc_ip=dc_ip,
        findings=findings,
        stats=stats
    )

    out = Path(args.output_dir) / "Reports"
    out.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dn = args.domain

    if args.report in ("console","all"): print_report(result)
    if args.report in ("json","all"):    export_json(result, str(out / f"ad_scan_{dn}_{ts}.json"))
    if args.report in ("html","all"):    export_html(result, str(out / f"ad_scan_{dn}_{ts}.html"))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user (Ctrl+C). Exiting.")
        sys.exit(130)