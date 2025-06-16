#!/usr/bin/env python3

import nmap
import argparse
from datetime import datetime

def scan(target, ports, output):
    nm = nmap.PortScanner()
    print(f"[+] Starting Nmap scan on {target} (ports: {ports})...")
    nm.scan(hosts=target, ports=ports, arguments='-T4')

    with open(output, "w") as report:
        report.write(f"Nmap Scan Report for {target}\n")
        report.write(f"Scan Time: {datetime.now()}\n")
        report.write("="*60 + "\n")
        for host in nm.all_hosts():
            report.write(f"Host: {host} ({nm[host].hostname()})\n")
            report.write(f"State: {nm[host].state()}\n")
            for proto in nm[host].all_protocols():
                report.write(f"Protocol: {proto}\n")
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    state = nm[host][proto][port]['state']
                    name = nm[host][proto][port]['name']
                    report.write(f"  Port: {port}\tState: {state}\tService: {name}\n")
            report.write("\n")
    print(f"[+] Scan completed. Results saved to {output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nmap Scanner Script")
    parser.add_argument("target", help="IP or domain to scan")
    parser.add_argument("-p", "--ports", default="1-1000", help="Ports to scan (default: 1-1000)")
    parser.add_argument("-o", "--output", default="scan_report.txt", help="Output file name")
    args = parser.parse_args()

    scan(args.target, args.ports, args.output)
