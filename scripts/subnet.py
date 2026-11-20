#!/usr/bin/env python3
"""Offline IPv4 subnet helper. Does not access devices or networks."""
import argparse
import ipaddress

def main():
    p = argparse.ArgumentParser(description="Calculate IPv4 network details offline")
    p.add_argument("cidr", help="IPv4 address/prefix, e.g. 192.168.10.10/24")
    args = p.parse_args()
    try:
        net = ipaddress.ip_interface(args.cidr).network
        print(f"Network: {net.network_address}")
        print(f"Netmask: {net.netmask}")
        print(f"Broadcast: {net.broadcast_address}")
        print(f"Prefix: /{net.prefixlen}")
        print(f"Total addresses: {net.num_addresses}")
        if net.prefixlen <= 30:
            print(f"Usable hosts: {net.num_addresses - 2}")
            print(f"First host: {net.network_address + 1}")
            print(f"Last host: {net.broadcast_address - 1}")
        else:
            print("Usable hosts: point-to-point/special-case; verify design")
    except ValueError as exc:
        p.error(str(exc))

if __name__ == "__main__":
    main()
