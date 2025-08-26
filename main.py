#!/usr/bin/env python3
import argparse

from core.controller import Controller


def main():
    parser = argparse.ArgumentParser(
        description="ReconX - Hybrid Web Enumeration Tool"
    )
    parser.add_argument(
        "target",
        help="Target domain to enumerate"
    )
    parser.add_argument(
        "-m", "--modules",
        nargs="+",
        choices=["dns"],
        default=["dns"],
        help="Select modules to run (default: dns)"
    )
    parser.add_argument(
        "-o", "--output",
        default="results.json",
        help="Output file name (default: results.json)"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of threads for enumeration (default: 10)"
    )
    parser.add_argument(
        "-w", "--wordlist",
        help="Custom wordlist file for subdomain enumeration"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["json", "csv", "txt"],
        default="json",
        help="Output format: 'json', 'csv', or 'txt' (default: json)"
    )

    args = parser.parse_args()
    controller = Controller(args)
    controller.run()

if __name__ == "__main__":
    main()
