#!/usr/bin/env python3
import argparse

from core.controller import Controller


def main():
    parser = argparse.ArgumentParser(description="ReconX - Hybrid Web Enumeration Tool")
    parser.add_argument("target", help="Target domain")
    parser.add_argument("-m", "--modules", nargs="+", choices=["dns"],
                        help="Pilih modul (default: dns)")
    parser.add_argument("-o", "--output", default="results.json", help="Output file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Jumlah threads")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file")
    args = parser.parse_args()

    controller = Controller(args)
    controller.run()

if __name__ == "__main__":
    main()
