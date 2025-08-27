#!/usr/bin/env python3
import argparse

from core.controller import Controller


class CustomHelpFormatter(argparse.RawTextHelpFormatter):
    def _format_action_invocation(self, action):
        if not action.option_strings:
            return super()._format_action_invocation(action)
        return ", ".join(action.option_strings) + (" <{}>".format(action.metavar) if action.metavar else "")


def main():
    ALL_DNS_RECORDS = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "CNAME",
        "TXT",
        "SOA",
        "PTR",
        "SRV",
        "CAA",
        "DNSKEY",
        "RRSIG",
    ]

    parser = argparse.ArgumentParser(
        prog="ReconX",
        description="ReconX - Hybrid Web Enumeration Tool",
        formatter_class=CustomHelpFormatter,
        add_help=False,
        usage=argparse.SUPPRESS,
        epilog=(
            "Examples:\n"
            "  ReconX example.com -m dns\n"
            "  ReconX target.com -m dns --dns-records A MX NS -o result.json -f json\n"
            "  ReconX target.com -m dns --dns-records all -o result.txt -f txt\n"
            "  ReconX site.com -m dns --threads 20 -w wordlist.txt\n"
            "  ReconX target.com -m banner\n"
            "  ReconX target.com -m endpoint\n"
            "  ReconX target.com -m ldap-smtp\n"
            "  ReconX target.com -m smb-ftp\n"
        ),
    )

    # --- TARGET SPECIFICATION ---
    target_group = parser.add_argument_group("TARGET SPECIFICATION")
    target_group.add_argument("target", help="Target domain to enumerate (e.g. example.com)")
    target_group.add_argument("-w", "--wordlist", help="Custom wordlist file for subdomain enumeration")

    # --- MODULES ---
    module_group = parser.add_argument_group("MODULE SELECTION")
    module_group.add_argument(
        "-m",
        "--modules",
        nargs="+",
        choices=["dns", "banner", "endpoint", "ldap-smtp", "smb-ftp"],
        default=["dns"],
        help=(
            "Modules to run (default: dns)\n"
            "  dns        : DNS Enumeration\n"
            "  banner     : Banner Enumeration (coming soon)\n"
            "  endpoint   : Endpoint Enumeration (coming soon)\n"
            "  ldap-smtp  : LDAP & SMTP Enumeration (coming soon)\n"
            "  smb-ftp    : SMB & FTP Enumeration (coming soon)"
        ),
    )
    module_group.add_argument(
        "--dns-records",
        nargs="+",
        default=["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA", "PTR"],
        help=(
            "DNS record types to enumerate (default: all)\n"
            "  Examples:\n"
            "    --dns-records A MX TXT\n"
            "    --dns-records A,MX,TXT\n"
            "    --dns-records all   (for all record types)"
        ),
    )

    # --- PERFORMANCE ---
    perf_group = parser.add_argument_group("PERFORMANCE")
    perf_group.add_argument(
        "-t",
        "--threads",
        type=int,
        default=10,
        help="Number of threads for enumeration (default: 10)",
    )

    # --- OUTPUT ---
    output_group = parser.add_argument_group("OUTPUT")
    output_group.add_argument(
        "-o",
        "--output",
        default="results.json",
        help="Output file name (default: results.json)",
    )
    output_group.add_argument(
        "-f",
        "--format",
        choices=["json", "csv", "txt", "xlsx"],
        default="json",
        help="Output format: json, csv, txt, xlsx (default: json)",
    )

    # --- LOGGING ---
    log_group = parser.add_argument_group("LOGGING")
    log_group.add_argument("--verbose", action="store_true", help="Enable verbose output (show detailded process logs)")
    log_group.add_argument(
        "--silent", action="store_true", help="Silent mode (suppress console output, only save to file)"
    )

    # --- MISC ---
    misc_group = parser.add_argument_group("MISC")
    misc_group.add_argument("-h", "--help", action="help", help="Show this help message and exit")

    args = parser.parse_args()

    # --- Normalize dns-records ---
    normalized_records = []
    for rec in args.dns_records:
        for r in rec.split(","):
            r = r.strip().upper()
            if r == "ALL":
                normalized_records.extend(ALL_DNS_RECORDS)
            elif r:
                normalized_records.append(r)

    # remove duplicate
    args.dns_records = sorted(set(normalized_records))

    # --- Module dispatcher ---
    for mod in args.modules:
        if mod != "dns":
            print(f"[!] Module '{mod}' is coming soon...")

    controller = Controller(args)
    controller.run()


if __name__ == "__main__":
    main()
