#!/usr/bin/env python3
import argparse
from core.controller import Controller


class CustomHelpFormatter(argparse.RawTextHelpFormatter):
    def _format_action_invocation(self, action):
        if not action.option_strings:
            return super()._format_action_invocation(action)
        return ", ".join(action.option_strings) + (
            " <{}>".format(action.metavar) if action.metavar else ""
        )


def main():
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
            "  ReconX site.com -m dns --threads 20 -w wordlist.txt\n"
        )
    )

    # --- TARGET SPECIFICATION ---
    target_group = parser.add_argument_group("TARGET SPECIFICATION")
    target_group.add_argument(
        "target",
        help="Target domain to enumerate (e.g. example.com)"
    )
    target_group.add_argument(
        "-w", "--wordlist",
        help="Custom wordlist file for subdomain enumeration"
    )

    # --- MODULES ---
    module_group = parser.add_argument_group("MODULE SELECTION")
    module_group.add_argument(
        "-m", "--modules",
        nargs="+",
        choices=["dns"],
        default=["dns"],
        help="Modules to run (default: dns)"
    )
    module_group.add_argument(
        "--dns-records",
        nargs="+",
        choices=["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA", "PTR"],
        default=["A", "AAAA", "MX", "NS", "CNAME", "TXT"],
        help="DNS record types to enumerate (default: A, AAAA, MX, NS, CNAME, TXT)"
    )

    # --- PERFORMANCE ---
    perf_group = parser.add_argument_group("PERFORMANCE")
    perf_group.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of threads for enumeration (default: 10)"
    )

    # --- OUTPUT ---
    output_group = parser.add_argument_group("OUTPUT")
    output_group.add_argument(
        "-o", "--output",
        default="results.json",
        help="Output file name (default: results.json)"
    )
    output_group.add_argument(
        "-f", "--format",
        choices=["json", "csv", "txt"],
        default="json",
        help="Output format: json, csv, or txt (default: json)"
    )

    # --- MISC ---
    misc_group = parser.add_argument_group("MISC")
    misc_group.add_argument(
        "-h", "--help",
        action="help",
        help="Show this help message and exit"
    )

    args = parser.parse_args()
    controller = Controller(args)
    controller.run()


if __name__ == "__main__":
    main()
