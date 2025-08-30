#!/usr/bin/env python3
import argparse

from core.controller import Controller
from utils.logger import global_logger as logger


class CustomHelpFormatter(argparse.RawTextHelpFormatter):
    def _format_action_invocation(self, action):
        if not action.option_strings:
            return super()._format_action_invocation(action)
        return ", ".join(action.option_strings) + (" <{}>".format(action.metavar) if action.metavar else "")


def main():
    # --- Available filter options per module ---
    MODULE_FILTERS = {
        "dns": ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA", "PTR", "SRV", "CAA", "DNSKEY", "RRSIG"],
        "banner": ["http", "https", "ftp", "ssh"],
        "endpoint": ["api", "api-docs"],
        "ldap-smtp": ["ldap", "smtp"],
        "smb-ftp": ["SMB", "FTP"],
    }

    parser = argparse.ArgumentParser(
        prog="EnumX",
        formatter_class=CustomHelpFormatter,
        add_help=False,
        usage="python3 main.py <target> [-w WORDLIST] [-m MODULES] [-F FILTER] "
        "[-t THREADS] [-o OUTPUT] [-f FORMAT] [-v VERBOSE | -s SILENT]",
    )

    # --- TARGET SPECIFICATION ---
    target_group = parser.add_argument_group("TARGET SPECIFICATION")
    target_group.add_argument("target", help="Target domain to enumerate (e.g. example.com)")
    target_group.add_argument("-w", "--wordlist", help="Custom wordlist file (depends on module & filter)")

    # --- MODULES ---
    module_group = parser.add_argument_group("MODULE SELECTION")
    module_group.add_argument(
        "-m",
        "--modules",
        nargs="+",
        choices=list(MODULE_FILTERS.keys()),
        default=["dns"],
        help=(
            "Modules to run (default: dns)\n"
            "  dns        : DNS Enumeration\n"
            "  banner     : Banner Enumeration (coming soon)\n"
            "  endpoint   : Endpoint Enumeration (supports filters)\n"
            "  ldap-smtp  : LDAP & SMTP Enumeration (coming soon)\n"
            "  smb-ftp    : SMB & FTP Enumeration (coming soon)"
        ),
    )

    # --- Generate dynamic filter help ---
    filter_help_text = "Filter options for the selected module (available options per module):\n"
    for mod, options in MODULE_FILTERS.items():
        filter_help_text += f"  {mod}: {', '.join(options)}\n"
    filter_help_text += "Use -F all to select all options for the module."

    module_group.add_argument("-F", "--filter", nargs="+", help=filter_help_text)

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
        choices=["json", "csv", "txt", "xlsx", "html", "md", "all"],
        default="json",
        help="Output format: json, csv, txt, xlsx, html, md, or all (default: json)",
    )

    # --- LOGGING ---
    log_group = parser.add_argument_group("LOGGING (default: verbose)")
    log_group.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output (show detailed process logs)",
    )
    log_group.add_argument(
        "-s",
        "--silent",
        action="store_true",
        help="Silent mode (suppress console output, only save to file)",
    )

    # --- MISC ---
    misc_group = parser.add_argument_group("MISC")
    misc_group.add_argument(
        "--base-path",
        default=None,
        help="Base path prefix for endpoint enumeration (e.g. /api, /v1). Default: None",
    )
    misc_group.add_argument("-h", "--help", action="help", help="Show this help message and exit")

    args = parser.parse_args()

    # --- LOGIC HANDLING ---
    if args.verbose and args.silent:
        parser.error("Options --verbose and --silent cannot be used together")

    if args.silent:
        logger.set_level("SILENT")
    else:
        logger.set_level("DEBUG")

    # --- MODULE FILTER ---
    if getattr(args, "filter", None):
        first_module = args.modules[0]
        if first_module == "dns":
            args.filter_dns = args.filter
        elif first_module == "banner":
            args.filter_banner = args.filter
        elif first_module == "endpoint":
            args.filter_endpoint = args.filter
        elif first_module == "ldap-smtp":
            args.filter_ldap_smtp = args.filter
        elif first_module == "smb-ftp":
            args.filter_smb_ftp = args.filter

    # Normalize DNS records if dns module is selected
    if "dns" in args.modules and hasattr(args, "filter_dns"):
        ALL_DNS_RECORDS = MODULE_FILTERS["dns"]
        normalized_records = []
        for rec in args.filter_dns:
            for r in rec.split(","):
                r = r.strip().upper()
                if r == "ALL":
                    normalized_records.extend(ALL_DNS_RECORDS)
                elif r:
                    normalized_records.append(r)
        args.filter_dns = sorted(set(normalized_records))

    # Normalize Endpoint filters if endpoint module is selected
    elif "endpoint" in args.modules and hasattr(args, "filter_endpoint"):
        ALL_ENDPOINTS = MODULE_FILTERS["endpoint"]
        normalized_endpoints = []
        for ep in args.filter_endpoint:
            for e in ep.split(","):
                e = e.strip().lower()
                if e == "all":
                    normalized_endpoints.extend(ALL_ENDPOINTS)
                elif e:
                    normalized_endpoints.append(e)
        args.filter_endpoint = sorted(set(normalized_endpoints))

    for mod in args.modules:
        if mod not in ["dns", "endpoint"]:
            logger.info(f"[!] Module '{mod}' is coming soon...")

    controller = Controller(args)
    controller.run()


if __name__ == "__main__":
    main()
