import csv
import json
import os

from utils.logger import Logger

logger = Logger()


class DNSHandler:
    @staticmethod
    def save(results, filepath, format_type="json"):
        subdomains = results.get("subdomains", [])

        if format_type == "json":
            with open(filepath, "w") as f:
                json.dump(results, f, indent=4)
            logger.info(f"[DNS] Saved JSON → {filepath}")

        elif format_type == "csv":
            with open(filepath, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Subdomain", "Record Type", "Class", "TTL", "Record Value"])
                for entry in subdomains:
                    sub = entry["subdomain"]
                    for rtype, values in entry.get("records", {}).items():
                        for val in values:
                            writer.writerow(
                                [sub, rtype, val.get("class", "IN"), val.get("ttl", ""), val.get("value", "")]
                            )
            logger.info(f"[DNS] Saved CSV → {filepath}")

        elif format_type == "txt":
            with open(filepath, "w") as f:
                for entry in subdomains:
                    f.write(f"{entry['subdomain']}\n")
                    for rtype, values in entry.get("records", {}).items():
                        for val in values:
                            f.write(f"  {rtype} {val.get('class','IN')} {val.get('ttl','')} → {val.get('value','')}\n")
            logger.info(f"[DNS] Saved TXT → {filepath}")
