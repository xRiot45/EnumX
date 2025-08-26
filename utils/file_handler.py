import csv
import json
from utils.logger import Logger

logger = Logger()


def save_results(results, filename, format_type="json"):
    all_subdomains = []
    for module_name, data in results.items():
        if isinstance(data, dict) and "subdomains" in data:
            all_subdomains.extend(data["subdomains"])

    if format_type == "json":
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
        logger.info(f"Results saved to {filename} in JSON format.")

    elif format_type == "csv":
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["subdomain", "ip"])
            for entry in all_subdomains:
                writer.writerow([entry["subdomain"], entry["ip"]])
        logger.info(f"Results saved as CSV → {filename}")

    elif format_type == "txt":
        with open(filename, "w") as f:
            for entry in all_subdomains:
                f.write(f"{entry['subdomain']} → {entry['ip']}\n")
        logger.info(f"Results saved as TXT → {filename}")

    else:
        logger.error(f"Unsupported format: {format_type}")
