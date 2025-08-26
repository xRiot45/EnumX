import csv
import json
import os

from utils.logger import Logger

logger = Logger()


def save_results(results, filename, format_type="json"):
    all_subdomains = []
    for module_name, data in results.items():
        if isinstance(data, dict) and "subdomains" in data:
            all_subdomains.extend(data["subdomains"])
    
    os.makedirs("output", exist_ok=True)
    folder_map = {
        "json" : "output/json",
        "csv"  : "output/csv",
        "txt"  : "output/txt"
    }
    
    folder = folder_map.get(format_type)
    if not folder:
        logger.error(f"Unsupported format: {format_type}")
        return
    
    os.makedirs(folder, exist_ok=True)
    filepath = os.path.join(folder, filename)

    if format_type == "json":
        with open(filepath, "w") as f:
            json.dump(results, f, indent=4)
        logger.info(f"Results saved to {filepath} in JSON format.")

    elif format_type == "csv":
        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["subdomain", "ip"])
            for entry in all_subdomains:
                writer.writerow([entry["subdomain"], entry["ip"]])
        logger.info(f"Results saved as CSV → {filepath}")

    elif format_type == "txt":
        with open(filepath, "w") as f:
            for entry in all_subdomains:
                f.write(f"{entry['subdomain']} → {entry['ip']}\n")
        logger.info(f"Results saved as TXT → {filepath}")

    else:
        logger.error(f"Unsupported format: {format_type}")
