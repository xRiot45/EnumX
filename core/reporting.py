import json

class Reporter:
    @staticmethod
    def save(results, output_file: str):
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=1)
        print(f"[+] Results saved to {output_file}")