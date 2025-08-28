# EnumX – Advanced Enumeration Toolkit

## 📖 Overview

**EnumX** is a modular enumeration toolkit designed for penetration testers, bug bounty hunters, and security researchers. The tool focuses on extracting valuable reconnaissance information from different network and application services. EnumX is built with scalability, modularity, and extensibility in mind, so that each module can be developed independently and combined into a single framework.

Currently, the toolkit supports **DNS Enumeration**, while other modules are under development. It also provides flexible result export formats to make it easier for researchers to analyze and share findings.

---

## ✨ Features

### Implemented Modules

* **DNS Enumeration**

  * Subdomain brute-forcing with wordlists
  * Multiple DNS record types supported (`A`, `AAAA`, `MX`, `NS`, `CNAME`, `TXT`, `SOA`, `PTR`, `SRV`, `CAA`, `DNSKEY`, `RRSIG`)
  * AXFR (Zone Transfer) checks
  * Wildcard DNS detection
  * DNSSEC information gathering
  * Passive enumeration integration (via external APIs)

### Upcoming Modules

* **Banner Enumeration** (Coming Soon)

  * Extracts banners from open ports (HTTP, SSH, FTP, SMTP, etc.)
* **Endpoint Enumeration** (Coming Soon)

  * Discovers hidden endpoints and paths for web applications
* **LDAP/SMTP Enumeration** (Coming Soon)

  * Enumerates LDAP users and SMTP VRFY checks
* **SMB/FTP Enumeration** (Coming Soon)

  * Enumerates SMB shares and FTP directories

### Output Formats

EnumX supports multiple output formats for flexibility in analysis:

* **JSON** → Structured, machine-readable
* **CSV** → Spreadsheet-friendly with grouped results
* **XLSX** → Enhanced Excel output with merged cells for clarity
* **TXT** → Readable text format for quick review

---

## 🚀 Installation

### Prerequisites

* Python **3.9+**
* Git
* Recommended OS: **Linux / macOS** (Windows supported with minor adjustments)

### Clone Repository

```bash
git clone https://github.com/yourusername/EnumX.git
cd EnumX
```

### Install Requirements

```bash
pip install -r requirements.txt
```

### Optional: Formatter Setup

The project uses a **Shell script** to run formatters (Black, isort, flake8). To format the codebase:

```bash
bash prettier.sh
```

---

## 🧪 Using a Virtual Environment (venv)

Creating a virtual environment keeps EnumX and its dependencies isolated from your system Python. The commands below assume you are in the project root (the folder that contains `requirements.txt`).

### macOS / Linux

```bash
# Create venv in a local folder named .venv
python3 -m venv .venv

# Activate the environment
source .venv/bin/activate

# Upgrade pip and install dependencies
python -m pip install --upgrade pip wheel
pip install -r requirements.txt

# (Optional) verify
python -V
pip -V
pip list
```

### Windows (PowerShell)

```powershell
# Create venv
py -3 -m venv .venv

# Activate the environment (note the leading &)
& .venv\\Scripts\\Activate.ps1

# Upgrade pip and install dependencies
python -m pip install --upgrade pip wheel
pip install -r requirements.txt
```

### Windows (cmd.exe)

```cmd
py -3 -m venv .venv
.venv\\Scripts\\activate.bat
python -m pip install --upgrade pip wheel
pip install -r requirements.txt
```

### Running EnumX inside venv

```bash
python3 main.py <target> [-w WORDLIST] [-m MODULES] [-F FILTER] [-t THREADS] [-o OUTPUT] [-f FORMAT] [-v VERBOSE | -s SILENT]
```

### Deactivate when you are done

```bash
deactivate
```

### Tips

* Keep the venv inside the repository (e.g., `.venv/`) and **do not commit it**. Add to `.gitignore`:

  ```gitignore
  .venv/
  output/
  .env
  __pycache__/
  ```
* If you need to pin exact versions used in your environment:

  ```bash
  pip freeze > requirements.lock.txt
  ```

## ⚙️ Usage

### Basic DNS Enumeration

```bash
python3 main.py google.com -w wordlists/wordlist-1.txt -m dns -F A -t 50 -o google-result -f all -v
```

#### Arguments

* `-m` → Module to run (e.g., `dns`)
* `-t` → Number of threads (default: 10)
* `-w` → Wordlist for subdomains
* `-F` → Filter options for the selected module
* `-v` → Enable verbose output (show detailed process logs)
* `-s` → Silent mode (suppress console output, only save to file)
* `<target>` → Domain or host to enumerate
* `<output>` → Output file (format inferred from extension)

#### Output Example (TXT)

```
mail.example.com
  A IN 300 → 192.0.2.10
  MX IN 600 → mail.example.com.
  TXT IN 3600 → "v=spf1 include:_spf.example.com ~all"
```

#### Output Example (CSV)

| Subdomain        | Record Type | Class | TTL  | Record Value       |
| ---------------- | ----------- | ----- | ---- | ------------------ |
| mail.example.com | A           | IN    | 300  | 192.0.2.10         |
|                  | MX          | IN    | 600  | mail.example.com.  |
|                  | TXT         | IN    | 3600 | v=spf1 include:... |

---

## 📂 Project Structure

```
EnumX/
├── main.py                 # CLI entry point
├── modules/                # Enumeration modules
│   └── dns_enum.py         # DNS Enumeration module
├── utils/                  # Helper utilities
│   ├── logger.py           # Logging system
│   └── wordlist.py/        # Load wordlist
├── output/                 # Results will be saved here
│   ├── json/
│   ├── csv/
│   ├── xlsx/
│   └── txt/
├── wordlists/              # Wordlists for brute force
├── requirements.txt        # Python dependencies
└── formatter.sh            # Code formatter script
```

---

## 🔧 Technology Stack

* **Python** → Core programming language
* **dnspython** → DNS queries & resolution
* **openpyxl** → XLSX export support
* **csv/json** (stdlib) → For CSV and JSON handling
* **Shell (Bash)** → For formatting automation

---

## 🛡️ Security Notes

* Zone transfer attempts are performed passively (failures are safe).
* Use responsibly and only against targets you have explicit permission to test.
* EnumX is built for **educational and authorized security testing purposes only**.

---

## 📌 Roadmap

* [x] DNS Enumeration
* [ ] Banner Enumeration
* [ ] Endpoint Enumeration
* [ ] LDAP/SMTP Enumeration
* [ ] SMB/FTP Enumeration
* [ ] Integration with Shodan, Censys, SecurityTrails APIs
* [ ] Improved visualization dashboards (HTML reports)

---

## 🤝 Contribution

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a new feature branch
3. Submit a pull request with clear explanations

---

## 📜 License

This project is licensed under the **MIT License**. See `LICENSE` for details.

---

## 🧑‍💻 Author

Developed by **xRiot45**.

---

## 🔗 Disclaimer

EnumX is intended **for legal security testing and research only**. The author is **not responsible** for any misuse of this tool against unauthorized systems.
