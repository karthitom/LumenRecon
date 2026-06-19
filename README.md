# 💡 LumenRecon — The Network Illuminator

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-22c55e?style=for-the-badge)
![Nmap Required](https://img.shields.io/badge/Requires-Nmap-EF4444?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-No%20Shell%20Injection-06b6d4?style=for-the-badge)

> **LumenRecon acts as a light in the dark, safely illuminating hidden services and open ports within authorised networks for defensive posture assessment.**
>
> Feed it a target IP or domain. It does the rest.

---

## What is LumenRecon?

LumenRecon is a modular, terminal-first network reconnaissance tool that wraps [Nmap](https://nmap.org) in a secure, beginner-friendly interface. Where traditional recon tools leave you reading raw command output, LumenRecon illuminates the results — colour-coded, structured, and ready to export.

Built strictly for **defensive security work**: understanding your own attack surface, validating firewall rules, and monitoring asset changes over time.

---

## Features

- 💡 **The illuminator model** — strict target validation ensures only permitted, well-formed addresses ever reach the network
- 🔒 `subprocess.run(shell=False)` with a `list[str]` command — zero OS command injection surface
- ⚡ **Three scan profiles** — from a 5-second quick sweep to a full 65535-port deep dive
- 🎨 **Rich terminal UI** — animated spinner, colour-coded port table, and a formatted beginner-friendly help menu
- 📁 **JSON and CSV export** to a dedicated `reports/` directory with timestamped filenames
- 🧩 **Fully modular codebase** — `cli.py` · `scanner.py` · `parser.py` · `reporter.py` · `main.py`
- 🛡️ Custom exceptions (`NmapNotFoundError`, `ScanTimeoutError`, `ScanError`) for clean, predictable error handling
- 🔭 Phase-2 ready: `diff_scans()` and `run_scan_with_metadata()` stubs for asset change detection

---

## Project Structure

```
lumenrecon/
├── main.py          # Orchestrator & entry point
├── cli.py           # Argument parsing & strict input validation
├── scanner.py       # Nmap subprocess execution (shell=False always)
├── parser.py        # Raw nmap output → structured dicts
├── reporter.py      # Terminal table rendering & file export
├── reports/         # Auto-created — exported JSON/CSV reports land here
├── requirements.txt
└── README.md
```

---

## Requirements

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | Uses modern type hint syntax |
| Nmap | Any modern | Must be on your system `PATH` |
| rich | 13.7.1 | Installed via `requirements.txt` |

---

## Installation

### 1 — Install Nmap

LumenRecon calls nmap as an external process. Install it for your OS first.

**Linux (Debian / Ubuntu)**
```bash
sudo apt-get update && sudo apt-get install -y nmap
```

**macOS (Homebrew)**
```bash
brew install nmap
```

**Windows**
Download and run the installer from [nmap.org/download.html](https://nmap.org/download.html).
Ensure the install directory (e.g. `C:\Program Files (x86)\Nmap`) is added to your `PATH`.

Verify the installation:
```bash
nmap --version
```

---

### 2 — Clone the repository

```bash
git clone https://github.com/karthitom/lumenrecon.git
cd lumenrecon
```


---

### 3 — Create a virtual environment (recommended)

```bash
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows (cmd)
.venv\Scripts\activate.bat

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

---

### 4 — Install Python dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

### Basic syntax

```
python main.py -t <target> [options]
```

### Flags at a glance

| Flag | Required | Default | Description |
|---|---|---|---|
| `-t` / `--target` | **Yes** | — | Target IPv4 (e.g. `192.168.1.1`) or domain (e.g. `example.com`) |
| `-s` / `--scan-type` | No | `fast` | Scan profile: `fast` · `service` · `full` |
| `-o` / `--output` | No | terminal only | Export format: `json` or `csv` |
| `--timeout` | No | `300` | Max seconds to wait for the scan |
| `-h` / `--help` | No | — | Show the full LumenRecon help menu |

---

## Usage Examples

### Minimal — quick scan, terminal output only
```bash
python main.py -t 192.168.1.1
```
Illuminates the top 100 most common ports. Results are printed to the terminal. Done in seconds.

---

### Service detection on a domain
```bash
python main.py -t example.com -s service
```
Scans the top 1000 ports and detects service names and version strings (e.g. `Apache httpd 2.4.54`). Shows exactly what software is listening on each port.

---

### Full scan with JSON export
```bash
python main.py -t 10.0.0.5 -s full -o json
```
Illuminates all 65535 ports with version detection. Saves a timestamped report to `reports/scan_10_0_0_5_<timestamp>.json`.

---

### CSV export with a longer timeout
```bash
python main.py -t 10.0.0.5 -o csv --timeout 600
```
Quick scan with CSV export. The `--timeout 600` gives slow or congested networks 10 minutes to respond.

---

### View the help menu
```bash
python main.py -h
```
Displays the full LumenRecon Rich-formatted help panel — argument descriptions, usage examples, and a scan speed guide.

---

## Scan Profiles

| Profile | Nmap flags | Ports scanned | Typical speed |
|---|---|---|---|
| `fast` | `-F` | Top 100 | ~5–15 seconds |
| `service` | `-sV` | Top 1000 + version detection | ~1–5 minutes |
| `full` | `-p- -sV` | All 65535 + version detection | 10–30+ minutes |

> **Tip:** For `full` scans on slow networks, use `--timeout 1800` or higher.

---

## Output Files

When `--output json` or `--output csv` is used, files are written to the `reports/` directory with UTC-timestamped names:

```
reports/
└── scan_192_168_1_1_20250619_143022.json
└── scan_example_com_20250619_143500.csv
```

**JSON structure**
```json
{
  "host": "192.168.1.1",
  "hostname": "router.local",
  "state": "up",
  "ports": [
    {
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "service": "http",
      "version": "Apache httpd 2.4.54"
    }
  ]
}
```

**CSV columns**
```
host, hostname, host_state, port, protocol, state, service, version
```

---

## Security Design

LumenRecon is built with security-first principles at every layer:

- **No shell execution.** `subprocess.run()` is always called with `shell=False` and a `list[str]` command. The target string is a single list element — it can never be interpreted as a shell command or inject additional flags.
- **Strict input allowlisting.** Targets are validated by Python's `ipaddress` module (for IPv4) and a compiled RFC-1123 regex (for domains) before any subprocess call is made.
- **Blocked reserved ranges.** Loopback (`127.x`), unspecified (`0.0.0.0`), multicast, and link-local addresses are explicitly rejected at the CLI layer.
- **Output format constrained.** The `--output` flag only accepts the literal strings `json` or `csv` — no free-form strings ever reach the filesystem layer.
- **Minimal nmap surface.** Scan profiles use only port-enumeration flags. No OS detection (`-O`), no scripting engine (`-sC`), no brute-forcing.
- **extra_flags guard.** Any caller-supplied nmap flags must be a `list[str]` where each element starts with `-`, preventing positional-argument injection through that parameter.

---

## Ethical & Legal Notice

> **Only scan systems you own or have explicit written authorisation to test.**
>
> Unauthorised port scanning may be illegal in your jurisdiction and violates most networks' terms of service. LumenRecon is designed and intended exclusively for:
> - Scanning your own infrastructure
> - Authorised penetration testing engagements
> - Defensive security assessments and firewall validation
>
> The authors accept no liability for misuse.

---

## Roadmap (Phase 2)

- [ ] Persistent state storage — save scan history and detect asset changes between runs
- [ ] `diff_scans()` — highlight newly opened or closed ports since the last scan
- [ ] IPv6 support
- [ ] HTML report export with the LumenRecon branding
- [ ] CI/CD integration mode (non-zero exit code on newly opened ports)

---

## License

MIT — see `LICENSE` for details.
