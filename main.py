"""
main.py — Entry Point
======================
Orchestrates the full scan workflow:
  CLI args → Scanner → Parser → Reporter (terminal + optional file export)
"""

import logging
import sys
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

# Local modules
import cli
import scanner
import parser
import reporter

# ---------------------------------------------------------------------------
# Logging — write to both terminal (WARNING+) and a rotating file (DEBUG+)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.WARNING,                   # console: warnings and above only
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Optional: uncomment to also log everything to a file
# _file_handler = logging.FileHandler("recon_tool.log")
# _file_handler.setLevel(logging.DEBUG)
# logging.getLogger().addHandler(_file_handler)

console = Console(highlight=False)


# ---------------------------------------------------------------------------
# ASCII banner
# ---------------------------------------------------------------------------

BANNER = r"""
 ____                          _____           _
|  _ \ ___  ___ ___  _ __    |_   _|__   ___ | |
| |_) / _ \/ __/ _ \| '_ \    | |/ _ \ / _ \| |
|  _ <  __/ (_| (_) | | | |   | | (_) | (_) | |
|_| \_\___|\___\___/|_| |_|   |_|\___/ \___/|_|

     Automated Network Recon & Asset Monitor
     ─────────────────────────────────────────
     For authorized use on permitted targets only.
"""


def print_banner() -> None:
    panel = Panel(
        Text(BANNER, style="bold green", justify="center"),
        box=box.DOUBLE_EDGE,
        border_style="bright_black",
        padding=(0, 2),
    )
    console.print(panel)


# ---------------------------------------------------------------------------
# Main workflow
# ---------------------------------------------------------------------------

def main() -> None:
    print_banner()

    # ------------------------------------------------------------------ #
    # 1. Parse & validate CLI arguments                                    #
    # ------------------------------------------------------------------ #
    args = cli.parse_args()

    console.print(
        f"  [dim]Target     :[/dim]  [bold cyan]{args.target}[/bold cyan]\n"
        f"  [dim]Scan Type  :[/dim]  [bold white]{args.scan_type}[/bold white]\n"
        f"  [dim]Output     :[/dim]  [bold white]{args.output or 'terminal only'}[/bold white]\n"
        f"  [dim]Timeout    :[/dim]  [bold white]{args.timeout}s[/bold white]\n"
    )

    # ------------------------------------------------------------------ #
    # 2. Run Nmap — show a spinner while waiting                           #
    # ------------------------------------------------------------------ #
    raw_output: str = ""

    with console.status(
        f"[bold green]Scanning [cyan]{args.target}[/cyan] "
        f"\\[{args.scan_type}] …[/bold green]",
        spinner="dots",
        spinner_style="bold green",
    ):
        try:
            scan_result = scanner.run_scan_from_args(args)
            raw_output = scan_result.stdout
        except scanner.NmapNotFoundError as exc:
            console.print(f"\n  [bold red]✖  {exc}[/bold red]\n")
            sys.exit(1)
        except scanner.ScanTimeoutError as exc:
            console.print(f"\n  [bold yellow]⏱  {exc}[/bold yellow]\n")
            sys.exit(1)
        except scanner.ScanError as exc:
            console.print(f"\n  [bold red]✖  {exc}[/bold red]\n")
            sys.exit(1)

    console.print("  [bold green]✔[/bold green]  Scan complete.\n")

    # ------------------------------------------------------------------ #
    # 3. Parse raw output → structured data                                #
    # ------------------------------------------------------------------ #
    scan_data = parser.parse_nmap_output(raw_output)

    # ------------------------------------------------------------------ #
    # 4. Render terminal table                                             #
    # ------------------------------------------------------------------ #
    reporter.render_table(scan_data)

    # ------------------------------------------------------------------ #
    # 5. Export to file if requested                                       #
    # ------------------------------------------------------------------ #
    if args.output:
        reporter.export_report(
            scan_data=scan_data,
            fmt=args.output,
            target=args.target,
        )

    # ------------------------------------------------------------------ #
    # Phase-2 placeholder: state comparison                                #
    # ------------------------------------------------------------------ #
    # from pathlib import Path
    # import json
    # latest_report = Path("reports") / "latest.json"
    # if latest_report.exists():
    #     previous = json.loads(latest_report.read_text())
    #     diff = parser.diff_scans(previous, scan_data)
    #     reporter.render_diff(diff)   # TODO in Phase 2


if __name__ == "__main__":
    main()
