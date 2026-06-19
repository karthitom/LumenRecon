"""
main.py — Orchestrator & Entry Point
======================================
Single entry point for NeonRecon.  Ties every module together in order:

    CLI args  →  Scanner  →  Parser  →  Reporter

Flow
----
    1.  Check for -h / --help → print custom Rich help menu, then exit.
    2.  Parse & validate arguments with cli.parse_args().
    3.  Print banner + scan summary header.
    4.  Run nmap via scanner.run_scan_from_args() behind a Rich spinner.
    5.  Parse raw stdout with parser.parse_nmap_output().
    6.  Render results table via reporter.render_table().
    7.  Optionally export to file via reporter.export_report().
"""

import logging
import sys

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# Local modules — all reside in the same package directory.
import cli
import parser
import reporter
import scanner

# ---------------------------------------------------------------------------
# Logging — WARNING+ to the terminal; DEBUG+ available if a file handler
# is added.  Modules emit records; we configure the root logger here only.
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Single shared console instance (no auto-highlight — we style manually).
console = Console(highlight=False)


# ---------------------------------------------------------------------------
# ASCII Banner  — cyberpunk / neon aesthetic
# ---------------------------------------------------------------------------

_BANNER = r"""
 ███╗   ██╗███████╗ ██████╗ ███╗   ██╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ████╗  ██║██╔════╝██╔═══██╗████╗  ██║    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██╔██╗ ██║█████╗  ██║   ██║██╔██╗ ██║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║╚██╗██║██╔══╝  ██║   ██║██║╚██╗██║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║ ╚████║███████╗╚██████╔╝██║ ╚████║    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
"""

_TAGLINE = (
    "⚡  Automated Network Recon & Asset Monitor  ⚡\n"
    "   [dim]For authorised use on permitted targets only.[/dim]"
)


def print_banner() -> None:
    """Render the NeonRecon ASCII banner inside a cyberpunk-style Rich panel."""
    banner_text = Text(_BANNER, style="bold bright_green", justify="center")
    tagline_text = Text.from_markup(_TAGLINE, justify="center")

    combined = Text.assemble(banner_text, "\n", tagline_text)

    panel = Panel(
        combined,
        box=box.DOUBLE_EDGE,
        border_style="bright_magenta",
        padding=(0, 2),
    )
    console.print(panel)
    console.print()


# ---------------------------------------------------------------------------
# Custom Help Menu  — replaces argparse's default -h output
# ---------------------------------------------------------------------------

def print_help() -> None:
    """
    Display a beginner-friendly Rich help panel and exit cleanly.

    Intercepted before argparse runs so we control the entire presentation.
    """
    console.print()

    # ---- Title -----------------------------------------------------------
    console.print(
        Panel(
            Text("NeonRecon — Help & Usage Guide", style="bold bright_cyan", justify="center"),
            box=box.HEAVY,
            border_style="bright_cyan",
            padding=(0, 4),
        )
    )
    console.print()

    # ---- What is this tool? ----------------------------------------------
    console.print(
        Panel(
            "[white]NeonRecon is a safe, automated network reconnaissance tool.\n"
            "It uses [bold cyan]Nmap[/bold cyan] to scan a target IP address or domain name and\n"
            "shows you which ports are open, what services are running, and\n"
            "optionally saves the results to a [bold]JSON[/bold] or [bold]CSV[/bold] file.\n\n"
            "[bold yellow]⚠  Only scan systems you own or have explicit written permission to test.[/bold yellow]",
            title="[bold magenta]What does this tool do?[/bold magenta]",
            border_style="magenta",
            padding=(1, 3),
        )
    )
    console.print()

    # ---- Arguments table -------------------------------------------------
    args_table = Table(
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold magenta",
        show_lines=True,
        expand=True,
        title="[bold magenta]Arguments[/bold magenta]",
    )

    args_table.add_column("Flag",        style="bold cyan",         width=22, no_wrap=True)
    args_table.add_column("Required?",   style="bold white",        width=12, justify="center")
    args_table.add_column("What it does",                           min_width=30)
    args_table.add_column("Example",     style="bold bright_green", min_width=28)

    args_table.add_row(
        "-t  /  --target",
        "[bold green]YES[/bold green]",
        "The IP address or domain name you want to scan.\n"
        "[dim]Must be a valid IPv4 or a real domain name.[/dim]",
        "-t 192.168.1.1\n-t example.com",
    )
    args_table.add_row(
        "-s  /  --scan-type",
        "[dim]no (default: fast)[/dim]",
        "[bold]fast[/bold]    → top 100 ports   [dim](quickest)[/dim]\n"
        "[bold]service[/bold] → top 1000 + versions\n"
        "[bold]full[/bold]    → all 65535 ports  [dim](slowest)[/dim]",
        "-s fast\n-s service\n-s full",
    )
    args_table.add_row(
        "-o  /  --output",
        "[dim]no (terminal only)[/dim]",
        "Save the report to a file in the [cyan]reports/[/cyan] folder.\n"
        "Accepted values: [bold]json[/bold] or [bold]csv[/bold] only.",
        "-o json\n-o csv",
    )
    args_table.add_row(
        "--timeout",
        "[dim]no (default: 300s)[/dim]",
        "How many seconds to wait before giving up.\n"
        "[dim]Raise this for slow networks or a full scan.[/dim]",
        "--timeout 60\n--timeout 600",
    )
    args_table.add_row(
        "-h  /  --help",
        "[dim]no[/dim]",
        "Show this help menu.",
        "-h",
    )

    console.print(args_table)
    console.print()

    # ---- Examples --------------------------------------------------------
    ex_table = Table(
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold magenta",
        show_lines=True,
        expand=True,
        title="[bold magenta]Usage Examples[/bold magenta]",
    )

    ex_table.add_column("Command",     style="bold bright_green", min_width=55)
    ex_table.add_column("What it does",                           min_width=38)

    ex_table.add_row(
        "python main.py -t 192.168.1.1",
        "Quick scan of top 100 ports.\nResults shown in terminal only.",
    )
    ex_table.add_row(
        "python main.py -t example.com -s service",
        "Service & version detection on a domain.\nShows software names and versions.",
    )
    ex_table.add_row(
        "python main.py -t 10.0.0.5 -s full -o json",
        "Full scan of all 65535 ports.\nSaves results to reports/ as JSON.",
    )
    ex_table.add_row(
        "python main.py -t 10.0.0.5 -o csv --timeout 600",
        "Quick scan with CSV export.\nExtra-long timeout for slow networks.",
    )

    console.print(ex_table)
    console.print()

    # ---- Scan speed guide ------------------------------------------------
    speed_panel = Panel(
        "[bold]fast[/bold]    [dim]─────[/dim]  Scans the [cyan]100 most common ports[/cyan].  "
        "Finishes in [green]seconds[/green].  Great for a quick look.\n"
        "[bold]service[/bold] [dim]─────[/dim]  Scans the [cyan]1000 most common ports[/cyan] "
        "and detects [green]service versions[/green].  Takes [yellow]1–5 minutes[/yellow].\n"
        "[bold]full[/bold]    [dim]─────[/dim]  Scans [cyan]all 65535 ports[/cyan].  "
        "Very thorough but can take [red]10–30+ minutes[/red].  Use with a higher --timeout.",
        title="[bold magenta]Scan Type Speed Guide[/bold magenta]",
        border_style="magenta",
        padding=(1, 3),
    )
    console.print(speed_panel)
    console.print()

    # ---- Footer ----------------------------------------------------------
    console.print(
        Rule(
            "[dim]NeonRecon — for authorised use on permitted targets only[/dim]",
            style="bright_black",
        )
    )
    console.print()
    sys.exit(0)


# ---------------------------------------------------------------------------
# Scan summary header  — printed after banner, before spinner starts
# ---------------------------------------------------------------------------

def _print_scan_summary(args) -> None:
    """Render a compact pre-scan summary panel."""
    output_label = (
        f"[bold white]{args.output.upper()}[/bold white] → [cyan]reports/[/cyan]"
        if args.output
        else "[dim]terminal only[/dim]"
    )

    summary = (
        f"  [dim]Target    :[/dim]   [bold cyan]{args.target}[/bold cyan]\n"
        f"  [dim]Scan Type :[/dim]   [bold white]{args.scan_type}[/bold white]\n"
        f"  [dim]Output    :[/dim]   {output_label}\n"
        f"  [dim]Timeout   :[/dim]   [bold white]{args.timeout}s[/bold white]"
    )

    console.print(
        Panel(
            summary,
            title="[bold magenta]⚡ Scan Configuration[/bold magenta]",
            border_style="bright_magenta",
            box=box.ROUNDED,
            padding=(1, 3),
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# Main orchestration flow
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Top-level entry point.  Orchestrates the full scan pipeline.

    Exit codes
    ----------
    0 — success
    1 — runtime error (nmap missing, scan failed, timeout, etc.)
    2 — bad arguments (argparse handles this automatically)
    """
    # ------------------------------------------------------------------ #
    # 0. Intercept -h / --help BEFORE argparse runs                       #
    #    We want our Rich help menu, not argparse's plain-text default.   #
    # ------------------------------------------------------------------ #
    if len(sys.argv) == 1 or any(a in sys.argv[1:] for a in ("-h", "--help")):
        print_banner()
        print_help()                     # calls sys.exit(0) internally

    # ------------------------------------------------------------------ #
    # 1. Print banner                                                      #
    # ------------------------------------------------------------------ #
    print_banner()

    # ------------------------------------------------------------------ #
    # 2. Parse & validate CLI arguments                                    #
    #    Any invalid input causes argparse to print an error and exit(2). #
    # ------------------------------------------------------------------ #
    args = cli.parse_args()

    # ------------------------------------------------------------------ #
    # 3. Show scan configuration summary                                  #
    # ------------------------------------------------------------------ #
    _print_scan_summary(args)

    # ------------------------------------------------------------------ #
    # 4. Execute Nmap scan behind a Rich loading spinner                  #
    # ------------------------------------------------------------------ #
    scan_result: scanner.ScanResult | None = None

    with console.status(
        f"[bold bright_green][ SCANNING ] [cyan]{args.target}[/cyan]  "
        f"[dim]profile=[/dim][white]{args.scan_type}[/white]  "
        f"[dim]timeout=[/dim][white]{args.timeout}s[/white] …[/bold bright_green]",
        spinner="dots",
        spinner_style="bold bright_magenta",
    ):
        try:
            scan_result = scanner.run_scan_from_args(args)

        except scanner.NmapNotFoundError as exc:
            console.print(
                f"\n  [bold red]✖  nmap not found[/bold red]\n"
                f"  [dim]{exc}[/dim]\n"
            )
            sys.exit(1)

        except scanner.ScanTimeoutError as exc:
            console.print(
                f"\n  [bold yellow]⏱  Scan timed out[/bold yellow]\n"
                f"  [dim]{exc}[/dim]\n"
            )
            sys.exit(1)

        except scanner.ScanError as exc:
            console.print(
                f"\n  [bold red]✖  Scan failed[/bold red]\n"
                f"  [dim]{exc}[/dim]\n"
            )
            sys.exit(1)

    # Spinner exited — confirm completion with timestamp.
    console.print(
        f"  [bold bright_green]✔  Scan complete[/bold bright_green]"
        f"  [dim]({scan_result.iso_timestamp})[/dim]\n"
    )

    # ------------------------------------------------------------------ #
    # 5. Parse raw nmap stdout into structured data                       #
    # ------------------------------------------------------------------ #
    scan_data = parser.parse_nmap_output(scan_result.stdout)

    # ------------------------------------------------------------------ #
    # 6. Render results to the terminal                                   #
    # ------------------------------------------------------------------ #
    reporter.render_table(scan_data)

    # ------------------------------------------------------------------ #
    # 7. Export to file if --output was requested                         #
    # ------------------------------------------------------------------ #
    if args.output:
        reporter.export_report(
            scan_data=scan_data,
            fmt=args.output,
            target=args.target,
        )

    # ------------------------------------------------------------------ #
    # Phase-2 placeholder: state comparison / asset diffing               #
    # ------------------------------------------------------------------ #
    # Uncomment when Phase 2 (persistent state) is implemented:
    #
    # from pathlib import Path
    # import json
    # latest = Path("reports") / "latest.json"
    # if latest.exists():
    #     previous = json.loads(latest.read_text())
    #     diff = parser.diff_scans(previous, scan_data)
    #     reporter.render_diff(diff)


if __name__ == "__main__":
    main()
