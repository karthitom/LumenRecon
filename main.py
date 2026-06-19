"""
main.py — Orchestrator & Entry Point  [LumenRecon v2.0]
=========================================================
Single entry point for LumenRecon — The Network Illuminator.
Ties every module together in order:

    CLI args  →  Scanner  →  Parser  →  Reporter

Flow
----
    1.  Check for -h / --help → print custom Rich help menu, then exit.
    2.  Parse & validate arguments with cli.parse_args().
    3.  Print banner + scan summary header.
    4.  Run nmap via scanner.run_scan_from_args() behind a Rich spinner.
        Returns list[ScanResult] for both single and subnet targets.
    5.  Parse each ScanResult.stdout with parser.parse_nmap_output().
    6.  Render results via reporter.render_table() (single host) or
        reporter.render_multi() (subnet).
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
# ASCII Banner  — sleek cyberpunk aesthetic for LumenRecon
# ---------------------------------------------------------------------------

_BANNER = r"""
 ██╗     ██╗   ██╗███╗   ███╗███████╗███╗   ██╗
 ██║     ██║   ██║████╗ ████║██╔════╝████╗  ██║
 ██║     ██║   ██║██╔████╔██║█████╗  ██╔██╗ ██║
 ██║     ██║   ██║██║╚██╔╝██║██╔══╝  ██║╚██╗██║
 ███████╗╚██████╔╝██║ ╚═╝ ██║███████╗██║ ╚████║
 ╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
"""

_TAGLINE = (
    "💡  The Network Illuminator  💡\n"
    "   [dim]Safely illuminating hidden services and open ports "
    "within authorised networks.[/dim]\n"
    "   [dim]For authorised use on permitted targets only.[/dim]"
)


def print_banner() -> None:
    """Render the LumenRecon ASCII banner inside a sleek cyberpunk-style Rich panel."""
    banner_text = Text(_BANNER, style="bold bright_cyan", justify="center")
    tagline_text = Text.from_markup(_TAGLINE, justify="center")

    combined = Text.assemble(banner_text, "\n", tagline_text)

    panel = Panel(
        combined,
        box=box.DOUBLE_EDGE,
        border_style="cyan",
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
            Text("LumenRecon  ·  The Network Illuminator  ·  Help & Usage Guide",
                 style="bold bright_cyan", justify="center"),
            box=box.HEAVY,
            border_style="cyan",
            padding=(0, 4),
        )
    )
    console.print()

    # ---- What is this tool? ----------------------------------------------
    console.print(
        Panel(
            "[white]LumenRecon acts as a light in the dark, safely illuminating hidden\n"
            "services and open ports within authorised networks.\n\n"
            "It uses [bold cyan]Nmap[/bold cyan] to scan a target IP address or domain name and\n"
            "shows you which ports are open, what services are running, and\n"
            "optionally saves the results to a [bold]JSON[/bold] or [bold]CSV[/bold] file.\n\n"
            "[bold yellow]⚠  Only scan systems you own or have explicit written permission to test.[/bold yellow]",
            title="[bold cyan]💡 What does LumenRecon do?[/bold cyan]",
            border_style="cyan",
            padding=(1, 3),
        )
    )
    console.print()

    # ---- Arguments table -------------------------------------------------
    args_table = Table(
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold cyan",
        show_lines=True,
        expand=True,
        title="[bold cyan]Arguments[/bold cyan]",
    )

    args_table.add_column("Flag",        style="bold cyan",         width=22, no_wrap=True)
    args_table.add_column("Required?",   style="bold white",        width=12, justify="center")
    args_table.add_column("What it does",                           min_width=30)
    args_table.add_column("Example",     style="bold bright_green", min_width=28)

    args_table.add_row(
        "-t  /  --target",
        "[bold green]YES[/bold green]",
        "The IP, CIDR subnet, or domain to scan.\n"
        "[dim]IPv4  : 192.168.1.1\n"
        "CIDR  : 192.168.1.0/24  (prefix /16–/32)\n"
        "Domain: example.com[/dim]",
        "-t 192.168.1.1\n-t 10.0.0.0/24\n-t example.com",
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
        "-T  /  --threads",
        "[dim]no (default: 10)[/dim]",
        "Parallel worker threads for subnet scans.\n"
        "[dim]Range: 1–50.  Ignored for single IP / domain.[/dim]",
        "-T 10\n-T 25",
    )
    args_table.add_row(
        "--timeout",
        "[dim]no (default: 300s)[/dim]",
        "Per-host timeout in seconds.\n"
        "[dim]Raise this for slow networks or full scans.[/dim]",
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
        header_style="bold cyan",
        show_lines=True,
        expand=True,
        title="[bold cyan]Usage Examples[/bold cyan]",
    )

    ex_table.add_column("Command",     style="bold bright_green", min_width=55)
    ex_table.add_column("What it does",                           min_width=38)

    ex_table.add_row(
        "python main.py -t 192.168.1.1",
        "Quick scan of top 100 ports.\nResults shown in terminal only.",
    )
    ex_table.add_row(
        "python main.py -t 192.168.1.0/24 -T 20",
        "Subnet sweep — 20 parallel threads.\nSkips down/filtered hosts automatically.",
    )
    ex_table.add_row(
        "python main.py -t example.com -s service",
        "Service & version detection on a domain.\nShows software names and versions.",
    )
    ex_table.add_row(
        "python main.py -t 10.0.0.0/24 -s fast -o json -T 30",
        "Fast subnet sweep — 30 threads.\nSaves all results to reports/ as JSON.",
    )
    ex_table.add_row(
        "python main.py -t 10.0.0.5 -s full -o csv --timeout 600",
        "Full scan of all 65535 ports.\nCSV export, extended timeout.",
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
        title="[bold cyan]Scan Type Speed Guide[/bold cyan]",
        border_style="cyan",
        padding=(1, 3),
    )
    console.print(speed_panel)
    console.print()

    # ---- Footer ----------------------------------------------------------
    console.print(
        Rule(
            "[dim]LumenRecon · The Network Illuminator · for authorised use on permitted targets only[/dim]",
            style="bright_black",
        )
    )
    console.print()
    sys.exit(0)


# ---------------------------------------------------------------------------
# Scan summary header  — printed after banner, before spinner starts
# ---------------------------------------------------------------------------

def _print_scan_summary(args) -> None:
    """Render a compact pre-scan summary panel, including thread count."""
    is_subnet = cli.is_subnet(args.target)
    output_label = (
        f"[bold white]{args.output.upper()}[/bold white] → [cyan]reports/[/cyan]"
        if args.output
        else "[dim]terminal only[/dim]"
    )
    threads_label = (
        f"[bold white]{args.threads}[/bold white]"
        if is_subnet
        else "[dim]N/A — single host[/dim]"
    )
    mode_label = (
        "[bold yellow]SUBNET[/bold yellow]" if is_subnet
        else "[bold white]SINGLE HOST[/bold white]"
    )

    summary = (
        f"  [dim]Target    :[/dim]   [bold cyan]{args.target}[/bold cyan]\n"
        f"  [dim]Mode      :[/dim]   {mode_label}\n"
        f"  [dim]Scan Type :[/dim]   [bold white]{args.scan_type}[/bold white]\n"
        f"  [dim]Threads   :[/dim]   {threads_label}\n"
        f"  [dim]Output    :[/dim]   {output_label}\n"
        f"  [dim]Timeout   :[/dim]   [bold white]{args.timeout}s[/bold white] per host"
    )

    console.print(
        Panel(
            summary,
            title="[bold cyan]💡 LumenRecon — Scan Configuration[/bold cyan]",
            border_style="cyan",
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
    # ------------------------------------------------------------------ #
    if len(sys.argv) == 1 or any(a in sys.argv[1:] for a in ("-h", "--help")):
        print_banner()
        print_help()   # calls sys.exit(0) internally

    # ------------------------------------------------------------------ #
    # 1. Print banner                                                      #
    # ------------------------------------------------------------------ #
    print_banner()

    # ------------------------------------------------------------------ #
    # 2. Parse & validate CLI arguments                                    #
    # ------------------------------------------------------------------ #
    args = cli.parse_args()

    # Determine mode once — used in several places below.
    is_subnet_scan = cli.is_subnet(args.target)

    # ------------------------------------------------------------------ #
    # 3. Scan configuration summary                                        #
    # ------------------------------------------------------------------ #
    _print_scan_summary(args)

    # ------------------------------------------------------------------ #
    # 4. Execute scan(s) behind a Rich spinner                             #
    # run_scan_from_args() always returns list[ScanResult].               #
    # ------------------------------------------------------------------ #
    scan_results: list[scanner.ScanResult] = []

    spinner_label = (
        f"[bold bright_cyan][ LUMENRECON ]  "
        f"[white]{args.target}[/white]  "
        f"[dim]mode=[/dim][white]{'subnet' if is_subnet_scan else 'single'}[/white]  "
        f"[dim]profile=[/dim][white]{args.scan_type}[/white]  "
        f"[dim]threads=[/dim][white]{args.threads if is_subnet_scan else 1}[/white]"
        f"  …[/bold bright_cyan]"
    )

    with console.status(spinner_label, spinner="dots", spinner_style="bold cyan"):
        try:
            scan_results = scanner.run_scan_from_args(args)

        except scanner.NmapNotFoundError as exc:
            console.print(
                f"\n  [bold red]✖  nmap not found[/bold red]\n  [dim]{exc}[/dim]\n"
            )
            sys.exit(1)

        except scanner.ScanTimeoutError as exc:
            console.print(
                f"\n  [bold yellow]⏱  Scan timed out[/bold yellow]\n  [dim]{exc}[/dim]\n"
            )
            sys.exit(1)

        except scanner.ScanError as exc:
            console.print(
                f"\n  [bold red]✖  Scan failed[/bold red]\n  [dim]{exc}[/dim]\n"
            )
            sys.exit(1)

    # Show completion — use the last result's timestamp for single scans.
    if scan_results:
        ts_label = scan_results[-1].iso_timestamp
        host_label = (
            f"{len(scan_results)} host(s) responded"
            if is_subnet_scan
            else scan_results[0].target
        )
        console.print(
            f"  [bold bright_green]✔  Scan complete[/bold bright_green]"
            f"  [dim]{host_label}  ({ts_label})[/dim]\n"
        )
    else:
        console.print(
            "  [bold yellow]⚠  Scan returned no results — "
            "all hosts may be down or filtered.[/bold yellow]\n"
        )
        sys.exit(0)

    # ------------------------------------------------------------------ #
    # 5. Parse each ScanResult.stdout → structured dicts                  #
    # ------------------------------------------------------------------ #
    parsed_results: list[dict] = [
        parser.parse_nmap_output(r.stdout) for r in scan_results
    ]

    # ------------------------------------------------------------------ #
    # 6. Render results                                                    #
    # ------------------------------------------------------------------ #
    if is_subnet_scan:
        # Multi-host grouped display
        reporter.render_multi(parsed_results)
    else:
        # Single-host display — unchanged from v1
        reporter.render_table(parsed_results[0])

    # ------------------------------------------------------------------ #
    # 7. Export to file if --output was requested                          #
    # ------------------------------------------------------------------ #
    if args.output:
        # Pass list for subnet, dict for single — reporter handles both.
        export_data = parsed_results if is_subnet_scan else parsed_results[0]
        reporter.export_report(
            scan_data=export_data,
            fmt=args.output,
            target=args.target,
        )

    # ------------------------------------------------------------------ #
    # Phase-2 placeholder: state comparison / asset diffing               #
    # ------------------------------------------------------------------ #
    # from pathlib import Path
    # import json
    # latest = Path("reports") / "latest.json"
    # if latest.exists():
    #     previous = json.loads(latest.read_text())
    #     diff = parser.diff_scans(previous, parsed_results[0])
    #     reporter.render_diff(diff)


if __name__ == "__main__":
    main()
