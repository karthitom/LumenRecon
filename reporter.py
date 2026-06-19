"""
reporter.py — Output & Reporting Module  [LumenRecon v2.0]
===========================================================
Handles two responsibilities:
  1. Render styled Rich terminal tables from parsed scan data.
  2. Export results to reports/ as JSON or CSV.

V2.0 changes
------------
  - render_table()     : unchanged — single host dict, as before.
  - render_multi()     : NEW — accepts list[dict] for subnet scans.
                         Renders one clearly-labelled table per host,
                         grouped with a summary header and footer.
  - export_report()    : now accepts both dict (single) and list[dict]
                         (subnet).  JSON exports the full structure;
                         CSV flattens all hosts into a single file.
"""

import csv
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Union

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

logger = logging.getLogger(__name__)

# Shared console — dark background assumed.
console = Console(highlight=False)

# All exported reports land here.
REPORTS_DIR = Path(__file__).parent / "reports"


# ---------------------------------------------------------------------------
# Terminal rendering — single host
# ---------------------------------------------------------------------------

def render_table(scan_data: dict) -> None:
    """
    Render a styled Rich port table for a single scanned host.

    Colour rules:
      open     → bold green
      closed   → bold red
      filtered → bold yellow
      other    → dim white

    Parameters
    ----------
    scan_data : dict
        Output of parser.parse_nmap_output().
    """
    host      = scan_data.get("host", "unknown")
    hostname  = scan_data.get("hostname", "")
    state     = scan_data.get("state", "unknown")
    ports     = scan_data.get("ports", [])

    # Host summary line
    host_label  = f"[bold cyan]{host}[/bold cyan]"
    if hostname:
        host_label += f"  [dim]({hostname})[/dim]"
    state_style = "bold green" if state == "up" else "bold red"
    console.print(
        f"\n  Host : {host_label}   "
        f"Status : [{state_style}]{state.upper()}[/{state_style}]\n"
    )

    if not ports:
        console.print(
            "  [yellow]No port data — host may be down or blocking all probes.[/yellow]\n"
        )
        return

    _print_port_table(host, ports)

    console.print(
        f"\n  [dim]Total: {len(ports)} port(s) | "
        f"Open: {sum(1 for p in ports if p['state'] == 'open')} | "
        f"Scanned at {_now_str()}[/dim]\n"
    )


# ---------------------------------------------------------------------------
# Terminal rendering — multiple hosts (subnet scan)
# ---------------------------------------------------------------------------

def render_multi(scan_data_list: list[dict]) -> None:
    """
    Render one clearly-labelled port table per host for a subnet scan,
    with a summary header and a final totals footer.

    Each host is separated by a Rule so the output remains readable even
    when 20+ IPs are displayed.

    Parameters
    ----------
    scan_data_list : list[dict]
        List of parser.parse_nmap_output() results, one per host.
        Hosts with no port data are displayed with a brief notice.
    """
    total_hosts = len(scan_data_list)
    live_hosts  = [d for d in scan_data_list if d.get("ports")]
    open_ports_total = sum(
        sum(1 for p in d.get("ports", []) if p["state"] == "open")
        for d in scan_data_list
    )

    # ---- Subnet summary header -------------------------------------------
    console.print()
    console.print(
        Panel(
            f"  [bold cyan]Subnet Scan Results[/bold cyan]\n\n"
            f"  [dim]Hosts scanned  :[/dim]  [bold white]{total_hosts}[/bold white]\n"
            f"  [dim]Hosts with data:[/dim]  [bold green]{len(live_hosts)}[/bold green]\n"
            f"  [dim]Total open ports:[/dim] [bold green]{open_ports_total}[/bold green]\n"
            f"  [dim]Completed at   :[/dim]  [bold white]{_now_str()}[/bold white]",
            title="[bold cyan]💡 LumenRecon — Subnet Illumination Complete[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(1, 3),
        )
    )
    console.print()

    if not scan_data_list:
        console.print(
            "  [yellow]No hosts responded in this subnet.[/yellow]\n"
        )
        return

    # ---- Per-host tables -------------------------------------------------
    for idx, scan_data in enumerate(scan_data_list, start=1):
        host     = scan_data.get("host", "unknown")
        hostname = scan_data.get("hostname", "")
        state    = scan_data.get("state", "unknown")
        ports    = scan_data.get("ports", [])

        # Separator rule between hosts (not before the first one)
        if idx > 1:
            console.print(Rule(style="bright_black"))

        # Host header line
        host_label  = f"[bold cyan]{host}[/bold cyan]"
        if hostname:
            host_label += f"  [dim]({hostname})[/dim]"
        state_style = "bold green" if state == "up" else "bold red"
        open_count  = sum(1 for p in ports if p["state"] == "open")

        console.print(
            f"\n  [{idx}/{total_hosts}]  Host : {host_label}  "
            f"Status : [{state_style}]{state.upper()}[/{state_style}]  "
            f"[dim]Open ports: {open_count}[/dim]\n"
        )

        if not ports:
            console.print(
                "  [dim yellow]  No open ports found — host may be "
                "filtered or no services running.[/dim yellow]\n"
            )
            continue

        _print_port_table(host, ports, compact=True)

    # ---- Summary footer --------------------------------------------------
    console.print()
    console.print(
        Rule(
            f"[dim]LumenRecon subnet scan — "
            f"{len(live_hosts)}/{total_hosts} hosts illuminated — "
            f"{open_ports_total} open port(s) found[/dim]",
            style="bright_black",
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# Shared table builder
# ---------------------------------------------------------------------------

def _print_port_table(host: str, ports: list[dict], compact: bool = False) -> None:
    """
    Build and print a Rich port table.

    Parameters
    ----------
    host : str
        Host label used in the table title.
    ports : list[dict]
        Port records from parser.parse_nmap_output().
    compact : bool
        When True, omit the table title (used in multi-host mode where
        the host label is already printed above).
    """
    table = Table(
        title=None if compact else f"[bold cyan]Scan Results — {host}[/bold cyan]",
        box=box.DOUBLE_EDGE,
        border_style="bright_black",
        header_style="bold cyan",
        show_lines=True,
        min_width=72,
    )

    table.add_column("PORT",    style="bold white",   justify="right",  width=8)
    table.add_column("PROTO",   style="cyan",          justify="center", width=7)
    table.add_column("STATE",   justify="center",      width=10)
    table.add_column("SERVICE", style="bright_white",  justify="left",   width=14)
    table.add_column("VERSION", style="dim white",     justify="left")

    for record in ports:
        table.add_row(
            str(record["port"]),
            record["protocol"].upper(),
            _state_cell(record["state"]),
            record["service"],
            record["version"] or "—",
        )

    console.print(table)


def _state_cell(state: str) -> Text:
    """Return a Rich Text cell colour-coded by port state."""
    colour_map = {
        "open":     ("bold green",  "OPEN"),
        "closed":   ("bold red",    "CLOSED"),
        "filtered": ("bold yellow", "FILTERED"),
    }
    style, label = colour_map.get(state.lower(), ("dim white", state.upper()))
    return Text(label, style=style, justify="center")


# ---------------------------------------------------------------------------
# File export — handles both single-host and multi-host data
# ---------------------------------------------------------------------------

def export_report(
    scan_data: Union[dict, list[dict]],
    fmt: Literal["json", "csv"],
    target: str,
) -> Path:
    """
    Save scan data to reports/ as JSON or CSV.

    Accepts both a single scan_data dict (single-host scan) and a list
    of dicts (subnet scan).  The file is named after the target and a
    UTC timestamp.

    Parameters
    ----------
    scan_data : dict | list[dict]
        Single or multiple outputs from parser.parse_nmap_output().
    fmt : "json" | "csv"
        Export format.
    target : str
        The scan target string (used in the filename).

    Returns
    -------
    Path
        Absolute path to the written file.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # Normalise to list for uniform handling.
    if isinstance(scan_data, dict):
        data_list = [scan_data]
    else:
        data_list = scan_data

    # Build a safe filename from the target string.
    safe_target = re.sub(r"[^\w\-]", "_", target)
    timestamp   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename    = f"scan_{safe_target}_{timestamp}.{fmt}"
    filepath    = REPORTS_DIR / filename

    if fmt == "json":
        # Wrap in a top-level dict so single and multi-host exports share
        # the same structure and are easy to process programmatically.
        payload = {
            "target":      target,
            "exported_at": datetime.now(timezone.utc).isoformat() + "Z",
            "host_count":  len(data_list),
            "hosts":       data_list,
        }
        _export_json(payload, filepath)
    else:
        _export_csv(data_list, filepath)

    console.print(
        f"  [bold green]✔[/bold green]  Report saved → "
        f"[underline cyan]{filepath}[/underline cyan]\n"
    )
    logger.info("Report exported to %s", filepath)
    return filepath


def _export_json(payload: dict, filepath: Path) -> None:
    """Write *payload* as pretty-printed UTF-8 JSON."""
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def _export_csv(data_list: list[dict], filepath: Path) -> None:
    """
    Write all hosts' port records as CSV rows.

    Columns: host, hostname, host_state, port, protocol, state, service, version
    Each host/port combination is one row.  Hosts with no ports get a
    single placeholder row.
    """
    fieldnames = [
        "host", "hostname", "host_state",
        "port", "protocol", "state", "service", "version",
    ]

    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()

        for scan_data in data_list:
            host       = scan_data.get("host", "")
            hostname   = scan_data.get("hostname", "")
            host_state = scan_data.get("state", "unknown")
            ports      = scan_data.get("ports", [])

            if not ports:
                writer.writerow({
                    "host": host, "hostname": hostname,
                    "host_state": host_state,
                    "port": "", "protocol": "", "state": "",
                    "service": "", "version": "",
                })
                continue

            for record in ports:
                writer.writerow({
                    "host":       host,
                    "hostname":   hostname,
                    "host_state": host_state,
                    "port":       record["port"],
                    "protocol":   record["protocol"],
                    "state":      record["state"],
                    "service":    record["service"],
                    "version":    record["version"],
                })


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
