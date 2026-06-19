"""
scanner.py — Core Scanner Module  [LumenRecon v2.1]
=====================================================
Safely invokes Nmap via subprocess and returns structured output for
downstream parsing.  No exploitation, no brute-forcing — strictly port
enumeration and service detection for authorised targets only.

Public API
----------
    run_scan(target, scan_type, timeout)   -> ScanResult
    run_scan_from_args(args)               -> list[ScanResult]
    discover_live_hosts(target, timeout)   -> list[str]
    is_nmap_available()                    -> bool

Two-Phase Scanning (v2.1)
--------------------------
Subnet scans now run in two distinct phases:

  Phase 1 — Host Discovery  (nmap -sn)
    discover_live_hosts() runs a fast ping sweep against the entire
    subnet using a single nmap -sn invocation.  Only IPs reported as
    "up" are returned.  This phase typically completes in seconds and
    eliminates all dead addresses before any port scanning begins,
    which is the primary fix for timeout exhaustion on sparse subnets.

  Phase 2 — Targeted Port Scan  (parallel, ThreadPoolExecutor)
    _run_subnet_scan() receives only the live IPs from Phase 1 and
    submits them to the thread pool.  Every worker calls run_scan()
    which calls subprocess.run(shell=False) — the security model is
    identical to a single-host scan.

  For single IPs / domains, discover_live_hosts() is called first to
  verify the host is up before committing to a full port scan.  If the
  host appears down the user is warned and given the option to abort.

Security model
--------------
    * subprocess.run() is called with shell=False at all times.
    * Every command is a strict list[str] — targets are single list
      elements, never interpolated into shell strings.
    * extra_flags elements must start with '-' (injection guard).
    * ThreadPoolExecutor workers are stateless — no shared mutable state.
    * Thread count is bounded by cli.py validation (max 50).
    * The ping-sweep command (nmap -sn) is built with the same
      _build_discovery_cmd() helper and the same shell=False policy.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console

import cli   # only used for cli.is_subnet() — no circular dependency risk

# ---------------------------------------------------------------------------
# Module-level logger and console
# ---------------------------------------------------------------------------
logger  = logging.getLogger(__name__)
console = Console(highlight=False)   # for Phase 1 status messages


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class NmapNotFoundError(EnvironmentError):
    """Raised when the nmap binary cannot be located on the system PATH."""


class ScanTimeoutError(TimeoutError):
    """Raised when an nmap process exceeds the configured wall-clock limit."""


class ScanError(RuntimeError):
    """Raised when nmap exits with a non-zero return code or a subprocess
    failure occurs that prevents result collection."""


# ---------------------------------------------------------------------------
# Scan profiles
# ---------------------------------------------------------------------------

# Single source of truth for nmap flags per profile.
# Deliberately minimal: no OS detection, no NSE scripts, no timing flags.
SCAN_PROFILES: dict[str, list[str]] = {
    "fast":    ["-F"],          # Top 100 most common ports
    "service": ["-sV"],         # Service/version detection, top 1000 ports
    "full":    ["-p-", "-sV"],  # All 65535 ports + service version info
}

_DEFAULT_SCAN_TYPE: str = "fast"
DEFAULT_TIMEOUT:    int = 300    # per-host port-scan timeout (seconds)

# Phase 1 ping-sweep timeout.
# Capped at 60 s regardless of the user's --timeout value so the discovery
# phase never blocks longer than a minute even on very slow networks.
_DISCOVERY_TIMEOUT_CAP: int = 60   # seconds


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """
    Structured container for a completed Nmap execution against one host.

    Attributes
    ----------
    target : str
        The IP address or domain that was scanned.
    scan_type : str
        Profile used: 'fast', 'service', or 'full'.
    stdout : str
        Raw nmap stdout.  Pass this to parser.parse_nmap_output().
    stderr : str
        Raw nmap stderr.  Useful for diagnostics and logging.
    returncode : int
        Process exit code.  0 = success.
    timestamp : datetime
        UTC moment recorded immediately before the subprocess call.
    cmd : list[str]
        The exact command list executed.  Preserved for auditability.
    """
    target:     str
    scan_type:  str
    stdout:     str
    stderr:     str
    returncode: int
    timestamp:  datetime
    cmd:        list[str] = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        """True when nmap exited cleanly (returncode == 0)."""
        return self.returncode == 0

    @property
    def iso_timestamp(self) -> str:
        """ISO-8601 UTC timestamp, e.g. '2026-06-19T10:30:00Z'."""
        return self.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")

    @property
    def has_data(self) -> bool:
        """True when the scan succeeded and produced non-empty stdout."""
        return self.succeeded and bool(self.stdout)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def is_nmap_available() -> bool:
    """Return True if the nmap binary is reachable on the system PATH."""
    found = shutil.which("nmap") is not None
    if not found:
        logger.warning(
            "nmap binary not found on PATH.  "
            "Install from https://nmap.org/download.html"
        )
    return found


def _resolve_scan_type(scan_type: str) -> str:
    """Return the normalised scan_type key, falling back to the default."""
    normalised = scan_type.lower().strip()
    if normalised not in SCAN_PROFILES:
        logger.warning(
            "Unknown scan_type '%s' — falling back to '%s'.",
            scan_type, _DEFAULT_SCAN_TYPE,
        )
        return _DEFAULT_SCAN_TYPE
    return normalised


def _build_cmd(
    target: str,
    scan_type: str,
    extra_flags: Optional[list[str]] = None,
) -> list[str]:
    """
    Build the nmap port-scan command as a strict list[str].

    The target is always the final element.  extra_flags elements must
    start with '-' to prevent positional-argument injection.

    Raises
    ------
    TypeError  — extra_flags is not a list, or an element is not a str.
    ValueError — an element is empty or does not start with '-'.
    """
    profile_flags = SCAN_PROFILES[scan_type]
    cmd: list[str] = ["nmap"] + profile_flags

    if extra_flags is not None:
        if not isinstance(extra_flags, list):
            raise TypeError(
                f"extra_flags must be list[str], got {type(extra_flags).__name__}."
            )
        for flag in extra_flags:
            if not isinstance(flag, str):
                raise TypeError(
                    f"extra_flags elements must be str, got {type(flag).__name__}."
                )
            if not flag:
                raise ValueError("extra_flags must not contain empty strings.")
            if not flag.startswith("-"):
                raise ValueError(
                    f"extra_flags element '{flag}' must start with '-' "
                    "(positional-argument injection guard)."
                )
        cmd.extend(extra_flags)

    cmd.append(target)   # target is always the final positional argument
    return cmd


def _build_discovery_cmd(target: str) -> list[str]:
    """
    Build the nmap ping-sweep command as a strict list[str].

    Uses -sn (no port scan, host discovery only) and -T4 (aggressive
    timing for faster sweeps on local networks).  The target is a CIDR
    string or single IP — always the final list element.

    -sn   : Skip port scanning; only determine host liveness.
    -T4   : Aggressive timing template (faster probes, less patience for
            slow responses).  Safe for local LANs; use -T3 on WAN.
    --open: Not used here; we want all "up" hosts regardless of whether
            any ports are open (port scanning is Phase 2's job).

    Parameters
    ----------
    target : str
        A validated CIDR string (e.g. '192.168.1.0/24') or single IP.
    """
    # The target is injected as the final positional list element,
    # never concatenated into a shell string.
    return ["nmap", "-sn", "-T4", target]


# ---------------------------------------------------------------------------
# Phase 1 — Host Discovery
# ---------------------------------------------------------------------------

# Regex to extract an IP address from an nmap "Nmap scan report for" line.
# Handles both bare IPs and "hostname (IP)" variants.
#
# Examples matched:
#   Nmap scan report for 192.168.1.1
#   Nmap scan report for router.local (192.168.1.1)
_REPORT_LINE_RE = re.compile(
    r"Nmap scan report for\s+"
    r"(?:[^\s(]+\s+\((?P<ip_in_parens>[^)]+)\)|(?P<bare_ip>\S+))"
)

# "Host is up" confirmation line — we only return IPs that follow this.
_HOST_UP_RE = re.compile(r"Host is up", re.IGNORECASE)


def discover_live_hosts(
    target: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[str]:
    """
    Phase 1: Run an nmap ping sweep to find live hosts.

    Executes ``nmap -sn -T4 <target>`` and parses stdout to extract only
    the IP addresses of hosts reported as "up".  No port scanning occurs.

    Works for both a CIDR subnet (returns all live IPs in the range) and
    a single IP address (returns a one-element list if up, empty if down).

    Parameters
    ----------
    target : str
        A validated CIDR string (e.g. '192.168.1.0/24') or single IPv4.
        Must have been sanitised by cli._validate_target() already.
    timeout : int
        Wall-clock timeout for the entire ping sweep in seconds.
        Automatically capped at _DISCOVERY_TIMEOUT_CAP (60 s) regardless
        of the value passed, so the discovery phase never blocks longer
        than a minute even when the user set --timeout 600.

    Returns
    -------
    list[str]
        Sorted list of IPv4 address strings that responded to probes.
        Empty list if no hosts are reachable.

    Raises
    ------
    NmapNotFoundError
        If nmap is not on the system PATH.
    ScanError
        If nmap exits with a non-zero return code during discovery.
    """
    if not is_nmap_available():
        raise NmapNotFoundError(
            "nmap is not installed or not on PATH.\n"
            "  Debian/Ubuntu : sudo apt-get install nmap\n"
            "  macOS Homebrew: brew install nmap\n"
            "  Windows       : https://nmap.org/download.html"
        )

    # Cap the discovery timeout — ping sweeps should be fast.
    discovery_timeout = min(timeout, _DISCOVERY_TIMEOUT_CAP)

    cmd = _build_discovery_cmd(target)
    logger.info("Phase 1 — Host Discovery: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            shell=False,          # NO shell interpretation
            capture_output=True,  # stdout and stderr separately
            text=True,            # decode bytes → str
            timeout=discovery_timeout,
        )
    except FileNotFoundError:
        raise NmapNotFoundError(
            "nmap binary could not be executed — it may have been removed."
        )
    except subprocess.TimeoutExpired:
        logger.warning(
            "Host discovery timed out after %ds for '%s'. "
            "Proceeding with empty host list.", discovery_timeout, target,
        )
        # Return empty rather than raising — the user can still try a
        # direct single-host scan with an explicit target.
        return []
    except subprocess.SubprocessError as exc:
        raise ScanError(f"Host discovery subprocess failed: {exc}") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or "No detail from nmap."
        logger.error(
            "nmap -sn returned code %d for '%s'.  Detail: %s",
            result.returncode, target, detail,
        )
        raise ScanError(
            f"nmap ping sweep exited with code {result.returncode}.\n"
            f"  stderr: {detail}"
        )

    # ---- Parse stdout to extract live IPs --------------------------------
    live_ips: list[str] = []
    current_ip: Optional[str] = None

    for line in result.stdout.splitlines():
        line = line.strip()

        # A "scan report" line introduces a new host entry.
        report_match = _REPORT_LINE_RE.search(line)
        if report_match:
            # Extract whichever capture group matched.
            current_ip = (
                report_match.group("ip_in_parens")
                or report_match.group("bare_ip")
            )
            continue

        # Only record the IP if the very next host-state line says "up".
        if current_ip and _HOST_UP_RE.search(line):
            live_ips.append(current_ip)
            logger.debug("Host discovery: '%s' is UP.", current_ip)
            current_ip = None   # reset for next host block

    # Sort numerically by IP address for deterministic output.
    try:
        live_ips.sort(key=lambda ip: ipaddress.IPv4Address(ip))
    except ValueError:
        # Non-IPv4 entries (e.g. hostnames) — sort lexicographically.
        live_ips.sort()

    logger.info(
        "Host discovery complete for '%s': %d live host(s) found.",
        target, len(live_ips),
    )
    return live_ips


# ---------------------------------------------------------------------------
# Core single-host scanner  (Phase 2 primitive)
# ---------------------------------------------------------------------------

def run_scan(
    target: str,
    scan_type: str = _DEFAULT_SCAN_TYPE,
    timeout: int = DEFAULT_TIMEOUT,
    extra_flags: Optional[list[str]] = None,
) -> ScanResult:
    """
    Execute an Nmap port scan against a single *target*.

    This is the low-level primitive.  The two-phase subnet flow calls
    this indirectly via _scan_worker().

    Parameters
    ----------
    target : str
        A validated single IPv4 address string or hostname.
    scan_type : str
        Scan profile: 'fast', 'service', or 'full'.
    timeout : int
        Hard wall-clock limit in seconds.
    extra_flags : list[str] | None
        Optional additional nmap flags (see _build_cmd).

    Returns
    -------
    ScanResult

    Raises
    ------
    NmapNotFoundError  — nmap missing from PATH.
    ScanTimeoutError   — scan exceeded the timeout.
    ScanError          — non-zero exit code or subprocess failure.
    """
    if not is_nmap_available():
        raise NmapNotFoundError(
            "nmap is not installed or not on PATH.\n"
            "  Debian/Ubuntu : sudo apt-get install nmap\n"
            "  macOS Homebrew: brew install nmap\n"
            "  Windows       : https://nmap.org/download.html"
        )

    effective_type = _resolve_scan_type(scan_type)
    cmd = _build_cmd(target, effective_type, extra_flags)

    logger.info("Phase 2 — Port Scan: %s", " ".join(cmd))
    scan_timestamp = datetime.now(tz=timezone.utc)

    try:
        result = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        logger.error("nmap binary disappeared between PATH check and exec.")
        raise NmapNotFoundError(
            "nmap binary could not be executed — it may have been removed."
        )
    except subprocess.TimeoutExpired:
        logger.warning(
            "Port scan timed out after %ds for target '%s'.", timeout, target
        )
        raise ScanTimeoutError(
            f"nmap timed out after {timeout}s for '{target}'.\n"
            "  Try a faster profile (-s fast) or increase --timeout."
        )
    except subprocess.SubprocessError as exc:
        logger.error("Subprocess error running nmap: %s", exc)
        raise ScanError(f"Failed to execute nmap: {exc}") from exc

    scan_result = ScanResult(
        target=target,
        scan_type=effective_type,
        stdout=result.stdout.strip(),
        stderr=result.stderr.strip(),
        returncode=result.returncode,
        timestamp=scan_timestamp,
        cmd=cmd,
    )

    if not scan_result.succeeded:
        detail = scan_result.stderr or "No detail from nmap."
        logger.error(
            "nmap returned code %d for '%s'. Detail: %s",
            scan_result.returncode, target, detail,
        )
        raise ScanError(
            f"nmap exited with code {scan_result.returncode} for '{target}'.\n"
            f"  stderr: {detail}"
        )

    if not scan_result.stdout:
        logger.warning(
            "nmap produced no output for '%s'. "
            "Host may be down or blocking all probes.", target,
        )

    logger.info(
        "Port scan complete — target='%s' type='%s' rc=%d.",
        target, effective_type, scan_result.returncode,
    )
    return scan_result


# ---------------------------------------------------------------------------
# Thread worker  — one per live host in Phase 2
# ---------------------------------------------------------------------------

def _scan_worker(
    ip: str,
    scan_type: str,
    timeout: int,
) -> Optional[ScanResult]:
    """
    Port-scan a single live IP address inside a ThreadPoolExecutor.

    Designed to be called only with IPs that passed Phase 1 discovery,
    so the "host is down" case should be rare here.  Still handles it
    gracefully to cover hosts that go offline between discovery and scan.

    Returns ScanResult on success, None if the host produced no data.
    NmapNotFoundError is re-raised so the pool manager can abort cleanly.
    """
    try:
        result = run_scan(target=ip, scan_type=scan_type, timeout=timeout)
    except ScanTimeoutError:
        # Unlikely after Phase 1 filtered out dead hosts, but possible on
        # very slow / filtered hosts.  Skip gracefully.
        logger.warning("Port scan timed out for '%s' — skipping.", ip)
        return None
    except ScanError as exc:
        # Non-zero nmap exit after Phase 1 confirmation — log and skip.
        logger.warning("Port scan error for '%s': %s — skipping.", ip, exc)
        return None
    except NmapNotFoundError:
        raise   # always fatal — bubble up to pool manager

    if not result.has_data:
        logger.debug("Host '%s' returned no port data — skipping.", ip)
        return None

    return result


# ---------------------------------------------------------------------------
# Two-phase subnet scan manager
# ---------------------------------------------------------------------------

def _run_subnet_scan(
    network: ipaddress.IPv4Network,
    scan_type: str,
    timeout: int,
    max_workers: int,
) -> list[ScanResult]:
    """
    Orchestrate the two-phase subnet scan:

      Phase 1 — discover_live_hosts(): ping sweep the entire subnet.
      Phase 2 — ThreadPoolExecutor: port-scan only the live IPs.

    Rich status messages are printed directly so the user sees progress
    without needing to watch log output.

    Parameters
    ----------
    network : ipaddress.IPv4Network
        The validated, canonical network object.
    scan_type : str
        Scan profile name.
    timeout : int
        Per-host port-scan timeout in seconds.  Discovery timeout is
        independently capped at _DISCOVERY_TIMEOUT_CAP.
    max_workers : int
        Maximum concurrent nmap processes for Phase 2.

    Returns
    -------
    list[ScanResult]
        Port-scan results for all responding live hosts, sorted by IP.
        Empty list if Phase 1 finds no live hosts.

    Raises
    ------
    NmapNotFoundError
        If nmap disappears during either phase.
    """
    subnet_str = str(network)

    # ------------------------------------------------------------------ #
    # Phase 1: Host Discovery                                              #
    # ------------------------------------------------------------------ #
    console.print(
        f"\n  [bold cyan][*][/bold cyan]  "
        f"Phase 1 — Host Discovery on [bold white]{subnet_str}[/bold white] …"
    )

    live_ips = discover_live_hosts(target=subnet_str, timeout=timeout)
    live_count = len(live_ips)

    if live_count == 0:
        console.print(
            f"  [bold yellow][!][/bold yellow]  "
            f"No live hosts found in [white]{subnet_str}[/white].  "
            "Skipping port scan.\n"
        )
        return []

    console.print(
        f"  [bold green][+][/bold green]  "
        f"Found [bold green]{live_count}[/bold green] active host(s) in "
        f"[white]{subnet_str}[/white].  "
        f"Starting Phase 2 — Port Scan "
        f"([dim]{max_workers} thread(s), profile={scan_type}[/dim]) …\n"
    )

    logger.info(
        "Phase 2 start — subnet=%s  live_hosts=%d  threads=%d  "
        "profile=%s  timeout=%ds",
        subnet_str, live_count, max_workers, scan_type, timeout,
    )

    # ------------------------------------------------------------------ #
    # Phase 2: Targeted Port Scan (only live IPs)                         #
    # ------------------------------------------------------------------ #
    results: list[ScanResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit one Future per confirmed-live IP.
        future_to_ip: dict = {
            executor.submit(_scan_worker, ip, scan_type, timeout): ip
            for ip in live_ips
        }

        completed = 0
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            completed += 1

            try:
                scan_result = future.result()
            except NmapNotFoundError:
                logger.error(
                    "nmap not found during Phase 2 — aborting all workers."
                )
                executor.shutdown(wait=False, cancel_futures=True)
                raise
            except Exception as exc:
                logger.warning(
                    "Unexpected error scanning '%s': %s — skipping.", ip, exc
                )
                continue

            if scan_result is not None:
                results.append(scan_result)
                logger.info(
                    "  [%d/%d]  '%s' — port scan complete.",
                    completed, live_count, ip,
                )
            else:
                logger.debug(
                    "  [%d/%d]  '%s' — skipped (no port data).",
                    completed, live_count, ip,
                )

    # Sort results numerically by IP address.
    results.sort(key=lambda r: ipaddress.IPv4Address(r.target))

    logger.info(
        "Subnet scan complete: %s — %d/%d live hosts produced port data.",
        subnet_str, len(results), live_count,
    )
    return results


# ---------------------------------------------------------------------------
# Public API — primary entry point for main.py
# ---------------------------------------------------------------------------

def run_scan_from_args(args: argparse.Namespace) -> list[ScanResult]:
    """
    Unpack a validated argparse.Namespace and execute the correct scan path.

    Always returns list[ScanResult]:
      - Single IP / domain → Phase 1 host check + [ScanResult] if up
      - CIDR subnet        → Phase 1 ping sweep → Phase 2 port scan

    Parameters
    ----------
    args : argparse.Namespace
        Must contain: target (str), scan_type (str), timeout (int),
        threads (int).  All produced by cli.parse_args().

    Returns
    -------
    list[ScanResult]
        Empty if no hosts responded (subnet) or host was down (single).

    Raises
    ------
    AttributeError     — Namespace missing required attributes.
    NmapNotFoundError  — nmap not on PATH.
    ScanTimeoutError   — single-host port scan exceeded timeout.
    ScanError          — non-zero nmap exit or subprocess failure.
    """
    required = ("target", "scan_type", "timeout", "threads")
    missing  = [a for a in required if not hasattr(args, a)]
    if missing:
        raise AttributeError(
            f"argparse.Namespace is missing: {missing}. "
            "Ensure cli.parse_args() produced this Namespace."
        )

    if not is_nmap_available():
        raise NmapNotFoundError(
            "nmap is not installed or not on PATH.\n"
            "  Debian/Ubuntu : sudo apt-get install nmap\n"
            "  macOS Homebrew: brew install nmap\n"
            "  Windows       : https://nmap.org/download.html"
        )

    # ------------------------------------------------------------------ #
    # Path A: Single IP or domain — verify host is up, then port-scan     #
    # ------------------------------------------------------------------ #
    if not cli.is_subnet(args.target):
        # Phase 1 for single hosts: quick liveness check before committing
        # to a full port scan.  If the host appears down, we warn but still
        # proceed — ICMP may be blocked even on live hosts.
        console.print(
            f"\n  [bold cyan][*][/bold cyan]  "
            f"Phase 1 — Verifying host [bold white]{args.target}[/bold white] …"
        )
        live = discover_live_hosts(target=args.target, timeout=args.timeout)
        if not live:
            console.print(
                f"  [bold yellow][!][/bold yellow]  "
                f"Host [white]{args.target}[/white] did not respond to ping probes.\n"
                "  [dim]Proceeding with port scan anyway "
                "(ICMP may be blocked).[/dim]\n"
            )
        else:
            console.print(
                f"  [bold green][+][/bold green]  "
                f"Host [bold green]{args.target}[/bold green] is up.  "
                "Starting port scan …\n"
            )

        # Always attempt the port scan for single hosts — ICMP-blocking
        # firewalls would produce false negatives otherwise.
        result = run_scan(
            target=args.target,
            scan_type=args.scan_type,
            timeout=args.timeout,
        )
        return [result]

    # ------------------------------------------------------------------ #
    # Path B: CIDR subnet — two-phase scan                                 #
    # ------------------------------------------------------------------ #
    network = ipaddress.IPv4Network(args.target, strict=False)

    return _run_subnet_scan(
        network=network,
        scan_type=args.scan_type,
        timeout=args.timeout,
        max_workers=args.threads,
    )


# ---------------------------------------------------------------------------
# Phase-2 placeholder
# ---------------------------------------------------------------------------

def run_scan_with_metadata(
    target: str,
    scan_type: str = _DEFAULT_SCAN_TYPE,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """PHASE-2 PLACEHOLDER — metadata dict for state-comparison workflows."""
    result = run_scan(target, scan_type=scan_type, timeout=timeout)
    return {
        "target":     result.target,
        "scan_type":  result.scan_type,
        "timestamp":  result.iso_timestamp,
        "stdout":     result.stdout,
        "stderr":     result.stderr,
        "returncode": result.returncode,
        "cmd":        result.cmd,
    }


# ---------------------------------------------------------------------------
# Stand-alone smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys as _sys

    test_target = _sys.argv[1] if len(_sys.argv) > 1 else "scanme.nmap.org"

    print(f"[scanner.py] nmap available : {is_nmap_available()}")
    print(f"[scanner.py] target         : {test_target}")
    print(f"[scanner.py] is_subnet      : {cli.is_subnet(test_target)}\n")

    # Quick discovery test
    print("[scanner.py] Running discover_live_hosts() …")
    live = discover_live_hosts(test_target, timeout=30)
    print(f"  Live hosts found: {live}\n")

    # Full pipeline test
    try:
        results = run_scan_from_args(
            argparse.Namespace(
                target=test_target,
                scan_type="fast",
                timeout=60,
                threads=10,
            )
        )
        for r in results:
            print(f"  [{r.target}] succeeded={r.succeeded}  "
                  f"ts={r.iso_timestamp}  stdout_len={len(r.stdout)}")
    except (NmapNotFoundError, ScanError, ScanTimeoutError) as exc:
        print(f"  Error: {exc}")
