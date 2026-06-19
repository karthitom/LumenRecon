"""
scanner.py — Core Scanner Module  [LumenRecon v2.0]
=====================================================
Safely invokes Nmap via subprocess and returns structured output for
downstream parsing.  No exploitation, no brute-forcing — strictly port
enumeration and service detection for authorised targets only.

Public API
----------
    run_scan(target, scan_type, timeout)         -> ScanResult
    run_scan_from_args(args)                     -> list[ScanResult]
    is_nmap_available()                          -> bool

V2.0 additions
--------------
    run_scan_from_args now returns list[ScanResult] in ALL cases:
      - Single IP / domain → list with exactly one element.
      - CIDR subnet        → list with one element per responsive host,
                             using ThreadPoolExecutor for parallelism.

    _scan_worker(ip, scan_type, timeout)         -> ScanResult | None
        Internal thread worker.  Returns None for hosts that are down or
        produce no usable output (filtered out before returning to caller).

    _run_subnet_scan(network, scan_type, timeout, max_workers)
                                                 -> list[ScanResult]
        Iterates usable hosts in *network*, submits each to the thread
        pool, collects and filters results.

Security model
--------------
    * subprocess.run() is called with shell=False at all times.
    * The command is always built as a strict list[str].
    * The target IP string is a single, final list element — never
      interpolated into a shell string.
    * extra_flags elements must start with '-' (positional-injection guard).
    * ThreadPoolExecutor workers are stateless; each owns its own
      subprocess call and ScanResult, so there is no shared mutable state
      between threads.
    * Thread count is bounded by the value validated in cli.py (max 50).
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import cli   # only used for cli.is_subnet() — no circular dependency risk

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class NmapNotFoundError(EnvironmentError):
    """Raised when the nmap binary cannot be located on the system PATH."""


class ScanTimeoutError(TimeoutError):
    """Raised when an nmap process exceeds the configured wall-clock limit.
    In subnet mode this is per-host; the overall scan continues."""


class ScanError(RuntimeError):
    """Raised when nmap exits with a non-zero return code or a subprocess
    failure occurs that prevents result collection."""


# ---------------------------------------------------------------------------
# Scan profiles
# ---------------------------------------------------------------------------

# Mapping from validated scan-type name → exact nmap flags.
# This is the single source of truth — change here and it propagates.
# Deliberately minimal: no timing flags, no OS detection, no NSE scripts.
SCAN_PROFILES: dict[str, list[str]] = {
    "fast":    ["-F"],          # Top 100 most common ports
    "service": ["-sV"],         # Service/version detection, top 1000 ports
    "full":    ["-p-", "-sV"],  # All 65535 ports + service version info
}

_DEFAULT_SCAN_TYPE: str = "fast"
DEFAULT_TIMEOUT:    int = 300   # seconds


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
        """ISO-8601 UTC timestamp, e.g. '2025-06-19T10:30:00Z'."""
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
    """
    Return the normalised scan_type key, falling back to the default if
    the value is unrecognised.  Logs a warning on fallback.
    """
    normalised = scan_type.lower().strip()
    if normalised not in SCAN_PROFILES:
        logger.warning(
            "Unknown scan_type '%s' — falling back to '%s'.",
            scan_type,
            _DEFAULT_SCAN_TYPE,
        )
        return _DEFAULT_SCAN_TYPE
    return normalised


def _build_cmd(
    target: str,
    scan_type: str,
    extra_flags: Optional[list[str]] = None,
) -> list[str]:
    """
    Build the nmap command as a strict list[str].

    The target is always the final element so no flag can be appended
    after it.  extra_flags elements must start with '-' to prevent
    positional-argument injection.

    Parameters
    ----------
    target : str
        Validated single IP address string.
    scan_type : str
        Resolved key from SCAN_PROFILES.
    extra_flags : list[str] | None
        Optional additional nmap flags.  Every element must be a str
        starting with '-'.

    Returns
    -------
    list[str]
        Complete command ready for subprocess.run(cmd, shell=False).

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

    # Target is always the final positional argument.
    cmd.append(target)
    return cmd


# ---------------------------------------------------------------------------
# Core single-host scanner
# ---------------------------------------------------------------------------

def run_scan(
    target: str,
    scan_type: str = _DEFAULT_SCAN_TYPE,
    timeout: int = DEFAULT_TIMEOUT,
    extra_flags: Optional[list[str]] = None,
) -> ScanResult:
    """
    Execute an Nmap scan against a single *target* and return a ScanResult.

    This function is the low-level primitive.  Subnet scanning builds on
    top of it via _scan_worker / _run_subnet_scan.

    Parameters
    ----------
    target : str
        A validated single IPv4 address string or hostname.
    scan_type : str
        Scan profile: 'fast', 'service', or 'full'.
    timeout : int
        Hard wall-clock limit in seconds (passed directly to subprocess).
    extra_flags : list[str] | None
        Optional additional nmap flags (see _build_cmd).

    Returns
    -------
    ScanResult

    Raises
    ------
    NmapNotFoundError  — nmap missing from PATH.
    ScanTimeoutError   — scan exceeded the timeout.
    ScanError          — non-zero nmap exit code or subprocess failure.
    """
    # --- Pre-flight -------------------------------------------------------
    if not is_nmap_available():
        raise NmapNotFoundError(
            "nmap is not installed or not on PATH.\n"
            "  Debian/Ubuntu : sudo apt-get install nmap\n"
            "  macOS Homebrew: brew install nmap\n"
            "  Windows       : https://nmap.org/download.html"
        )

    # --- Build command ----------------------------------------------------
    effective_type = _resolve_scan_type(scan_type)
    cmd = _build_cmd(target, effective_type, extra_flags)

    logger.info("Executing: %s", " ".join(cmd))
    scan_timestamp = datetime.now(tz=timezone.utc)

    # --- Execute ----------------------------------------------------------
    try:
        result = subprocess.run(
            cmd,                 # strict list — never a shell string
            shell=False,         # explicit: NO shell interpretation
            capture_output=True, # stdout and stderr captured separately
            text=True,           # decode bytes → str (UTF-8 default)
            timeout=timeout,     # hard wall-clock limit
        )
    except FileNotFoundError:
        # Race condition: nmap vanished after shutil.which() confirmed it.
        logger.error("nmap binary disappeared between PATH check and exec.")
        raise NmapNotFoundError(
            "nmap binary could not be executed — it may have been removed."
        )
    except subprocess.TimeoutExpired:
        logger.warning(
            "Scan timed out after %ds for target '%s'.", timeout, target
        )
        raise ScanTimeoutError(
            f"Nmap timed out after {timeout}s for '{target}'.\n"
            f"  Try a faster profile (-s fast) or increase --timeout."
        )
    except subprocess.SubprocessError as exc:
        logger.error("Subprocess error running nmap: %s", exc)
        raise ScanError(f"Failed to execute nmap: {exc}") from exc

    # --- Wrap result ------------------------------------------------------
    scan_result = ScanResult(
        target=target,
        scan_type=effective_type,
        stdout=result.stdout.strip(),
        stderr=result.stderr.strip(),
        returncode=result.returncode,
        timestamp=scan_timestamp,
        cmd=cmd,
    )

    # --- Check exit code --------------------------------------------------
    if not scan_result.succeeded:
        detail = scan_result.stderr or "No additional detail from nmap."
        logger.error(
            "nmap returned code %d for '%s'.  Detail: %s",
            scan_result.returncode, target, detail,
        )
        raise ScanError(
            f"nmap exited with code {scan_result.returncode} for '{target}'.\n"
            f"  stderr: {detail}"
        )

    if not scan_result.stdout:
        logger.warning(
            "nmap produced no output for '%s'.  "
            "Host may be down or blocking all probes.", target,
        )

    logger.info(
        "Scan complete — target='%s' type='%s' rc=%d.",
        target, effective_type, scan_result.returncode,
    )
    return scan_result


# ---------------------------------------------------------------------------
# Thread worker  — called by the ThreadPoolExecutor, one per host
# ---------------------------------------------------------------------------

def _scan_worker(
    ip: str,
    scan_type: str,
    timeout: int,
) -> Optional[ScanResult]:
    """
    Scan a single IP address and return the ScanResult, or None if the
    host appears to be down or produced no open-port data.

    This function is designed to be called from a ThreadPoolExecutor.
    It is intentionally tolerant — per-host errors are logged but do not
    propagate, keeping the overall subnet scan alive.

    Parameters
    ----------
    ip : str
        A single IPv4 address string (produced by iterating
        IPv4Network.hosts()).
    scan_type : str
        Scan profile name.
    timeout : int
        Per-host wall-clock timeout in seconds.

    Returns
    -------
    ScanResult | None
        A ScanResult when the host responds and has open/filtered ports.
        None when the host is down, unresponsive, or nmap found nothing.
    """
    try:
        result = run_scan(target=ip, scan_type=scan_type, timeout=timeout)
    except ScanTimeoutError:
        # Per-host timeout in a subnet scan is not fatal — host is likely
        # filtered or unreachable; skip it silently.
        logger.debug("Host '%s' timed out — skipping.", ip)
        return None
    except ScanError as exc:
        # Non-zero nmap exit usually means host is down.  Skip quietly.
        logger.debug("Host '%s' scan error (likely down): %s", ip, exc)
        return None
    except NmapNotFoundError:
        # nmap vanished mid-scan — re-raise so the pool manager can abort.
        raise

    # Drop results with empty stdout — host is down or blocking all probes.
    if not result.has_data:
        logger.debug("Host '%s' returned no port data — skipping.", ip)
        return None

    return result


# ---------------------------------------------------------------------------
# Subnet scan manager
# ---------------------------------------------------------------------------

def _run_subnet_scan(
    network: ipaddress.IPv4Network,
    scan_type: str,
    timeout: int,
    max_workers: int,
) -> list[ScanResult]:
    """
    Scan all usable hosts in *network* in parallel using a thread pool.

    Each worker calls _scan_worker() which calls run_scan() which calls
    subprocess.run(shell=False) — the security model is identical to a
    single-host scan.  Workers share no mutable state.

    Parameters
    ----------
    network : ipaddress.IPv4Network
        The validated, canonical network to sweep.
    scan_type : str
        Scan profile name.
    timeout : int
        Per-host wall-clock timeout in seconds.
    max_workers : int
        Maximum number of concurrent nmap processes.  Bounded by cli.py
        to _MAX_THREADS (50).

    Returns
    -------
    list[ScanResult]
        Results for hosts that responded with port data, sorted by IP.
        Hosts that are down or unresponsive are silently excluded.

    Raises
    ------
    NmapNotFoundError
        Propagated immediately if nmap disappears during the sweep.
    """
    # Collect all usable host addresses as plain strings.
    # IPv4Network.hosts() excludes the network and broadcast addresses.
    host_ips: list[str] = [str(ip) for ip in network.hosts()]
    total = len(host_ips)

    logger.info(
        "Starting subnet scan: %s  hosts=%d  threads=%d  profile=%s  timeout=%ds",
        network, total, max_workers, scan_type, timeout,
    )

    results: list[ScanResult] = []

    # ThreadPoolExecutor is used as a context manager so all threads are
    # cleanly joined on exit (normal or exception).
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all hosts at once.  Each Future maps to one IP address.
        future_to_ip = {
            executor.submit(_scan_worker, ip, scan_type, timeout): ip
            for ip in host_ips
        }

        # Process results as they complete (not in submission order).
        # This is more efficient than waiting for all to finish before
        # processing any.
        completed = 0
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            completed += 1

            try:
                scan_result = future.result()
            except NmapNotFoundError:
                # nmap disappeared — cancel remaining futures and abort.
                logger.error(
                    "nmap not found during subnet scan — aborting all workers."
                )
                executor.shutdown(wait=False, cancel_futures=True)
                raise

            except Exception as exc:
                # Any other unexpected exception from the worker: log and
                # continue so one bad host doesn't kill the whole sweep.
                logger.warning(
                    "Unexpected error scanning '%s': %s — skipping.", ip, exc
                )
                continue

            if scan_result is not None:
                results.append(scan_result)
                logger.info(
                    "Host '%s' responded (%d/%d complete).",
                    ip, completed, total,
                )
            else:
                logger.debug(
                    "Host '%s' skipped — down or no data (%d/%d).",
                    ip, completed, total,
                )

    # Sort by IP address numerically for consistent, predictable output.
    results.sort(key=lambda r: ipaddress.IPv4Address(r.target))

    logger.info(
        "Subnet scan complete: %s — %d/%d hosts responded.",
        network, len(results), total,
    )
    return results


# ---------------------------------------------------------------------------
# Public API — primary entry point for main.py
# ---------------------------------------------------------------------------

def run_scan_from_args(args: argparse.Namespace) -> list[ScanResult]:
    """
    Parse the validated argparse.Namespace from cli.parse_args() and
    execute the appropriate scan path.

    Always returns list[ScanResult]:
      - Single IP / domain → [ScanResult]  (one-element list)
      - CIDR subnet        → [ScanResult, ...]  (one per responsive host)

    Parameters
    ----------
    args : argparse.Namespace
        Must contain: target (str), scan_type (str), timeout (int),
        threads (int).  All produced by cli.parse_args().

    Returns
    -------
    list[ScanResult]
        May be empty if a subnet scan finds no responsive hosts.

    Raises
    ------
    AttributeError       — Namespace missing required attributes.
    NmapNotFoundError    — nmap not on PATH.
    ScanTimeoutError     — single-host scan exceeded timeout.
    ScanError            — single-host scan returned non-zero exit code.
    """
    # Validate Namespace shape before touching subprocess.
    required = ("target", "scan_type", "timeout", "threads")
    missing  = [a for a in required if not hasattr(args, a)]
    if missing:
        raise AttributeError(
            f"argparse.Namespace is missing: {missing}. "
            "Ensure cli.parse_args() produced this Namespace."
        )

    # Pre-flight nmap check applies to both paths.
    if not is_nmap_available():
        raise NmapNotFoundError(
            "nmap is not installed or not on PATH.\n"
            "  Debian/Ubuntu : sudo apt-get install nmap\n"
            "  macOS Homebrew: brew install nmap\n"
            "  Windows       : https://nmap.org/download.html"
        )

    # ------------------------------------------------------------------ #
    # Path A: Single IP or domain                                          #
    # ------------------------------------------------------------------ #
    if not cli.is_subnet(args.target):
        result = run_scan(
            target=args.target,
            scan_type=args.scan_type,
            timeout=args.timeout,
        )
        return [result]

    # ------------------------------------------------------------------ #
    # Path B: CIDR subnet — multi-threaded sweep                          #
    # ------------------------------------------------------------------ #
    # The target was already validated and canonicalised by cli.py, so
    # strict=False is safe here.
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
    """
    PHASE-2 PLACEHOLDER — Returns structured metadata alongside raw output.
    Useful for state-comparison / asset-diffing workflows.
    """
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
    print(f"[scanner.py] profiles       : {list(SCAN_PROFILES.keys())}")
    print(f"[scanner.py] target         : {test_target}")
    print(f"[scanner.py] is_subnet      : {cli.is_subnet(test_target)}\n")

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
