"""
scanner.py — Core Scanner Module
==================================
Safely invokes Nmap via subprocess and returns structured output for
downstream parsing.  No exploitation, no brute-forcing — strictly port
enumeration and service detection for authorised targets only.

Public API
----------
    run_scan(target, scan_type, timeout)  -> ScanResult
    run_scan_from_args(args)              -> ScanResult   (accepts argparse.Namespace)
    is_nmap_available()                   -> bool

Supported scan profiles
-----------------------
    fast     : nmap -F          (top 100 ports, quickest sweep)
    service  : nmap -sV         (version/service detection, top 1000 ports)
    full     : nmap -p- -sV     (all 65535 ports + service version info)

Security model
--------------
    * subprocess.run() is called with shell=False at all times.
    * The command is always built as a strict list[str] — the target string
      is a single list element and is NEVER interpolated into a shell string.
    * No user-supplied value is ever joined into a command string.
    * extra_flags, when provided, must be a list[str]; a TypeError is raised
      for any other type, preventing accidental shell-string injection.
"""

from __future__ import annotations

import argparse
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Module-level logger
# Callers configure the root logger (e.g. in main.py); we just emit records.
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class NmapNotFoundError(EnvironmentError):
    """Raised when the nmap binary cannot be located on the system PATH."""


class ScanTimeoutError(TimeoutError):
    """Raised when the nmap process exceeds the configured wall-clock limit."""


class ScanError(RuntimeError):
    """Raised when nmap exits with a non-zero return code or another
    subprocess-level failure occurs."""


# ---------------------------------------------------------------------------
# Scan profiles
# ---------------------------------------------------------------------------

# Maps the validated scan-type name coming from cli.py to the exact list of
# nmap flags to use.  This is the ONLY place flags are defined — changing a
# profile here propagates everywhere automatically.
#
# Deliberately minimal: no -T timing flags, no OS detection, no scripting
# engine — those open doors to behaviours beyond simple port enumeration.
SCAN_PROFILES: dict[str, list[str]] = {
    "fast":    ["-F"],         # Top 100 most common ports
    "service": ["-sV"],        # Service/version detection, top 1000 ports
    "full":    ["-p-", "-sV"], # All 65535 ports + service version info
}

# Fallback when an unrecognised scan_type arrives (should not happen after
# cli.py validation, but defensive programming is cheap).
_DEFAULT_SCAN_TYPE: str = "fast"

# Default wall-clock timeout used when the caller does not specify one.
DEFAULT_TIMEOUT: int = 300  # 5 minutes


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """
    Structured container for a completed (or failed) Nmap execution.

    Attributes
    ----------
    target : str
        The validated IP address or domain that was scanned.
    scan_type : str
        The profile used ('fast', 'service', or 'full').
    stdout : str
        Raw standard-output text from nmap.  Feed this to parser.py.
    stderr : str
        Raw standard-error text from nmap.  Useful for diagnostics.
    returncode : int
        Process exit code.  0 = success.
    timestamp : datetime
        UTC timestamp recorded immediately before the subprocess call.
    cmd : list[str]
        The exact command list that was executed.  Logged for auditability.
    """
    target:     str
    scan_type:  str
    stdout:     str
    stderr:     str
    returncode: int
    timestamp:  datetime
    cmd:        list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def succeeded(self) -> bool:
        """True when nmap exited cleanly (returncode == 0)."""
        return self.returncode == 0

    @property
    def iso_timestamp(self) -> str:
        """ISO-8601 UTC timestamp string, e.g. '2025-06-19T10:30:00Z'."""
        return self.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def is_nmap_available() -> bool:
    """
    Return True if the nmap binary is found anywhere on the system PATH.

    Uses shutil.which() — no subprocess call required, no side effects.
    """
    found = shutil.which("nmap") is not None
    if not found:
        logger.warning(
            "nmap binary not found on PATH. "
            "Install it from https://nmap.org/download.html"
        )
    return found


def _build_cmd(
    target: str,
    scan_type: str,
    extra_flags: Optional[list[str]],
) -> list[str]:
    """
    Build the nmap command as a strict list of strings.

    Parameters
    ----------
    target : str
        Validated IP address or domain name.
    scan_type : str
        One of the keys in SCAN_PROFILES.
    extra_flags : list[str] | None
        Optional additional nmap flags.  Must be a list — never a string.

    Returns
    -------
    list[str]
        Complete command ready for subprocess.run(cmd, shell=False).

    Raises
    ------
    TypeError
        If extra_flags is not a list of strings (guards against accidental
        shell-string injection via this parameter).
    ValueError
        If extra_flags contains an empty string or a non-flag element that
        starts with a character other than '-' (basic sanity guard).
    """
    # --- Resolve profile --------------------------------------------------
    normalised = scan_type.lower().strip()
    if normalised not in SCAN_PROFILES:
        logger.warning(
            "Unknown scan_type '%s' — falling back to '%s'.",
            scan_type,
            _DEFAULT_SCAN_TYPE,
        )
        normalised = _DEFAULT_SCAN_TYPE

    profile_flags: list[str] = SCAN_PROFILES[normalised]

    # --- Base command -----------------------------------------------------
    # list[str] form: subprocess never passes this through a shell.
    cmd: list[str] = ["nmap"] + profile_flags

    # --- Extra flags (optional, caller-supplied) --------------------------
    if extra_flags is not None:
        if not isinstance(extra_flags, list):
            raise TypeError(
                f"extra_flags must be a list of strings, got {type(extra_flags).__name__}."
            )
        for flag in extra_flags:
            if not isinstance(flag, str):
                raise TypeError(
                    f"Every element of extra_flags must be a str, got {type(flag).__name__}."
                )
            if not flag:
                raise ValueError("extra_flags must not contain empty strings.")
            # Each flag must begin with '-' to prevent accidental target
            # or positional-argument injection through this parameter.
            if not flag.startswith("-"):
                raise ValueError(
                    f"extra_flags element '{flag}' does not look like an nmap flag "
                    "(expected it to start with '-')."
                )
        cmd.extend(extra_flags)

    # --- Target is always the final positional argument -------------------
    # Appended last so that no flag can be injected after it.
    cmd.append(target)

    return cmd


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_scan(
    target: str,
    scan_type: str = _DEFAULT_SCAN_TYPE,
    timeout: int = DEFAULT_TIMEOUT,
    extra_flags: Optional[list[str]] = None,
) -> ScanResult:
    """
    Execute an Nmap scan against *target* and return a :class:`ScanResult`.

    Parameters
    ----------
    target : str
        A validated IPv4 address or hostname (already sanitised by cli.py).
    scan_type : str
        Scan profile name — 'fast', 'service', or 'full'.  Defaults to
        'fast'.  Unknown values fall back to 'fast' with a warning.
    timeout : int
        Hard wall-clock limit in seconds.  Passed directly to
        subprocess.run(timeout=…).  Defaults to 300 s.
    extra_flags : list[str] | None
        Additional nmap flags as a list of strings.  Each element must start
        with '-' to prevent positional-argument injection.  Use sparingly and
        never pass untrusted data here.

    Returns
    -------
    ScanResult
        Dataclass containing stdout, stderr, returncode, timestamp, and the
        exact command that was run.

    Raises
    ------
    NmapNotFoundError
        If nmap is not installed or not on the system PATH.
    ScanTimeoutError
        If the scan exceeds *timeout* seconds.
    ScanError
        If nmap exits with a non-zero return code, or if subprocess itself
        raises an unexpected error.
    TypeError / ValueError
        If extra_flags is malformed (see _build_cmd).
    """
    # ------------------------------------------------------------------ #
    # 1. Pre-flight: confirm nmap is reachable                             #
    # ------------------------------------------------------------------ #
    if not is_nmap_available():
        raise NmapNotFoundError(
            "nmap is not installed or not on PATH.\n"
            "  Install guide: https://nmap.org/download.html\n"
            "  On Debian/Ubuntu: sudo apt-get install nmap\n"
            "  On macOS (Homebrew): brew install nmap\n"
            "  On Windows: download the installer from nmap.org"
        )

    # ------------------------------------------------------------------ #
    # 2. Build the command list                                            #
    # ------------------------------------------------------------------ #
    cmd = _build_cmd(target, scan_type, extra_flags)

    # Resolve the scan_type that _build_cmd actually used (may have
    # fallen back to default) so ScanResult reflects reality.
    effective_scan_type = scan_type.lower().strip()
    if effective_scan_type not in SCAN_PROFILES:
        effective_scan_type = _DEFAULT_SCAN_TYPE

    logger.info("Executing: %s", " ".join(cmd))

    # ------------------------------------------------------------------ #
    # 3. Record timestamp just before execution                            #
    # ------------------------------------------------------------------ #
    scan_timestamp = datetime.now(tz=timezone.utc)

    # ------------------------------------------------------------------ #
    # 4. Execute — shell=False is the default but stated explicitly for    #
    #    clarity and auditability.                                         #
    # ------------------------------------------------------------------ #
    try:
        result = subprocess.run(
            cmd,                    # strict list — never a shell string
            shell=False,            # explicit: NO shell interpretation
            capture_output=True,    # stdout and stderr captured separately
            text=True,              # decode bytes → str (UTF-8 by default)
            timeout=timeout,        # hard wall-clock limit from the user
        )

    except FileNotFoundError:
        # Belt-and-suspenders: nmap was found by shutil.which() above but
        # vanished before we could execute it (race condition on PATH).
        logger.error(
            "nmap binary disappeared between PATH check and execution."
        )
        raise NmapNotFoundError(
            "nmap binary could not be executed. "
            "It may have been removed or the PATH changed mid-run."
        )

    except subprocess.TimeoutExpired:
        logger.error(
            "Scan timed out after %ds for target '%s'.", timeout, target
        )
        raise ScanTimeoutError(
            f"Nmap scan timed out after {timeout}s against '{target}'.\n"
            "  Options:\n"
            "  • Use a faster scan profile:  -s fast\n"
            f"  • Increase the timeout:       --timeout {timeout * 2}"
        )

    except subprocess.SubprocessError as exc:
        logger.error("Subprocess error running nmap: %s", exc)
        raise ScanError(
            f"Failed to execute nmap: {exc}"
        ) from exc

    # ------------------------------------------------------------------ #
    # 5. Wrap into ScanResult                                              #
    # ------------------------------------------------------------------ #
    scan_result = ScanResult(
        target=target,
        scan_type=effective_scan_type,
        stdout=result.stdout.strip(),
        stderr=result.stderr.strip(),
        returncode=result.returncode,
        timestamp=scan_timestamp,
        cmd=cmd,
    )

    # ------------------------------------------------------------------ #
    # 6. Inspect the return code                                           #
    # ------------------------------------------------------------------ #
    if not scan_result.succeeded:
        # nmap writes diagnostic detail to stderr on failure.
        detail = scan_result.stderr or "No additional detail from nmap."
        logger.error(
            "nmap exited with code %d for target '%s'. Detail: %s",
            scan_result.returncode,
            target,
            detail,
        )
        raise ScanError(
            f"nmap exited with a non-zero return code ({scan_result.returncode}) "
            f"for target '{target}'.\n"
            f"  nmap stderr: {detail}"
        )

    # ------------------------------------------------------------------ #
    # 7. Warn if stdout is unexpectedly empty (host may be down / filtered)#
    # ------------------------------------------------------------------ #
    if not scan_result.stdout:
        logger.warning(
            "nmap produced no stdout for target '%s'. "
            "The host may be down, unreachable, or blocking all probes.",
            target,
        )

    logger.info(
        "Scan complete — target='%s', scan_type='%s', returncode=%d.",
        target,
        effective_scan_type,
        scan_result.returncode,
    )

    return scan_result


def run_scan_from_args(args: argparse.Namespace) -> ScanResult:
    """
    Convenience wrapper: unpack a validated ``argparse.Namespace`` from
    ``cli.parse_args()`` and delegate to :func:`run_scan`.

    This is the primary entry-point used by ``main.py``.

    Parameters
    ----------
    args : argparse.Namespace
        Must have the following attributes (all provided by cli.py):
            - target    (str)   validated IPv4 or domain
            - scan_type (str)   'fast', 'service', or 'full'
            - timeout   (int)   positive integer, seconds

    Returns
    -------
    ScanResult
        See :func:`run_scan`.

    Raises
    ------
    AttributeError
        If the Namespace is missing required attributes — signals a
        mismatch between cli.py and scanner.py that needs fixing.
    NmapNotFoundError, ScanTimeoutError, ScanError
        Propagated unchanged from :func:`run_scan`.
    """
    # Validate the Namespace shape before touching subprocess.
    required = ("target", "scan_type", "timeout")
    missing = [attr for attr in required if not hasattr(args, attr)]
    if missing:
        raise AttributeError(
            f"argparse.Namespace is missing required attributes: {missing}. "
            "Ensure cli.parse_args() produced this Namespace."
        )

    return run_scan(
        target=args.target,
        scan_type=args.scan_type,
        timeout=args.timeout,
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
    PHASE-2 PLACEHOLDER — Returns both the :class:`ScanResult` and a
    flat metadata dict suitable for state-comparison / asset-diffing.

    Parameters
    ----------
    target : str
        Validated IP address or hostname.
    scan_type : str
        Scan profile name.
    timeout : int
        Timeout in seconds.

    Returns
    -------
    dict
        {
            "target":     str,
            "scan_type":  str,
            "timestamp":  str  (ISO-8601 UTC),
            "stdout":     str,
            "stderr":     str,
            "returncode": int,
            "cmd":        list[str],
        }
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
# Run:  python scanner.py
# (requires nmap to be installed; uses a safe non-routable test target)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    test_target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"

    print(f"[scanner.py] nmap available: {is_nmap_available()}")
    print(f"[scanner.py] Testing scan profiles: {list(SCAN_PROFILES.keys())}")
    print(f"[scanner.py] Running 'fast' scan against: {test_target}\n")

    try:
        scan = run_scan(target=test_target, scan_type="fast", timeout=60)
        print(f"  succeeded  : {scan.succeeded}")
        print(f"  timestamp  : {scan.iso_timestamp}")
        print(f"  cmd        : {' '.join(scan.cmd)}")
        print(f"  returncode : {scan.returncode}")
        print(f"  stdout     :\n{scan.stdout[:500]}{'...' if len(scan.stdout) > 500 else ''}")
        if scan.stderr:
            print(f"  stderr     : {scan.stderr[:200]}")
    except NmapNotFoundError as e:
        print(f"  [NmapNotFoundError] {e}")
    except ScanTimeoutError as e:
        print(f"  [ScanTimeoutError] {e}")
    except ScanError as e:
        print(f"  [ScanError] {e}")
