"""
cli.py — Command-Line Interface Module  [LumenRecon v2.0]
==========================================================
Provides a robust, validated argument parser for LumenRecon.

V2.0 additions
--------------
  - -t / --target now accepts CIDR subnet notation (e.g. 192.168.1.0/24)
    in addition to single IPv4 addresses and domain names.
  - -T / --threads sets the worker-thread count for subnet scans (1–50).

Usage examples
--------------
    python main.py -t 192.168.1.1
    python main.py -t 192.168.1.0/24 -T 20 -s fast
    python main.py -t example.com -o json -s service --timeout 120

Security notes
--------------
  - Target input is validated through a strict three-branch pipeline:
      1. IPv4 single address   (ipaddress.IPv4Address)
      2. CIDR subnet notation  (ipaddress.IPv4Network)
      3. Domain / hostname     (RFC-1123 compiled regex)
    Only strings that survive one of these branches ever reach the scanner.
  - Reserved/special address ranges are blocked on both single IPs and the
    network address of a submitted subnet.
  - Thread count is hard-capped at 50 to prevent resource exhaustion.
  - No shell interpolation occurs anywhere in this module.
"""

import argparse
import ipaddress
import re
from typing import Optional


# ---------------------------------------------------------------------------
# Validation constants
# ---------------------------------------------------------------------------

# RFC-1123 hostname label allowlist regex.
# Intentionally rejects: labels > 63 chars, leading/trailing hyphens,
# pure-numeric labels (handled by ipaddress), shell metacharacters,
# path separators, and the '/' character (which would look like CIDR).
_DOMAIN_RE = re.compile(
    r"""
    ^                           # start of string
    (?!-)                       # label must not start with a hyphen
    (?:                         # one or more dot-separated labels
        [A-Za-z0-9]             # label starts with alphanumeric
        (?:[A-Za-z0-9\-]{0,61}  # up to 61 more alphanumeric / hyphen chars
        [A-Za-z0-9])?           # label ends with alphanumeric (if > 1 char)
        \.                      # dot separator
    )*
    [A-Za-z0-9]                 # TLD starts with alphanumeric
    (?:[A-Za-z0-9\-]{0,61}      # TLD body
    [A-Za-z0-9])?               # TLD ends with alphanumeric
    \.?                         # optional trailing dot (FQDN)
    $                           # end of string
    """,
    re.VERBOSE,
)

# Per RFC 1035 § 3.1 — maximum total length of a domain name.
_DOMAIN_MAX_LEN: int = 253

# Subnet size guard: refuse subnets larger than /16 (65534 usable hosts).
# This prevents accidental wide-area scanning on a mistyped prefix length.
# Adjust in authorised lab environments only.
_MAX_PREFIX_LEN_ALLOWED: int = 16   # /16 = up to 65534 hosts (absolute max)
_MIN_PREFIX_LEN_SAFE:    int = 16   # enforce same value as a hard floor

# Valid scan profiles — must stay in sync with scanner.SCAN_PROFILES.
_SCAN_TYPES: tuple[str, ...] = ("fast", "service", "full")

# Valid output formats.
_OUTPUT_FORMATS: tuple[str, ...] = ("json", "csv")

# Default values.
_DEFAULT_TIMEOUT: int = 300   # seconds
_DEFAULT_THREADS: int = 10    # worker threads for subnet scans
_MAX_THREADS:     int = 50    # hard ceiling to prevent resource exhaustion


# ---------------------------------------------------------------------------
# Input validators — used as argparse `type=` callables
# ---------------------------------------------------------------------------

def _validate_target(value: str) -> str:
    """
    Validate that *value* is one of:
      (a) A single well-formed, routable IPv4 address, or
      (b) A valid CIDR subnet (e.g. 192.168.1.0/24, prefix /16 to /32), or
      (c) A legal RFC-1123 domain / hostname.

    The validation pipeline is ordered from most-specific to least:
      IPv4Address  →  IPv4Network  →  domain regex

    Parameters
    ----------
    value : str
        Raw user-supplied string from the command line.

    Returns
    -------
    str
        The stripped, normalised target string.  For CIDR notation the
        network address is normalised (e.g. '192.168.1.5/24' becomes
        '192.168.1.0/24') so the scanner always receives a canonical form.

    Raises
    ------
    argparse.ArgumentTypeError
        On any validation failure, with a human-readable explanation.
    """
    cleaned = value.strip().lower()

    if not cleaned:
        raise argparse.ArgumentTypeError("Target must not be empty.")

    # ------------------------------------------------------------------ #
    # Branch 1: Single IPv4 address                                        #
    # ------------------------------------------------------------------ #
    # Only attempt this branch if the string contains no '/' character,
    # because '192.168.1.0/24' would parse as IPv4Address('192.168.1.0')
    # and silently discard the prefix length.
    if "/" not in cleaned:
        try:
            addr = ipaddress.IPv4Address(cleaned)
            _check_address_flags(addr, cleaned)   # raises on reserved ranges
            return cleaned
        except ValueError:
            pass   # Not a bare IPv4 address — try CIDR next.

    # ------------------------------------------------------------------ #
    # Branch 2: CIDR subnet notation                                       #
    # ------------------------------------------------------------------ #
    if "/" in cleaned:
        try:
            # strict=False: host bits set are silently zeroed so the user
            # can write 192.168.1.5/24 and get 192.168.1.0/24 back.
            network = ipaddress.IPv4Network(cleaned, strict=False)
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"'{value}' is not a valid IPv4 CIDR subnet.\n"
                "  Expected format: 192.168.1.0/24  (prefix length /8 – /32)"
            )

        # Validate the network address itself (not every host — the network
        # address represents the intent of the whole range).
        _check_address_flags(network.network_address, str(network.network_address))

        # Enforce a minimum prefix length to prevent scanning /8 or wider.
        if network.prefixlen < _MIN_PREFIX_LEN_SAFE:
            raise argparse.ArgumentTypeError(
                f"Subnet '{value}' has a /{network.prefixlen} prefix — "
                f"that covers {network.num_addresses:,} addresses.\n"
                f"  The minimum allowed prefix is /{_MIN_PREFIX_LEN_SAFE} "
                f"({2 ** (32 - _MIN_PREFIX_LEN_SAFE):,} addresses).\n"
                "  Use a more specific subnet or scan individual hosts."
            )

        # Return the canonical (host-bits-zeroed) CIDR string.
        return str(network)

    # ------------------------------------------------------------------ #
    # Branch 3: Domain / hostname                                          #
    # ------------------------------------------------------------------ #
    if len(cleaned) > _DOMAIN_MAX_LEN:
        raise argparse.ArgumentTypeError(
            f"Domain name too long ({len(cleaned)} chars; max {_DOMAIN_MAX_LEN})."
        )

    if not _DOMAIN_RE.match(cleaned):
        raise argparse.ArgumentTypeError(
            f"'{value}' is not a valid IPv4 address, CIDR subnet, or domain name.\n"
            "  Single IP  : 192.168.1.1\n"
            "  CIDR subnet: 192.168.1.0/24\n"
            "  Domain     : example.com"
        )

    # Reject purely numeric labels that look like malformed IPv4.
    labels = cleaned.rstrip(".").split(".")
    if all(label.isdigit() for label in labels):
        raise argparse.ArgumentTypeError(
            f"'{value}' looks like an IPv4 address but is not valid.\n"
            "  Each octet must be 0–255.  Example: 192.168.1.1"
        )

    return cleaned


def _check_address_flags(addr: ipaddress.IPv4Address, label: str) -> None:
    """
    Raise ArgumentTypeError if *addr* is a reserved range that should never
    be a scan target in a legitimate recon workflow.

    Parameters
    ----------
    addr : ipaddress.IPv4Address
        The address to check.
    label : str
        Human-readable label to include in the error message (the original
        user-supplied string or the network address string).

    Raises
    ------
    argparse.ArgumentTypeError
        If the address is loopback, unspecified, multicast, or link-local.
    """
    if addr.is_loopback:
        raise argparse.ArgumentTypeError(
            f"Loopback address '{label}' is not a valid scan target."
        )
    if addr.is_unspecified:
        raise argparse.ArgumentTypeError(
            f"Unspecified address '{label}' (0.0.0.0) is not a valid scan target."
        )
    if addr.is_multicast:
        raise argparse.ArgumentTypeError(
            f"Multicast address '{label}' is not a valid scan target."
        )
    if addr.is_link_local:
        raise argparse.ArgumentTypeError(
            f"Link-local address '{label}' is not a valid scan target."
        )


def _validate_output(value: str) -> str:
    """
    Constrain --output to the exact strings 'json' or 'csv'.

    Parameters
    ----------
    value : str
        Raw user-supplied string.

    Returns
    -------
    str
        Lower-cased, validated format string.

    Raises
    ------
    argparse.ArgumentTypeError
        If the value is not one of the accepted format strings.
    """
    normalised = value.strip().lower()
    if normalised not in _OUTPUT_FORMATS:
        raise argparse.ArgumentTypeError(
            f"Output format '{value}' is not supported. "
            f"Choose from: {', '.join(_OUTPUT_FORMATS)}"
        )
    return normalised


def _validate_timeout(value: str) -> int:
    """
    Validate that --timeout is a positive integer ≤ 86400 (24 h).

    Parameters
    ----------
    value : str
        Raw user-supplied string.

    Returns
    -------
    int
        Validated timeout in seconds.

    Raises
    ------
    argparse.ArgumentTypeError
        If the value is not a positive integer or exceeds the upper bound.
    """
    try:
        seconds = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Timeout '{value}' must be an integer (seconds)."
        )

    if seconds <= 0:
        raise argparse.ArgumentTypeError(
            "Timeout must be a positive integer (e.g. 60, 300)."
        )
    if seconds > 86_400:
        raise argparse.ArgumentTypeError(
            f"Timeout {seconds}s exceeds the maximum allowed value of 86400s (24 h)."
        )
    return seconds


def _validate_threads(value: str) -> int:
    """
    Validate that -T / --threads is a positive integer between 1 and
    _MAX_THREADS (inclusive).

    Keeping the ceiling at 50 threads prevents runaway resource consumption
    when scanning large subnets on resource-constrained machines.

    Parameters
    ----------
    value : str
        Raw user-supplied string.

    Returns
    -------
    int
        Validated thread count.

    Raises
    ------
    argparse.ArgumentTypeError
        If the value is outside the permitted range.
    """
    try:
        count = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Thread count '{value}' must be an integer."
        )

    if count < 1:
        raise argparse.ArgumentTypeError(
            "Thread count must be at least 1."
        )
    if count > _MAX_THREADS:
        raise argparse.ArgumentTypeError(
            f"Thread count {count} exceeds the maximum of {_MAX_THREADS}.\n"
            "  High thread counts can overwhelm network equipment and your machine.\n"
            f"  Use -T {_MAX_THREADS} or lower."
        )
    return count


# ---------------------------------------------------------------------------
# Parser factory
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    """
    Construct and return the fully configured ArgumentParser for LumenRecon.

    Separating construction from parsing makes this trivial to unit-test
    without touching sys.argv or triggering side-effects.

    Returns
    -------
    argparse.ArgumentParser
        Ready for .parse_args().
    """
    p = argparse.ArgumentParser(
        prog="lumenrecon",
        description=(
            "LumenRecon v2.0 — Advanced Network Asset Monitor\n"
            "The Network Illuminator: safely illuminating hidden services and\n"
            "open ports within authorised networks for defensive posture assessment.\n"
            "Supports single IPs, domain names, and CIDR subnet scanning.\n"
            "For authorised use on permitted targets only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )

    # ------------------------------------------------------------------ #
    # Required                                                             #
    # ------------------------------------------------------------------ #
    p.add_argument(
        "-t", "--target",
        required=True,
        metavar="<IP|CIDR|DOMAIN>",
        type=_validate_target,
        help=(
            "Target to scan. Accepted formats:\n"
            "  Single IPv4 : 192.168.1.1\n"
            "  CIDR subnet : 192.168.1.0/24  (prefix /16 to /32)\n"
            "  Domain name : example.com\n"
            "Must be a host or network you are authorised to test."
        ),
    )

    # ------------------------------------------------------------------ #
    # Optional — output format                                             #
    # ------------------------------------------------------------------ #
    p.add_argument(
        "-o", "--output",
        required=False,
        default=None,
        metavar="<json|csv>",
        type=_validate_output,
        help=(
            "Save the scan report to a file in reports/. "
            "Accepted values: json, csv. "
            "Omit to display results in the terminal only."
        ),
    )

    # ------------------------------------------------------------------ #
    # Optional — scan profile                                              #
    # ------------------------------------------------------------------ #
    p.add_argument(
        "-s", "--scan-type",
        dest="scan_type",
        required=False,
        default="fast",
        choices=_SCAN_TYPES,
        metavar="<fast|service|full>",
        help=(
            "Nmap scan profile. "
            "fast=top-100 ports (default), "
            "service=version detection on top-1000 ports, "
            "full=all 65535 ports + version detection."
        ),
    )

    # ------------------------------------------------------------------ #
    # Optional — per-host timeout                                          #
    # ------------------------------------------------------------------ #
    p.add_argument(
        "--timeout",
        required=False,
        default=_DEFAULT_TIMEOUT,
        metavar="<seconds>",
        type=_validate_timeout,
        help=(
            f"Per-host scan timeout in seconds. "
            f"Default: {_DEFAULT_TIMEOUT}s. "
            "Increase for slow networks or full-port scans."
        ),
    )

    # ------------------------------------------------------------------ #
    # Optional — thread count (v2.0, subnet scans only)                   #
    # ------------------------------------------------------------------ #
    p.add_argument(
        "-T", "--threads",
        required=False,
        default=_DEFAULT_THREADS,
        metavar=f"<1–{_MAX_THREADS}>",
        type=_validate_threads,
        help=(
            f"Number of parallel worker threads for subnet scanning. "
            f"Default: {_DEFAULT_THREADS}. "
            f"Maximum: {_MAX_THREADS}. "
            "Has no effect when scanning a single IP or domain."
        ),
    )

    return p


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """
    Parse, validate, and return the command-line arguments.

    The single entry-point consumed by ``main.py``.  All validation is
    performed by the ``type=`` callables registered above — any failure
    causes argparse to print a clean error message and call sys.exit(2).

    Parameters
    ----------
    argv : list[str] | None
        Argument list to parse.  Defaults to sys.argv[1:] when None.
        Pass an explicit list in unit tests to avoid touching sys.argv.

    Returns
    -------
    argparse.Namespace
        Attributes:
            target    (str)          validated IPv4, CIDR, or domain
            output    (str | None)   'json', 'csv', or None
            scan_type (str)          'fast', 'service', or 'full'
            timeout   (int)          positive integer, seconds
            threads   (int)          1–50, worker thread count
    """
    return _build_parser().parse_args(argv)


# ---------------------------------------------------------------------------
# Helpers for callers to inspect the parsed target type
# ---------------------------------------------------------------------------

def is_subnet(target: str) -> bool:
    """
    Return True if *target* is a CIDR subnet string (contains '/').

    This is the canonical way for scanner.py and main.py to branch
    between single-host and multi-host scan paths without re-parsing.

    Parameters
    ----------
    target : str
        A string that was previously returned by _validate_target().
    """
    return "/" in target


# ---------------------------------------------------------------------------
# Stand-alone smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    args = parse_args()
    print("[cli.py] Parsed arguments:")
    print(f"  target    = {args.target!r}  (subnet={is_subnet(args.target)})")
    print(f"  output    = {args.output!r}")
    print(f"  scan_type = {args.scan_type!r}")
    print(f"  timeout   = {args.timeout!r}")
    print(f"  threads   = {args.threads!r}")
