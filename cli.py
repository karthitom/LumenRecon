"""
cli.py — Command-Line Interface Module
========================================
Provides a robust, validated argument parser for the Recon Tool.

Usage examples:
    python main.py -t 192.168.1.1
    python main.py -t example.com -o json --scan-type service --timeout 120

Security notes:
    - Target input is validated against a strict allowlist regex and the
      standard-library `ipaddress` module before it ever reaches the scanner.
    - No shell interpolation of user-supplied values occurs here; the raw
      validated string is passed as a list element to subprocess in scanner.py.
    - Output format is constrained to an explicit choices list — no free-form
      strings can reach the file-writing layer.
"""

import argparse
import ipaddress
import re
import sys
from typing import Optional


# ---------------------------------------------------------------------------
# Validation constants
# ---------------------------------------------------------------------------

# RFC-1123 hostname label: 1-63 chars, alphanumeric or hyphens, no leading/
# trailing hyphen.  A full domain is one or more such labels separated by dots,
# with an optional trailing dot (FQDN).  TLD must be at least 2 characters.
#
# This intentionally does NOT accept:
#   - Labels longer than 63 characters
#   - Labels starting or ending with a hyphen
#   - Pure numeric labels that would look like IPv4 octets (those are handled
#     separately by the ipaddress module)
#   - Wildcards, shell metacharacters, or path separators
_DOMAIN_RE = re.compile(
    r"""
    ^                           # start of string
    (?!-)                       # label must not start with a hyphen
    (?:                         # one or more dot-separated labels
        [A-Za-z0-9]             # label starts with alphanumeric
        (?:[A-Za-z0-9\-]{0,61}  # up to 61 more alphanum/hyphen chars
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

# Maximum total length of a domain name per RFC 1035 § 3.1.
_DOMAIN_MAX_LEN: int = 253

# Valid scan profiles (must stay in sync with scanner.SCAN_PROFILES).
_SCAN_TYPES: tuple[str, ...] = ("fast", "service", "full")

# Valid output formats.
_OUTPUT_FORMATS: tuple[str, ...] = ("json", "csv")

# Default scan timeout in seconds (mirrors scanner.DEFAULT_TIMEOUT).
_DEFAULT_TIMEOUT: int = 300


# ---------------------------------------------------------------------------
# Input validators — used as argparse `type` callables
# ---------------------------------------------------------------------------

def _validate_target(value: str) -> str:
    """
    Validate that *value* is either a well-formed IPv4 address or a legal
    domain / hostname.

    Parameters
    ----------
    value : str
        Raw user-supplied string from the command line.

    Returns
    -------
    str
        The stripped, lower-cased target string if valid.

    Raises
    ------
    argparse.ArgumentTypeError
        If the value fails both IPv4 and domain validation, so argparse can
        emit a clean error and exit without a traceback.
    """
    # Strip surrounding whitespace; lower-case for normalisation.
    cleaned = value.strip().lower()

    if not cleaned:
        raise argparse.ArgumentTypeError("Target must not be empty.")

    # --- 1. Try IPv4 first (ipaddress handles all edge cases) -------------
    try:
        addr = ipaddress.IPv4Address(cleaned)

        # Reject reserved/special ranges that should never be scan targets
        # in a legitimate recon workflow (loopback, link-local, multicast,
        # unspecified).  You may relax these guards in a lab environment.
        if addr.is_loopback:
            raise argparse.ArgumentTypeError(
                f"Loopback address '{cleaned}' is not a valid scan target."
            )
        if addr.is_unspecified:
            raise argparse.ArgumentTypeError(
                f"Unspecified address '{cleaned}' (0.0.0.0) is not a valid scan target."
            )
        if addr.is_multicast:
            raise argparse.ArgumentTypeError(
                f"Multicast address '{cleaned}' is not a valid scan target."
            )
        if addr.is_link_local:
            raise argparse.ArgumentTypeError(
                f"Link-local address '{cleaned}' is not a valid scan target."
            )

        # Valid, routable (or private) IPv4 — accept it.
        return cleaned

    except ValueError:
        pass  # Not an IPv4 — fall through to domain check.

    # --- 2. Try domain / hostname -----------------------------------------
    if len(cleaned) > _DOMAIN_MAX_LEN:
        raise argparse.ArgumentTypeError(
            f"Domain name too long ({len(cleaned)} chars; max {_DOMAIN_MAX_LEN})."
        )

    if not _DOMAIN_RE.match(cleaned):
        raise argparse.ArgumentTypeError(
            f"'{value}' is not a valid IPv4 address or domain name.\n"
            "  Expected examples: 192.168.1.1  |  example.com  |  sub.domain.org"
        )

    # Reject purely numeric labels (e.g. "192.168.1.999") that look like a
    # malformed IPv4 but aren't a valid hostname either.
    labels = cleaned.rstrip(".").split(".")
    if all(label.isdigit() for label in labels):
        raise argparse.ArgumentTypeError(
            f"'{value}' looks like an IPv4 address but is not valid.\n"
            "  Each octet must be 0–255. Expected example: 192.168.1.1"
        )

    return cleaned


def _validate_output(value: str) -> str:
    """
    Constrain the -o / --output argument to the exact strings 'json' or
    'csv'.  Argparse's built-in `choices=` would also work, but using a
    custom validator gives a friendlier, lower-case normalised error.

    Parameters
    ----------
    value : str
        Raw user-supplied string.

    Returns
    -------
    str
        Lower-cased format string if valid.

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
    Validate that the timeout is a positive integer within a sensible range.

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
            "Timeout must be a positive integer (e.g., 60, 300)."
        )

    # Soft upper cap: 24 hours.  Adjust if you genuinely need longer scans.
    if seconds > 86_400:
        raise argparse.ArgumentTypeError(
            f"Timeout {seconds}s exceeds the maximum allowed value of 86400s (24 h)."
        )

    return seconds


# ---------------------------------------------------------------------------
# Parser factory
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    """
    Construct and return the ArgumentParser for the Recon Tool CLI.

    Keeping parser construction in its own function makes it trivial to unit-
    test argument definitions without side-effects.

    Returns
    -------
    argparse.ArgumentParser
        Fully configured parser ready for `.parse_args()`.
    """
    parser = argparse.ArgumentParser(
        prog="recon_tool",
        description=(
            "Recon Tool — Automated Network Reconnaissance & Asset Monitor\n"
            "For authorized use on permitted targets only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )

    # ------------------------------------------------------------------ #
    # Required argument                                                    #
    # ------------------------------------------------------------------ #
    parser.add_argument(
        "-t", "--target",
        required=True,
        metavar="<IP|DOMAIN>",
        type=_validate_target,           # custom validator runs inline
        help=(
            "Target IPv4 address (e.g. 192.168.1.1) or domain name "
            "(e.g. example.com) to scan. "
            "Must be a host you are authorised to test."
        ),
    )

    # ------------------------------------------------------------------ #
    # Optional: output format                                              #
    # ------------------------------------------------------------------ #
    parser.add_argument(
        "-o", "--output",
        required=False,
        default=None,
        metavar="<json|csv>",
        type=_validate_output,           # constrained to 'json' or 'csv'
        help=(
            "Save the scan report to a file. "
            "Accepted values: json, csv. "
            "If omitted, results are printed to the terminal only."
        ),
    )

    # ------------------------------------------------------------------ #
    # Optional: scan type                                                  #
    # ------------------------------------------------------------------ #
    parser.add_argument(
        "-s", "--scan-type",
        dest="scan_type",                # maps to args.scan_type
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
    # Optional: timeout                                                    #
    # ------------------------------------------------------------------ #
    parser.add_argument(
        "--timeout",
        required=False,
        default=_DEFAULT_TIMEOUT,
        metavar="<seconds>",
        type=_validate_timeout,
        help=(
            f"Maximum seconds to wait for the scan to complete. "
            f"Default: {_DEFAULT_TIMEOUT}s. "
            "Increase for large subnets or slow networks."
        ),
    )

    return parser


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """
    Parse, validate, and return the command-line arguments.

    This is the single entry-point consumed by ``main.py``.  Validation is
    performed by the `type=` callables registered on each argument — any
    failure causes argparse to print a clean error and call ``sys.exit(2)``
    automatically, so callers do not need to wrap this in a try/except.

    Parameters
    ----------
    argv : list[str] | None
        Argument list to parse.  Defaults to ``sys.argv[1:]`` when ``None``.
        Pass an explicit list in tests to avoid touching the real argv.

    Returns
    -------
    argparse.Namespace
        Namespace with the following attributes:
            - target    (str)            validated IPv4 or domain
            - output    (str | None)     'json', 'csv', or None
            - scan_type (str)            'fast', 'service', or 'full'
            - timeout   (int)            positive integer, seconds
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args


# ---------------------------------------------------------------------------
# Stand-alone smoke-test (python cli.py -t 192.168.1.1 -o json)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parsed = parse_args()
    print(f"[cli.py] Parsed arguments:")
    print(f"  target    = {parsed.target!r}")
    print(f"  output    = {parsed.output!r}")
    print(f"  scan_type = {parsed.scan_type!r}")
    print(f"  timeout   = {parsed.timeout!r}")
