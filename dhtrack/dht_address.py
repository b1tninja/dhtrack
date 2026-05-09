"""
DHT address handling utilities for IPv4/IPv6 normalization.

Uses Python's built-in ``ipaddress`` module to detect, convert, and
normalize IPv4-mapped IPv6 addresses (e.g. ``::ffff:1.2.3.4``) throughout
the DHT system.  This eliminates scattered string checks and ensures
consistent address family detection across all DHT operations.

Key functionality:
- Detect IPv4-mapped IPv6 addresses
- Normalize addresses to canonical form
- Determine correct address family from raw IP string
"""

import ipaddress
import socket


def is_ipv4_mapped(ip: str) -> bool:
    """Check if an IP address is an IPv4-mapped IPv6 address.

    IPv4-mapped addresses have the form ::ffff:x.x.x.x.

    Parameters
    ----------
    ip : str
        The IP address string to check.

    Returns
    -------
    bool
        True if this is an IPv4-mapped IPv6 address.
    """
    try:
        addr = ipaddress.ip_address(ip)
        # ipv4_mapped is only available on IPv6Address, not IPv4Address
        if isinstance(addr, ipaddress.IPv6Address):
            return addr.ipv4_mapped is not None
        return False
    except ValueError:
        return False


def to_canonical(ip: str) -> str:
    """Convert an IPv4-mapped IPv6 address to its IPv4 canonical form.

    ::ffff:192.168.1.1 -> 192.168.1.1
    Otherwise returns the original IP unchanged (compressed form).

    Parameters
    ----------
    ip : str
        The IP address string to normalize.

    Returns
    -------
    str
        The canonical IPv4 address, or the original IPv6 address
        if it's not IPv4-mapped.
    """
    try:
        return str(ipaddress.ip_address(ip).compressed)
    except ValueError:
        return ip


def determine_family(ip: str) -> tuple[int, str]:
    """Determine the correct address family and canonical IP for a given string.

    Parameters
    ----------
    ip : str
        The IP address string.

    Returns
    -------
    tuple[int, str]
        A tuple of (socket.AF_INET or socket.AF_INET6, canonical_ip).
    """
    try:
        addr = ipaddress.ip_address(ip)
        canonical = addr.compressed
        if isinstance(addr, ipaddress.IPv4Address):
            return socket.AF_INET, canonical
        return socket.AF_INET6, canonical
    except ValueError:
        return socket.AF_INET, ip


def is_reserved_ipv6(ip: str) -> bool:
    """Check if an IPv6 address is in a reserved/private range.

    Per BEP 42 and RFC 4291, the following IPv6 ranges are equivalent to
    IPv4 private/reserved addresses and should be treated specially:

    - ``::/96`` to ``::ffff:ffff:ffff:ffff`` — IPv4-mapped addresses
    - ``::ffff:0:0/96`` — IPv4-embedded IPv6 (same as above, legacy)
    - ``64:ff9b::/96`` — Well-Known Prefix (RFC 6052)
    - ``100::/64`` — Discard Prefix (RFC 6666)
    - ``fc00::/7`` — Unique Local Addresses (ULA, equivalent to 10.0.0.0/8,
      172.16.0.0/12, 192.168.0.0/16)
    - ``fe80::/10`` — Link-Local Unicast (equivalent to 169.254.0.0/16)
    - ``::1/128`` — Loopback (equivalent to 127.0.0.0/8)
    - ``ff00::/8`` — Multicast (not routable)
    - ``2001::/32`` — Teredo tunneling (RFC 4380), NAT traversal that
      encodes IPv4 addresses and should be treated as IPv4-equivalent

    Parameters
    ----------
    ip : str
        The IP address string.

    Returns
    -------
    bool
        True if the address is in a reserved/private range.
    """
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
        if not isinstance(addr, ipaddress.IPv6Address):
            return False
    except ValueError:
        return False

    # Unique Local Addresses (ULA) — equivalent to IPv4 RFC 1918 ranges
    if addr in ipaddress.ip_network("fc00::/7"):
        return True

    # Link-Local — equivalent to IPv4 169.254.0.0/16
    if addr in ipaddress.ip_network("fe80::/10"):
        return True

    # Loopback — equivalent to IPv4 127.0.0.0/8
    if addr == ipaddress.ip_address("::1"):
        return True

    # IPv4-mapped IPv6 addresses per RFC 4291
    # These have the form ::ffff:x.x.x.x
    if addr in ipaddress.ip_network("::ffff:0:0/96"):
        return True

    # Well-Known Prefix (RFC 6052)
    if addr in ipaddress.ip_network("64:ff9b::/96"):
        return True

    # Discard Prefix (RFC 6666)
    if addr in ipaddress.ip_network("100::/64"):
        return True

    # Multicast
    if addr in ipaddress.ip_network("ff00::/8"):
        return True

    # Teredo — NAT traversal tunneling protocol (RFC 4380).
    # Teredo addresses are in 2001::/32 and encode an IPv4 address and port.
    # They should be treated as IPv4-equivalent per the DHT spec.
    if addr in ipaddress.ip_network("2001::/32"):
        return True

    return False


def normalize_endpoint(ip: str, port: int) -> tuple[str, int, bool]:
    """Normalize an IP/port endpoint pair.

    Returns the canonical IP, port, and whether it's truly IPv6.

    Parameters
    ----------
    ip : str
        The IP address string.
    port : int
        The port number.

    Returns
    -------
    tuple[str, int, bool]
        (canonical_ip, port, is_truly_ipv6).
    """
    try:
        addr = ipaddress.ip_address(ip)
        canonical = addr.compressed
        # ipv4_mapped is only available on IPv6Address
        if isinstance(addr, ipaddress.IPv6Address):
            is_truly_ipv6 = addr.ipv4_mapped is None
        else:
            is_truly_ipv6 = False
        return canonical, port, is_truly_ipv6
    except ValueError:
        return ip, port, False
