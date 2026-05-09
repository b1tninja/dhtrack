"""
BitTorrent Peer ID parsing and identification (BEP 0020).

The 20-byte peer ID field sent in tracker requests and in the peer
handshake has traditionally been used not only to identify peers but
also to identify the client implementation and version.

This module provides:
- Endpoint dataclass for network addresses
- PeerInfo dataclass for parsed peer ID information
- PeerIdParser class for identifying clients from peer IDs
- Support for 60+ client implementations across multiple formats
"""

from __future__ import annotations

from dataclasses import dataclass

from dhtrack.dht import Endpoint  # canonical endpoint type

# ---------------------------------------------------------------------------
# Endpoint dataclass
# ---------------------------------------------------------------------------


__all__ = ["Endpoint", "PeerIdParser", "PeerInfo"]


# ---------------------------------------------------------------------------
# Peer ID Conventions (BEP 0020)
# ---------------------------------------------------------------------------


@dataclass
class PeerInfo:
    """Structured information parsed from a BitTorrent peer ID.

    Attributes
    ----------
    client_name : str
        Human-readable client name (e.g., 'Azureus', 'Transmission', 'Mainline').
    client_code : str
        Two-character client identifier found in the peer ID.
    version : tuple[int, ...] | None
        Parsed version numbers as a tuple of integers (e.g., (4, 20, 8)).
    build : int | None
        Build number where applicable (e.g., Opera).
    is_debug : bool
        Whether this is a debug build (e.g., XBT debug builds).
    nickname : str | None
        User nickname where applicable (e.g., Rufus, G3 Torrent).
    peer_id_format : str
        The format style: 'mainline', 'dash', 'shadow', 'bitcomet', 'bitlord',
        'xbt', 'opera', 'mldonkey', 'bow', 'queenbee', 'bittyrant',
        'torrentopia', 'bitspirit', 'rufus', 'g3', 'flashget', 'allpeers',
        'utorrent', 'libtorrent', 'qbittorrent', 'transmission', 'deluge',
        'webtorrent', 'rtorrent', 'btdownload', 'unknown'.
    raw_peer_id : bytes
        The original raw peer ID bytes.
    comment : str | None
        Additional comment about the client or version.
    """

    client_name: str
    client_code: str
    version: tuple[int, ...] | None = None
    build: int | None = None
    is_debug: bool = False
    nickname: str | None = None
    peer_id_format: str = "unknown"
    raw_peer_id: bytes = b""
    comment: str | None = None


class PeerIdParser:
    """Parser for BitTorrent peer ID conventions per BEP 0020.

    The 20-byte peer ID field encodes client implementation, version,
    and sometimes user-specific information. This class identifies clients
    and extracts version details from peer IDs.

    Known client formats supported:
        - Mainline (M4-3-6--)
        - Dash-style (-AZ2060-)
        - Shadow/BitTornado (S58B----)
        - BitComet (exbc + version)
        - BitLord (exbcLORD + version)
        - XBT (XBTxxx)
        - Opera (OP + build #)
        - MLdonkey (-MLx.x.x-)
        - Bits on Wheels (-BOWxxx-)
        - Queen Bee (Q1-0-0--)
        - BitTyrant (AZ2500BT)
        - uTorrent (uT0000-)
        - libtorrent-based (lt/lib/LE)
        - qBittorrent (qB)
        - Transmission (TR)
        - Deluge (DE)
        - WebTorrent (WW/WD)
        - rtorrent (RT)
        - And many more...
    """

    # Map two-character client codes to human-readable names
    # Format: code -> (client_name, peer_id_format)
    CLIENT_MAP: dict[str, tuple[str, str]] = {
        # Dash-style clients (most common format)
        "AG": ("Ares", "dash"),
        "A~": ("Ares", "dash"),
        "AR": ("Arctic", "dash"),
        "AV": ("Avicora", "dash"),
        "AX": ("BitPump", "dash"),
        "AZ": ("Azureus", "dash"),
        "BB": ("BitBuddy", "dash"),
        "BC": ("BitComet", "bitcomet"),
        "BF": ("Bitflu", "dash"),
        "BG": ("BTG", "dash"),  # Uses Rasterbar libtorrent
        "BR": ("BitRocket", "dash"),
        "BS": ("BTSlave", "dash"),  # BitSpirit is detected earlier via _is_bitspirit_style
        "BX": ("Bittorrent X", "dash"),
        "CD": ("Enhanced CTorrent", "dash"),
        "CT": ("CTorrent", "dash"),
        "DE": ("DelugeTorrent", "dash"),
        "DP": ("Propagate Data Client", "dash"),
        "EB": ("EBit", "dash"),
        "ES": ("electric Sheep", "dash"),
        "FT": ("FoxTorrent", "dash"),
        "FW": ("FrostWire", "dash"),
        "FX": ("Freebox BitTorrent", "dash"),
        "GS": ("GSTorrent", "dash"),
        "HL": ("Halite", "dash"),
        "HN": ("Hydranode", "dash"),
        "KG": ("KGet", "dash"),
        "KT": ("KTorrent", "dash"),
        "LH": ("LH-ABC", "dash"),
        "LP": ("Lphant", "dash"),
        "LT": ("libtorrent", "libtorrent"),
        "LE": ("libtorrent", "libtorrent"),
        "lt": ("libTorrent", "libtorrent"),
        "LW": ("LimeWire", "dash"),
        "MO": ("MonoTorrent", "dash"),
        "MP": ("MooPolice", "dash"),
        "MR": ("Miro", "dash"),
        "MT": ("MoonlightTorrent", "dash"),
        "NX": ("Net Transport", "dash"),
        "PD": ("Pando", "dash"),
        "qB": ("qBittorrent", "dash"),
        "QD": ("QQDownload", "dash"),
        "QT": ("Qt 4 Torrent example", "dash"),
        "RT": ("Retriever", "dash"),
        "S~": ("Shareaza", "dash"),
        "SB": ("Swiftbit", "dash"),
        "SS": ("SwarmScope", "dash"),
        "ST": ("SymTorrent", "dash"),
        "st": ("sharktorrent", "dash"),
        "SZ": ("Shareaza", "dash"),
        "TN": ("TorrentDotNET", "dash"),
        "TR": ("Transmission", "dash"),
        "TS": ("Torrentstorm", "dash"),
        "TT": ("TuoTu", "dash"),  # TorrenTopia is detected earlier via its own check
        "UL": ("uLeecher!", "dash"),
        "UT": ("µTorrent", "dash"),
        "UW": ("µTorrent Web", "dash"),
        "VG": ("Vagaa", "dash"),
        "WD": ("WebTorrent Desktop", "dash"),
        "WT": ("BitLet", "dash"),
        "WW": ("WebTorrent", "dash"),
        "WY": ("FireTorrent", "dash"),
        "XL": ("Xunlei", "dash"),
        "XT": ("XanTorrent", "dash"),
        "XX": ("Xtorrent", "dash"),
        "ZT": ("ZipTorrent", "dash"),
        # Shadow/BitTornado style
        "A": ("ABC", "shadow"),
        "O": ("Osprey Permaseed", "shadow"),
        "R": ("Tribler", "shadow"),
        "S": ("Shadow's client", "shadow"),
        "T": ("BitTornado", "shadow"),
        "U": ("UPnP NAT Bit Torrent", "shadow"),
        # uTorrent variants (uT prefix)
        "uT": ("µTorrent", "utorrent"),
        # FlashGet
        "FG": ("FlashGet", "flashget"),
        # AllPeers
        "AP": ("AllPeers", "allpeers"),
        # Opera
        "OP": ("Opera", "opera"),
        # Queen Bee
        "Q": ("Queen Bee", "queenbee"),
        # BitTyrant (Azureus fork)
        "BT": ("BitTyrant", "bittyrant"),
        # Rufus
        "RS": ("Rufus", "rufus"),
        # G3 Torrent
        "G3": ("G3 Torrent", "g3"),
        # XBT
        "XB": ("XBT", "xbt"),
        # MLdonkey (starts with -ML)
        "ML": ("MLdonkey", "mldonkey"),
        # Bits on Wheels
        "BOW": ("Bits on Wheels", "bow"),
        # Mainline
        "M": ("Mainline", "mainline"),
    }

    # Known dash-style client codes that we can identify
    DASH_CLIENTS = set(CLIENT_MAP.keys())

    @classmethod
    def parse(cls, peer_id: bytes) -> PeerInfo:
        """Parse a peer ID and extract client information.

        Parameters
        ----------
        peer_id : bytes
            The 20-byte peer ID from a BitTorrent client.

        Returns
        -------
        PeerInfo
            Structured information about the client.
        """
        if not peer_id or len(peer_id) == 0:
            return PeerInfo(
                client_name="Unknown",
                client_code="",
                peer_id_format="unknown",
                raw_peer_id=peer_id or b"",
            )

        # Try each format in order of specificity

        # 1. Mainline format: M4-3-6-- (M + version with dashes)
        if peer_id[0:1] == b"M" and cls._is_mainline_style(peer_id):
            return cls._parse_mainline(peer_id)

        # 2. uTorrent style: uT0000- (uT + version + -)
        if peer_id[0:2] == b"uT":
            return cls._parse_utorrent(peer_id)

        # 3. BitLord style: exbcLORD + version bytes (must precede BitComet's exbc check)
        if peer_id[0:8] == b"exbcLORD":
            return cls._parse_bitlord(peer_id)

        # 4. BitComet style: exbc + version bytes
        if peer_id[0:4] == b"exbc":
            return cls._parse_bitcomet(peer_id)

        # 5. XBT style: XBTxxx (d or - for debug)
        if peer_id[0:3] == b"XBT":
            return cls._parse_xbt(peer_id)

        # 6. Opera style: OP + 4 digits build number (must precede Shadow's O check)
        if peer_id[0:2] == b"OP" and cls._is_opera_style(peer_id):
            return cls._parse_opera(peer_id)

        # 7. BitTyrant style: AZ2500BT + random (must precede Shadow's A check)
        if peer_id[0:8] == b"AZ2500BT":
            return cls._parse_bittyrant(peer_id)

        # 8. AllPeers style: AP + version + - (must precede Shadow's A check)
        if peer_id[0:2] == b"AP":
            return cls._parse_allpeers(peer_id)

        # 9. Shadow/BitTornado style: S58B----- (single char + 4 version chars + ---)
        if cls._is_shadow_style(peer_id):
            return cls._parse_shadow(peer_id)

        # 10. MLdonkey style: -MLx.x.x-
        if peer_id[0:3] == b"-ML":
            return cls._parse_mldonkey(peer_id)

        # 11. Bits on Wheels style: -BOWxxx-yyyyyyyyyyyy
        if peer_id[0:4] == b"-BOW":
            return cls._parse_bow(peer_id)

        # 12. Queen Bee style: Q1-0-0--
        if peer_id[0:1] == b"Q" and cls._is_queenbee_style(peer_id):
            return cls._parse_queenbee(peer_id)

        # 13. TorrenTopia style: 346------
        if peer_id[0:3] == b"346":
            return cls._parse_torrentopia(peer_id)

        # 14. BitSpirit style: \0\3BS or \0\2BS
        if cls._is_bitspirit_style(peer_id):
            return cls._parse_bitspirit(peer_id)

        # 15. Rufus style: ASCII version + RS + nickname
        if cls._is_rufus_style(peer_id):
            return cls._parse_rufus(peer_id)

        # 16. G3 Torrent style: -G3 + nickname
        if peer_id[0:3] == b"-G3":
            return cls._parse_g3(peer_id)

        # 17. FlashGet style: FG + version (Azureus-style without trailing -)
        if peer_id[0:2] == b"FG":
            return cls._parse_flashget(peer_id)

        # 18. Dash-style: -XXnnnnn- (dash + 2 char code + 6 digits + dash)
        if peer_id[0:1] == b"-" and len(peer_id) >= 10:
            return cls._parse_dash(peer_id)

        # 19. Check for known client codes at positions 0-1 (non-dash)
        two_char = peer_id[0:2].decode("ascii", errors="replace")
        if two_char in cls.CLIENT_MAP:
            client_name, fmt = cls.CLIENT_MAP[two_char]
            return PeerInfo(
                client_name=client_name,
                client_code=two_char,
                peer_id_format=fmt,
                raw_peer_id=peer_id,
            )

        # 20. Single-char known clients (Shadow-style without version parsing)
        first_char = peer_id[0:1].decode("ascii", errors="replace")
        if first_char in {c for c, _ in cls.CLIENT_MAP.items() if len(c) == 1}:
            client_name, fmt = cls.CLIENT_MAP[first_char]
            return PeerInfo(
                client_name=client_name,
                client_code=first_char,
                peer_id_format=fmt,
                raw_peer_id=peer_id,
            )

        # Unknown format
        return PeerInfo(
            client_name="Unknown",
            client_code=peer_id[0:2].decode("ascii", errors="replace"),
            peer_id_format="unknown",
            raw_peer_id=peer_id,
        )

    @classmethod
    def _is_mainline_style(cls, peer_id: bytes) -> bool:
        """Check if peer ID follows mainline format: M4-3-6--"""
        if len(peer_id) < 7:
            return False
        if peer_id[0:1] != b"M":
            return False
        # Second char should be a digit (major version)
        if not peer_id[1:2].isdigit():
            return False
        # Third char should be '-'
        if peer_id[2:3] != b"-":
            return False
        return True

    @classmethod
    def _parse_mainline(cls, peer_id: bytes) -> PeerInfo:
        """Parse mainline client peer ID: M4-3-6--"""
        version_parts = []
        i = 1
        while i < len(peer_id) and peer_id[i : i + 1] != b"-":
            if peer_id[i : i + 1].isdigit():
                version_parts.append(int(peer_id[i : i + 1]))
            i += 1
        i += 1  # Skip the '-'

        # Parse remaining version parts separated by '-'
        while i < len(peer_id):
            end = peer_id.find(b"-", i)
            if end == -1:
                end = len(peer_id)
            part = peer_id[i:end]
            if part.isdigit() and len(part) > 0:
                version_parts.append(int(part))
            i = end + 1 if end < len(peer_id) else end

        return PeerInfo(
            client_name="Mainline",
            client_code="M",
            version=tuple(version_parts) if version_parts else None,
            peer_id_format="mainline",
            raw_peer_id=peer_id,
        )

    @classmethod
    def _is_shadow_style(cls, peer_id: bytes) -> bool:
        """Check if peer ID follows Shadow/BitTornado format."""
        if len(peer_id) < 7:
            return False
        first = chr(peer_id[0])
        valid_chars = set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.-")
        # First char should be a known client identifier
        if first not in "AOSRTU":
            return False
        # Next 4 chars should be version chars
        for i in range(1, 5):
            if chr(peer_id[i]) not in valid_chars:
                return False
        # Remaining should be dashes or random
        return True

    @classmethod
    def _parse_shadow(cls, peer_id: bytes) -> PeerInfo:
        """Parse Shadow/BitTornado peer ID: S58B-----"""
        client_names = {
            b"A": "ABC",
            b"O": "Osprey Permaseed",
            b"Q": "BTQueue",
            b"R": "Tribler",
            b"S": "Shadow's client",
            b"T": "BitTornado",
            b"U": "UPnP NAT Bit Torrent",
        }
        client_name = client_names.get(peer_id[0:1], "Unknown")

        # Extract version characters (bytes 1-4)
        version_chars = peer_id[1:5]
        version_str = ""
        for c in version_chars:
            ch = chr(c)
            if ch.isdigit():
                version_str += ch
            elif ch in ".-":
                version_str += ch

        version = None
        if version_str:
            try:
                # Parse version like "5811" -> (5, 8, 11) or "420" -> (4, 20)
                parts = version_str.split(".")
                version_list = []
                for p in parts:
                    if p:
                        version_list.append(int(p))
                if version_list:
                    version = tuple(version_list)
            except (ValueError, TypeError):
                pass

        return PeerInfo(
            client_name=client_name,
            client_code=peer_id[0:1].decode("ascii", errors="replace"),
            version=version,
            peer_id_format="shadow",
            raw_peer_id=peer_id,
        )

    @classmethod
    def _parse_utorrent(cls, peer_id: bytes) -> PeerInfo:
        """Parse uTorrent peer ID: uT0000-xxxxxx"""
        # Version is at bytes 2-5 (4 digits)
        version_str = peer_id[2:6].decode("ascii", errors="replace")
        version = None
        if version_str.isdigit() and len(version_str) == 4:
            major = int(version_str[0])
            minor = int(version_str[1])
            build = int(version_str[2:4])
            version = (major, minor, build)

        return PeerInfo(
            client_name="µTorrent",
            client_code="uT",
            version=version,
            peer_id_format="utorrent",
            raw_peer_id=peer_id,
        )

    @classmethod
    def _parse_bitcomet(cls, peer_id: bytes) -> PeerInfo:
        """Parse BitComet peer ID: exbc + version bytes + random"""
        # Version bytes at position 4-5
        if len(peer_id) < 6:
            return PeerInfo(
                client_name="BitComet",
                client_code="exbc",
                peer_id_format="bitcomet",
                raw_peer_id=peer_id,
            )

        major = peer_id[4]
        minor = peer_id[5]
        version = (major, minor)

        return PeerInfo(
            client_name="BitComet",
            client_code="exbc",
            version=version,
            peer_id_format="bitcomet",
            raw_peer_id=peer_id,
        )

    @classmethod
    def _parse_bitlord(cls, peer_id: bytes) -> PeerInfo:
        """Parse BitLord peer ID: exbcLORD + version bytes + random"""
        if len(peer_id) < 8:
            return PeerInfo(
                client_name="BitLord",
                client_code="exbc",
                peer_id_format="bitlord",
                raw_peer_id=peer_id,
            )

        major = peer_id[8] if len(peer_id) > 8 else 0
        minor = peer_id[9] if len(peer_id) > 9 else 0
        version = (major, minor) if major > 0 or minor > 0 else None

        return PeerInfo(
            client_name="BitLord",
            client_code="exbc",
            version=version,
            peer_id_format="bitlord",
            raw_peer_id=peer_id,
        )

    @classmethod
    def _parse_xbt(cls, peer_id: bytes) -> PeerInfo:
        """Parse XBT peer ID: XBTxxx where x is digit, then d/- for debug"""
        version_str = peer_id[3:6].decode("ascii", errors="replace")
        is_debug = len(peer_id) > 6 and peer_id[6:7] == b"d"

        version = None
        if version_str.isdigit() and len(version_str) == 3:
            version = (int(version_str[0]), int(version_str[1]), int(version_str[2]))

        return PeerInfo(
            client_name="XBT",
            client_code="XB",
            version=version,
            is_debug=is_debug,
            peer_id_format="xbt",
            raw_peer_id=peer_id,
            comment="Debug build" if is_debug else None,
        )

    @classmethod
    def _is_opera_style(cls, peer_id: bytes) -> bool:
        """Check if peer ID follows Opera format: OP + 4 digits"""
        if len(peer_id) < 6:
            return False
        return peer_id[2:6].isdigit()

    @classmethod
    def _parse_opera(cls, peer_id: bytes) -> PeerInfo:
        """Parse Opera peer ID: OP + build number"""
        build_str = peer_id[2:6].decode("ascii", errors="replace")
        build = int(build_str) if build_str.isdigit() else None

        return PeerInfo(
            client_name="Opera",
            client_code="OP",
            build=build,
            peer_id_format="opera",
            raw_peer_id=peer_id,
        )

    @classmethod
    def _parse_mldonkey(cls, peer_id: bytes) -> PeerInfo:
        """Parse MLdonkey peer ID: -MLx.x.x-"""
        # Find the version between -ML and the trailing -; version starts at byte 3
        version_str = ""
        end = peer_id.find(b"-", 3)
        if end > 3:
            version_str = peer_id[3:end].decode("ascii", errors="replace")
        else:
            version_str = peer_id[3:].decode("ascii", errors="replace")

        version = None
        if version_str:
            try:
                version_list = [int(p) for p in version_str.split(".") if p.isdigit()]
                if version_list:
                    version = tuple(version_list)
            except (ValueError, TypeError):
                pass

        return PeerInfo(
            client_name="MLdonkey",
            client_code="ML",
            version=version,
            peer_id_format="mldonkey",
            raw_peer_id=peer_id,
        )

    @classmethod
    def _parse_bow(cls, peer_id: bytes) -> PeerInfo:
        """Parse Bits on Wheels peer ID: -BOWxxx-yyyyyyyyyyyy"""
        # Version chars at position 4-6
        version_chars = peer_id[4:7].decode("ascii", errors="replace")

        return PeerInfo(
            client_name="Bits on Wheels",
            client_code="BOW",
            peer_id_format="bow",
            raw_peer_id=peer_id,
            comment=f"Version indicator: {version_chars}",
        )

    @classmethod
    def _is_queenbee_style(cls, peer_id: bytes) -> bool:
        """Check if peer ID follows Queen Bee format: Q1-0-0--"""
        if len(peer_id) < 7:
            return False
        if peer_id[0:1] != b"Q":
            return False
        # Should have dash-separated version parts
        parts = peer_id[1:7].split(b"-")
        return len(parts) >= 2

    @classmethod
    def _parse_queenbee(cls, peer_id: bytes) -> PeerInfo:
        """Parse Queen Bee peer ID: Q1-0-0--"""
        version_parts = []
        i = 1
        while i < len(peer_id):
            end = peer_id.find(b"-", i)
            if end == -1:
                end = len(peer_id)
            part = peer_id[i:end]
            if part.isdigit() and len(part) > 0:
                version_parts.append(int(part))
            i = end + 1 if end < len(peer_id) else end

        return PeerInfo(
            client_name="Queen Bee",
            client_code="Q",
            version=tuple(version_parts) if version_parts else None,
            peer_id_format="queenbee",
            raw_peer_id=peer_id,
        )

    @classmethod
    def _parse_bittyrant(cls, peer_id: bytes) -> PeerInfo:
        """Parse BitTyrant peer ID: AZ2500BT + random"""
        return PeerInfo(
            client_name="BitTyrant",
            client_code="BT",
            peer_id_format="bittyrant",
            raw_peer_id=peer_id,
            comment="Azureus fork",
        )

    @classmethod
    def _parse_torrentopia(cls, peer_id: bytes) -> PeerInfo:
        """Parse TorrenTopia peer ID: 346------"""
        return PeerInfo(
            client_name="TorrenTopia",
            client_code="TT",
            peer_id_format="torrentopia",
            raw_peer_id=peer_id,
            comment="Claims to be Mainline 3.4.6",
        )

    @classmethod
    def _is_bitspirit_style(cls, peer_id: bytes) -> bool:
        """Check if peer ID follows BitSpirit format."""
        if len(peer_id) < 4:
            return False
        # BitSpirit: \0\3BS or \0\2BS
        return peer_id[0:1] == b"\x00" and peer_id[2:4] == b"BS"

    @classmethod
    def _parse_bitspirit(cls, peer_id: bytes) -> PeerInfo:
        """Parse BitSpirit peer ID."""
        version_byte = peer_id[1:2]
        version = int(version_byte[0]) if version_byte else 0

        version_info = f"Version {version}.x" if version else "Unknown version"

        return PeerInfo(
            client_name="BitSpirit",
            client_code="BS",
            peer_id_format="bitspirit",
            raw_peer_id=peer_id,
            comment=version_info,
        )

    @classmethod
    def _is_rufus_style(cls, peer_id: bytes) -> bool:
        """Check if peer ID follows Rufus format: ASCII version + RS + nickname."""
        if len(peer_id) < 4:
            return False
        # First two bytes are ASCII version digits
        # Third and fourth bytes are 'RS'
        return peer_id[2:4] == b"RS"

    @classmethod
    def _parse_rufus(cls, peer_id: bytes) -> PeerInfo:
        """Parse Rufus peer ID: version + RS + nickname + random."""
        # Version is first 2 bytes
        version_str = peer_id[0:2].decode("ascii", errors="replace")

        # Nickname starts at byte 4
        nickname = ""
        for i in range(4, min(len(peer_id), 14)):
            c = chr(peer_id[i])
            if c.isalnum() or c == "_":
                nickname += c
            else:
                break

        version = None
        if version_str.isdigit():
            version = (int(version_str),)

        return PeerInfo(
            client_name="Rufus",
            client_code="RS",
            version=version,
            nickname=nickname if nickname else None,
            peer_id_format="rufus",
            raw_peer_id=peer_id,
        )

    @classmethod
    def _parse_g3(cls, peer_id: bytes) -> PeerInfo:
        """Parse G3 Torrent peer ID: -G3 + up to 9 chars of nickname."""
        nickname = ""
        for i in range(3, min(len(peer_id), 12)):
            c = chr(peer_id[i])
            if c.isalnum() or c == "_":
                nickname += c
            else:
                break

        return PeerInfo(
            client_name="G3 Torrent",
            client_code="G3",
            nickname=nickname if nickname else None,
            peer_id_format="g3",
            raw_peer_id=peer_id,
        )

    @classmethod
    def _parse_flashget(cls, peer_id: bytes) -> PeerInfo:
        """Parse FlashGet peer ID: FG + version (Azureus-style without trailing -)."""
        version_str = peer_id[2:6].decode("ascii", errors="replace")
        version = None
        if version_str.isdigit() and len(version_str) == 4:
            version = (int(version_str[0:2]), int(version_str[2:4]))

        return PeerInfo(
            client_name="FlashGet",
            client_code="FG",
            version=version,
            peer_id_format="flashget",
            raw_peer_id=peer_id,
        )

    @classmethod
    def _parse_allpeers(cls, peer_id: bytes) -> PeerInfo:
        """Parse AllPeers peer ID: AP + version + - + random."""
        # Find version after AP
        end = peer_id.find(b"-", 2)
        version_str = ""
        if end > 2:
            version_str = peer_id[2:end].decode("ascii", errors="replace")

        version = None
        if version_str.isdigit():
            version = (int(version_str),)

        return PeerInfo(
            client_name="AllPeers",
            client_code="AP",
            version=version,
            peer_id_format="allpeers",
            raw_peer_id=peer_id,
        )

    @classmethod
    def _parse_dash(cls, peer_id: bytes) -> PeerInfo:
        """Parse dash-style peer ID: -XXnnnnn-."""
        client_code = peer_id[1:3].decode("ascii", errors="replace")
        version_str = peer_id[3:9].decode("ascii", errors="replace")

        # Parse version (6 digits, typically YYNNNN or YYNNNn)
        version = None
        if version_str[:2].isdigit() and version_str[2:6].isdigit():
            major = int(version_str[:2])
            minor_build = int(version_str[2:6])
            version = (major, minor_build)

        client_name = "Unknown"
        fmt = "dash"
        if client_code in cls.CLIENT_MAP:
            client_name, fmt = cls.CLIENT_MAP[client_code]

        return PeerInfo(
            client_name=client_name,
            client_code=client_code,
            version=version,
            peer_id_format=fmt,
            raw_peer_id=peer_id,
        )

    @classmethod
    def identify(cls, peer_id: bytes) -> str:
        """Get a human-readable client identification string.

        Parameters
        ----------
        peer_id : bytes
            The 20-byte peer ID.

        Returns
        -------
        str
            Human-readable identification string.
        """
        info = cls.parse(peer_id)
        parts = [info.client_name]

        if info.version:
            parts.append("v" + ".".join(str(v) for v in info.version))

        if info.is_debug:
            parts.append("(debug)")

        if info.nickname:
            parts.append(f"nick={info.nickname}")

        if info.comment:
            parts.append(info.comment)

        return " ".join(parts)
