"""Generic extension framework for BEP 10 (Extension Protocol).

This module provides a framework for registering, discovering, and managing
protocol extensions that communicate via the BEP 10 extension protocol.

The extension system works as follows:

1. Extensions register themselves with the ExtensionRegistry
2. The ExtensionManager coordinates extension lifecycle
3. Extensions negotiate with peers via the ExtensionNegotiator
4. Extensions handle messages via registered handlers

Examples
--------
>>> from dhtrack.extension import ExtensionManager
>>> manager = ExtensionManager()
>>> # Extensions are automatically discovered via the registry
>>> manager.initialize()
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from dhtrack.peer import (
        ExtensionNegotiator,
        HolePunchHandler,
        MetadataExchange,
        PEXManager,
        PeerConnection,
    )
    from dhtrack.peerid import Endpoint

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Extension Protocol Constants
# ---------------------------------------------------------------------------


class ExtensionType:
    """Well-known extension types."""

    METADATA = "ut_metadata"      # BEP 9 - Metadata Exchange
    PEX = "ut_pex"                # BEP 11 - Peer Exchange
    HOLEPUNCH = "ut_holepunch"    # BEP 55 - NAT Holepunching


# ---------------------------------------------------------------------------
# Extension Base Class
# ---------------------------------------------------------------------------


class Extension:
    """Base class for all protocol extensions.

    Extensions implement this interface to participate in the BEP 10
    extension protocol. Subclasses should define:

    - NAME: The extension name (e.g., "ut_metadata")
    - SUPPORTED_MSG_TYPES: Set of supported message types
    - on_handshake(): Called when a handshake is received
    - on_message(): Called when a message is received

    Attributes
    ----------
    name : str
        The extension name as defined in BEP 10.
    version : str
        The extension version string.
    enabled : bool
        Whether this extension is currently enabled.
    """

    NAME: str = ""
    SUPPORTED_MSG_TYPES: set[int] = set()

    def __init__(self, enabled: bool = True) -> None:
        """Initialize the extension.

        Parameters
        ----------
        enabled : bool
            Whether to enable this extension by default.
        """
        self.name = self.NAME
        self.version = "1.0"
        self.enabled = enabled

    def create_handshake_payload(self) -> dict[str, Any]:
        """Create the handshake payload for this extension.

        Returns
        -------
        dict[str, Any]
            Extension-specific handshake data.
        """
        return {}

    def on_handshake(self, data: bytes) -> bool:
        """Handle an incoming handshake.

        Parameters
        ----------
        data : bytes
            The handshake data from the peer.

        Returns
        -------
        bool
            True if the handshake was accepted, False otherwise.
        """
        return False

    def on_message(self, msg_type: int, payload: bytes) -> Optional[bytes]:
        """Handle an incoming message.

        Parameters
        ----------
        msg_type : int
            The message type.
        payload : bytes
            The message payload.

        Returns
        -------
        bytes or None
            Response payload, or None if no response.
        """
        return None

    def on_extended_message(self, msg_type: int, payload: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Handle an incoming bencoded extended message.

        Parameters
        ----------
        msg_type : int
            The message type (0 = handshake, 1 = message).
        payload : dict[str, Any]
            The decoded payload.

        Returns
        -------
        dict or None
            Response payload, or None if no response.
        """
        return None

    def __repr__(self) -> str:
        status = "enabled" if self.enabled else "disabled"
        return f"{self.__class__.__name__}(name={self.name!r}, {status})"


# ---------------------------------------------------------------------------
# Extension Registry
# ---------------------------------------------------------------------------


class ExtensionRegistry:
    """Registry for extension implementations.

    Manages extension discovery, registration, and lookup.
    Extensions are registered by their name and can be looked up
    by name or by type.

    Attributes
    ----------
    _extensions : dict[str, Extension]
        Mapping of extension name to instance.
    """

    def __init__(self) -> None:
        """Initialize the registry."""
        self._extensions: dict[str, Extension] = {}

    def register(self, extension: Extension) -> None:
        """Register an extension.

        Parameters
        ----------
        extension : Extension
            The extension to register.
        """
        if not extension.enabled:
            return

        if extension.name in self._extensions:
            logger.warning("Extension %s already registered, replacing", extension.name)

        self._extensions[extension.name] = extension
        logger.debug("Registered extension: %s", extension.name)

    def unregister(self, name: str) -> None:
        """Unregister an extension by name.

        Parameters
        ----------
        name : str
            The extension name.
        """
        self._extensions.pop(name, None)

    def get(self, name: str) -> Optional[Extension]:
        """Get an extension by name.

        Parameters
        ----------
        name : str
            The extension name.

        Returns
        -------
        Extension or None
            The extension instance, or None if not found.
        """
        return self._extensions.get(name)

    def get_all(self) -> list[Extension]:
        """Get all registered extensions.

        Returns
        -------
        list of Extension
            All registered extension instances.
        """
        return list(self._extensions.values())

    def get_supported_names(self) -> list[str]:
        """Get all registered extension names.

        Returns
        -------
        list of str
            Extension names.
        """
        return list(self._extensions.keys())

    def has(self, name: str) -> bool:
        """Check if an extension is registered.

        Parameters
        ----------
        name : str
            The extension name.

        Returns
        -------
        bool
            True if the extension is registered.
        """
        return name in self._extensions


# ---------------------------------------------------------------------------
# Built-in Extensions
# ---------------------------------------------------------------------------


class MetadataExtension(Extension):
    """BEP 9 - Metadata Exchange Extension.

    This extension enables peers to exchange torrent metadata
    (the info dictionary) without using a tracker.
    """

    NAME = ExtensionType.METADATA
    SUPPORTED_MSG_TYPES = {0, 1, 2, 3}  # HANDSHAKE, DATA, REJECT, REQUEST

    def __init__(self, metadata: MetadataExchange) -> None:
        """Initialize the metadata extension.

        Parameters
        ----------
        metadata : MetadataExchange
            The metadata exchange handler.
        """
        super().__init__()
        self._metadata = metadata

    def create_handshake_payload(self) -> dict[str, Any]:
        """Create the handshake payload.

        Returns
        -------
        dict[str, Any]
            Payload with total_size and piece_length.
        """
        return {
            "total_size": self._metadata._get_total_size(),
            "piece_length": self._metadata.piece_length,
        }

    def on_handshake(self, data: bytes) -> bool:
        """Handle an incoming handshake.

        Parameters
        ----------
        data : bytes
            The handshake data.

        Returns
        -------
        bool
            True if accepted.
        """
        try:
            from dhtrack import bencode as bencode_module
            parsed = bencode_module.decode(data)
            return isinstance(parsed, dict)
        except Exception:
            return False

    def on_message(self, msg_type: int, payload: bytes) -> Optional[bytes]:
        """Handle an incoming message.

        Parameters
        ----------
        msg_type : int
            Message type (0=HANDSHAKE, 1=DATA, 2=REJECT, 3=REQUEST).
        payload : bytes
            The message payload.

        Returns
        -------
        bytes or None
            Response payload if applicable.
        """
        if msg_type == 1:  # DATA
            try:
                from dhtrack import bencode as bencode_module
                result = self._metadata.handle_data(payload)
                if result:
                    return bencode_module.encode({"status": "complete"})
            except Exception as exc:
                logger.debug("Error handling metadata data: %s", exc)
        return None


class PEXExtension(Extension):
    """BEP 11 - Peer Exchange Extension.

    This extension enables peers to exchange peer lists,
    allowing discovery of additional peers without using
    a tracker or DHT.
    """

    NAME = ExtensionType.PEX
    SUPPORTED_MSG_TYPES = {0}  # Only standard PEX messages

    def __init__(self, pex_manager: PEXManager) -> None:
        """Initialize the PEX extension.

        Parameters
        ----------
        pex_manager : PEXManager
            The PEX manager instance.
        """
        super().__init__()
        self._pex = pex_manager

    def create_handshake_payload(self) -> dict[str, Any]:
        """Create the handshake payload.

        Returns
        -------
        dict[str, Any]
            Empty handshake (PEX has no handshake payload).
        """
        return {}

    def on_message(self, msg_type: int, payload: bytes) -> Optional[bytes]:
        """Handle an incoming PEX message.

        Parameters
        ----------
        msg_type : int
            Message type.
        payload : bytes
            The PEX message payload.

        Returns
        -------
        bytes or None
            Response if applicable.
        """
        if msg_type == 0:
            try:
                from dhtrack import bencode as bencode_module
                new_peers, removed_peers, events = self._pex.parse_pex_message(payload)

                # Add new peers
                for peer in new_peers:
                    if events & 0x01:  # PEX_EVENT_NEW
                        self._pex.add_peer(peer)

                return None
            except Exception as exc:
                logger.debug("Error handling PEX message: %s", exc)
        return None


class HolePunchExtension(Extension):
    """BEP 55 - NAT Hole Punching Extension.

    This extension enables peers behind NAT to establish
    direct connections through a relay.

    Message types (BEP 55):
        0x00 - rendezvous: initiate holepunch via relay
        0x01 - connect: instruct peer to connect to another peer
        0x02 - error: report failure

    The extension uses binary payload format per BEP 55 spec.
    """

    NAME = ExtensionType.HOLEPUNCH
    SUPPORTED_MSG_TYPES = {0, 1, 2}  # RENDEZVOUS, CONNECT, ERROR

    def __init__(
        self,
        holepunch_handler: HolePunchHandler,
        is_relay: bool = False,
    ) -> None:
        """Initialize the holepunch extension.

        Parameters
        ----------
        holepunch_handler : HolePunchHandler
            The holepunch handler instance.
        is_relay : bool
            Whether this peer acts as a relaying peer.
        """
        super().__init__()
        self._handler = holepunch_handler
        self._is_relay = is_relay

    def create_handshake_payload(self) -> dict[str, Any]:
        """Create the handshake payload.

        Returns
        -------
        dict[str, Any]
            Empty handshake (holepunch has no handshake payload).
        """
        return {}

    def on_handshake(self, data: bytes) -> bool:
        """Handle an incoming handshake.

        Parameters
        ----------
        data : bytes
            The handshake data.

        Returns
        -------
        bool
            True always (holepunch has no handshake payload).
        """
        return True

    def on_message(self, msg_type: int, payload: bytes) -> Optional[bytes]:
        """Handle an incoming binary holepunch message (BEP 55).

        Parameters
        ----------
        msg_type : int
            Message type: 0=RENDEZVOUS, 1=CONNECT, 2=ERROR.
        payload : bytes
            The binary message payload.

        Returns
        -------
        bytes or None
            Response payload if applicable (error responses).
        """
        try:
            if msg_type == 0:  # RENDEZVOUS
                # This is a relay receiving a rendezvous request
                if not self._is_relay:
                    return None
                decoded, _ = self._handler.handle_rendezvous(payload)
                # The relay checks if it's connected to the target and
                # sends connect messages to both sides
                # Response is handled by the caller via the decoded data
                return None

            elif msg_type == 1:  # CONNECT
                decoded = self._handler.handle_connect(payload)
                # The callback on_holepunch_connect handles the connection
                return None

            elif msg_type == 2:  # ERROR
                decoded = self._handler.handle_error(payload)
                # Error is stored, no response needed
                return None

        except Exception as exc:
            logger.debug("Error handling holepunch message: %s", exc)
        return None

    def create_rendezvous(self, target_ip: str, target_port: int) -> bytes:
        """Create a rendezvous message payload.

        Parameters
        ----------
        target_ip : str
            Target peer's IP address.
        target_port : int
            Target peer's port.

        Returns
        -------
        bytes
            Binary rendezvous message.
        """
        return self._handler.create_rendezvous_message(target_ip, target_port)

    def create_connect(self, peer_ip: str, peer_port: int) -> bytes:
        """Create a connect message payload.

        Parameters
        ----------
        peer_ip : str
            Peer's IP address to connect to.
        peer_port : int
            Peer's port.

        Returns
        -------
        bytes
            Binary connect message.
        """
        return self._handler.create_connect_message(peer_ip, peer_port)

    def create_error(
        self,
        ip: str,
        port: int,
        err_code: int,
    ) -> bytes:
        """Create an error message payload.

        Parameters
        ----------
        ip : str
            The endpoint IP (echoed back).
        port : int
            The endpoint port (echoed back).
        err_code : int
            Error code.

        Returns
        -------
        bytes
            Binary error message.
        """
        return self._handler.create_error_message(ip, port, err_code)

    def set_relay_mode(self, is_relay: bool) -> None:
        """Set whether this peer acts as a relay.

        Parameters
        ----------
        is_relay : bool
            True if this peer should process rendezvous messages.
        """
        self._is_relay = is_relay

    def set_callback(
        self,
        callback,
    ) -> None:
        """Set the connect callback.

        Parameters
        ----------
        callback : callable or None
            Callback invoked when a CONNECT message is received.
            Signature: callback(target_ip, target_port, is_ipv6)
        """
        self._handler.on_holepunch_connect = callback


# ---------------------------------------------------------------------------
# Extension Manager
# ---------------------------------------------------------------------------


@dataclass
class ExtensionManager:
    """Manages the lifecycle of all protocol extensions.

    The extension manager coordinates extension registration,
    handshake negotiation, and message routing.

    Attributes
    ----------
    registry : ExtensionRegistry
        The extension registry.
    enabled_extensions : set[str]
        Currently enabled extension names.
    """

    registry: ExtensionRegistry = field(default_factory=ExtensionRegistry)
    enabled_extensions: set[str] = field(default_factory=set)

    def initialize(self) -> None:
        """Initialize all registered extensions."""
        logger.debug("Initializing extension manager")
        self.enabled_extensions = set(self.registry.get_supported_names())

    def register_builtin_extensions(self) -> None:
        """Register all built-in extensions."""
        # Note: Actual instantiation happens when creating peers
        logger.debug("Registered extensions: %s",
                     self.registry.get_supported_names())

    def get_handshake_names(self) -> list[str]:
        """Get the list of extension names for the handshake.

        Returns
        -------
        list of str
            Extension names to include in handshake.
        """
        return list(self.enabled_extensions)

    def handle_handshake(self, extension_name: str, data: bytes) -> bool:
        """Route a handshake to the appropriate extension.

        Parameters
        ----------
        extension_name : str
            The extension name.
        data : bytes
            The handshake data.

        Returns
        -------
        bool
            True if the handshake was handled.
        """
        ext = self.registry.get(extension_name)
        if ext and ext.enabled:
            return ext.on_handshake(data)
        return False

    def handle_message(self, extension_name: str, msg_type: int, payload: bytes) -> Optional[bytes]:
        """Route a message to the appropriate extension.

        Parameters
        ----------
        extension_name : str
            The extension name.
        msg_type : int
            The message type.
        payload : bytes
            The message payload.

        Returns
        -------
        bytes or None
            Response payload if applicable.
        """
        ext = self.registry.get(extension_name)
        if ext and ext.enabled:
            return ext.on_message(msg_type, payload)
        return None

    def create_extended_message(
        self,
        extension_name: str,
        msg_type: int,
        payload: dict[str, Any],
    ) -> bytes:
        """Create an extended message for a specific extension.

        Parameters
        ----------
        extension_name : str
            The extension name.
        msg_type : int
            The message type.
        payload : dict[str, Any]
            The message payload.

        Returns
        -------
        bytes
            Complete extended message bytes.
        """
        from dhtrack.peer import ExtensionNegotiator, EXTENSION_MSG_TYPE_MESSAGE

        negotiator = ExtensionNegotiator()
        return negotiator.send_extended_message(
            EXTENSION_MSG_TYPE_MESSAGE,
            {"m": extension_name, **payload},
        )