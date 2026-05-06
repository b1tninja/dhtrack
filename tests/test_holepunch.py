"""Tests for BEP 55 - NAT Hole Punching Extension.

This module tests:
- Binary payload encoding/decoding
- Rendezvous message creation and handling
- Connect message creation and handling
- Error message creation and handling
- HolePunchHandler functionality
- HolePunchExtension integration
"""

import pytest
import struct

from dhtrack.peer import (
    HolePunchHandler,
    encode_holepunch_message,
    decode_holepunch_message,
    HOLEPUNCH_RENDEZVOUS,
    HOLEPUNCH_CONNECT,
    HOLEPUNCH_ERROR,
    HOLEPUNCH_ADDR_IPV4,
    HOLEPUNCH_ADDR_IPV6,
    HOLEPUNCH_ERR_NO_PEER,
    HOLEPUNCH_ERR_NOT_CONNECTED,
    HOLEPUNCH_ERR_NO_SUPPORT,
    HOLEPUNCH_ERR_NO_SELF,
    ExtensionError,
)
from dhtrack.peerid import Endpoint
from dhtrack.extension import HolePunchExtension


class TestEncodeHolePunchMessage:
    """Tests for encode_holepunch_message."""

    def test_encode_rendezvous_ipv4(self):
        """Test encoding a rendezvous message with IPv4."""
        payload = encode_holepunch_message(
            HOLEPUNCH_RENDEZVOUS, "192.168.1.1", 6881
        )

        # Verify structure: msg_type(1) + addr_type(1) + ip(4) + port(2) = 8 bytes
        assert len(payload) == 8
        assert payload[0] == HOLEPUNCH_RENDEZVOUS
        assert payload[1] == HOLEPUNCH_ADDR_IPV4
        # IP 192.168.1.1 in big-endian
        assert payload[2:6] == b"\xc0\xa8\x01\x01"
        # Port 6881 in big-endian
        assert payload[6:8] == struct.pack("!H", 6881)

    def test_encode_rendezvous_ipv6(self):
        """Test encoding a rendezvous message with IPv6."""
        payload = encode_holepunch_message(
            HOLEPUNCH_RENDEZVOUS, "2001:db8::1", 6881
        )

        # IPv6: msg_type(1) + addr_type(1) + ip(16) + port(2) = 20 bytes
        assert len(payload) == 20
        assert payload[0] == HOLEPUNCH_RENDEZVOUS
        assert payload[1] == HOLEPUNCH_ADDR_IPV6
        # IP 2001:0db8::0001 in big-endian
        assert payload[2:18] == bytes.fromhex("20010db8000000000000000000000001")
        assert payload[18:20] == struct.pack("!H", 6881)

    def test_encode_connect_ipv4(self):
        """Test encoding a connect message with IPv4."""
        payload = encode_holepunch_message(
            HOLEPUNCH_CONNECT, "10.0.0.1", 50000
        )

        assert len(payload) == 8
        assert payload[0] == HOLEPUNCH_CONNECT
        assert payload[1] == HOLEPUNCH_ADDR_IPV4

    def test_encode_error_ipv4(self):
        """Test encoding an error message with IPv4."""
        payload = encode_holepunch_message(
            HOLEPUNCH_ERROR, "192.168.1.1", 6881, HOLEPUNCH_ERR_NO_PEER
        )

        # Error: msg_type(1) + addr_type(1) + ip(4) + port(2) + err_code(4) = 12 bytes
        assert len(payload) == 12
        assert payload[0] == HOLEPUNCH_ERROR
        assert payload[1] == HOLEPUNCH_ADDR_IPV4
        assert payload[2:6] == b"\xc0\xa8\x01\x01"
        assert payload[6:8] == struct.pack("!H", 6881)
        assert payload[8:12] == struct.pack("!I", HOLEPUNCH_ERR_NO_PEER)

    def test_encode_error_ipv6(self):
        """Test encoding an error message with IPv6."""
        payload = encode_holepunch_message(
            HOLEPUNCH_ERROR, "2001:db8::1", 6881, HOLEPUNCH_ERR_NO_SUPPORT
        )

        # Error IPv6: msg_type(1) + addr_type(1) + ip(16) + port(2) + err_code(4) = 24 bytes
        assert len(payload) == 24
        assert payload[0] == HOLEPUNCH_ERROR
        assert payload[1] == HOLEPUNCH_ADDR_IPV6

    def test_encode_invalid_message_type(self):
        """Test that invalid message types raise ExtensionError."""
        with pytest.raises(ExtensionError, match="Invalid holepunch message type"):
            encode_holepunch_message(0xFF, "192.168.1.1", 6881)

    def test_encode_invalid_port(self):
        """Test that invalid ports raise ExtensionError."""
        with pytest.raises(ExtensionError, match="Invalid port number"):
            encode_holepunch_message(HOLEPUNCH_CONNECT, "192.168.1.1", -1)

        with pytest.raises(ExtensionError, match="Invalid port number"):
            encode_holepunch_message(HOLEPUNCH_CONNECT, "192.168.1.1", 70000)

    def test_encode_invalid_ip(self):
        """Test that invalid IPs raise ExtensionError."""
        with pytest.raises(ExtensionError, match="Invalid IP address"):
            encode_holepunch_message(HOLEPUNCH_CONNECT, "invalid", 6881)


class TestDecodeHolePunchMessage:
    """Tests for decode_holepunch_message."""

    def test_decode_rendezvous_ipv4(self):
        """Test decoding a rendezvous message with IPv4."""
        payload = encode_holepunch_message(
            HOLEPUNCH_RENDEZVOUS, "192.168.1.1", 6881
        )
        decoded = decode_holepunch_message(payload)

        assert decoded["msg_type"] == HOLEPUNCH_RENDEZVOUS
        assert decoded["addr_type"] == HOLEPUNCH_ADDR_IPV4
        assert decoded["ip"] == "192.168.1.1"
        assert decoded["port"] == 6881
        assert "err_code" not in decoded

    def test_decode_connect_ipv6(self):
        """Test decoding a connect message with IPv6."""
        payload = encode_holepunch_message(
            HOLEPUNCH_CONNECT, "2001:db8::1", 50000
        )
        decoded = decode_holepunch_message(payload)

        assert decoded["msg_type"] == HOLEPUNCH_CONNECT
        assert decoded["addr_type"] == HOLEPUNCH_ADDR_IPV6
        assert decoded["ip"] == "2001:db8::1"
        assert decoded["port"] == 50000

    def test_decode_error_ipv4(self):
        """Test decoding an error message with IPv4."""
        payload = encode_holepunch_message(
            HOLEPUNCH_ERROR, "10.0.0.1", 8080, HOLEPUNCH_ERR_NOT_CONNECTED
        )
        decoded = decode_holepunch_message(payload)

        assert decoded["msg_type"] == HOLEPUNCH_ERROR
        assert decoded["ip"] == "10.0.0.1"
        assert decoded["port"] == 8080
        assert decoded["err_code"] == HOLEPUNCH_ERR_NOT_CONNECTED

    def test_decode_too_short(self):
        """Test that messages that are too short raise ExtensionError."""
        with pytest.raises(ExtensionError, match="too short"):
            decode_holepunch_message(b"\x00\x01\x02\x03")

    def test_decode_invalid_msg_type(self):
        """Test that invalid message types raise ExtensionError."""
        invalid_payload = bytearray(b"\xFF\x00")
        invalid_payload.extend(b"\xc0\xa8\x01\x01")
        invalid_payload.extend(struct.pack("!H", 6881))

        with pytest.raises(ExtensionError, match="Invalid holepunch message type"):
            decode_holepunch_message(bytes(invalid_payload))

    def test_decode_invalid_addr_type(self):
        """Test that invalid address types raise ExtensionError."""
        invalid_payload = bytearray(b"\x00\xFF")  # invalid addr_type
        invalid_payload.extend(b"\xc0\xa8\x01\x01")
        invalid_payload.extend(struct.pack("!H", 6881))

        with pytest.raises(ExtensionError, match="Invalid holepunch address type"):
            decode_holepunch_message(bytes(invalid_payload))

    def test_roundtrip_ipv4(self):
        """Test encode/decode roundtrip for IPv4."""
        original_ip = "172.16.0.1"
        original_port = 9000

        encoded = encode_holepunch_message(HOLEPUNCH_CONNECT, original_ip, original_port)
        decoded = decode_holepunch_message(encoded)

        assert decoded["ip"] == original_ip
        assert decoded["port"] == original_port

    def test_roundtrip_ipv6(self):
        """Test encode/decode roundtrip for IPv6."""
        original_ip = "fe80::1"
        original_port = 7000

        encoded = encode_holepunch_message(HOLEPUNCH_RENDEZVOUS, original_ip, original_port)
        decoded = decode_holepunch_message(encoded)

        assert decoded["ip"] == original_ip
        assert decoded["port"] == original_port


class TestHolePunchHandler:
    """Tests for HolePunchHandler."""

    def test_create_rendezvous_message(self):
        """Test creating a rendezvous message."""
        handler = HolePunchHandler()
        payload = handler.create_rendezvous_message("192.168.1.100", 6881)

        assert len(payload) == 8
        assert payload[0] == HOLEPUNCH_RENDEZVOUS

    def test_create_connect_message(self):
        """Test creating a connect message."""
        handler = HolePunchHandler()
        payload = handler.create_connect_message("10.0.0.50", 50000)

        assert len(payload) == 8
        assert payload[0] == HOLEPUNCH_CONNECT

    def test_create_error_message(self):
        """Test creating an error message."""
        handler = HolePunchHandler()
        payload = handler.create_error_message(
            "192.168.1.1", 6881, HOLEPUNCH_ERR_NO_PEER
        )

        assert len(payload) == 12
        assert payload[0] == HOLEPUNCH_ERROR
        # Check error code
        err_code = struct.unpack("!I", payload[8:12])[0]
        assert err_code == HOLEPUNCH_ERR_NO_PEER

    def test_handle_rendezvous(self):
        """Test handling a rendezvous message."""
        handler = HolePunchHandler()
        payload = handler.create_rendezvous_message("192.168.1.100", 6881)

        decoded, response = handler.handle_rendezvous(payload)

        assert decoded["msg_type"] == HOLEPUNCH_RENDEZVOUS
        assert decoded["ip"] == "192.168.1.100"
        assert decoded["port"] == 6881
        # rendezvous returns None for response (caller handles)
        assert response is None

    def test_handle_connect_with_callback(self):
        """Test handling a connect message invokes callback."""
        handler = HolePunchHandler()
        results = []

        def on_connect(ip, port, is_ipv6):
            results.append((ip, port, is_ipv6))

        handler.on_holepunch_connect = on_connect
        payload = handler.create_connect_message("10.0.0.1", 50000)

        decoded = handler.handle_connect(payload)

        assert decoded["msg_type"] == HOLEPUNCH_CONNECT
        assert decoded["ip"] == "10.0.0.1"
        assert decoded["port"] == 50000
        assert len(results) == 1
        assert results[0] == ("10.0.0.1", 50000, False)

    def test_handle_connect_ipv6_with_callback(self):
        """Test handling an IPv6 connect message invokes callback."""
        handler = HolePunchHandler()
        results = []

        def on_connect(ip, port, is_ipv6):
            results.append((ip, port, is_ipv6))

        handler.on_holepunch_connect = on_connect
        payload = handler.create_connect_message("2001:db8::1", 6881)

        decoded = handler.handle_connect(payload)

        assert decoded["msg_type"] == HOLEPUNCH_CONNECT
        assert len(results) == 1
        assert results[0] == ("2001:db8::1", 6881, True)

    def test_handle_error(self):
        """Test handling an error message."""
        handler = HolePunchHandler()
        payload = handler.create_error_message(
            "192.168.1.1", 6881, HOLEPUNCH_ERR_NO_SUPPORT
        )

        decoded = handler.handle_error(payload)

        assert decoded["msg_type"] == HOLEPUNCH_ERROR
        assert decoded["ip"] == "192.168.1.1"
        assert decoded["port"] == 6881
        assert decoded["err_code"] == HOLEPUNCH_ERR_NO_SUPPORT

    def test_is_self_address_true(self):
        """Test is_self_address returns True for matching address."""
        endpoint = Endpoint(ip="192.168.1.1", port=6881, is_ipv6=False)
        handler = HolePunchHandler(endpoint=endpoint)

        assert handler.is_self_address("192.168.1.1", 6881) is True

    def test_is_self_address_false_ip(self):
        """Test is_self_address returns False for different IP."""
        endpoint = Endpoint(ip="192.168.1.1", port=6881, is_ipv6=False)
        handler = HolePunchHandler(endpoint=endpoint)

        assert handler.is_self_address("10.0.0.1", 6881) is False

    def test_is_self_address_false_port(self):
        """Test is_self_address returns False for different port."""
        endpoint = Endpoint(ip="192.168.1.1", port=6881, is_ipv6=False)
        handler = HolePunchHandler(endpoint=endpoint)

        assert handler.is_self_address("192.168.1.1", 9000) is False

    def test_is_self_address_no_endpoint(self):
        """Test is_self_address returns False when no endpoint set."""
        handler = HolePunchHandler(endpoint=None)

        assert handler.is_self_address("192.168.1.1", 6881) is False

    def test_handle_connect_no_callback(self):
        """Test handling connect without a callback does not fail."""
        handler = HolePunchHandler()
        # No callback set
        payload = handler.create_connect_message("10.0.0.1", 50000)

        decoded = handler.handle_connect(payload)

        assert decoded["msg_type"] == HOLEPUNCH_CONNECT


class TestHolePunchExtension:
    """Tests for HolePunchExtension."""

    def test_extension_name(self):
        """Test the extension name."""
        handler = HolePunchHandler()
        ext = HolePunchExtension(handler)

        assert ext.NAME == "ut_holepunch"
        assert ext.SUPPORTED_MSG_TYPES == {0, 1, 2}

    def test_extension_handshake(self):
        """Test the extension handshake."""
        handler = HolePunchHandler()
        ext = HolePunchExtension(handler)

        payload = ext.create_handshake_payload()
        assert payload == {}

        result = ext.on_handshake(b"")
        assert result is True

    def test_extension_rendezvous_message(self):
        """Test creating a rendezvous message through the extension."""
        handler = HolePunchHandler()
        ext = HolePunchExtension(handler)

        payload = ext.create_rendezvous("192.168.1.1", 6881)
        assert len(payload) == 8
        assert payload[0] == HOLEPUNCH_RENDEZVOUS

    def test_extension_connect_message(self):
        """Test creating a connect message through the extension."""
        handler = HolePunchHandler()
        ext = HolePunchExtension(handler)

        payload = ext.create_connect("10.0.0.1", 50000)
        assert len(payload) == 8
        assert payload[0] == HOLEPUNCH_CONNECT

    def test_extension_error_message(self):
        """Test creating an error message through the extension."""
        handler = HolePunchHandler()
        ext = HolePunchExtension(handler)

        payload = ext.create_error("192.168.1.1", 6881, HOLEPUNCH_ERR_NO_PEER)
        assert len(payload) == 12
        assert payload[0] == HOLEPUNCH_ERROR

    def test_extension_on_message_rendezvous(self):
        """Test handling a rendezvous message through the extension."""
        handler = HolePunchHandler()
        ext = HolePunchExtension(handler, is_relay=True)

        payload = handler.create_rendezvous_message("192.168.1.100", 6881)
        result = ext.on_message(0, payload)  # msg_type 0 = RENDEZVOUS

        assert result is None

    def test_extension_on_message_connect(self):
        """Test handling a connect message through the extension."""
        handler = HolePunchHandler()
        ext = HolePunchExtension(handler)

        payload = handler.create_connect_message("10.0.0.1", 50000)
        result = ext.on_message(1, payload)  # msg_type 1 = CONNECT

        assert result is None

    def test_extension_on_message_error(self):
        """Test handling an error message through the extension."""
        handler = HolePunchHandler()
        ext = HolePunchExtension(handler)

        payload = handler.create_error_message(
            "192.168.1.1", 6881, HOLEPUNCH_ERR_NOT_CONNECTED
        )
        result = ext.on_message(2, payload)  # msg_type 2 = ERROR

        assert result is None

    def test_extension_set_callback(self):
        """Test setting the callback through the extension."""
        handler = HolePunchHandler()
        ext = HolePunchExtension(handler)

        def my_callback(ip, port, is_ipv6):
            pass

        ext.set_callback(my_callback)
        assert handler.on_holepunch_connect is my_callback

    def test_extension_set_relay_mode(self):
        """Test setting relay mode through the extension."""
        handler = HolePunchHandler()
        ext = HolePunchExtension(handler, is_relay=False)

        ext.set_relay_mode(True)
        assert ext._is_relay is True


class TestAllErrorCodes:
    """Test all BEP 55 error codes."""

    def test_err_no_peer(self):
        """Test HOLEPUNCH_ERR_NO_PEER."""
        handler = HolePunchHandler()
        payload = handler.create_error_message(
            "192.168.1.1", 6881, HOLEPUNCH_ERR_NO_PEER
        )
        decoded = decode_holepunch_message(payload)
        assert decoded["err_code"] == HOLEPUNCH_ERR_NO_PEER

    def test_err_not_connected(self):
        """Test HOLEPUNCH_ERR_NOT_CONNECTED."""
        handler = HolePunchHandler()
        payload = handler.create_error_message(
            "192.168.1.1", 6881, HOLEPUNCH_ERR_NOT_CONNECTED
        )
        decoded = decode_holepunch_message(payload)
        assert decoded["err_code"] == HOLEPUNCH_ERR_NOT_CONNECTED

    def test_err_no_support(self):
        """Test HOLEPUNCH_ERR_NO_SUPPORT."""
        handler = HolePunchHandler()
        payload = handler.create_error_message(
            "192.168.1.1", 6881, HOLEPUNCH_ERR_NO_SUPPORT
        )
        decoded = decode_holepunch_message(payload)
        assert decoded["err_code"] == HOLEPUNCH_ERR_NO_SUPPORT

    def test_err_no_self(self):
        """Test HOLEPUNCH_ERR_NO_SELF."""
        handler = HolePunchHandler()
        payload = handler.create_error_message(
            "192.168.1.1", 6881, HOLEPUNCH_ERR_NO_SELF
        )
        decoded = decode_holepunch_message(payload)
        assert decoded["err_code"] == HOLEPUNCH_ERR_NO_SELF


class TestHolePunchProtocolFlow:
    """Test the complete holepunch protocol flow."""

    def test_rendezvous_flow(self):
        """Test the rendezvous message flow."""
        # Initiator creates rendezvous message
        initiator_handler = HolePunchHandler()
        rendezvous_payload = initiator_handler.create_rendezvous_message(
            "192.168.1.100", 6881
        )

        # Relay receives and processes rendezvous
        relay_handler = HolePunchHandler()
        decoded, _ = relay_handler.handle_rendezvous(rendezvous_payload)

        assert decoded["ip"] == "192.168.1.100"
        assert decoded["port"] == 6881

    def test_connect_flow(self):
        """Test the connect message flow."""
        handler = HolePunchHandler()
        results = []

        def on_connect(ip, port, is_ipv6):
            results.append((ip, port, is_ipv6))

        handler.on_holepunch_connect = on_connect

        # Create and handle connect message
        connect_payload = handler.create_connect_message("10.0.0.50", 50000)
        decoded = handler.handle_connect(connect_payload)

        assert decoded["msg_type"] == HOLEPUNCH_CONNECT
        assert len(results) == 1
        assert results[0][0] == "10.0.0.50"
        assert results[0][1] == 50000
        assert results[0][2] is False  # is_ipv6 = False for IPv4

    def test_error_flow(self):
        """Test the error message flow."""
        handler = HolePunchHandler()

        # Create error for various reasons
        for err_code in [HOLEPUNCH_ERR_NO_PEER, HOLEPUNCH_ERR_NOT_CONNECTED,
                         HOLEPUNCH_ERR_NO_SUPPORT, HOLEPUNCH_ERR_NO_SELF]:
            payload = handler.create_error_message(
                "192.168.1.1", 6881, err_code
            )
            decoded = handler.handle_error(payload)
            assert decoded["err_code"] == err_code