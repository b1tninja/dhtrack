"""Peer / Endpoint Scope — filtered DHT wire tail, outbound actions, swarm hints."""

from __future__ import annotations

import os
import time

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from dhtrack.dht import DHTNode
from dhtrack.endpoint_swarm_index import (
    EVIDENCE_INBOUND_ANNOUNCE_PEER,
    EVIDENCE_INBOUND_GET_PEERS,
    EndpointSwarmIndex,
)
from dhtrack.gui.krpc_actions import (
    send_announce_peer,
    send_find_node,
    send_get_peers,
    send_ping,
)


def _looks_ipv6(ip: str) -> bool:
    return ":" in ip.strip()


_WIRE_TAIL_MAX = 2000


class PeerEndpointScopeWidget(QWidget):
    """One UDP endpoint scoped view: DBG-style wire tail + kRPC shortcuts + swarm hints."""

    def __init__(self, dht_node: DHTNode, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.dht_node = dht_node
        self._swarm_index = EndpointSwarmIndex()
        self._paused_wire = False
        self._follow_tail = True
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        title = QLabel("Peer / Endpoint Scope")
        title.setStyleSheet("color: #89b4fa; font-size: 14px; font-weight: bold;")
        layout.addWidget(title)

        hint = QLabel(
            "Set IP and UDP port (DHT); wire tail mirrors dhtrack.wire-style summaries for that "
            "endpoint only. Swarm hints accrue globally from inbound get_peers / announce_peer "
            "queries and appear when this endpoint matches.",
        )
        hint.setStyleSheet("color: #a6adc8; font-size: 10px;")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        scope = QHBoxLayout()
        scope.addWidget(QLabel("IP"))
        self._ip_edit = QLineEdit()
        self._ip_edit.setPlaceholderText("e.g. 203.0.113.42 or fd00::1")
        self._ip_edit.setMinimumWidth(200)
        scope.addWidget(self._ip_edit, stretch=1)
        scope.addWidget(QLabel("UDP port"))
        self._port_spin = QSpinBox()
        self._port_spin.setRange(1, 65535)
        self._port_spin.setValue(6881)
        scope.addWidget(self._port_spin)
        self._v6_chk = QCheckBox("IPv6")
        scope.addWidget(self._v6_chk)
        scope.addStretch(1)
        layout.addLayout(scope)

        act = QHBoxLayout()
        self._ping_btn = QPushButton("Ping")
        self._ping_btn.clicked.connect(self._act_ping)
        self._fn_btn = QPushButton("Find node")
        self._fn_btn.clicked.connect(self._act_find_node)
        self._gp_btn = QPushButton("Get peers")
        self._gp_btn.clicked.connect(self._act_get_peers)
        self._an_btn = QPushButton("Announce peer")
        self._an_btn.clicked.connect(self._act_announce_peer)

        act.addWidget(self._ping_btn)
        act.addWidget(self._fn_btn)
        act.addWidget(self._gp_btn)
        act.addWidget(self._an_btn)
        layout.addLayout(act)

        args = QHBoxLayout()
        args.addWidget(QLabel("Hex (target / info-hash, 40 hex, optional find_node):"))
        self._hex_edit = QLineEdit()
        self._hex_edit.setPlaceholderText(
            "Info-hash or find_node target — leave blank for random 20-byte find_node target",
        )
        self._hex_edit.setFont(self._hex_edit.font())
        args.addWidget(self._hex_edit, stretch=1)
        self._implied_chk = QCheckBox("announce implied_port")
        args.addWidget(self._implied_chk)
        layout.addLayout(args)

        self._status_lbl = QLabel("")
        self._status_lbl.setStyleSheet("color: #fab387; font-size: 11px;")
        layout.addWidget(self._status_lbl)

        split = QSplitter(Qt.Orientation.Vertical)

        wire_bar = QHBoxLayout()
        wire_bar_w = QWidget()
        wire_bar_w.setLayout(wire_bar)
        wire_bar.addWidget(QLabel("WIRE tail (scoped)"))
        self._pause_wire_btn = QPushButton("Pause tail")
        self._pause_wire_btn.setCheckable(True)
        self._pause_wire_btn.toggled.connect(self._on_wire_pause_toggled)
        wire_bar.addWidget(self._pause_wire_btn)
        self._follow_chk = QCheckBox("Follow")
        self._follow_chk.setChecked(True)
        self._follow_chk.toggled.connect(lambda c: setattr(self, "_follow_tail", bool(c)))
        wire_bar.addWidget(self._follow_chk)
        clr = QPushButton("Clear tail")
        clr.clicked.connect(self._clear_tail)
        wire_bar.addWidget(clr)
        wire_bar.addStretch(1)

        vb = QVBoxLayout()
        vb_inner = QWidget()
        vb_inner.setLayout(vb)
        vb.addWidget(wire_bar_w)
        self._wire_plain = QPlainTextEdit()
        self._wire_plain.setReadOnly(True)
        self._wire_plain.setMaximumBlockCount(_WIRE_TAIL_MAX + 50)
        self._wire_plain.setStyleSheet(
            "QPlainTextEdit { background-color: #11111b; color: #cdd6f4; font-family: monospace; }",
        )
        vb.addWidget(self._wire_plain, stretch=1)

        wire_page = QWidget()
        outer_wire = QVBoxLayout(wire_page)
        outer_wire.setContentsMargins(0, 0, 0, 0)
        outer_wire.addWidget(vb_inner)

        swarm_w = QWidget()
        sw_layout = QVBoxLayout(swarm_w)
        sw_layout.setContentsMargins(0, 0, 0, 0)
        sw_layout.addWidget(QLabel("Swarm hints observed for scoped endpoint"))
        self._hints_table = QTableWidget(0, 5)
        self._hints_table.setHorizontalHeaderLabels(
            ["Info-hash", "Evidence", "Last seen", "Hits", "Notes"],
        )
        self._hints_table.horizontalHeader().setStretchLastSection(True)
        self._hints_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._hints_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        sw_layout.addWidget(self._hints_table)

        rh = QPushButton("Refresh hints")
        rh.clicked.connect(self._refresh_hints_ui)
        sw_layout.addWidget(rh)

        split.addWidget(wire_page)
        split.addWidget(swarm_w)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 1)
        layout.addWidget(split, stretch=1)

        self._ip_edit.editingFinished.connect(self._refresh_hints_ui)
        self._port_spin.valueChanged.connect(lambda _v: self._refresh_hints_ui())
        self._v6_chk.stateChanged.connect(lambda _v: self._refresh_hints_ui())

    def _on_wire_pause_toggled(self, on: bool) -> None:
        self._paused_wire = bool(on)
        self._pause_wire_btn.setText("Resume tail" if on else "Pause tail")

    def _clear_tail(self) -> None:
        self._wire_plain.clear()

    def _scope_ipv6_ui(self) -> bool:
        if self._v6_chk.isChecked():
            return True
        return _looks_ipv6(self._ip_edit.text())

    def current_scope_endpoint(self) -> tuple[str, int, bool] | None:
        ip_raw = self._ip_edit.text().strip()
        if not ip_raw:
            return None
        return (ip_raw, int(self._port_spin.value()), self._scope_ipv6_ui())

    def _scope_matches_wire(self, ip: str, port: int, is_ipv6_datagram: bool) -> bool:
        sc = self.current_scope_endpoint()
        if sc is None:
            return False
        sip, sport, suv6 = sc
        if int(port) != sport:
            return False
        if bool(is_ipv6_datagram) != bool(suv6):
            # avoid mixing IPv4 vs IPv6 view when user checked v6 incorrectly
            return False
        return sip.strip() == EndpointSwarmIndex.normalize_ip(ip.strip())

    def format_wire_append(
        self,
        direction: str,
        addr_s: str,
        size: int,
        *,
        decode_status: str,
        txid_hex: str,
        method: str,
        note: str,
    ) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime())
        nit = note or ""
        return (
            f"{ts} [{direction}] {addr_s} sz={size} txid={txid_hex or 'N/A'} "
            f"method={method or '?'} [{decode_status}]{nit and ' ' + nit}"
        )

    def marshal_wire_tail(
        self,
        *,
        direction: str,
        ip: str,
        port: int,
        is_ipv6: bool,
        size: int,
        hex_str: str,
        decode_status: str,
        decode_repr: str,
        txid_hex: str,
        method: str,
        note: str,
    ) -> None:
        if not self._scope_matches_wire(ip, port, is_ipv6):
            return
        if self._paused_wire:
            return
        addr_s = f"[{ip}]:{port}" if is_ipv6 else f"{ip}:{port}"
        short_decode = decode_repr.strip().replace("\n", "\\n")[:400]
        main = self.format_wire_append(
            direction,
            addr_s,
            size,
            decode_status=decode_status,
            txid_hex=txid_hex,
            method=method,
            note=note,
        )
        block = main + ("\n    hex: " + hex_str + "\n    decoded: " + short_decode + "\n")
        self._wire_plain.appendPlainText(block.rstrip())

    def ingest_message_parsed(
        self,
        ip: str,
        port: int,
        is_ipv6: bool,
        msg_info: dict,
        *,
        direction: str,
    ) -> None:
        """Record passive swarm hints for any remote endpoint (scoped table filters display)."""
        if direction != "incoming":
            return
        if msg_info.get("status") != "query":
            return
        q = (msg_info.get("q") or msg_info.get("msg_type") or "").strip().lower()
        ih = msg_info.get("info_hash_hex", "") or ""
        if not ih or len(ih) != 40:
            return
        if q == "get_peers":
            ev = EVIDENCE_INBOUND_GET_PEERS
        elif q == "announce_peer":
            ev = EVIDENCE_INBOUND_ANNOUNCE_PEER
        else:
            return
        self._swarm_index.record_hint(ip=ip, port=port, is_ipv6=is_ipv6, info_hash_hex=ih, evidence=ev)
        ep = self.current_scope_endpoint()
        if ep and self._scope_matches_wire(ip, port, is_ipv6):
            self._refresh_hints_ui()

    def _refresh_hints_ui(self) -> None:
        ep = self.current_scope_endpoint()
        self._hints_table.setRowCount(0)
        if ep is None:
            return
        ip, port, is_v6 = ep
        rows = self._swarm_index.snapshot(ip=ip, port=port, is_ipv6=is_v6)
        self._hints_table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            self._hints_table.setItem(r, 0, QTableWidgetItem(row.info_hash_hex))
            self._hints_table.setItem(r, 1, QTableWidgetItem(", ".join(sorted(row.evidence))))
            lt = time.strftime("%H:%M:%S", time.localtime(row.last_seen))
            self._hints_table.setItem(r, 2, QTableWidgetItem(lt))
            self._hints_table.setItem(r, 3, QTableWidgetItem(str(row.hit_count)))
            self._hints_table.setItem(r, 4, QTableWidgetItem("Passive DHT query args only."))

    def _bad_scope(self) -> tuple[str, int, bool] | None:
        ep = self.current_scope_endpoint()
        if ep is None:
            self._status_lbl.setText("Enter IP address.")
            return None
        return ep

    def _parse_optional_hex(self) -> bytes | None:
        raw = self._hex_edit.text().strip()
        if not raw:
            return None
        cleaned = raw.replace(" ", "")
        try:
            b = bytes.fromhex(cleaned)
        except ValueError:
            self._status_lbl.setText("Invalid hex.")
            return None
        return b if len(b) == 20 else None

    def _act_ping(self) -> None:
        ep = self._bad_scope()
        if not ep:
            return
        r = send_ping(self.dht_node, ep[0], ep[1], is_ipv6=ep[2], create_if_missing=True)
        self._status_lbl.setText(r.detail if r.ok else r.detail)

    def _act_find_node(self) -> None:
        ep = self._bad_scope()
        if not ep:
            return
        tgt = self._parse_optional_hex()
        if tgt is None:
            tgt = os.urandom(20)
        r = send_find_node(
            self.dht_node,
            ep[0],
            ep[1],
            target_id=tgt,
            is_ipv6=ep[2],
            create_if_missing=True,
        )
        self._status_lbl.setText(r.detail if r.ok else r.detail)

    def _act_get_peers(self) -> None:
        ep = self._bad_scope()
        if not ep:
            return
        tgt = self._parse_optional_hex()
        if tgt is None:
            self._status_lbl.setText("Get peers requires 40-character info-hash hex.")
            return
        if len(tgt) != 20:
            self._status_lbl.setText("info-hash must decode to exactly 20 bytes.")
            return
        r = send_get_peers(
            self.dht_node,
            ep[0],
            ep[1],
            info_hash=tgt,
            is_ipv6=ep[2],
            create_if_missing=True,
        )
        self._status_lbl.setText(r.detail if r.ok else r.detail)

    def _act_announce_peer(self) -> None:
        ep = self._bad_scope()
        if not ep:
            return
        tgt = self._parse_optional_hex()
        if tgt is None:
            self._status_lbl.setText("Announce_peer requires 40-character info-hash hex.")
            return
        r = send_announce_peer(
            self.dht_node,
            ep[0],
            ep[1],
            info_hash=tgt,
            implied_port=self._implied_chk.isChecked(),
            is_ipv6=ep[2],
            create_if_missing=True,
        )
        self._status_lbl.setText(r.detail if r.ok else r.detail)
