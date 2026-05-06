"""
GTK GUI for dhtrack - DHT Swarm Inspector.

Provides a graphical interface for monitoring DHT node activity,
viewing discovered peers, and inspecting torrent metadata.

Usage
-----
Run the GUI application:

    >>> from dhtrack.gui import main
    >>> main()
"""

from __future__ import annotations

import asyncio
import binascii
import logging
import os
import socket
import struct
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from gi.repository import Gio, GLib, Gtk

from dhtrack.dht import (
    DHTNode,
    DHTPeer,
    DEFAULT_BOOTSTRAP_NODES,
    DEFAULT_PEERS_FILE,
)
from dhtrack.peerid import Endpoint
from dhtrack.torrent import Torrent

logger = logging.getLogger(__name__)


class PeerModel:
    """GtkListStore model for displaying DHT peers.

    Columns:
        0: node_id (str)
        1: ip (str)
        2: port (str)
        3: last_seen (str)
    """

    def __init__(self) -> None:
        """Initialize the peer list store."""
        self.store = Gtk.ListStore(
            str,  # node_id
            str,  # ip
            str,  # port
            str,  # last_seen
        )

    def add_peer(self, peer: DHTPeer) -> None:
        """Add or update a peer in the list store.

        Parameters
        ----------
        peer : DHTPeer
            The DHT peer to add.
        """
        node_id_hex = (
            binascii.b2a_hex(peer.node_id).decode('ascii')
            if peer.node_id
            else 'UNKNOWN'
        )
        ip_str = peer.endpoint.ip
        port_str = str(peer.endpoint.port)
        last_seen = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

        # Check if peer already exists
        found = False
        for row in self.store:
            if row[1] == ip_str and row[2] == port_str:
                row[0] = node_id_hex
                row[3] = last_seen
                found = True
                break

        if not found:
            self.store.append([node_id_hex, ip_str, port_str, last_seen])

    def clear(self) -> None:
        """Clear all peers from the store."""
        self.store.clear()

    def get_peer_count(self) -> int:
        """Get the number of peers in the store.

        Returns
        -------
        int
            The number of peers.
        """
        return self.store.iter_n_children(None)


class ConsoleModel:
    """GtkTextBuffer model for displaying console output.

    Parameters
    ----------
    max_lines : int
        Maximum number of lines to keep in the buffer.
    """

    def __init__(self, max_lines: int = 1000) -> None:
        """Initialize the console buffer."""
        self.buffer = Gtk.TextBuffer()
        self.buffer.set_text('')
        self.max_lines = max_lines
        self._lock = threading.Lock()

    def append(self, message: str) -> None:
        """Append a message to the console.

        Parameters
        ----------
        message : str
            The message to append.
        """
        timestamp = datetime.now(timezone.utc).strftime('%H:%M:%S')
        line = f'[{timestamp}] {message}\n'

        def _append() -> bool:
            end = self.buffer.get_end_iter()
            self.buffer.insert(end, line)

            # Trim old lines if necessary
            start = self.buffer.get_start_iter()
            line_count = end.get_line() - start.get_line()
            if line_count > self.max_lines:
                self.buffer.delete(start, end)

            return False

        GLib.idle_add(_append)

    def clear(self) -> None:
        """Clear the console buffer."""
        self.buffer.set_text('')

    def set_text(self, text: str) -> None:
        """Replace all console text.

        Parameters
        ----------
        text : str
            The new text content.
        """
        self.buffer.set_text(text)


class DHTApplication(Gtk.Application):
    """Main application window for the DHT Swarm Inspector.

    Parameters
    ----------
    application_id : str
        The GTK application ID.
    peers_file : str
        Path to the peers persistence file.
    """

    def __init__(
        self,
        peers_file: str = DEFAULT_PEERS_FILE,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            application_id='com.dhtrack.client',
            flags=Gio.ApplicationFlags.FLAGS_NONE,
            **kwargs,
        )

        self.peers_file = peers_file
        self.dht_node: Optional[DHTNode] = None
        self.peer_model = PeerModel()
        self.console_model = ConsoleModel()
        self._running = False
        self._bootstrap_thread: Optional[threading.Thread] = None

    def do_activate(self) -> None:
        """Handle application activation."""
        self._create_window()
        self._load_ui()
        self._connect_signals()
        self.window.show_all()

    def _create_window(self) -> None:
        """Create the main application window."""
        self.window = Gtk.ApplicationWindow(application=self)
        self.window.set_title('dhtrack - DHT Swarm Inspector')
        self.window.set_default_size(900, 650)
        self.window.set_icon_name('network-workgroup' if hasattr(Gtk, 'Stock') else 'preferences-system')

    def _load_ui(self) -> None:
        """Load the UI from the Glade file."""
        # Try to find the glade file in various locations
        glade_paths = [
            os.path.join(os.path.dirname(__file__), 'dhtrack.glade'),
            'dhtrack.glade',
        ]

        glade_path = None
        for path in glade_paths:
            if os.path.exists(path):
                glade_path = path
                break

        if glade_path:
            try:
                builder = Gtk.Builder()
                builder.add_from_file(glade_path)
                self._build_from_builder(builder)
            except GLib.GError:
                logger.warning('Failed to load Glade file, building UI programmatically')
                self._build_programmatic_ui()
        else:
            logger.warning('Glade file not found, building UI programmatically')
            self._build_programmatic_ui()

    def _build_from_builder(self, builder: Gtk.Builder) -> None:
        """Build the UI from a Gtk.Builder.

        Parameters
        ----------
        builder : Gtk.Builder
            The loaded Glade builder.
        """
        self.window = builder.get_object('winMain') or self.window

        # Get UI components
        self.bufStatus = builder.get_object('bufStatus') or Gtk.TextBuffer()
        self.lblStatus = builder.get_object('lblStatus') or Gtk.Label()
        self.lstPeers = builder.get_object('lstPeers') or Gtk.ListStore()
        self.txtStatus = builder.get_object('txtStatus') or Gtk.TextView()

        # Set up the text view
        if self.txtStatus:
            self.txtStatus.set_buffer(self.bufStatus)
            self.txtStatus.set_editable(False)

        # Set up the peer list
        self.peer_model.store = builder.get_object('lstPeers') or self.peer_model.store

    def _build_programmatic_ui(self) -> None:
        """Build the UI programmatically when Glade file is unavailable."""
        # Main vertical box
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        # Status bar at bottom
        self.lblStatus = Gtk.Label(label='Ready')
        self.lblStatus.set_halign(Gtk.Align.START)
        self.lblStatus.set_margin_start(10)
        self.lblStatus.set_margin_end(10)

        # Console text view
        self.bufStatus = Gtk.TextBuffer()
        self.txtStatus = Gtk.TextView(buffer=self.bufStatus)
        self.txtStatus.set_editable(False)
        self.txtStatus.set_wrap_mode(Gtk.WrapMode.WORD)

        scrolled_console = Gtk.ScrolledWindow()
        scrolled_console.set_policy(
            Gtk.PolicyType.AUTOMATIC,
            Gtk.PolicyType.AUTOMATIC,
        )
        scrolled_console.add(self.txtStatus)

        # Peer list
        self.peer_model = PeerModel()
        self.lstPeers = self.peer_model.store

        tree_view = Gtk.TreeView(model=self.lstPeers)

        # Add columns
        renderer = Gtk.CellRendererText()
        col1 = Gtk.TreeViewColumn('Node ID', renderer, text=0)
        tree_view.append_column(col1)

        renderer2 = Gtk.CellRendererText()
        col2 = Gtk.TreeViewColumn('IP', renderer2, text=1)
        tree_view.append_column(col2)

        renderer3 = Gtk.CellRendererText()
        col3 = Gtk.TreeViewColumn('Port', renderer3, text=2)
        tree_view.append_column(col3)

        scrolled_peers = Gtk.ScrolledWindow()
        scrolled_peers.set_policy(
            Gtk.PolicyType.AUTOMATIC,
            Gtk.PolicyType.AUTOMATIC,
        )
        scrolled_peers.add(tree_view)
        scrolled_peers.set_vexpand(True)

        # Build notebook
        notebook = Gtk.Notebook()

        page1 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        page1.add(scrolled_console)
        notebook.append_page(page1, Gtk.Label(label='Console'))

        page2 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        page2.add(scrolled_peers)
        notebook.append_page(page2, Gtk.Label(label='Peers'))

        vbox.add(notebook)
        vbox.add(self.lblStatus)

        self.window.add(vbox)

    def _connect_signals(self) -> None:
        """Connect UI signal handlers."""
        self.window.connect('delete-event', self._on_delete_window)
        self.window.connect('destroy', self._on_destroy)

    def _on_delete_window(self, widget: Any, event: Any, data: Any = None) -> None:
        """Handle window close request.

        Parameters
        ----------
        widget : Any
            The widget that emitted the signal.
        event : Any
            The delete event.
        data : Any
            Additional data.
        """
        self.stop()
        return False

    def _on_destroy(self, widget: Any, data: Any = None) -> None:
        """Handle window destroy event.

        Parameters
        ----------
        widget : Any
            The widget that emitted the signal.
        data : Any
            Additional data.
        """
        self.stop()
        Gtk.main_quit()

    def start(self) -> None:
        """Start the DHT node and begin discovery."""
        if self._running:
            return

        self._running = True
        self.console_model.append('Starting DHT node...')

        try:
            # Create DHT node
            self.dht_node = DHTNode(peers_file=self.peers_file)

            # Load existing peers
            loaded = self.dht_node.load_peers()
            if loaded > 0:
                self.console_model.append(f'Loaded {loaded} existing peers')

            # Start bootstrap in background thread
            self._bootstrap_thread = threading.Thread(
                target=self._bootstrap,
                daemon=True,
            )
            self._bootstrap_thread.start()

            # Start peer polling
            GLib.timeout_add_seconds(5, self._poll_peers)

            self.lblStatus.set_text('DHT node running')
            self.console_model.append('DHT node started successfully')

        except Exception as exc:
            self.console_model.append(f'Error starting DHT node: {exc}')
            self.lblStatus.set_text('Error')
            self._running = False

    def stop(self) -> None:
        """Stop the DHT node and save peers."""
        if not self._running:
            return

        self._running = False
        self.console_model.append('Stopping DHT node...')

        if self.dht_node:
            self.dht_node.save_peers()
            self.dht_node.close()

        self.lblStatus.set_text('Stopped')
        self.console_model.append('DHT node stopped')

    def _bootstrap(self) -> None:
        """Run bootstrap in a background thread."""
        try:
            if self.dht_node:
                self.console_model.append('Bootstrapping with known routers...')
                self.dht_node.bootstrap(DEFAULT_BOOTSTRAP_NODES)
                self.console_model.append(f'Bootstrap complete. {len(self.dht_node.peers)} peers found.')
        except Exception as exc:
            self.console_model.append(f'Bootstrap error: {exc}')

    def _poll_peers(self) -> bool:
        """Periodically poll for peer updates.

        Returns
        -------
        bool
            True to continue polling.
        """
        if not self._running or not self.dht_node:
            return False

        try:
            for peer in self.dht_node.peers.values():
                self.peer_model.add_peer(peer)
        except Exception as exc:
            logger.debug('Error polling peers: %s', exc)

        return True

    def get_status_text(self) -> str:
        """Get the current status text.

        Returns
        -------
        str
            The status text.
        """
        if self.dht_node:
            return f'Node ID: {binascii.b2a_hex(self.dht_node.node_id).decode("ascii")}'
        return 'Not running'


def main() -> None:
    """Run the GTK GUI application.

    This is the main entry point for the GUI application.
    """
    app = DHTApplication()
    app.run(sys.argv)


if __name__ == '__main__':
    main()