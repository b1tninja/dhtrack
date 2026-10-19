"""Compatibility shim. The settings object lives in :mod:`dhtrack.settings`."""

from dhtrack.settings import (
    _DEFAULT_BOOTSTRAP_NODES,
    GuiSettings,
    apply_to_runtime,
    default_peers_file,
    default_torrent_library_directory,
    load,
    resolved_peers_file,
    resolved_torrent_library_directory,
    save,
    settings_path,
    torrent_resume_subdirectory,
)

__all__ = [
    "_DEFAULT_BOOTSTRAP_NODES",
    "GuiSettings",
    "apply_to_runtime",
    "default_peers_file",
    "default_torrent_library_directory",
    "load",
    "resolved_peers_file",
    "resolved_torrent_library_directory",
    "save",
    "settings_path",
    "torrent_resume_subdirectory",
]
