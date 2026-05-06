# dhtrack

A modern DHT swarm inspector for the BitTorrent protocol. Built with Python 3.10+ and GTK4.

[![CI](https://github.com/dhtrack/dhtrack/actions/workflows/ci.yml/badge.svg)](https://github.com/dhtrack/dhtrack/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Features

- **DHT Node**: Run a full DHT node that participates in the BitTorrent Kademlia network
- **Peer Discovery**: Discover and track peers across the DHT network
- **Torrent Parsing**: Parse and analyze .torrent files with metadata extraction
- **GUI & CLI**: Both graphical and command-line interfaces
- **IPv4 & IPv6**: Full dual-stack network support

## Installation

### From PyPI (coming soon)

```bash
pip install dhtrack
```

### From Source

```bash
git clone https://github.com/dhtrack/dhtrack.git
cd dhtrack
pip install -e ".[dev]"
```

### Requirements

- **Python 3.10+**
- **PyGObject 3.40+** (for GUI)
- **pymongo** (optional, for torrent storage)

## Usage

### Command-Line Interface

Run a DHT node from the terminal:

```bash
# Basic usage
python -m dhtrack.cli

# With verbose logging
python -m dhtrack.cli --verbose

# Custom peers file
python -m dhtrack.cli --peers-file /tmp/dht_peers.dat

# Custom bootstrap nodes
python -m dhtrack.cli --bootstrap router.bittorrent.com 6881

# Run for a specific time
python -m dhtrack.cli --run-time 300

# All options
python -m dhtrack.cli --verbose --peers-file peers.dat --save-interval 30 --run-time 0
```

### Graphical Interface

Launch the GTK GUI:

```bash
python -m dhtrack.cli --gui
```

Or run directly:

```bash
python -c "from dhtrack.gui import main; main()"
```

### As a Library

```python
from dhtrack.bencode import decode, encode
from dhtrack.dht import DHTNode
from dhtrack.torrent import Torrent

# Decode BEncode data
data = decode(b'i42e')  # Returns: 42

# Encode Python objects
encoded = encode([b'info', 42])  # Returns: b'lli42ee'

# Create and run a DHT node
node = DHTNode()
node.load_peers()
node.bootstrap()

# Parse a torrent file
torrent = Torrent.parse_file('example.torrent')
print(f"Name: {torrent.name}")
print(f"Infohash: {torrent.infohash.hex()}")
print(f"Trackers: {torrent.trackers}")
```

## Project Structure

```
dhtrack/
├── __init__.py          # Package initialization
├── __main__.py          # Module entry point
├── bencode.py           # BEncode encoding/decoding
├── dht.py               # DHT node implementation
├── torrent.py           # Torrent file parsing
├── cli.py               # Command-line interface
├── gui.py               # GTK graphical interface
├── dhtrack.glade        # GTK UI definition
tests/
├── __init__.py
├── test_bencode.py      # BEncode tests
pyproject.toml           # Package configuration
requirements.txt         # Dependencies
```

## Development

### Setting Up

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run linters
ruff check dhtrack/ tests/
ruff format dhtrack/ tests/
black dhtrack/ tests/
isort dhtrack/ tests/
mypy dhtrack/

# Run tests
pytest
pytest --cov=dhtrack --cov-report=html
```

### Code Style

This project uses:
- **ruff** for linting
- **black** for code formatting
- **isort** for import sorting
- **mypy** for type checking

Configure your editor to use these tools, or run them via pre-commit:

```bash
pre-commit install
pre-commit run --all-files
```

## Architecture

### BEncode (`bencode.py`)

Implements the [BEncode serialization format](https://bittorrent.org/beps/bep_0005.html)
used by BitTorrent and the DHT protocol. Fully compliant with [BEP 5](https://bittorrent.org/beps/bep_0005.html).

- Integers: `i<digits>e`
- Byte strings: `<length>:<data>`
- Lists: `l<items>e`
- Dictionaries: `d<key><value>e` (keys sorted by byte value per BEP 5)

### DHT (`dht.py`)

Implements the Kademlia DHT protocol:
- **DHTNode**: Manages socket connections and peer routing
- **DHTPeer**: Represents a remote DHT node
- **NodeMetric**: XOR distance calculation for Kademlia routing
- Supports both IPv4 and IPv6

### Torrent (`torrent.py`)

Handles .torrent file parsing:
- Infohash computation (SHA-1 of info dict)
- Metadata extraction (name, files, trackers)
- Optional MongoDB integration for torrent storage

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`pytest`)
6. Submit a pull request

## Acknowledgments

- Based on the BitTorrent DHT protocol (Kademlia)
- GTK GUI built with PyGObject
- Inspired by [python-bittorrent](https://github.com/bittorrent/python-bittorrent)