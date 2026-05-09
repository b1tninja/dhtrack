from __future__ import annotations

import os

import pytest


@pytest.fixture
def node():
    """Integration DHT node fixture for test_harness_dht.

    The harness exercises the real internet DHT and is not suitable for
    unit-test runs by default. Set ``DHTRACK_RUN_INTERNET_TESTS=1`` to enable.
    """
    if os.environ.get("DHTRACK_RUN_INTERNET_TESTS") not in ("1", "true", "TRUE", "yes", "YES"):
        pytest.skip("internet DHT harness disabled (set DHTRACK_RUN_INTERNET_TESTS=1)")

    from dhtrack.dht import DHTNode

    n = DHTNode()
    # The harness functions expect a started node; keep it minimal.
    # test_harness_dht itself performs bootstrap and higher-level actions.
    return n
