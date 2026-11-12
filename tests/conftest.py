"""Fixtures for the tests that run the proxy as a subprocess. Helpers are in harness.py."""

from __future__ import annotations

from typing import Optional

import pytest

from harness import RawPeer, Workspace


@pytest.fixture
def workspace(tmp_path):
    """Factory: `workspace("default: deny\\n")`, or `workspace(None)` for no --policy at all."""

    def make(policy_text: Optional[str]) -> Workspace:
        return Workspace(tmp_path, policy_text)

    return make


@pytest.fixture
def raw_peers():
    """Factory for RawPeer that guarantees no test leaves a process behind."""
    peers: list[RawPeer] = []

    def track(peer: RawPeer) -> RawPeer:
        peers.append(peer)
        return peer

    yield track
    for peer in peers:
        try:
            peer.close()
        except Exception:
            pass
