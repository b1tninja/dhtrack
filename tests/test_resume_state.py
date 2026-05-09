from __future__ import annotations

from pathlib import Path

from dhtrack.downloader import bitfield_from_hex, bitfield_has, bitfield_set, bitfield_to_hex
from dhtrack.resume import ResumeState


def test_resume_state_roundtrip(tmp_path: Path) -> None:
    st = ResumeState(
        infohash_hex="aa" * 20,
        piece_length=16384,
        total_length=40000,
        num_pieces=3,
        completed="",
    )
    p = tmp_path / "x.resume.json"
    st.save(p)
    st2 = ResumeState.load(p)
    assert st2 is not None
    assert st2.infohash_hex == st.infohash_hex
    assert st2.num_pieces == 3


def test_bitfield_helpers() -> None:
    bf = bytearray(bitfield_from_hex("", 10))
    assert len(bf) == 2
    assert not bitfield_has(bf, 0)
    bitfield_set(bf, 0)
    bitfield_set(bf, 9)
    assert bitfield_has(bf, 0)
    assert bitfield_has(bf, 9)
    hx = bitfield_to_hex(bytes(bf))
    bf2 = bitfield_from_hex(hx, 10)
    assert bf2 == bytes(bf)
