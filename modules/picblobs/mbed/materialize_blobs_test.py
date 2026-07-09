from __future__ import annotations

import stat
from pathlib import Path

import pytest

from materialize_blobs import (
    CLIENT_CONFIG_SIZE,
    SERVER_CONFIG_SIZE,
    configure_client_blob,
    configure_server_blob,
    load_auth_key,
    parse_auth_key,
    parse_ipv4,
    write_header,
)


def test_configures_both_peers_with_same_nonzero_key() -> None:
    key = bytes(range(1, 33))
    server = configure_server_blob(
        b"server" + bytes(SERVER_CONFIG_SIZE), 4242, key
    )
    client = configure_client_blob(
        b"client" + bytes(CLIENT_CONFIG_SIZE),
        4242,
        parse_ipv4("192.0.2.7"),
        key,
    )

    assert server[-32:] == key
    assert client[-32:] == key
    assert server[-34:-32] == b"\x92\x10"
    assert client[-38:-36] == b"\x92\x10"
    assert client[-36:-32] == b"\xc0\x00\x02\x07"


def test_rejects_all_zero_auth_key() -> None:
    with pytest.raises(ValueError, match="must not be all zero"):
        parse_auth_key("00" * 32)


def test_loads_raw_auth_key_file(tmp_path: Path) -> None:
    key = bytes(range(1, 33))
    path = tmp_path / "auth.key"
    path.write_bytes(key)

    assert load_auth_key(str(path), None) == key


def test_writes_self_contained_header(tmp_path: Path) -> None:
    path = tmp_path / "blob.h"
    write_header(path, "test_blob", b"\x01\x02\xff")
    content = path.read_text(encoding="utf-8")
    mode = stat.S_IMODE(path.stat().st_mode)

    assert "static const unsigned char test_blob[]" in content
    assert "0x01, 0x02, 0xff" in content
    assert "test_blob_len = 3" in content
    assert mode == 0o600


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
