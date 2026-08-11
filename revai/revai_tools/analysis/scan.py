"""Crypto-constant and packer-marker scanning (byte-signature based)."""

from __future__ import annotations

from typing import Any

# Byte fingerprints of common crypto structures / constants.
_CRYPTO_SIGS: list[tuple[str, bytes]] = [
    ("aes_sbox", bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")),
    ("aes_te0", bytes.fromhex("c66363a5f87c7c84ee777799f66b6b8d")),
    ("rc4_sbox_init", b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"),
    ("sha256_init", bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a")),
    ("md5_init", bytes.fromhex("67452301efcdab8998badcfe10325476")),
    ("rsa_65537", bytes.fromhex("01000100")),
    ("base64_alphabet", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
]

_PACKER_MARKERS: list[tuple[str, bytes]] = [
    ("upx", b"UPX!"),
    ("mpress", b"MPRESS"),
    ("aspack", b"ASPack"),
    ("nspack", b"nsp0"),
    ("pecompact", b"PEC2"),
    ("themida", b"Themida"),
    ("vmp", b"VmP"),
    ("enigma", b"Enigma Protector"),
    ("pelock", b"PELOCK"),
    ("obsidium", b"Obsidium"),
]


def scan_file(data: bytes) -> dict[str, Any]:
    crypto: list[str] = []
    for name, sig in _CRYPTO_SIGS:
        if sig in data:
            crypto.append(name)
    packers: list[str] = []
    for name, marker in _PACKER_MARKERS:
        if marker in data:
            packers.append(name)
    overlay_size = 0
    return {"crypto_constants": crypto, "packer_markers": packers,
            "overlay_size": overlay_size}
