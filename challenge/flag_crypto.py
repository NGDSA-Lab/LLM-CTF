"""Light obfuscation for the flag constants stored in flag_config.py.

This is a XOR stream keyed by sha256(salt+counter). It only keeps the flags out of a casual
`grep` of the source; it is NOT encryption (the salts sit next to the blobs). The per-team
suffix added by rewrite_flags.py is what makes each team's flags unique.
"""
import hashlib


def derive_key(salt: str, length: int) -> bytes:
    stream = b""
    counter = 0
    while len(stream) < length:
        stream += hashlib.sha256(f"{salt}{counter}".encode()).digest()
        counter += 1
    return stream[:length]


def unshroud(hex_blob: str, salt: str) -> str:
    data = bytes.fromhex(hex_blob)
    key = derive_key(salt, len(data))
    return bytes(b ^ k for b, k in zip(data, key)).decode("utf-8")


def shroud(plaintext: str, salt: str) -> str:
    data = plaintext.encode("utf-8")
    key = derive_key(salt, len(data))
    return bytes(b ^ k for b, k in zip(data, key)).hex()
