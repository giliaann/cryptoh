"""Encryption and decryption with AES, DES and IDEA in ECB, CBC, CFB and OFB modes."""

import logging
import os

from cryptography.hazmat.decrepit.ciphers import algorithms as legacy_algorithms
from cryptography.hazmat.decrepit.ciphers import modes as legacy_modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptoh.errors import CryptohError
from cryptoh.files import read_file

log = logging.getLogger(__name__)

ALGORITHMS = ("aes", "des", "idea")
MODES = ("ecb", "cbc", "cfb", "ofb")

# allowed key lengths in bytes
KEY_SIZES = {"aes": (16, 24, 32), "des": (8,), "idea": (16,)}
# block sizes in bytes (= required IV length)
BLOCK_SIZES = {"aes": 16, "des": 8, "idea": 8}
PADDED_MODES = ("ecb", "cbc")


def _algorithm(name: str, key: bytes):
    allowed = KEY_SIZES[name]
    if len(key) not in allowed:
        sizes = "/".join(str(s) for s in allowed)
        raise CryptohError(
            f"{name.upper()} key must be {sizes} bytes ({'/'.join(str(s * 8) for s in allowed)} bits), "
            f"got {len(key)} bytes"
        )
    if name == "aes":
        return algorithms.AES(key)
    if name == "des":
        # 3DES with key K|K|K is equivalent to single DES with key K
        return legacy_algorithms.TripleDES(key * 3)
    return legacy_algorithms.IDEA(key)


def _mode(name: str, iv: bytes):
    if name == "ecb":
        return modes.ECB()
    if name == "cbc":
        return modes.CBC(iv)
    if name == "cfb":
        return legacy_modes.CFB(iv)
    return legacy_modes.OFB(iv)


def _read_secret(path: str, as_hex: bool, what: str) -> bytes:
    """Reads a key or IV file: raw bytes, or hexadecimal text when as_hex is set."""
    raw = read_file(path)
    if as_hex:
        try:
            return bytes.fromhex(raw.decode("ascii").strip())
        except (UnicodeDecodeError, ValueError):
            raise CryptohError(f"{what} file '{path}' does not contain a valid hexadecimal string") from None
    if raw.endswith(b"\n"):
        log.warning("%s file '%s' ends with a newline — it is part of the %s (use --%s-hex for hex text)",
                    what, path, what, what.lower())
    return raw


def generate(bits: int, what: str) -> bytes:
    """Returns random bytes for a key or IV of the given length in bits (a positive multiple of 8)."""
    if bits <= 0 or bits % 8 != 0:
        raise CryptohError(f"{what} length must be a positive multiple of 8 bits, got {bits}")
    return os.urandom(bits // 8)


def format_secret(data: bytes, as_hex: bool) -> bytes:
    """Key/IV file content: raw bytes, or hexadecimal text ending with a newline."""
    return data.hex().encode("ascii") + b"\n" if as_hex else data


def load_key(key_file: str, as_hex: bool) -> bytes:
    return _read_secret(key_file, as_hex, "key")


def load_iv(alg: str, mode: str, iv_file: str | None, as_hex: bool) -> bytes:
    """Reads and validates the IV for the given algorithm and mode; ECB uses no IV."""
    if mode == "ecb":
        if iv_file is not None:
            log.warning("IV is ignored in ECB mode — '%s' was not read", iv_file)
        return b""
    if iv_file is None:
        raise CryptohError(f"mode {mode.upper()} requires an IV file (--iv FILE); create one with 'cryptoh geniv'")
    iv = _read_secret(iv_file, as_hex, "IV")
    size = BLOCK_SIZES[alg]
    if len(iv) != size:
        raise CryptohError(
            f"{alg.upper()} IV must be {size} bytes ({size * 8} bits), got {len(iv)} bytes ({len(iv) * 8} bits)"
        )
    return iv


def _warn_ecb(mode: str) -> None:
    if mode == "ecb":
        log.warning("ECB mode encrypts identical blocks identically — it does not hide data patterns")


def encrypt(data: bytes, alg: str, mode: str, key: bytes, iv: bytes) -> bytes:
    algorithm = _algorithm(alg, key)
    _warn_ecb(mode)
    if mode in PADDED_MODES:
        padder = padding.PKCS7(algorithm.block_size).padder()
        data = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithm, _mode(mode, iv)).encryptor()
    result = encryptor.update(data) + encryptor.finalize()
    log.info("encrypted with %s-%s: %d bytes", alg.upper(), mode.upper(), len(result))
    return result


def decrypt(data: bytes, alg: str, mode: str, key: bytes, iv: bytes) -> bytes:
    algorithm = _algorithm(alg, key)
    _warn_ecb(mode)
    block_bytes = algorithm.block_size // 8
    if mode in PADDED_MODES and len(data) % block_bytes != 0:
        raise CryptohError(
            f"ciphertext length ({len(data)} bytes) is not a multiple of the {block_bytes}-byte block"
        )
    decryptor = Cipher(algorithm, _mode(mode, iv)).decryptor()
    result = decryptor.update(data) + decryptor.finalize()
    if mode in PADDED_MODES:
        unpadder = padding.PKCS7(algorithm.block_size).unpadder()
        try:
            result = unpadder.update(result) + unpadder.finalize()
        except ValueError:
            raise CryptohError("invalid padding — wrong key, algorithm or mode, or corrupted ciphertext") from None
    log.info("decrypted with %s-%s: %d bytes", alg.upper(), mode.upper(), len(result))
    return result
