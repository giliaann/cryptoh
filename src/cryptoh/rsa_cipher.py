"""RSA key generation and textbook RSA encryption of whole files.

Format: with k = length of n in bytes, the file is split into chunks of k − 1 bytes, the last chunk is
right-padded with 0x00 to k − 1 bytes, every chunk is read as a big-endian number m and c = m^e mod n is
written as k big-endian bytes. There is no cryptographic padding — encryption is deterministic.
"""

import logging
import secrets
from dataclasses import dataclass

import gmpy2
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptoh.errors import CryptohError
from cryptoh.files import read_file

log = logging.getLogger(__name__)

KEY_BITS = (512, 1024, 2048, 3072, 4096)
PUBLIC_EXPONENT = 65537
# cryptography (OpenSSL) refuses to generate keys shorter than this
_LIBRARY_MIN_BITS = 1024
# Miller–Rabin rounds: error probability <= 4^-64
_MR_ROUNDS = 64
# at most this many block numbers are listed in a warning
_SHOWN_BLOCKS = 10


@dataclass(frozen=True)
class RsaKey:
    n: int
    e: int
    d: int | None = None
    p: int | None = None
    q: int | None = None

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    @property
    def block_bytes(self) -> int:
        """Ciphertext block length k; plaintext chunks have k − 1 bytes, so every chunk is smaller than n."""
        return (self.n.bit_length() + 7) // 8

    @property
    def is_private(self) -> bool:
        return self.d is not None


def _is_probable_prime(n: int) -> bool:
    """Miller–Rabin test with random bases from the OS CSPRNG."""
    if n < 4:
        return n in (2, 3)
    if n % 2 == 0:
        return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(_MR_ROUNDS):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_prime(bits: int) -> int:
    """Random prime with exactly BITS bits and the two top bits set (so p*q has 2*BITS bits)."""
    while True:
        candidate = secrets.randbits(bits) | (0b11 << (bits - 2)) | 1
        if (candidate - 1) % PUBLIC_EXPONENT and _is_probable_prime(candidate):
            return candidate


def _generate_small(bits: int) -> RsaKey:
    """Key generation for lengths the library refuses."""
    while True:
        p, q = _random_prime(bits // 2), _random_prime(bits - bits // 2)
        if p != q and (p * q).bit_length() == bits:
            break
    return RsaKey(p * q, PUBLIC_EXPONENT, pow(PUBLIC_EXPONENT, -1, (p - 1) * (q - 1)), p, q)


def generate(bits: int) -> RsaKey:
    if bits not in KEY_BITS:
        raise CryptohError(f"RSA key length must be one of {', '.join(map(str, KEY_BITS))} bits, got {bits}")
    if bits < 2048:
        log.warning("a %d-bit RSA key is insecure — use it for teaching only", bits)
    if bits < _LIBRARY_MIN_BITS:
        log.info("generating %d-bit primes with Miller–Rabin (the library refuses keys under %d bits)",
                 bits // 2, _LIBRARY_MIN_BITS)
        return _generate_small(bits)
    numbers = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=bits).private_numbers()
    return RsaKey(numbers.public_numbers.n, numbers.public_numbers.e, numbers.d, numbers.p, numbers.q)


def format_key(key: RsaKey, private: bool) -> bytes:
    """Key file content: PKCS#8 PEM for a private key, SubjectPublicKeyInfo PEM for a public key."""
    public = rsa.RSAPublicNumbers(key.e, key.n)
    if not private:
        return public.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    private_key = rsa.RSAPrivateNumbers(
        p=key.p,
        q=key.q,
        d=key.d,
        dmp1=rsa.rsa_crt_dmp1(key.d, key.p),
        dmq1=rsa.rsa_crt_dmq1(key.d, key.q),
        iqmp=rsa.rsa_crt_iqmp(key.p, key.q),
        public_numbers=public,
    ).private_key()
    return private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def load_key(path: str) -> RsaKey:
    """Reads a PEM key from 'cryptoh genrsa' (private or public)."""
    raw = read_file(path)
    try:
        key = serialization.load_pem_private_key(raw, None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        try:
            key = serialization.load_pem_public_key(raw)
        except (ValueError, UnsupportedAlgorithm):
            raise CryptohError(f"'{path}' is not an RSA key in PEM format; create one with 'cryptoh genrsa'") from None
    if isinstance(key, rsa.RSAPrivateKey):
        numbers = key.private_numbers()
        return RsaKey(numbers.public_numbers.n, numbers.public_numbers.e, numbers.d, numbers.p, numbers.q)
    if isinstance(key, rsa.RSAPublicKey):
        numbers = key.public_numbers()
        return RsaKey(numbers.n, numbers.e)
    raise CryptohError(f"'{path}' contains a non-RSA key")


def _blocks_note(blocks: list[int]) -> str:
    shown = ", ".join(map(str, blocks[:_SHOWN_BLOCKS]))
    return shown + (f" … ({len(blocks)} in total)" if len(blocks) > _SHOWN_BLOCKS else "")


def encrypt(data: bytes, key: RsaKey) -> bytes:
    k = key.block_bytes
    chunk = k - 1
    if not data:
        log.warning("input is empty — the ciphertext is empty")
    n, e = gmpy2.mpz(key.n), gmpy2.mpz(key.e)
    result = bytearray()
    for i in range(0, len(data), chunk):
        m = int.from_bytes(data[i : i + chunk].ljust(chunk, b"\0"), "big")
        result += int(gmpy2.powmod(m, e, n)).to_bytes(k, "big")
    if len(data) % chunk:
        log.info("last chunk padded with %d zero bytes", chunk - len(data) % chunk)
    log.info("encrypted with RSA-%d (no padding): %d chunks of %d bytes -> %d bytes",
             key.bits, len(result) // k, chunk, len(result))
    return bytes(result)


def _decryptor(key: RsaKey):
    """Returns c -> c^d mod n computed with the Chinese remainder theorem."""
    p, q = gmpy2.mpz(key.p), gmpy2.mpz(key.q)
    dp, dq, q_inv = gmpy2.mpz(key.d % (key.p - 1)), gmpy2.mpz(key.d % (key.q - 1)), gmpy2.invert(q, p)

    def crt(c):
        m1, m2 = gmpy2.powmod(c, dp, p), gmpy2.powmod(c, dq, q)
        return m2 + (q_inv * (m1 - m2) % p) * q

    return crt


def decrypt(data: bytes, key: RsaKey) -> bytes:
    """Decrypts block by block; the trailing zero bytes of the last block (the padding) are removed."""
    if not key.is_private:
        raise CryptohError("decryption needs the private key")
    k = key.block_bytes
    chunk = k - 1
    if len(data) % k:
        log.warning("ciphertext length (%d bytes) is not a multiple of the %d-byte RSA-%d block — "
                    "the last %d bytes are decrypted as a shorter number", len(data), k, key.bits, len(data) % k)
    power = _decryptor(key)
    too_large: list[int] = []
    overflow: list[int] = []
    result = bytearray()
    for index, i in enumerate(range(0, len(data), k)):
        c = int.from_bytes(data[i : i + k], "big")
        if c >= key.n:
            too_large.append(index)
        m = int(power(c % key.n))
        if m >= 1 << (8 * chunk):
            # possible only for a modified ciphertext; keep the low k − 1 bytes
            overflow.append(index)
            m &= (1 << (8 * chunk)) - 1
        result += m.to_bytes(chunk, "big")
    if too_large:
        log.warning("blocks not smaller than n (reduced mod n) — the ciphertext is corrupted: %s",
                    _blocks_note(too_large))
    if overflow:
        log.warning("blocks decrypting to more than %d bytes (top byte dropped) — the ciphertext is corrupted: %s",
                    chunk, _blocks_note(overflow))
    if result:
        last = len(result) - chunk
        stripped = bytes(result[last:]).rstrip(b"\0")
        log.debug("removed %d trailing zero bytes of the last block", chunk - len(stripped))
        result[last:] = stripped
    log.info("decrypted with RSA-%d (no padding): %d blocks -> %d bytes", key.bits, -(-len(data) // k), len(result))
    return bytes(result)
