"""Splitting text into blocks, modifying and deleting bytes and bits, repeating text."""

import logging

from cryptoh.errors import CryptohError

log = logging.getLogger(__name__)


def block_size(bits: int) -> int:
    """Converts a block length in bits to bytes."""
    if bits <= 0 or bits % 8 != 0:
        raise CryptohError(f"block length must be a positive multiple of 8 bits, got {bits}")
    return bits // 8


def split_blocks(data: bytes, bits: int) -> list[bytes]:
    size = block_size(bits)
    blocks = [data[i : i + size] for i in range(0, len(data), size)]
    if not blocks:
        log.warning("file is empty — no blocks")
    elif len(blocks[-1]) < size:
        log.warning(
            "last block (%d) has %d bits instead of %d",
            len(blocks) - 1,
            len(blocks[-1]) * 8,
            bits,
        )
    return blocks


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")


def format_blocks(blocks: list[bytes], as_hex: bool = False) -> str:
    width = len(str(max(len(blocks) - 1, 0)))
    lines = []
    for i, block in enumerate(blocks):
        shown = block.hex(" ") if as_hex else _escape(block.decode("utf-8", errors="replace"))
        lines.append(f"{i:>{width}}: {shown}")
    return "".join(line + "\n" for line in lines)


def _offset(data: bytes, bits: int, block: int, byte: int) -> int:
    size = block_size(bits)
    if block < 0 or byte < 0:
        raise CryptohError("block and byte numbers must be non-negative")
    if byte >= size:
        raise CryptohError(f"byte number {byte} is outside a block of {size} bytes")
    pos = block * size + byte
    if pos >= len(data):
        raise CryptohError(
            f"position block {block}, byte {byte} (offset {pos}) is outside the file of {len(data)} bytes"
        )
    return pos


def parse_byte_value(value: str) -> int:
    """Accepts a single character (1 byte in UTF-8) or a hexadecimal 0xNN value."""
    if value.lower().startswith("0x") and len(value) > 2:
        try:
            num = int(value, 16)
        except ValueError:
            raise CryptohError(f"invalid hexadecimal value '{value}'") from None
        if not 0 <= num <= 0xFF:
            raise CryptohError(f"value {value} does not fit in a byte (0x00–0xff)")
        return num
    encoded = value.encode("utf-8")
    if len(encoded) != 1:
        raise CryptohError(
            f"value '{value}' takes {len(encoded)} bytes — give a single ASCII character or 0xNN"
        )
    return encoded[0]


def set_byte(data: bytes, bits: int, block: int, byte: int, value: int) -> bytes:
    pos = _offset(data, bits, block, byte)
    if data[pos] == value:
        log.warning("byte %d in block %d already has value 0x%02x", byte, block, value)
    log.info("changing offset %d: 0x%02x -> 0x%02x", pos, data[pos], value)
    return data[:pos] + bytes([value]) + data[pos + 1 :]


def parse_position(text: str) -> tuple[int, int]:
    """Parses a position in BLOCK:BYTE format."""
    try:
        block, byte = text.split(":")
        return int(block), int(byte)
    except ValueError:
        raise CryptohError(f"invalid position '{text}', expected BLOCK:BYTE, e.g. 2:5") from None


def delete_bytes(data: bytes, bits: int, positions: list[tuple[int, int]]) -> bytes:
    offsets: set[int] = set()
    for block, byte in positions:
        pos = _offset(data, bits, block, byte)
        if pos in offsets:
            log.warning("position %d:%d given more than once — it will be deleted once", block, byte)
        offsets.add(pos)
    # delete from the end so earlier positions do not shift
    result = bytearray(data)
    for pos in sorted(offsets, reverse=True):
        del result[pos]
    log.info("deleted %d bytes", len(offsets))
    return bytes(result)


def insert_byte(data: bytes, bits: int, block: int, byte: int, value: int) -> bytes:
    """Inserts a byte so that it becomes byte BYTE of block BLOCK; later bytes shift right."""
    size = block_size(bits)
    if block < 0 or byte < 0:
        raise CryptohError("block and byte numbers must be non-negative")
    if byte >= size:
        raise CryptohError(f"byte number {byte} is outside a block of {size} bytes")
    pos = block * size + byte
    if pos > len(data):
        raise CryptohError(
            f"position block {block}, byte {byte} (offset {pos}) is past the end of the file of {len(data)} bytes"
        )
    log.info("inserting 0x%02x at offset %d", value, pos)
    return data[:pos] + bytes([value]) + data[pos:]


def parse_block_value(value: str, bits: int) -> bytes:
    """Parses block content given as hexadecimal text (whitespace ignored)."""
    try:
        content = bytes.fromhex(value)
    except ValueError:
        raise CryptohError(f"invalid hexadecimal block '{value}'") from None
    if len(content) != block_size(bits):
        raise CryptohError(f"block '{value}' has {len(content) * 8} bits instead of {bits}")
    return content


def insert_block(data: bytes, bits: int, block: int, content: bytes) -> bytes:
    """Inserts a whole block so that it becomes block number BLOCK; later blocks shift right."""
    size = block_size(bits)
    if len(content) != size:
        raise CryptohError(f"block content has {len(content) * 8} bits instead of {bits}")
    if block < 0:
        raise CryptohError("block number must be non-negative")
    pos = block * size
    if pos > len(data):
        raise CryptohError(f"block {block} (offset {pos}) is past the end of the file of {len(data)} bytes")
    log.info("inserting block %s at offset %d", content.hex(" "), pos)
    return data[:pos] + content + data[pos:]


def _bit_index(bit: int) -> int:
    """Checks a bit number (0 = most significant bit of the byte, 7 = least significant)."""
    if not 0 <= bit <= 7:
        raise CryptohError(f"bit number {bit} is outside a byte (0–7, 0 = most significant)")
    return bit


def invert_bit(data: bytes, bits: int, block: int, byte: int, bit: int) -> bytes:
    pos = _offset(data, bits, block, byte)
    value = data[pos] ^ (0x80 >> _bit_index(bit))
    log.info("inverting bit %d at offset %d: 0x%02x -> 0x%02x", bit, pos, data[pos], value)
    return data[:pos] + bytes([value]) + data[pos + 1 :]


def parse_bit_position(text: str) -> tuple[int, int, int]:
    """Parses a position in BLOCK:BYTE:BIT format."""
    try:
        block, byte, bit = text.split(":")
        return int(block), int(byte), int(bit)
    except ValueError:
        raise CryptohError(f"invalid position '{text}', expected BLOCK:BYTE:BIT, e.g. 2:5:0") from None


def delete_bits(data: bytes, bits: int, positions: list[tuple[int, int, int]]) -> bytes:
    """Deletes bits from the file treated as a bit stream (most significant bit first).

    Later bits shift left; if the result is not a whole number of bytes, the last byte
    is padded with zero bits.
    """
    offsets: set[int] = set()
    for block, byte, bit in positions:
        pos = _offset(data, bits, block, byte) * 8 + _bit_index(bit)
        if pos in offsets:
            log.warning("position %d:%d:%d given more than once — it will be deleted once", block, byte, bit)
        offsets.add(pos)
    stream = "".join(f"{b:08b}" for b in data)
    kept = "".join(c for i, c in enumerate(stream) if i not in offsets)
    padding = -len(kept) % 8
    if padding:
        log.warning(
            "%d bits left — the last byte is padded with %d zero bits (%d bits deleted in total)",
            len(kept),
            padding,
            len(offsets),
        )
    kept += "0" * padding
    log.info("deleted %d bits", len(offsets))
    return bytes(int(kept[i : i + 8], 2) for i in range(0, len(kept), 8))


def repeat_text(text: str, length: int) -> bytes:
    if length <= 0:
        raise CryptohError(f"number of bytes must be positive, got {length}")
    data = text.encode("utf-8")
    if not data:
        raise CryptohError("text to repeat must not be empty")
    result = (data * (length // len(data) + 1))[:length]
    try:
        result.decode("utf-8")
    except UnicodeDecodeError:
        log.warning("truncating to %d bytes splits a multi-byte UTF-8 character", length)
    return result
