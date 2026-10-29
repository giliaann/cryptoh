"""Entropy and charts: entropy bar chart, character frequency histogram and autocorrelation."""

import logging
import math
from pathlib import Path

import matplotlib
import numpy as np

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from cryptoh.errors import CryptohError  # noqa: E402
from cryptoh.files import prepare_output_path  # noqa: E402

log = logging.getLogger(__name__)


ALPHABET_SIZE = 256  # all possible byte values


def byte_counts(data: bytes) -> list[int]:
    """Occurrence count of every byte value 0x00..0xff (zeros included)."""
    counts = [0] * ALPHABET_SIZE
    for byte in data:
        counts[byte] += 1
    return counts


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte, over the 256-symbol byte alphabet."""
    if not data:
        return 0.0
    total = len(data)
    return -sum(c / total * math.log2(c / total) for c in byte_counts(data) if c)


def max_entropy(data: bytes) -> float:
    """Maximum entropy for the 256-symbol byte alphabet: log2(256) = 8 bits."""
    return math.log2(ALPHABET_SIZE)


def _save(fig, path: str) -> None:
    out = prepare_output_path(path)
    try:
        fig.savefig(out, dpi=150, bbox_inches="tight")
    except (OSError, ValueError) as e:
        raise CryptohError(f"cannot save chart to '{path}': {e}") from e
    finally:
        plt.close(fig)
    log.info("saved chart to '%s'", path)


def entropy_chart(files: dict[str, bytes], output: str) -> list[tuple[str, float, float]]:
    rows = []
    for name, data in files.items():
        if not data:
            log.warning("file '%s' is empty — its entropy is 0", name)
        rows.append((name, entropy(data), max_entropy(data)))

    labels = [Path(name).name for name, _, _ in rows]
    x = range(len(rows))
    fig, ax = plt.subplots(figsize=(max(6, 1.2 * len(rows) + 2), 5))
    bars = ax.bar(list(x), [r[1] for r in rows], 0.6)
    ax.bar_label(bars, fmt="%.3f", fontsize=8)
    ax.set_xticks(list(x), labels, rotation=20 if len(rows) > 3 else 0, ha="right" if len(rows) > 3 else "center")
    ax.set_ylabel("bits per symbol")
    ax.set_title(f"Text entropy (maximum entropy = {math.log2(ALPHABET_SIZE):.2f} for {ALPHABET_SIZE} bytes)")
    ax.set_ylim(0, math.log2(ALPHABET_SIZE) * 1.1)
    _save(fig, output)
    return rows


def histogram_chart(name: str, data: bytes, output: str) -> list[int]:
    if not data:
        raise CryptohError(f"file '{name}' is empty — no characters for a histogram")
    counts = byte_counts(data)
    distinct = sum(1 for c in counts if c)

    fig, ax = plt.subplots(figsize=(30, 6))
    ax.bar(range(ALPHABET_SIZE), counts, width=0.8)
    ax.set_xticks(range(ALPHABET_SIZE), [f"{b:02X}" for b in range(ALPHABET_SIZE)], fontsize=6, rotation=90)
    ax.set_xlim(-0.6, ALPHABET_SIZE - 0.4)
    ax.set_xlabel("byte (hex)")
    ax.set_ylabel("occurrences")
    ax.set_title(f"Byte histogram: {Path(name).name} ({len(data)} bytes, {distinct} of {ALPHABET_SIZE} distinct)")
    _save(fig, output)
    return counts


def autocorrelation(data: bytes, max_shift: int) -> list[int]:
    """Number of positions i with data[i] == data[i + k], for shifts k = 1..max_shift (no wrap-around)."""
    a = np.frombuffer(data, dtype=np.uint8)
    return [int(np.count_nonzero(a[:-k] == a[k:])) for k in range(1, max_shift + 1)]


def autocorrelation_chart(files: dict[str, bytes], max_shift: int, output: str) -> list[tuple[str, int, list[int]]]:
    if max_shift <= 0:
        raise CryptohError(f"maximum shift must be positive, got {max_shift}")
    rows = []
    for name, data in files.items():
        if len(data) < 2:
            raise CryptohError(f"file '{name}' has {len(data)} bytes — at least 2 are needed for autocorrelation")
        shift = min(max_shift, len(data) - 1)
        if shift < max_shift:
            log.warning("file '%s' has %d bytes — shifts limited to %d", name, len(data), shift)
        rows.append((name, shift, autocorrelation(data, shift)))

    fig, ax = plt.subplots(figsize=(12, 5))
    for name, shift, counts in rows:
        ax.plot(range(1, shift + 1), counts, linewidth=1, label=f"{Path(name).name} ({len(files[name])} bytes)")
    ax.set_xlim(0.5, max(shift for _, shift, _ in rows) + 0.5)
    ax.set_ylim(bottom=0)
    ax.set_xlabel("shift (bytes)")
    ax.set_ylabel("matching bytes")
    ax.set_title("Autocorrelation: bytes equal to the byte shifted by k positions")
    ax.grid(alpha=0.3)
    ax.legend()
    _save(fig, output)
    return rows
