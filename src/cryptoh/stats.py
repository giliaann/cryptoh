"""Entropy and charts: entropy bar chart and character frequency histogram."""

import logging
import math
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from cryptoh.errors import CryptohError  # noqa: E402
from cryptoh.files import prepare_output_path  # noqa: E402

log = logging.getLogger(__name__)


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    total = len(data)
    return -sum(c / total * math.log2(c / total) for c in Counter(data).values())


def max_entropy(data: bytes) -> float:
    """Maximum entropy for the alphabet of symbols that occur in the text."""
    distinct = len(set(data))
    return math.log2(distinct) if distinct > 1 else 0.0


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
    width = 0.38
    fig, ax = plt.subplots(figsize=(max(6, 1.6 * len(rows) + 2), 5))
    bars_h = ax.bar([i - width / 2 for i in x], [r[1] for r in rows], width, label="Entropy")
    bars_max = ax.bar([i + width / 2 for i in x], [r[2] for r in rows], width, label="Maximum entropy")
    ax.bar_label(bars_h, fmt="%.3f", fontsize=8)
    ax.bar_label(bars_max, fmt="%.3f", fontsize=8)
    ax.set_xticks(list(x), labels, rotation=20 if len(rows) > 3 else 0, ha="right" if len(rows) > 3 else "center")
    ax.set_ylabel("bits per symbol")
    ax.set_title("Text entropy")
    ax.set_ylim(0, max([8.0] + [r[2] for r in rows]) * 1.1)
    ax.legend()
    _save(fig, output)
    return rows


def _label(byte: int) -> str:
    special = {0x0A: "\\n", 0x0D: "\\r", 0x09: "\\t", 0x20: "␣"}
    if byte in special:
        return special[byte]
    if 0x21 <= byte <= 0x7E:
        return chr(byte)
    return f"0x{byte:02x}"


def histogram_chart(name: str, data: bytes, output: str) -> Counter:
    if not data:
        raise CryptohError(f"file '{name}' is empty — no characters for a histogram")
    counts = Counter(data)
    items = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    if len(items) > 100:
        log.warning("text contains %d distinct bytes — axis labels may be unreadable", len(items))

    fig, ax = plt.subplots(figsize=(max(8, 0.22 * len(items) + 2), 5))
    ax.bar(range(len(items)), [c for _, c in items])
    ax.set_xticks(range(len(items)), [_label(b) for b, _ in items], fontsize=7, rotation=90)
    ax.set_xlim(-0.6, len(items) - 0.4)
    ax.set_xlabel("character (byte)")
    ax.set_ylabel("occurrences")
    ax.set_title(f"Character histogram: {Path(name).name} ({len(data)} bytes, {len(items)} distinct)")
    _save(fig, output)
    return counts
