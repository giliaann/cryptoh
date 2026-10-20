"""Shared input/output helpers."""

import logging
import sys
from pathlib import Path

from cryptoh.errors import CryptohError

log = logging.getLogger(__name__)


def read_file(path: str) -> bytes:
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        raise CryptohError(f"cannot read file '{path}': {e.strerror}") from e
    log.debug("read %d bytes from '%s'", len(data), path)
    return data


def prepare_output_path(path: str) -> Path:
    """Creates the parent directory and warns before overwriting an existing file."""
    out = Path(path)
    if out.is_dir():
        raise CryptohError(f"'{path}' is a directory, expected a file path")
    if out.exists():
        log.warning("file '%s' exists and will be overwritten", path)
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise CryptohError(f"cannot create directory '{out.parent}': {e.strerror}") from e
    return out


def write_output(data: bytes, path: str | None) -> None:
    """Writes data to a file, or to stdout when no path is given."""
    if path is None:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return
    out = prepare_output_path(path)
    try:
        out.write_bytes(data)
    except OSError as e:
        raise CryptohError(f"cannot write file '{path}': {e.strerror}") from e
    log.info("wrote %d bytes to '%s'", len(data), path)
