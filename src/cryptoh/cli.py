"""Command line interface of cryptoh."""

import argparse
import logging
import os
import sys
from typing import NoReturn

from cryptoh import blocks, cipher
from cryptoh.errors import CryptohError
from cryptoh.files import read_file, write_output

log = logging.getLogger("cryptoh")

_COLORS = {logging.WARNING: "\033[33m", logging.ERROR: "\033[31m", logging.CRITICAL: "\033[31m"}


class _ColorFormatter(logging.Formatter):
    """Colors the level name: red for errors, yellow for warnings."""

    def format(self, record: logging.LogRecord) -> str:
        color = _COLORS.get(record.levelno)
        level = f"{color}{record.levelname}\033[0m" if color else record.levelname
        return f"cryptoh: {level}: {super().format(record)}"


def _use_color() -> bool:
    return sys.stderr.isatty() and not os.environ.get("NO_COLOR")


class _ColorArgumentParser(argparse.ArgumentParser):
    """Colors argparse messages like the log: red for errors, yellow for warnings."""

    def _label(self, name: str, level: int) -> str:
        return f"{_COLORS[level]}{name}\033[0m" if _use_color() else name

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: {self._label('error', logging.ERROR)}: {message}\n")

    # private argparse hook, used e.g. for deprecated arguments (Python 3.13+)
    def _warning(self, message: str) -> None:
        self._print_message(f"{self.prog}: {self._label('warning', logging.WARNING)}: {message}\n", sys.stderr)


def _setup_logging(verbose: bool, quiet: bool) -> None:
    handler = logging.StreamHandler(sys.stderr)
    if _use_color():
        handler.setFormatter(_ColorFormatter("%(message)s"))
    else:
        handler.setFormatter(logging.Formatter("cryptoh: %(levelname)s: %(message)s"))
    root = logging.getLogger("cryptoh")
    root.handlers[:] = [handler]
    root.propagate = False
    root.setLevel(logging.DEBUG if verbose else logging.ERROR if quiet else logging.WARNING)
    # library warnings (e.g. warnings.warn) also go to stderr through logging
    logging.captureWarnings(True)
    logging.getLogger("py.warnings").handlers[:] = [handler]


def cmd_printblocks(args: argparse.Namespace) -> None:
    data = read_file(args.file)
    text = blocks.format_blocks(blocks.split_blocks(data, args.bits), as_hex=args.hex)
    write_output(text.encode("utf-8"), args.output)


def cmd_setbyte(args: argparse.Namespace) -> None:
    data = read_file(args.file)
    value = blocks.parse_byte_value(args.value)
    write_output(blocks.set_byte(data, args.bits, args.block, args.byte, value), args.output)


def cmd_delbyte(args: argparse.Namespace) -> None:
    data = read_file(args.file)
    positions = [blocks.parse_position(p) for p in args.pos]
    write_output(blocks.delete_bytes(data, args.bits, positions), args.output)


def cmd_invbit(args: argparse.Namespace) -> None:
    data = read_file(args.file)
    write_output(blocks.invert_bit(data, args.bits, args.block, args.byte, args.bit), args.output)


def cmd_delbit(args: argparse.Namespace) -> None:
    data = read_file(args.file)
    positions = [blocks.parse_bit_position(p) for p in args.pos]
    write_output(blocks.delete_bits(data, args.bits, positions), args.output)


def _cmd_generate(args: argparse.Namespace, what: str) -> None:
    data = cipher.generate(args.bits, what)
    if not args.hex and args.output is None and sys.stdout.isatty():
        log.warning("writing raw %s bytes to the terminal — use --hex, -o FILE or a redirection", what)
    write_output(cipher.format_secret(data, args.hex), args.output)


def cmd_genkey(args: argparse.Namespace) -> None:
    _cmd_generate(args, "key")


def cmd_geniv(args: argparse.Namespace) -> None:
    _cmd_generate(args, "IV")


def cmd_encrypt(args: argparse.Namespace) -> None:
    key = cipher.load_key(args.key, args.key_hex)
    iv = cipher.load_iv(args.alg, args.mode, args.iv, args.iv_hex)
    data = read_file(args.file)
    result = cipher.encrypt(data, args.alg, args.mode, key, iv)
    if args.output is None and sys.stdout.isatty():
        log.warning("writing binary ciphertext to the terminal — use -o FILE or a redirection")
    write_output(result, args.output)


def cmd_decrypt(args: argparse.Namespace) -> None:
    key = cipher.load_key(args.key, args.key_hex)
    iv = cipher.load_iv(args.alg, args.mode, args.iv, args.iv_hex)
    data = read_file(args.file)
    write_output(cipher.decrypt(data, args.alg, args.mode, key, iv), args.output)


def cmd_entropy(args: argparse.Namespace) -> None:
    from cryptoh import stats  # matplotlib is imported only when needed

    files = {path: read_file(path) for path in args.files}
    rows = stats.entropy_chart(files, args.output)
    width = max(len(name) for name, _, _ in rows)
    print(f"{'file':<{width}}  {'entropy':>9}  {'maximum':>9}")
    for name, h, h_max in rows:
        print(f"{name:<{width}}  {h:>9.4f}  {h_max:>9.4f}")


def cmd_histogram(args: argparse.Namespace) -> None:
    from cryptoh import stats

    data = read_file(args.file)
    counts = stats.histogram_chart(args.file, data, args.output)
    distinct = sum(1 for n in counts if n)
    print(f"saved histogram of all 256 byte values ({distinct} occurring) to '{args.output}'")


def cmd_repeat(args: argparse.Namespace) -> None:
    write_output(blocks.repeat_text(args.text, args.bytes), args.output)


def _add_bits(p: argparse.ArgumentParser) -> None:
    p.add_argument("-b", "--bits", type=int, required=True, help="block length in bits (multiple of 8)")


def _add_output(p: argparse.ArgumentParser, required: bool = False) -> None:
    if required:
        p.add_argument("-o", "--output", required=True, metavar="FILE", help="output file path (e.g. chart.png)")
    else:
        p.add_argument("-o", "--output", metavar="FILE", help="output file (default: stdout)")


def build_parser() -> tuple[argparse.ArgumentParser, argparse._SubParsersAction]:
    parser = _ColorArgumentParser(
        prog="cryptoh",
        description="A tool for analysing and encrypting texts.",
        epilog="Use 'cryptoh help COMMAND' to see details of a command.",
    )
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("-v", "--verbose", action="store_true", help="detailed messages on stderr")
    verbosity.add_argument("-q", "--quiet", action="store_true", help="only errors on stderr")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser(
        "printblocks",
        help="print text in blocks, each on a new line",
        description="Splits a file into blocks of the given length and prints them in lines numbered from 0.",
    )
    p.add_argument("file", metavar="FILE", help="input file")
    _add_bits(p)
    p.add_argument("--hex", action="store_true", help="show blocks in hexadecimal")
    _add_output(p)
    p.set_defaults(func=cmd_printblocks)

    p = sub.add_parser(
        "setbyte",
        help="change a byte in a chosen block",
        description="Changes byte number BYTE in block number BLOCK (both counted from 0).",
    )
    p.add_argument("file", metavar="FILE", help="input file (not modified)")
    _add_bits(p)
    p.add_argument("--block", type=int, required=True, help="block number (from 0)")
    p.add_argument("--byte", type=int, required=True, help="byte number within the block (from 0)")
    p.add_argument("--value", required=True, help="new value: a single ASCII character or 0xNN")
    _add_output(p)
    p.set_defaults(func=cmd_setbyte)

    p = sub.add_parser(
        "delbyte",
        help="delete bytes at chosen positions",
        description="Deletes bytes at the given BLOCK:BYTE positions (counted from 0 in the input file).",
    )
    p.add_argument("file", metavar="FILE", help="input file (not modified)")
    _add_bits(p)
    p.add_argument("--pos", nargs="+", required=True, metavar="BLOCK:BYTE", help="positions to delete, e.g. 0:1 3:7")
    _add_output(p)
    p.set_defaults(func=cmd_delbyte)

    p = sub.add_parser(
        "invbit",
        help="invert a bit in a chosen byte of a block",
        description="Inverts bit number BIT (0 = most significant, 7 = least significant) of byte number "
        "BYTE in block number BLOCK (both counted from 0).",
    )
    p.add_argument("file", metavar="FILE", help="input file (not modified)")
    _add_bits(p)
    p.add_argument("--block", type=int, required=True, help="block number (from 0)")
    p.add_argument("--byte", type=int, required=True, help="byte number within the block (from 0)")
    p.add_argument("--bit", type=int, required=True, help="bit number within the byte (0 = most significant)")
    _add_output(p)
    p.set_defaults(func=cmd_invbit)

    p = sub.add_parser(
        "delbit",
        help="delete bits at chosen positions",
        description="Deletes bits at the given BLOCK:BYTE:BIT positions (counted from 0 in the input file; "
        "bit 0 = most significant). Later bits shift left; if the result is not a whole number of bytes, "
        "the last byte is padded with zero bits.",
    )
    p.add_argument("file", metavar="FILE", help="input file (not modified)")
    _add_bits(p)
    p.add_argument(
        "--pos", nargs="+", required=True, metavar="BLOCK:BYTE:BIT", help="positions to delete, e.g. 0:1:0 3:7:5"
    )
    _add_output(p)
    p.set_defaults(func=cmd_delbit)

    for name, func, what, lengths in (
        ("genkey", cmd_genkey, "key", "AES 128/192/256 bits, DES 64 bits, IDEA 128 bits"),
        ("geniv", cmd_geniv, "IV", "AES 128 bits, DES/IDEA 64 bits"),
    ):
        p = sub.add_parser(
            name,
            help=f"generate a random {what}",
            description=f"Generates a random {what} of BITS bits as raw bytes, or as hexadecimal text "
            f"with --hex. Lengths: {lengths}.",
        )
        p.add_argument("-b", "--bits", type=int, required=True, help=f"{what} length in bits (multiple of 8)")
        p.add_argument("--hex", action="store_true", help="write hexadecimal text instead of raw bytes")
        _add_output(p)
        p.set_defaults(func=func)

    for name, func, verb in (("encrypt", cmd_encrypt, "encrypt"), ("decrypt", cmd_decrypt, "decrypt")):
        p = sub.add_parser(
            name,
            help=f"{verb} a file (AES/DES/IDEA, ECB/CBC/CFB/OFB)",
            description=f"{verb.capitalize()} a file with the chosen algorithm and mode. "
            "The output is the raw result, without the IV. "
            "Key lengths: AES 16/24/32 B, DES 8 B, IDEA 16 B. "
            "IV length (CBC/CFB/OFB) equals the block size: AES 128 bits, DES/IDEA 64 bits "
            "Create key and IV files with 'cryptoh genkey' and 'cryptoh geniv'.",
        )
        p.add_argument("file", metavar="FILE", help="input file")
        p.add_argument("-a", "--alg", choices=cipher.ALGORITHMS, required=True, help="algorithm")
        p.add_argument("-m", "--mode", choices=cipher.MODES, required=True, help="mode of operation")
        p.add_argument("-k", "--key", required=True, metavar="FILE", help="file containing the key (raw bytes)")
        p.add_argument("--key-hex", action="store_true", help="the key file contains hexadecimal text")
        p.add_argument("--iv", metavar="FILE", help="file containing the IV (raw bytes; required for CBC/CFB/OFB)")
        p.add_argument("--iv-hex", action="store_true", help="the IV file contains hexadecimal text")
        _add_output(p)
        p.set_defaults(func=func)

    p = sub.add_parser(
        "entropy",
        help="bar chart of entropies (maximum entropy shown in the title)",
        description="Computes the Shannon entropy and the maximum entropy (log2(256) = 8 bits, "
        "the full byte alphabet) of the given files and saves a bar chart.",
    )
    p.add_argument("files", nargs="+", metavar="FILE", help="input files")
    _add_output(p, required=True)
    p.set_defaults(func=cmd_entropy)

    p = sub.add_parser(
        "histogram",
        help="character frequency histogram",
        description="Creates a histogram of all 256 byte values (zeros included, hex labels) in a file "
        "and saves it as a chart.",
    )
    p.add_argument("file", metavar="FILE", help="input file")
    _add_output(p, required=True)
    p.set_defaults(func=cmd_histogram)

    p = sub.add_parser(
        "repeat",
        help="repeat text up to a given number of bytes",
        description="Repeats TEXT until exactly N bytes are filled (the last repetition is truncated).",
    )
    p.add_argument("text", metavar="TEXT", help="text to repeat")
    p.add_argument("-n", "--bytes", type=int, required=True, metavar="N", help="target number of bytes")
    _add_output(p)
    p.set_defaults(func=cmd_repeat)

    p = sub.add_parser("help", help="show help", description="Shows general help or help for the given command.")
    p.add_argument("topic", nargs="?", metavar="COMMAND", help="command to show help for")
    p.set_defaults(func=None)

    return parser, sub


def main(argv: list[str] | None = None) -> int:
    parser, sub = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose, args.quiet)

    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "help":
        if args.topic is None:
            parser.print_help()
        elif args.topic in sub.choices:
            sub.choices[args.topic].print_help()
        else:
            log.error("unknown command '%s'; available: %s", args.topic, ", ".join(sub.choices))
            return 1
        return 0

    try:
        args.func(args)
    except CryptohError as e:
        log.error("%s", e)
        log.debug("details:", exc_info=True)
        return 1
    except BrokenPipeError:
        # the pipe reader (e.g. head) closed its input — not an error
        sys.stderr.close()
        return 0
    except OSError as e:
        log.error("I/O error: %s", e)
        log.debug("details:", exc_info=True)
        return 1
    except Exception as e:
        log.error("unexpected error: %s", e, exc_info=args.verbose)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
