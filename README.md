# cryptoh

A command line tool for analysing and encrypting texts. Dependencies are managed with [uv](https://docs.astral.sh/uv/).

```sh
uv sync                     # install dependencies
uv run cryptoh help         # list commands
uv run cryptoh help COMMAND # help for a command
```

Warnings and errors go to stderr (`-v` — more details, `-q` — errors only); stdout contains only results.
Exit code: 0 — success, 1 — error, 2 — invalid arguments.

## Commands

| Command | Description | Output |
|---|---|---|
| `printblocks FILE -b BITS [--hex]` | text split into blocks of BITS bits, lines numbered from 0 | stdout or `-o` |
| `setbyte FILE -b BITS --block B --byte K --value V` | change byte K in block B (`V`: a character or `0xNN`) | stdout or `-o` |
| `delbyte FILE -b BITS --pos B:K [B:K ...]` | delete bytes at the given positions | stdout or `-o` |
| `encrypt` / `decrypt FILE -a {aes,des,idea} -m {ecb,cbc,cfb,ofb} (-k KEY \| -K FILE) [--key-hex] [--iv HEX \| --iv-file FILE]` | encryption / decryption | stdout or `-o` |
| `entropy FILE [FILE ...] -o CHART` | bar chart of entropies (maximum entropy 8.00 in the title) | `-o` (required) |
| `histogram FILE -o CHART` | histogram of all 256 byte values | `-o` (required) |
| `repeat TEXT -n N` | repeat text up to exactly N bytes | stdout or `-o` |
| `help [COMMAND]` | help | stdout |

## Encryption

- Key lengths: AES 16/24/32 B, DES 8 B, IDEA 16 B.
- ECB/CBC use PKCS7 padding; CFB/OFB work without padding.
- The output is the **raw ciphertext** — the IV is not stored in it, so block operations
  (`printblocks`, `setbyte`, `delbyte`) and `entropy` work on the real cipher blocks, and the file is
  compatible with other tools (e.g. `openssl enc -K … -iv …`).
- CBC/CFB/OFB need an IV of the cipher's block size (AES 16 B, DES/IDEA 8 B):
  - `encrypt`: give it with `--iv HEX` or `--iv-file FILE` (raw bytes); otherwise a random IV is generated
    and printed to stderr. `--iv-out FILE` saves the IV used.
  - `decrypt`: the IV is required (`--iv` or `--iv-file`).
- ECB uses no IV.

Entropy: `H = -Σ p·log2(p)` computed over the alphabet of all 256 byte values; maximum entropy = `log2(256) = 8` bits.
The histogram shows all 256 byte values `00`–`FF` (hex labels), including those that do not occur.

## Examples

```sh
uv run cryptoh printblocks text.txt -b 64
uv run cryptoh setbyte text.txt -b 64 --block 2 --byte 3 --value X -o changed.txt
uv run cryptoh delbyte text.txt -b 64 --pos 0:0 1:4 -o shortened.txt
uv run cryptoh encrypt text.txt -a idea -m cbc -k 0123456789abcdef --iv-out iv.bin -o cipher.bin
uv run cryptoh decrypt cipher.bin -a idea -m cbc -k 0123456789abcdef --iv-file iv.bin
uv run cryptoh encrypt text.txt -a aes -m ofb -k 00112233445566778899aabbccddeeff --key-hex --iv 000102030405060708090a0b0c0d0e0f
uv run cryptoh entropy text.txt cipher.bin -o charts/entropy.png
uv run cryptoh histogram text.txt -o charts/histogram.png
uv run cryptoh repeat "Hello world. " -n 1024 -o repeated.txt
```
