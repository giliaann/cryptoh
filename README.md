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
| `invbit FILE -b BITS --block B --byte K --bit N` | invert bit N of byte K in block B (bit 0 = most significant) | stdout or `-o` |
| `delbit FILE -b BITS --pos B:K:N [B:K:N ...]` | delete bits at the given positions; later bits shift left, the last byte is padded with zero bits | stdout or `-o` |
| `genkey -b BITS [--hex]` | random key of BITS bits (raw bytes or hex text) | stdout or `-o` |
| `geniv -b BITS [--hex]` | random IV of BITS bits (raw bytes or hex text) | stdout or `-o` |
| `encrypt` / `decrypt FILE -a {aes,des,idea} -m {ecb,cbc,cfb,ofb} -k KEYFILE [--key-hex] [--iv IVFILE [--iv-hex]]` | encryption / decryption | stdout or `-o` |
| `entropy FILE [FILE ...] -o CHART` | bar chart of entropies (maximum entropy 8.00 in the title) | `-o` (required) |
| `histogram FILE -o CHART` | histogram of all 256 byte values | `-o` (required) |
| `repeat TEXT -n N` | repeat text up to exactly N bytes | stdout or `-o` |
| `help [COMMAND]` | help | stdout |

## Encryption

### Algorithms

Implemented with the [`cryptography`](https://cryptography.io/) library (see [Libraries](#libraries)).

| `-a` | Algorithm | Block | Key | Rounds | Notes |
|---|---|---|---|---|---|
| `aes` | AES (Rijndael, FIPS 197): **AES-128 / AES-192 / AES-256**, chosen by the key length | 128 bits | 128 / 192 / 256 bits | 10 / 12 / 14 | the current standard |
| `des` | **single DES** (FIPS 46-3) | 64 bits | 64 bits (56 effective, every 8th bit is parity and is ignored) | 16 | computed as 3DES-EDE with key `K\|K\|K`, which is equivalent to single DES; insecure, for teaching only |
| `idea` | **IDEA** (Lai–Massey, 1991) | 64 bits | 128 bits | 8.5 | legacy algorithm |

| `-m` | Mode | IV | Padding |
|---|---|---|---|
| `ecb` | Electronic Codebook — every block encrypted separately | none | PKCS7 |
| `cbc` | Cipher Block Chaining | 1 block | PKCS7 |
| `cfb` | Cipher Feedback with **full-block feedback** (CFB-128 for AES, CFB-64 for DES/IDEA; not CFB-8 or CFB-1) | 1 block | none (stream mode) |
| `ofb` | Output Feedback with full-block feedback | 1 block | none (stream mode) |

The results match OpenSSL: `aes` + `cfb` = `openssl enc -aes-128-cfb` (likewise `-aes-192-…`/`-aes-256-…`),
`des` + `cbc` = `openssl enc -des-cbc` (needs `-provider legacy -provider default` in OpenSSL 3+).

### Usage

- Key lengths: AES 16/24/32 B, DES 8 B, IDEA 16 B.
- ECB/CBC use PKCS7 padding; CFB/OFB work without padding.
- The output is the **raw ciphertext** — the IV is not stored in it, so block operations
  (`printblocks`, `setbyte`, `delbyte`, `invbit`, `delbit`) and `entropy` work on the real cipher blocks, and the file is
  compatible with other tools (e.g. `openssl enc -K … -iv …`).
- The key and the IV are given only as files: `-k FILE` and `--iv FILE`. By default a file holds
  **raw bytes**; with `--key-hex` / `--iv-hex` it holds **hexadecimal text** (whitespace and a trailing
  newline are ignored). The bytes passed to the cipher are the same in both cases.
- Create them with `genkey -b BITS` / `geniv -b BITS` (raw bytes; add `--hex` for hexadecimal text),
  to stdout or to a file with `-o`.
- CBC/CFB/OFB require an IV whose length equals the cipher's block size (AES 128 bits, DES/IDEA 64 bits);
  the same IV file is needed for decryption. The IV is never generated automatically.
- ECB uses no IV (`--iv` is ignored with a warning).

Entropy: `H = -Σ p·log2(p)` computed over the alphabet of all 256 byte values; maximum entropy = `log2(256) = 8` bits.
The histogram shows all 256 byte values `00`–`FF` (hex labels), including those that do not occur.

## Libraries

Python ≥ 3.14. Versions below are the ones pinned in `uv.lock`.

### Cryptographic

| Library | Version | Used for |
|---|---|---|
| [`cryptography`](https://cryptography.io/) (pyca) | 50.0.2 | all encryption and decryption (`src/cryptoh/cipher.py`): `hazmat.primitives.ciphers` — `Cipher`, AES, ECB/CBC modes; `hazmat.decrepit.ciphers` — legacy algorithms and modes: TripleDES (used as single DES), IDEA, CFB, OFB; `hazmat.primitives.padding` — PKCS7 |
| OpenSSL (bundled in the `cryptography` wheel) | 4.0.3 | the actual cipher implementations behind `cryptography` |
| `os.urandom` (Python standard library) | — | random keys and IVs in `genkey` / `geniv` — the operating system's CSPRNG (`getrandom()` on Linux) |

The project implements no cryptographic algorithm itself; it only selects the algorithm and mode,
checks key/IV lengths and reads/writes the data.

### Non-cryptographic

| Library | Version | Used for |
|---|---|---|
| [`matplotlib`](https://matplotlib.org/) | 3.11.2 | entropy and histogram charts (`src/cryptoh/stats.py`), rendered with the non-interactive `Agg` backend to image files; imported only by `entropy` and `histogram` |
| Python standard library | — | `argparse` (command line), `logging` (messages on stderr), `math` (`log2` for entropy), `pathlib` / `sys` (file and stdout I/O) |

## Examples

```sh
uv run cryptoh printblocks text.txt -b 64
uv run cryptoh setbyte text.txt -b 64 --block 2 --byte 3 --value X -o changed.txt
uv run cryptoh delbyte text.txt -b 64 --pos 0:0 1:4 -o shortened.txt
uv run cryptoh invbit cipher.bin -b 64 --block 1 --byte 0 --bit 7 -o flipped.bin
uv run cryptoh delbit cipher.bin -b 64 --pos 0:0:0 2:3:4 -o shortened.bin
uv run cryptoh genkey -b 128 -o key.bin
uv run cryptoh geniv -b 64 -o iv.bin
uv run cryptoh encrypt text.txt -a idea -m cbc -k key.bin --iv iv.bin -o cipher.bin
uv run cryptoh decrypt cipher.bin -a idea -m cbc -k key.bin --iv iv.bin
uv run cryptoh genkey -b 256 --hex -o key.hex
uv run cryptoh geniv -b 128 --hex -o iv.hex
uv run cryptoh encrypt text.txt -a aes -m ofb -k key.hex --key-hex --iv iv.hex --iv-hex -o cipher_aes.bin
uv run cryptoh entropy text.txt cipher.bin -o charts/entropy.png
uv run cryptoh histogram text.txt -o charts/histogram.png
uv run cryptoh repeat "Hello world. " -n 1024 -o repeated.txt
```
