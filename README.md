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
| `insbyte FILE -b BITS --block B --byte K --value V` | insert a byte so it becomes byte K of block B; later bytes shift right | stdout or `-o` |
| `insblock FILE -b BITS --block B [--value HEX]` | insert a block (random by default) so it becomes block B; later blocks shift right | stdout or `-o` |
| `invbit FILE -b BITS --block B --byte K --bit N` | invert bit N of byte K in block B (bit 0 = most significant) | stdout or `-o` |
| `delbit FILE -b BITS --pos B:K:N [B:K:N ...]` | delete bits at the given positions; later bits shift left, the last byte is padded with zero bits | stdout or `-o` |
| `genkey -b BITS [--hex]` | random key of BITS bits (raw bytes or hex text) | stdout or `-o` |
| `geniv -b BITS [--hex]` | random IV of BITS bits (raw bytes or hex text) | stdout or `-o` |
| `genrsa -b {512,1024,2048,3072,4096} [--pub PUBFILE]` | RSA private key (PEM); the public key goes to `--pub` | stdout or `-o` |
| `encrypt` / `decrypt FILE -a {aes,des,idea} -m {ecb,cbc,cfb,ofb} -k KEYFILE [--key-hex] [--iv IVFILE [--iv-hex]] [-t]` | encryption / decryption; `-t` prints the time to stderr | stdout or `-o` |
| `encrypt` / `decrypt FILE -a rsa -k PEMFILE [-t]` | textbook RSA encryption / decryption of the whole file (no symmetric cipher) | stdout or `-o` |
| `entropy FILE [FILE ...] -o CHART` | bar chart of entropies (maximum entropy 8.00 in the title) | `-o` (required) |
| `histogram FILE -o CHART` | histogram of all 256 byte values | `-o` (required) |
| `autocorr FILE [FILE ...] [-n MAXSHIFT] -o CHART` | autocorrelation chart: matching bytes for shifts 1–MAXSHIFT (default 256) | `-o` (required) |
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

### RSA

- **Encryption** — textbook RSA, **no cryptographic padding**, deterministic. With `k` = length of `n` in bytes
  (64 for 512 bits, 128 for 1024, 256 for 2048):
  1. the file is split into chunks of `k − 1` bytes (so every chunk is a number smaller than `n`);
  2. the last, shorter chunk is right-padded with `0x00` bytes to `k − 1` bytes;
  3. every chunk is read as a big-endian number `m`, and `c = m^e mod n` is written as `k` big-endian bytes.

  The ciphertext is only `k / (k − 1)` times longer than the input (+1.6% for 512 bits). Every chunk is
  encrypted independently, like ECB: equal chunks give equal blocks.
- **Decryption** — `m = c^d mod n` for every `k`-byte block (computed with the Chinese remainder theorem), written as
  `k − 1` bytes; trailing `0x00` bytes of the last block are removed as padding (so a file that ends with zero bytes
  loses them). A modified ciphertext is still decrypted, with warnings, so
  that error propagation can be observed:
  - a changed byte damages only its own block (`k − 1` bytes of the output); the other blocks are correct;
  - a block not smaller than `n` is reduced mod `n`; a result that does not fit in `k − 1` bytes loses its top byte;
  - a deleted or inserted byte moves the block boundaries, so every block from that point on is damaged; when the
    length is not a multiple of `k`, the last shorter block is decrypted as a shorter number.
- **Keys** — `-k` is a PEM file from `genrsa`: the private key as PKCS#8, the public key as SubjectPublicKeyInfo
  (both readable by OpenSSL, `openssl rsa -in key.pem -check`). Encryption accepts either; decryption needs the
  private key. `-m`, `--iv`, `--key-hex`, `--iv-hex` are ignored with a warning.
- **Key generation** — the public exponent is 65537. Keys of 1024 bits and more are generated by `cryptography`.
  The library refuses keys under 1024 bits, so 512-bit keys are generated by this project: two random 256-bit primes
  (top two bits set, so `n` has exactly 512 bits) checked with 64 rounds of Miller–Rabin with random bases from
  `secrets`. Keys under 2048 bits produce a warning.
- **Security** — textbook RSA is deterministic and malleable (`c · s^e` decrypts to `m · s`); it is used here to make
  the block structure observable (determinism, error propagation). Real systems use OAEP and encrypt only a
  symmetric key with RSA.

### Timing

`-t` / `--time` on `encrypt` / `decrypt` measures only the cipher operation (`time.perf_counter_ns`, without reading
the key or the file and without writing the result) and prints e.g.
`cryptoh: time: decryption RSA-2048: 1620.118 ms (524800 -> 522541 bytes, 0.31 MiB/s)` to stderr. It is written
directly, so it is shown even with `-q`. The first OpenSSL call in a process includes a one-time initialisation, so
for small files the measurement of a single AES/DES/IDEA run can be noticeably higher than the steady-state speed.
RSA arithmetic is done by GMP (`gmpy2`), not OpenSSL, so RSA and symmetric times come from different
implementations; decryption is much slower than encryption because `d` is large and `e = 65537` is small.

## Statistics

Entropy: `H = -Σ p·log2(p)` computed over the alphabet of all 256 byte values; maximum entropy = `log2(256) = 8` bits.
The histogram shows all 256 byte values `00`–`FF` (hex labels), including those that do not occur.

Autocorrelation: for every shift `k = 1..N` it counts the positions `i` with `data[i] == data[i + k]` — the text is
compared with itself shifted by `k` bytes, without wrap-around, so `n − k` pairs are compared. Several files are
drawn as lines on one chart (`N` is limited to `size − 1` for short files). The table on stdout shows, per file, the
mean count, the mean expected for uniformly random bytes (`(n − k) / 256`), and the highest count with its shift —
periodic text gives peaks at multiples of its period, while good ciphertext stays near the random level.

## Libraries

Python ≥ 3.14. Versions below are the ones pinned in `uv.lock`.

### Cryptographic

| Library | Version | Used for |
|---|---|---|
| [`cryptography`](https://cryptography.io/) (pyca) | 50.0.2 | symmetric encryption and decryption (`src/cryptoh/cipher.py`): `hazmat.primitives.ciphers` — `Cipher`, AES, ECB/CBC modes; `hazmat.decrepit.ciphers` — legacy algorithms and modes: TripleDES (used as single DES), IDEA, CFB, OFB; `hazmat.primitives.padding` — PKCS7. RSA keys (`src/cryptoh/rsa_cipher.py`): `hazmat.primitives.asymmetric.rsa` — key generation (≥ 1024 bits), `RSAPrivateNumbers` / `RSAPublicNumbers`; `hazmat.primitives.serialization` — PEM |
| [`gmpy2`](https://gmpy2.readthedocs.io/) (GMP) | 2.3.2 | RSA encryption and decryption (`src/cryptoh/rsa_cipher.py`): modular exponentiation `powmod` and inverse `invert` — about 7× faster than Python's `pow` for decryption |
| `secrets` / `pow` (Python standard library) | — | 512-bit RSA key generation only: random prime candidates and Miller–Rabin bases (`secrets`), modular exponentiation and inverse (`pow`) |
| OpenSSL (bundled in the `cryptography` wheel) | 4.0.3 | the actual AES/DES/IDEA implementations and RSA key generation behind `cryptography` |
| `os.urandom` (Python standard library) | — | random keys and IVs in `genkey` / `geniv` — the operating system's CSPRNG (`getrandom()` on Linux) |

The symmetric ciphers come entirely from the library; the project only selects the algorithm and mode, checks
key/IV lengths and reads/writes the data. RSA is the exception: no library offers RSA without padding (`cryptography`
deliberately supports only OAEP and PKCS#1 v1.5), so the textbook RSA block format and the prime generation for
512-bit keys (see [RSA](#rsa)) are implemented here, with the big-number arithmetic done by GMP.

### Non-cryptographic

| Library | Version | Used for |
|---|---|---|
| [`matplotlib`](https://matplotlib.org/) | 3.11.2 | entropy, histogram and autocorrelation charts (`src/cryptoh/stats.py`), rendered with the non-interactive `Agg` backend to image files; imported only by `entropy`, `histogram` and `autocorr` |
| [`numpy`](https://numpy.org/) (a dependency of matplotlib) | 2.5.4 | vectorised byte comparison for autocorrelation |
| Python standard library | — | `argparse` (command line), `logging` (messages on stderr), `math` (`log2` for entropy), `pathlib` / `sys` (file and stdout I/O), `time` (`perf_counter_ns` for `--time`) |

## Examples

```sh
uv run cryptoh printblocks text.txt -b 64
uv run cryptoh setbyte text.txt -b 64 --block 2 --byte 3 --value X -o changed.txt
uv run cryptoh delbyte text.txt -b 64 --pos 0:0 1:4 -o shortened.txt
uv run cryptoh insbyte cipher.bin -b 128 --block 4 --byte 2 --value X -o inserted.bin
uv run cryptoh insblock cipher.bin -b 128 --block 4 -o extra_block.bin
uv run cryptoh invbit cipher.bin -b 64 --block 1 --byte 0 --bit 7 -o flipped.bin
uv run cryptoh delbit cipher.bin -b 64 --pos 0:0:0 2:3:4 -o shortened.bin
uv run cryptoh genkey -b 128 -o key.bin
uv run cryptoh geniv -b 64 -o iv.bin
uv run cryptoh encrypt text.txt -a idea -m cbc -k key.bin --iv iv.bin -o cipher.bin
uv run cryptoh decrypt cipher.bin -a idea -m cbc -k key.bin --iv iv.bin
uv run cryptoh genkey -b 256 --hex -o key.hex
uv run cryptoh geniv -b 128 --hex -o iv.hex
uv run cryptoh encrypt text.txt -a aes -m ofb -k key.hex --key-hex --iv iv.hex --iv-hex -o cipher_aes.bin
uv run cryptoh genrsa -b 2048 -o rsa.pem --pub rsa.pub
uv run cryptoh encrypt text.txt -a rsa -k rsa.pub -o cipher_rsa.bin --time
uv run cryptoh decrypt cipher_rsa.bin -a rsa -k rsa.pem --time
uv run cryptoh encrypt text.txt -a aes -m cbc -k key.hex --key-hex --iv iv.hex --iv-hex -o /dev/null --time
uv run cryptoh entropy text.txt cipher.bin -o charts/entropy.png
uv run cryptoh autocorr text.txt cipher.bin cipher_rsa.bin -n 128 -o charts/autocorr.png
uv run cryptoh histogram text.txt -o charts/histogram.png
uv run cryptoh repeat "Hello world. " -n 1024 -o repeated.txt
```
