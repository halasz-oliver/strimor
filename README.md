# Strimor

**Streaming encryption wrapper for libsodium (C++17)**

**Strimor = Stream + Armor**

A small weekend project to learn how libsodium’s `XChaCha20-Poly1305` secretstream API works. It wraps the API in a simple C++ interface for authenticated encryption — now with real file streaming.

**Work in progress.** Started this on a Sunday night and keep tweaking it whenever I feel like it. Expect rough edges and changes.

---

## Features

* Authenticated encryption using XChaCha20-Poly1305 (libsodium)
* Simple `Encryptor` and `Decryptor` classes
* Chunk-based encryption/decryption
* Actual file streaming — processes 64KB chunks, no full-file buffering
* Random key generation
* Header-only
* Minimal dependencies (just libsodium)
* Not audited — don’t use in production unless you know what you’re doing

---

## Build

### macOS (Homebrew)

```bash
brew install libsodium
mkdir build && cd build
cmake ..
make
./strimor_example
```

### Linux

```bash
sudo apt install libsodium-dev
mkdir build && cd build
cmake ..
make
./strimor_example
```

You should see something like:

```
=== Strimor Examples ===

generated key: 3307d32fde216aa85524f88006dba7863848411a218b333307507ef2b39525f8

Example 1: In-memory encryption
--------------------------------
original:  hello streaming world!
decrypted: hello streaming world!

Example 2: File streaming
--------------------------
encrypted test_input.txt -> test_encrypted.bin
decrypted test_encrypted.bin -> test_output.txt
✓ files match perfectly!
```

---

## Usage

### In-memory encryption

```cpp
#include "strimor.hpp"
using namespace strimor;

int main() {
    Key key;

    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    Encryptor enc(key);
    enc.start(header);

    const char* msg = "hello world";
    auto ciphertext = enc.update_final(
        reinterpret_cast<const unsigned char*>(msg),
        strlen(msg)
    );

    Decryptor dec(key);
    dec.start(header);

    auto plaintext = dec.update(ciphertext.data(), ciphertext.size());
    // plaintext == "hello world"
}
```

For multi-chunk encryption:

```cpp
Encryptor enc(key);
enc.start(header);

auto chunk1 = enc.update(data1, len1);
auto chunk2 = enc.update(data2, len2);
auto final  = enc.finalize();
```

### File streaming

```cpp
#include "strimor.hpp"
using namespace strimor;

int main() {
    Key key;

    encrypt_file("large_file.txt", "large_file.encrypted", key);
    decrypt_file("large_file.encrypted", "large_file_decrypted.txt", key);

    // Handles any file size, memory stays around 64KB
}
```

Or use the CLI tool:

```bash
./strimor_file_stream encrypt myfile.txt myfile.encrypted
./strimor_file_stream decrypt myfile.encrypted myfile_decrypted.txt
```

---

## How it works

Strimor uses libsodium’s secretstream API, which provides:

* Authenticated encryption (prevents tampering)
* Ordered message integrity
* Replay protection
* XChaCha20’s extended nonce for long streams

Each chunk is encrypted and tagged for authenticity. The header (24 bytes) stores the initial nonce and must be saved or transmitted alongside the ciphertext.

File streaming flow:

1. Read input file in 64KB chunks
2. Encrypt/decrypt each chunk
3. Write immediately to the output
4. Move on to the next chunk

This allows multi-gigabyte files to be processed without ever loading them fully into memory.

Encrypted file layout:

```
[24-byte header][encrypted chunk 1][encrypted chunk 2]...[final chunk with TAG_FINAL]
```

---

## Limitations

* No built-in key derivation (yet)
* Minimal error handling
* “Weekend project” quality — don’t expect enterprise polish
* File helpers live inline in the header for simplicity
* Chunk size fixed at 64KB (works fine so far)

---

## Notes

This library is intentionally minimal. If you need password-based keys, KDFs, or a more feature-rich API, you’re probably better off using libsodium directly or another library.

The main goal was to understand how authenticated streaming encryption actually works — and to test performance on large files.

---

## Performance

Benchmarks run automatically on GitHub Actions (Ubuntu latest):

<!-- BENCHMARK_START -->

```
Benchmark results go here when ready
```

<!-- BENCHMARK_END -->

Run locally:

```bash
cd build
./strimor_benchmark
```

The benchmarks measure in-memory operations. File streaming adds almost no extra overhead — it’s just chunked I/O.

---

## License

MIT — use it however you want, just don’t blame me if it breaks.
