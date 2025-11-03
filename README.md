# Strimor

**Streaming encryption wrapper for libsodium (C++17)**

Strimor = Stream + Armor

Just a weekend project to learn how libsodium's XChaCha20-Poly1305 secretstream API works. Wraps it in a simple C++ interface for authenticated encryption.

**Work in progress** - started this on a Sunday evening and plan to keep improving it. Expect changes and additions.

---

## Features

- XChaCha20-Poly1305 authenticated encryption via libsodium
- Simple Encryptor and Decryptor classes
- Chunk-based encryption and decryption
- Random key generation
- Header-only library
- Minimal dependencies (just libsodium)
- Not audited, don't use in production

---

## Build

**macOS with Homebrew:**
```bash
brew install libsodium
mkdir build && cd build
cmake ..
make
./strimor_example
```

**Linux:**
```bash
sudo apt install libsodium-dev
mkdir build && cd build
cmake ..
make
./strimor_example
```

You should see output like:
```
key: 3307d32fde216aa85524f88006dba7863848411a218b333307507ef2b39525f8
decrypted: hello streaming world!
```

---

## Usage

```cpp
#include "strimor.hpp"
using namespace strimor;

int main() {
    // Generate a random key
    Key key;
    
    // Set up encryption
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    Encryptor enc(key);
    enc.start(header);
    
    // Encrypt some data with finalization tag
    const char* msg = "hello world";
    auto ciphertext = enc.update_final(
        reinterpret_cast<const unsigned char*>(msg), 
        strlen(msg)
    );
    
    // Set up decryption
    Decryptor dec(key);
    dec.start(header);
    
    // Decrypt
    auto plaintext = dec.update(ciphertext.data(), ciphertext.size());
    
    // plaintext now contains "hello world"
}
```

For multi-chunk encryption, use `update()` for intermediate chunks and `finalize()` for the last chunk:

```cpp
Encryptor enc(key);
enc.start(header);

auto chunk1 = enc.update(data1, len1);  // intermediate chunk
auto chunk2 = enc.update(data2, len2);  // another chunk
auto final = enc.finalize();            // final chunk with TAG_FINAL
```

---

## How it works

Uses libsodium's secretstream API which provides:
- Authenticated encryption (can't be tampered with)
- Message ordering and integrity
- Protection against replay attacks
- Extended nonce (XChaCha20) for long streams

Each encrypted chunk includes an authentication tag. The header contains the initial nonce and must be transmitted along with the ciphertext.

---

## Limitations

- Chunks are buffered in memory, not true byte-by-byte streaming
- No key derivation functions included
- No built-in file I/O helpers
- Basic error handling with exceptions
- Weekend project quality code

---

## Notes

The API is intentionally minimal. If you need more features like key derivation, password hashing, or file streaming helpers, you should probably just use libsodium directly or look for a more mature library.

This was mainly a learning exercise to understand how authenticated streaming encryption works under the hood.

---

## Performance

Benchmarks run automatically on every commit (Ubuntu latest, GitHub Actions):

<!-- BENCHMARK_START -->
```
Benchmark here
```
<!-- BENCHMARK_END -->

Run benchmarks locally:
```bash
cd build
./strimor_benchmark
```

---

## License

MIT - do whatever you want with it, just don't blame me if something breaks.