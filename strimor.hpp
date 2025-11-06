// strimor.hpp
// started 2025 nov 3 20:01 - just hacking around after work
// not final or safe for production (yet)
// nov 6 update: added actual file streaming

#ifndef STRIMOR_HPP
#define STRIMOR_HPP

#include <sodium.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <cstring>

namespace strimor {

struct Error final : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct Key {
    unsigned char data[crypto_secretstream_xchacha20poly1305_KEYBYTES]{};

    Key() { randombytes_buf(data, sizeof data); }

    [[nodiscard]] std::string to_hex() const {
        char buf[crypto_secretstream_xchacha20poly1305_KEYBYTES * 2 + 1];
        sodium_bin2hex(buf, sizeof buf, data, sizeof data);
        return {buf};
    }
};

struct Encryptor {
    crypto_secretstream_xchacha20poly1305_state st{};
    bool started = false;

    explicit Encryptor(const Key& key) : key_(key) {
        if (sodium_init() < 0) throw Error("sodium_init failed");
        std::memset(&st, 0, sizeof st);
    }

    void start(unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES]) {
        if (crypto_secretstream_xchacha20poly1305_init_push(&st, header, key_.data) != 0) {
            throw Error("init_push failed??");
        }
        started = true;
    }

    std::vector<unsigned char> update(const unsigned char* in, size_t len) {
        if (!started) throw Error("not started");
        std::vector<unsigned char> out(len + crypto_secretstream_xchacha20poly1305_ABYTES);
        unsigned long long written = 0;
        crypto_secretstream_xchacha20poly1305_push(&st, out.data(), &written, in, len, nullptr, 0, 0);
        out.resize(written);
        return out;
    }

    std::vector<unsigned char> update_final(const unsigned char* in, size_t len) {
        if (!started) throw Error("not started");
        std::vector<unsigned char> out(len + crypto_secretstream_xchacha20poly1305_ABYTES);
        unsigned long long written = 0;
        crypto_secretstream_xchacha20poly1305_push(&st, out.data(), &written, in, len, nullptr, 0,
                                                   crypto_secretstream_xchacha20poly1305_TAG_FINAL);
        out.resize(written);
        return out;
    }

    std::vector<unsigned char> finalize() {
        unsigned long long written = 0;
        std::vector<unsigned char> out(crypto_secretstream_xchacha20poly1305_ABYTES);
        crypto_secretstream_xchacha20poly1305_push(&st, out.data(), &written, nullptr, 0, nullptr, 0,
                                                   crypto_secretstream_xchacha20poly1305_TAG_FINAL);
        out.resize(written);
        return out;
    }

private:
    Key key_;
};

struct Decryptor {
    crypto_secretstream_xchacha20poly1305_state st{};
    bool started = false;
    Key key;

    explicit Decryptor(const Key& k) : key(k) {
        if (sodium_init() < 0) throw Error("sodium fail init");
    }

    void start(const unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES]) {
        if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key.data) != 0)
            throw Error("bad header or key idk");
        started = true;
    }

    std::vector<unsigned char> update(const unsigned char* in, size_t len) {
        if (!started) throw Error("not started decrypt");
        std::vector<unsigned char> out(len);
        unsigned long long out_len = 0;
        unsigned char tag;
        int r = crypto_secretstream_xchacha20poly1305_pull(&st, out.data(), &out_len, &tag,
                                                           in, len, nullptr, 0);
        if (r != 0) throw Error("auth fail?? corrupted?");
        out.resize(out_len);
        return out;
    }
};

// file streaming helpers - actually streams now instead of loading everything
// chunk size feels good, not too big not too small
constexpr size_t STREAM_CHUNK_SIZE = 64 * 1024; // 64 KB

inline void encrypt_file(const std::string& in_path, const std::string& out_path, const Key& key) {
    std::ifstream in(in_path, std::ios::binary);
    if (!in) throw Error("cant open input file");

    std::ofstream out(out_path, std::ios::binary);
    if (!out) throw Error("cant open output file");

    // setup encryption
    Encryptor enc(key);
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    enc.start(header);

    // write header first
    out.write(reinterpret_cast<char*>(header), sizeof header);

    // stream through file chunk by chunk
    std::vector<unsigned char> buf(STREAM_CHUNK_SIZE);
    while (in) {
        in.read(reinterpret_cast<char*>(buf.data()), STREAM_CHUNK_SIZE);
        const auto bytes_read = in.gcount();

        if (bytes_read > 0) {
            std::vector<unsigned char> encrypted;

            // check if this is last chunk
            if (in.peek() == EOF) {
                encrypted = enc.update_final(buf.data(), bytes_read);
            } else {
                encrypted = enc.update(buf.data(), bytes_read);
            }

            out.write(reinterpret_cast<char*>(encrypted.data()), encrypted.size());
        }
    }

    // if file was empty or ended on chunk boundary, still need final tag
    if (in.eof() && in.gcount() == 0) {
        auto final_chunk = enc.finalize();
        out.write(reinterpret_cast<char*>(final_chunk.data()), final_chunk.size());
    }
}

inline void decrypt_file(const std::string& in_path, const std::string& out_path, const Key& key) {
    std::ifstream in(in_path, std::ios::binary);
    if (!in) throw Error("cant open encrypted file");

    std::ofstream out(out_path, std::ios::binary);
    if (!out) throw Error("cant open output file");

    // read header
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    in.read(reinterpret_cast<char*>(header), sizeof header);
    if (!in) throw Error("file too short for header??");

    // setup decryption
    Decryptor dec(key);
    dec.start(header);

    // stream through encrypted chunks
    std::vector<unsigned char> buf(STREAM_CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES);
    while (in) {
        in.read(reinterpret_cast<char*>(buf.data()), buf.size());
        const auto bytes_read = in.gcount();

        if (bytes_read > 0) {
            auto decrypted = dec.update(buf.data(), bytes_read);
            out.write(reinterpret_cast<char*>(decrypted.data()), decrypted.size());
        }
    }
}

} // namespace strimor

#endif