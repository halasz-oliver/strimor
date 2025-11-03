#include "strimor.hpp"
#include <chrono>
#include <iostream>
#include <vector>
#include <iomanip>

using namespace strimor;
using namespace std::chrono;

void benchmark_size(const size_t size_bytes) {
    // Generate test data
    const std::vector<unsigned char> data(size_bytes, 0x42);

    const Key key;
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    // Encryption benchmark
    const auto start = high_resolution_clock::now();

    Encryptor enc(key);
    enc.start(header);
    const auto ciphertext = enc.update_final(data.data(), data.size());

    const auto enc_end = high_resolution_clock::now();
    const auto enc_duration = duration_cast<microseconds>(enc_end - start).count();

    // Decryption benchmark
    const auto dec_start = high_resolution_clock::now();

    Decryptor dec(key);
    dec.start(header);
    auto plaintext = dec.update(ciphertext.data(), ciphertext.size());

    const auto dec_end = high_resolution_clock::now();
    const auto dec_duration = duration_cast<microseconds>(dec_end - dec_start).count();

    // Calculate throughput
    const double enc_mbps = (size_bytes / 1024.0 / 1024.0) / (enc_duration / 1000000.0);
    const double dec_mbps = (size_bytes / 1024.0 / 1024.0) / (dec_duration / 1000000.0);

    std::cout << std::setw(10) << (size_bytes / 1024) << " KB | "
              << std::setw(8) << enc_duration << " μs | "
              << std::setw(8) << std::fixed << std::setprecision(2) << enc_mbps << " MB/s | "
              << std::setw(8) << dec_duration << " μs | "
              << std::setw(8) << dec_mbps << " MB/s" << std::endl;
}

int main() {
    std::cout << "Strimor Benchmark Results" << std::endl;
    std::cout << "=========================" << std::endl;
    std::cout << std::endl;

    std::cout << "Data Size  | Encrypt Time | Encrypt Speed | Decrypt Time | Decrypt Speed" << std::endl;
    std::cout << "-----------|--------------|---------------|--------------|---------------" << std::endl;

    benchmark_size(1024);           // 1 KB
    benchmark_size(10 * 1024);      // 10 KB
    benchmark_size(100 * 1024);     // 100 KB
    benchmark_size(1024 * 1024);    // 1 MB
    benchmark_size(10 * 1024 * 1024); // 10 MB

    return 0;
}