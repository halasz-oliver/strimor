#include "strimor.hpp"
#include <fstream>
#include <iostream>

using namespace strimor;

int main() {
    try {
        std::cout << "=== Strimor Examples ===" << std::endl << std::endl;

        // generate random key
        Key key;
        std::cout << "generated key: " << key.to_hex() << std::endl << std::endl;

        // === Example 1: In-memory encryption ===
        std::cout << "Example 1: In-memory encryption" << std::endl;
        std::cout << "--------------------------------" << std::endl;

        unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
        Encryptor enc(key);
        enc.start(header);

        const std::string msg = "hello streaming world!";
        std::vector<unsigned char> encChunk = enc.update_final(
            reinterpret_cast<const unsigned char*>(msg.data()), msg.size());

        // write to file
        std::ofstream out("cipher.bin", std::ios::binary);
        out.write(reinterpret_cast<char*>(header), sizeof header);
        out.write(reinterpret_cast<char*>(encChunk.data()), encChunk.size());
        out.close();

        // read back
        std::ifstream in("cipher.bin", std::ios::binary);
        unsigned char hdr[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
        in.read(reinterpret_cast<char*>(hdr), sizeof hdr);
        std::vector<unsigned char> fileData(
            (std::istreambuf_iterator<char>(in)),
            std::istreambuf_iterator<char>()
        );
        in.close();

        Decryptor dec(key);
        dec.start(hdr);
        std::vector<unsigned char> plain = dec.update(fileData.data(), fileData.size());

        std::cout << "original:  " << msg << std::endl;
        std::cout << "decrypted: " << std::string(plain.begin(), plain.end()) << std::endl;
        std::cout << std::endl;

        // === Example 2: File streaming ===
        std::cout << "Example 2: File streaming (the real deal)" << std::endl;
        std::cout << "------------------------------------------" << std::endl;

        // create a test file with some content
        std::ofstream test_file("test_input.txt");
        test_file << "this is a test file for streaming encryption!\n";
        test_file << "it can handle multiple lines and large files.\n";
        test_file << "chunks are processed one at a time, saving memory.\n";
        for (int i = 0; i < 100; i++) {
            test_file << "line " << i << ": the quick brown fox jumps over the lazy dog\n";
        }
        test_file.close();

        // encrypt the file with streaming
        encrypt_file("test_input.txt", "test_encrypted.bin", key);
        std::cout << "encrypted test_input.txt -> test_encrypted.bin" << std::endl;

        // decrypt it back
        decrypt_file("test_encrypted.bin", "test_output.txt", key);
        std::cout << "decrypted test_encrypted.bin -> test_output.txt" << std::endl;

        // verify it matches
        std::ifstream original("test_input.txt");
        std::ifstream decrypted("test_output.txt");
        std::string orig_line, dec_line;
        bool match = true;
        while (std::getline(original, orig_line) && std::getline(decrypted, dec_line)) {
            if (orig_line != dec_line) {
                match = false;
                break;
            }
        }
        if (match && original.eof() && decrypted.eof()) {
            std::cout << "✓ files match perfectly!" << std::endl;
        } else {
            std::cout << "✗ something went wrong" << std::endl;
        }

    } catch (const Error& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }
}