#include "strimor.hpp"
#include <fstream>
#include <iostream>

using namespace strimor;

// quick test
int main() {
    try {
        // generate random key
        Key key;
        std::cout << "key: " << key.to_hex() << std::endl;

        // create header buffer
        unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

        // encryptor
        Encryptor enc(key);
        enc.start(header);

        // message to encrypt
        const std::string msg = "hello streaming world!";

        // encrypt message and finalize in one go with TAG_FINAL
        std::vector<unsigned char> encChunk = enc.update_final(
            reinterpret_cast<const unsigned char*>(msg.data()), msg.size());

        // write header + ciphertext to file
        std::ofstream out("cipher.bin", std::ios::binary);
        out.write(reinterpret_cast<char*>(header), sizeof header);
        out.write(reinterpret_cast<char*>(encChunk.data()), encChunk.size());
        out.close();

        // read file back
        std::ifstream in("cipher.bin", std::ios::binary);
        unsigned char hdr[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
        in.read(reinterpret_cast<char*>(hdr), sizeof hdr);

        std::vector<unsigned char> fileData(
            (std::istreambuf_iterator<char>(in)),
            std::istreambuf_iterator<char>()
        );
        in.close();

        // decryptor
        Decryptor dec(key);
        dec.start(hdr);

        std::vector<unsigned char> plain = dec.update(fileData.data(), fileData.size());

        std::cout << "decrypted: " << std::string(plain.begin(), plain.end()) << std::endl;

    } catch (const Error& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }
}