#include "strimor.hpp"
#include <iostream>
#include <sys/stat.h>

using namespace strimor;

// helper to get file size
size_t get_file_size(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0) {
        return st.st_size;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "usage: " << argv[0] << " <encrypt|decrypt> <input> <output>" << std::endl;
        std::cerr << "example: " << argv[0] << " encrypt myfile.txt myfile.encrypted" << std::endl;
        return 1;
    }

    const std::string mode = argv[1];
    const std::string input = argv[2];
    const std::string output = argv[3];

    try {
        // for this demo we generate a new key each time
        // in real use you'd want to save/load keys properly
        Key key;
        std::cout << "key: " << key.to_hex() << std::endl;
        std::cout << "(save this key if you want to decrypt later!)" << std::endl << std::endl;

        const size_t input_size = get_file_size(input);

        if (mode == "encrypt") {
            std::cout << "encrypting " << input << " (" << input_size << " bytes)..." << std::endl;
            encrypt_file(input, output, key);
            const size_t output_size = get_file_size(output);
            std::cout << "wrote " << output << " (" << output_size << " bytes)" << std::endl;
            std::cout << "overhead: " << (output_size - input_size) << " bytes" << std::endl;
        }
        else if (mode == "decrypt") {
            std::cout << "decrypting " << input << " (" << input_size << " bytes)..." << std::endl;
            decrypt_file(input, output, key);
            const size_t output_size = get_file_size(output);
            std::cout << "wrote " << output << " (" << output_size << " bytes)" << std::endl;
        }
        else {
            std::cerr << "mode must be 'encrypt' or 'decrypt'" << std::endl;
            return 1;
        }

        std::cout << "done!" << std::endl;

    } catch (const Error& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }
}