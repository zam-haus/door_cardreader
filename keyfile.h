//
// Created by phi1010 on 6/25/25.
//

#ifndef KEYFILE_H
#define KEYFILE_H
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include "exceptions.h"

static std::vector<uint8_t> read_key_file(const std::string &key_file, int key_size) {
    std::ifstream file(key_file, std::ios::binary);
    if (!file)
        throw ExitException(EXIT_FAILURE, "Failed to open PICC master key file: %s", key_file.c_str());

    auto key = std::vector<uint8_t>(key_size);
    file.read(reinterpret_cast<char *>(key.data()), key_size);
    if (file.gcount() != key_size)
        throw ExitException(EXIT_FAILURE, "Failed to read PICC master key, expected 16 bytes but got %zd bytes",
                            file.gcount());

    return key;
}
#endif //KEYFILE_H
