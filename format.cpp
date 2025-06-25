#include <err.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <nfc/nfc.h>
#include <freefare.h>
#include <iostream>
#include <vector>
#include <memory>
#include <fstream>
#include <functional>
#include <exception>
#include <string>
#include <cstdarg>
#include <limits>
#include <stdexcept>

#include "ScopeGuard.h"
#include "../freefare_errorcodes.h"
#include "exceptions.h"
#include "keyfile.h"

const std::string picc_master_key_file = "./keys/picc.master.key";
const std::string app1_master_key_file = "./keys/app1.master.key";
const std::string app1_rw_key_file = "./keys/app1.rw1.key";


void authenticate_with_picc_master_key(FreefareTag tag) {
    auto picc_master_key_vector = read_key_file(picc_master_key_file, 16);
    MifareDESFireKey picc_master_key = mifare_desfire_aes_key_new_with_version(picc_master_key_vector.data(), 0);
    auto picc_master_key_guard = ScopeGuard([&]() { mifare_desfire_key_free(picc_master_key); });

    MifareDESFireKey picc_master_key_default_des = mifare_desfire_des_key_new_with_version((uint8_t[8]){0});
    auto picc_master_key_default_des_guard = ScopeGuard([&]() {
        mifare_desfire_key_free(picc_master_key_default_des);
    });

    MifareDESFireKey picc_master_key_default_aes = mifare_desfire_aes_key_new_with_version((uint8_t[16]){0},0);
    auto picc_master_key_default_aes_guard = ScopeGuard([&]() {
        mifare_desfire_key_free(picc_master_key_default_aes);
    });

    // Try to authenticate with the new AES key
    if (print_error_code(mifare_desfire_authenticate(tag, 0, picc_master_key), tag) < 0) {
        std::cerr << "Failed to authenticate with master key" << std::endl;

        // Set the PICC master key to the constant AES key
        if (print_error_code(mifare_desfire_authenticate(tag, 0, picc_master_key_default_des), tag) < 0) {
            std::cerr << "Failed to authenticate with default des key" << std::endl;
            // Set the PICC master key to the constant AES key
            if (print_error_code(mifare_desfire_authenticate(tag, 0, picc_master_key_default_aes), tag) < 0) {
                throw ExitException(EXIT_FAILURE, "Failed to authenticate with default aes key.");
            } else
                std::cerr << "Authenticated with default aes key" << std::endl;
        } else
            std::cerr << "Authenticated with default des key" << std::endl;
    } else {
        std::cerr << "Authenticated with master key..." << std::endl;
    }
}


void change_picc_master_key_to_default(FreefareTag tag) {
    // Create a default DES/AES key (8/16 bytes of zeros)
    uint8_t default_key_data[8] = {0};
    MifareDESFireKey default_key = mifare_desfire_des_key_new_with_version(default_key_data);
    auto default_key_guard = ScopeGuard([&]() { mifare_desfire_key_free(default_key); });

    // Set the master key to the default key (again, for demonstration)
    if (print_error_code(mifare_desfire_change_key(tag, 0, default_key, nullptr), tag) < 0) {
        std::cerr << "Failed to change PICC master key to default." << std::endl;
    } else {
        std::cerr << "PICC master key changed to default aes key." << std::endl;
    }
}

int main(int argc, char *argv[]) {
    try {
        nfc_context *context;
        nfc_init(&context);
        if (!context)
            throw ExitException(EXIT_FAILURE, "Unable to init libnfc");
        auto context_guard = ScopeGuard([&]() { nfc_exit(context); });

        std::vector<nfc_connstring> devices(8);
        size_t device_count = nfc_list_devices(context, devices.data(), devices.size());
        if (device_count <= 0)
            throw ExitException(EXIT_FAILURE, "No NFC device found.");

        for (size_t i = 0; i < device_count; i++) {
            std::cerr << "Found NFC device: " << devices[i] << std::endl;
        }

        nfc_device *device = nfc_open(context, devices[0]);
        if (!device)
            throw ExitException(EXIT_FAILURE, "nfc_open() failed.");
        auto device_guard = ScopeGuard([&]() { nfc_close(device); });

        FreefareTag *tags = freefare_get_tags(device);
        if (!tags)
            throw ExitException(EXIT_FAILURE, "Error listing tags.");
        auto tags_guard = ScopeGuard([&]() { freefare_free_tags(tags); });

        FreefareTag tag = nullptr;
        for (int i = 0; tags[i]; i++) {
            if (freefare_get_tag_type(tags[i]) == MIFARE_DESFIRE) {
                tag = tags[i];
                break;
            } else {
                std::cerr << "Skipping tag of type: " << freefare_get_tag_type(tags[i]) << std::endl;
            }
        }
        if (!tag) {
            throw ExitException(EXIT_FAILURE, "No MIFARE DESFire tag found.");
        }

        if (print_error_code(mifare_desfire_connect(tag), tag) < 0)
            throw ExitException(EXIT_FAILURE, "Can't connect to DESFire tag.");
        auto tag_guard = ScopeGuard([&]() { mifare_desfire_disconnect(tag); });

        authenticate_with_picc_master_key(tag);

        std::cerr << "Formatting PICC..." << std::endl;
        if (print_error_code(mifare_desfire_format_picc(tag), tag) < 0)
            throw ExitException(EXIT_FAILURE, "Failed to format PICC.");
        std::cerr << "Formatting completed." << std::endl;

        std::cerr << "Attempting authentication to formatted PICC..." << std::endl;
        authenticate_with_picc_master_key(tag);

        std::cerr << "Changing PICC master key to default..." << std::endl;
        change_picc_master_key_to_default(tag);

        std::cerr << "Attempting authentication to formatted PICC..." << std::endl;
        authenticate_with_picc_master_key(tag);

        return EXIT_SUCCESS;
    } catch (ExitException &e) {
        std::cerr << e.what() << std::endl;
        return e.exit_code();
    }
}
