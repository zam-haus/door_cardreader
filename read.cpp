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
#include <iomanip>
#include <limits>
#include <stdexcept>

#include "ScopeGuard.h"
#include "freefare_errorcodes.h"
#include "exceptions.h"
#include "keyfile.h"

const std::string picc_master_key_file = "./keys/picc.master.key";
const std::string app1_master_key_file = "./keys/app1.master.key";
const std::string app1_r_key_file = "./keys/app1.r2.key";
const uint8_t app1_r_key_no = 2;


void authenticate_with_app1_rw_key(FreefareTag tag) {
    auto app1_r_key_vector = read_key_file(app1_r_key_file, 16);
    MifareDESFireKey app1_r_key = mifare_desfire_aes_key_new_with_version(app1_r_key_vector.data(), 0);
    auto app1_r_key_guard = ScopeGuard([&]() { mifare_desfire_key_free(app1_r_key); });

    if (print_error_code(mifare_desfire_authenticate(tag, app1_r_key_no, app1_r_key), tag) < 0) {
        throw ExitException(EXIT_FAILURE, "Failed to authenticate with app1 r key.");
    }
    std::cerr << "Authenticated with app1 r key." << std::endl;
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


        const uint32_t APP_AID = 0x112233; // TODO
        MifareDESFireAID aid = mifare_desfire_aid_new(APP_AID);
        // TODO check if this is correct, there is no special function to free AID
        auto aid_guard = ScopeGuard([&]() { free(aid); });

        if (print_error_code(mifare_desfire_select_application(tag, aid), tag) < 0) {
            throw ExitException(EXIT_FAILURE, "Failed to select application.");
        }
        std::cerr << "Application selected successfully." << std::endl;

        authenticate_with_app1_rw_key(tag);

        // Read file 1 contents and output as hex
        uint8_t file_id = 1;
        uint32_t file_size = 0;
        mifare_desfire_file_settings settings={};
        if (print_error_code(mifare_desfire_get_file_settings(tag, file_id, &settings), tag) < 0) {
            throw ExitException(EXIT_FAILURE, "Failed to get file settings.");
        }
        if (settings.file_type != MDFT_STANDARD_DATA_FILE && settings.file_type != MDFT_BACKUP_DATA_FILE) {
            throw ExitException(EXIT_FAILURE, "File 1 is not a data file.");
        }
        file_size = settings.settings.standard_file.file_size;

        std::vector<uint8_t> data(file_size);
        if (print_error_code(mifare_desfire_read_data(tag, file_id, 0, file_size, data.data()), tag) < 0) {
            throw ExitException(EXIT_FAILURE, "Failed to read file 1.");
        }

        std::cerr << "File 1 contents (hex): "<< std::endl;
        for (uint32_t i = 0; i < file_size; ++i) {
            std::cout << std::hex << std::uppercase
                      << std::setw(2) << std::setfill('0')
                      << static_cast<int>(data[i]);
        }
        std::cout << std::dec << std::nouppercase << std::endl;

        return EXIT_SUCCESS;
    } catch (ExitException &e) {
        std::cerr << e.what() << std::endl;
        return e.exit_code();
    }
}
