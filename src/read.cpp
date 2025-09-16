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
#include <docopt.h>
#include <iostream>
#include "ScopeGuard.h"
#include "freefare_errorcodes.h"
#include "exceptions.h"
#include "keyfile.h"


static const char USAGE[] =
        R"(Naval Fate.

    Usage:
      read <key_file> <key_number> <application_id> <file_number>

    Options:
      -h --help     Show this screen.
      --version     Show version.

    Use hexadecimal to specify the application ID with 0x000000
)";

const std::string picc_master_key_file = "./keys/picc.master.key";
const std::string app1_master_key_file = "./keys/app1.master.key";


void authenticate_with_key(FreefareTag tag, const std::string &key_file, int key_no) {
    auto app1_r_key_vector = read_key_file(key_file, 16);
    MifareDESFireKey app1_r_key = mifare_desfire_aes_key_new_with_version(app1_r_key_vector.data(), 0);
    auto app1_r_key_guard = ScopeGuard([&]() { mifare_desfire_key_free(app1_r_key); });

    if (print_error_code(mifare_desfire_authenticate(tag, key_no, app1_r_key), tag) < 0) {
        throw ExitException(EXIT_FAILURE, "Failed to authenticate with app1 r key.");
    }
    std::cerr << "Authenticated with app1 r key." << std::endl;
}


int main(int argc, char *argv[]) {
    std::map<std::string, docopt::value> args
            = docopt::docopt(USAGE,
                             {argv + 1, argv + argc},
                             true, // show help if requested
                             "Desfire Cardreader Utils 1.0"); // version string

    int file_number = std::stoul(args["<file_number>"].asString(), nullptr, 0);
    int application_id = std::stoul(args["<application_id>"].asString(), nullptr, 0);
    std::string key_file = args["<key_file>"].asString();
    int key_number = std::stoul(args["<key_number>"].asString(), nullptr, 0);

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

        FreefareTag *tags = nullptr;
        auto tags_guard = ScopeGuard([&]() { if (tags) freefare_free_tags(tags); });
        FreefareTag tag = nullptr;
        std::cerr << "Searching for MIFARE DESFire tags..." << std::endl;
        while (!tag) {
            if (tags)
                freefare_free_tags(tags);
            tags = freefare_get_tags(device);
            if (!tags)
                throw ExitException(EXIT_FAILURE, "Error listing tags.");

            for (int i = 0; tags[i]; i++) {
                if (freefare_get_tag_type(tags[i]) == MIFARE_DESFIRE) {
                    tag = tags[i];
                    break;
                } else {
                    std::cerr << "Skipping tag of type: " << freefare_get_tag_type(tags[i]) << std::endl;
                }
            }
        }
        std::cerr << "Found MIFARE DESFire tag. Connecting..." << std::endl;

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

        if (!key_file.empty())
            authenticate_with_key(tag, key_file, key_number);

        // Read file 1 contents and output as hex
        uint32_t file_size = 0;
        mifare_desfire_file_settings settings = {};
        if (print_error_code(mifare_desfire_get_file_settings(tag, file_number, &settings), tag) < 0) {
            throw ExitException(EXIT_FAILURE, "Failed to get file settings.");
        }
        if (settings.file_type != MDFT_STANDARD_DATA_FILE && settings.file_type != MDFT_BACKUP_DATA_FILE) {
            throw ExitException(EXIT_FAILURE, "File 1 is not a data file.");
        }
        file_size = settings.settings.standard_file.file_size;

        std::vector<uint8_t> data(file_size);
        if (print_error_code(mifare_desfire_read_data(tag, file_number, 0, file_size, data.data()), tag) < 0) {
            throw ExitException(EXIT_FAILURE, "Failed to read file 1.");
        }

        std::cerr << "File 1 contents (hex): " << std::endl;
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
