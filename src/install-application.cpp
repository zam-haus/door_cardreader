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
#include "freefare_errorcodes.h"
#include "exceptions.h"
#include "keyfile.h"

const std::string picc_master_key_file = "./keys/picc.master.key";
const std::string app1_master_key_file = "./keys/app1.master.key";
const std::string app1_rw_key_file = "./keys/app1.rw1.key";


std::vector<uint8_t> random_data_vector(size_t size) {
    std::vector<uint8_t> data(size);
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
    if (!urandom)
        throw std::runtime_error("Failed to open /dev/urandom");
    if (size > std::numeric_limits<std::streamsize>::max())
        throw std::runtime_error("Requested size exceeds maximum stream size");
    auto streamsize = static_cast<std::streamsize>(size);
    urandom.read(reinterpret_cast<char *>(data.data()), streamsize);
    if (urandom.gcount() != streamsize)
        throw std::runtime_error("Failed to read enough random bytes");
    return data;
}


void change_picc_master_key_and_authenticate(FreefareTag tag) {
    auto picc_master_key_vector = read_key_file(picc_master_key_file, 16);
    MifareDESFireKey picc_master_key = mifare_desfire_aes_key_new_with_version(picc_master_key_vector.data(), 0);
    auto picc_master_key_guard = ScopeGuard([&]() { mifare_desfire_key_free(picc_master_key); });

    MifareDESFireKey picc_master_key_default = mifare_desfire_des_key_new_with_version((uint8_t[8]){0});
    auto picc_master_key_default_guard = ScopeGuard([&]() { mifare_desfire_key_free(picc_master_key_default); });

    // Try to authenticate with the new AES key
    if (print_error_code(mifare_desfire_authenticate(tag, 0, picc_master_key), tag) < 0) {
        std::cerr << "Failed to authenticate with new AES key, setting PICC master key." << std::endl;

        // Set the PICC master key to the constant AES key
        if (print_error_code(mifare_desfire_authenticate(tag, 0, picc_master_key_default), tag) < 0) {
            throw ExitException(EXIT_FAILURE, "Failed to authenticate with default key.");
        }
        std::cerr << "Authenticated with default key, setting PICC master key." << std::endl;
        if (print_error_code(mifare_desfire_change_key(tag, 0, picc_master_key, nullptr), tag) < 0) {
            throw ExitException(EXIT_FAILURE, "Failed to set PICC master key.");
        }
        std::cerr << "PICC master key set successfully." << std::endl;
        // Authenticate with the new key
        if (print_error_code(mifare_desfire_authenticate(tag, 0, picc_master_key), tag) < 0) {
            throw ExitException(EXIT_FAILURE, "Failed to authenticate with new master key.");
        }
        std::cerr << "Authenticated with new master key." << std::endl;
    }

    // Allow master key to be changed (bit 0),
    // allow directory listing (bit 1)
    // disable file creation without master key (bit 2),
    // allow settings change (bit 3)
    // unused bits 4-7
    uint8_t new_settings =
            0b00001011;

    if (print_error_code(mifare_desfire_change_key_settings(tag, new_settings), tag) < 0) {
        throw ExitException(EXIT_FAILURE, "Failed to change PICC master key settings.");
    }
    std::cerr << "PICC master key settings changed successfully." << std::endl;
}

// Create application
void create_and_select_app(FreefareTag tag, MifareDESFireAID aid, uint8_t num_keys) {
    uint8_t app_master_key_changeable = 1 << 0;
    uint8_t directory_list_access_without_app_master_key = 1 << 1;
    uint8_t create_delete_file_without_app_master_key = 1 << 2;
    uint8_t settings_changeable = 1 << 3;

    // 0-13: Key 0 -- Key 13 required
    // 14: Each key for itself
    // 15: all (except master key?) are frozen
    uint8_t key_change_required_key_number = 0 << 4;

    uint8_t key_settings =
            app_master_key_changeable |
            directory_list_access_without_app_master_key |
            create_delete_file_without_app_master_key |
            settings_changeable |
            key_change_required_key_number;

    if (num_keys > 14 || num_keys < 1) {
        throw ExitException(EXIT_FAILURE, "Number of keys must be between 1 and 14.");
    }
    uint8_t use_aes_key = 1 << 7 | 0 << 6;;
    uint8_t key_no_upper_bits = use_aes_key;
    // b3-b0: Number of keys that can be stored within the application (0x01-0x0D).
    if (mifare_desfire_create_application(tag, aid, key_settings, num_keys | key_no_upper_bits) < 0) {
        std::cerr << "Failed to create application." << std::endl;
    } else {
        std::cerr << "Successfully created application." << std::endl;
    }

    if (print_error_code(mifare_desfire_select_application(tag, aid), tag) < 0) {
        throw ExitException(EXIT_FAILURE, "Failed to select application.");
    }
    std::cerr << "Application selected successfully." << std::endl;
}

void change_app_key_and_authenticate
(FreefareTag tag, const std::string &key_file, const std::string &master_key_file, uint8_t key_no) {
    auto app1_key_vector = read_key_file(key_file, 16);
    MifareDESFireKey app1_key = mifare_desfire_aes_key_new_with_version(app1_key_vector.data(), 0);
    auto app1_key_guard = ScopeGuard([&]() { mifare_desfire_key_free(app1_key); });

    auto app1_master_key_vector = read_key_file(master_key_file, 16);
    MifareDESFireKey app1_master_key = mifare_desfire_aes_key_new_with_version(app1_master_key_vector.data(), 0);
    auto app1_master_key_guard = ScopeGuard([&]() { mifare_desfire_key_free(app1_master_key); });

    MifareDESFireKey app1_key_default = mifare_desfire_aes_key_new_with_version((uint8_t[16]){0}, 0);
    auto app1_key_default_guard = ScopeGuard([&]() { mifare_desfire_key_free(app1_key_default); });

    if (print_error_code(mifare_desfire_authenticate(tag, 0, app1_master_key), tag) < 0) {
        std::cerr << "Failed to authenticate with app master key." << std::endl;
        // Try authenticating with AES_KEY in case it's already set
        if (print_error_code(mifare_desfire_authenticate(tag, key_no, app1_key_default), tag) < 0) {
            throw ExitException(EXIT_FAILURE, "Failed to authenticate with default and master key.");
        }
        std::cerr << "Authenticated with new app key." << std::endl;
    } else {
        std::cerr << "Successfully authenticated with app master key." << std::endl;
    }
    // Set app key to AES_KEY
    if (print_error_code(mifare_desfire_change_key(tag, key_no, app1_key, nullptr), tag) < 0) {
        std::cerr << "Failed to change application key." << std::endl;
    } else {
        std::cerr << "Change key successfully." << std::endl;
    }
    if (print_error_code(mifare_desfire_authenticate(tag, key_no, app1_key), tag) < 0)
        throw ExitException(EXIT_FAILURE, "Failed to authenticate with new app key.");
    std::cerr << "Authenticated with new app key." << std::endl;
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

        change_picc_master_key_and_authenticate(tag);

        const uint32_t APP_AID = 0x112233; // TODO
        MifareDESFireAID aid = mifare_desfire_aid_new(APP_AID);
        // TODO check if this is correct, there is no special function to free AID
        auto aid_guard = ScopeGuard([&]() { free(aid); });

        create_and_select_app(tag, aid, 14);

        std::cerr << "Changing application master key..." << std::endl;
        change_app_key_and_authenticate(tag, app1_master_key_file, app1_master_key_file, 0);

        // Generate 32 random bytes
        std::vector<uint8_t> secret = random_data_vector(32);


        // Create standard data files with IDs 2-14 read-writable by key 1 and readable by key number == file id
        for (int i = 2; i <= 14; ++i) {
            uint8_t FILE_ID = i;
            // Create a read-only standard data file
            uint8_t comm_settings = 0b11; // CMAC (bit 0) and encrypted (bit 1) communication
            // Each of the access rights defines what key is needed for the specific access.
            // Key 0-13 are numbers, but 14 means free access and 15 means no access.
            uint16_t access_rights = MDAR(/*r*/i,/*w*/1,/*rw*/1,/*change access rights*/0);

            if (mifare_desfire_create_std_data_file(tag, FILE_ID, comm_settings, access_rights, secret.size()) < 0) {
                // Ignore if already exists
                std::cerr << "Failed to create data file." << std::endl;
            } else {
                std::cerr << "Successfully created data file." << std::endl;
            }
        }

        std::cerr << "Changing application read-write key..." << std::endl;
        change_app_key_and_authenticate(tag, app1_rw_key_file, app1_master_key_file, 1);
        for (int i = 2; i <= 14; ++i) {
            uint8_t FILE_ID = i;

            // Write the random secret to the file
            if (mifare_desfire_write_data(tag, FILE_ID, 0, secret.size(), secret.data()) != secret.size()) {
                throw ExitException(EXIT_FAILURE, "Failed to write secret to data file.");
            }

            std::cerr << "Random 32-byte secret written to file." << std::endl;
        }

        // Change keys ./keys/app1.r2.key to ./keys/app1.r13.key
        for (uint8_t key_no = 2; key_no <= 13; ++key_no) {
            std::string key_file = "./keys/app1.r" + std::to_string(key_no) + ".key";
            std::cerr << "Changing application read key " << static_cast<int>(key_no) << "..." << std::endl;
            change_app_key_and_authenticate(tag, key_file, app1_master_key_file, key_no);
        }

        printf("Setup complete: PICC master key set, application and read-only file created.\n");

        return EXIT_SUCCESS;
    } catch (ExitException &e) {
        std::cerr << e.what() << std::endl;
        return e.exit_code();
    }
}
