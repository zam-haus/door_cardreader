#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <nfc/nfc.h>

#include <freefare.h>
#include <iostream>
#include <ostream>

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
const std::string app1_rw_key_file = "./keys/app1.rw1.key";


void authenticate_with_picc_master_key(FreefareTag tag) {
    auto picc_master_key_vector = read_key_file(picc_master_key_file, 16);
    MifareDESFireKey picc_master_key = mifare_desfire_aes_key_new_with_version(picc_master_key_vector.data(), 0);
    auto picc_master_key_guard = ScopeGuard([&]() { mifare_desfire_key_free(picc_master_key); });

    MifareDESFireKey picc_master_key_default = mifare_desfire_des_key_new_with_version((uint8_t[8]){0});
    auto picc_master_key_default_guard = ScopeGuard([&]() { mifare_desfire_key_free(picc_master_key_default); });

    // Try to authenticate with the new AES key
    if (print_error_code(mifare_desfire_authenticate(tag, 0, picc_master_key), tag) < 0) {
        std::cerr << "Failed to authenticate with master key" << std::endl;

        // Set the PICC master key to the constant AES key
        if (print_error_code(mifare_desfire_authenticate(tag, 0, picc_master_key_default), tag) < 0) {
            throw ExitException(EXIT_FAILURE, "Failed to authenticate with default key.");
        }
        std::cerr << "Authenticated with default key" << std::endl;
    } else {
        std::cerr << "Authenticated with master key..." << std::endl;
    }
}


void change_picc_master_key_to_default(FreefareTag tag) {
    // Create a default DES key (8 bytes of zeros)
    uint8_t default_key_data[8] = {0};
    MifareDESFireKey default_key = mifare_desfire_des_key_new_with_version(default_key_data);
    auto default_key_guard = ScopeGuard([&]() { mifare_desfire_key_free(default_key); });

    // Set the master key to the default key (again, for demonstration)
    if (print_error_code(mifare_desfire_change_key(tag, 0, default_key, nullptr), tag) < 0) {
        throw ExitException(EXIT_FAILURE, "Failed to change PICC master key to default.");
    }

    std::cerr << "PICC master key changed to default key." << std::endl;
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

        int res;
        char *tag_uid = freefare_get_tag_uid(tag);
        auto tag_uid_guard = ScopeGuard([&]() { free(tag_uid); });

        struct mifare_desfire_version_info info = {};

        res = mifare_desfire_get_version(tag, &info);
        if (res < 0) {
            freefare_perror(tag, "mifare_desfire_get_version");
            throw ExitException(EXIT_FAILURE, "Failed to get version information.");
        }

        printf("===> Version information for tag %s:\n", tag_uid);
        printf("UID:                      0x%02x%02x%02x%02x%02x%02x%02x\n", info.uid[0], info.uid[1],
               info.uid[2], info.uid[3], info.uid[4], info.uid[5], info.uid[6]);
        printf("Batch number:             0x%02x%02x%02x%02x%02x\n", info.batch_number[0], info.batch_number[1],
               info.batch_number[2], info.batch_number[3], info.batch_number[4]);
        printf("Production date:          week %x, 20%02x\n", info.production_week, info.production_year);
        printf("Hardware Information:\n");
        printf("    Vendor ID:            0x%02x\n", info.hardware.vendor_id);
        printf("    Type:                 0x%02x\n", info.hardware.type);
        printf("    Subtype:              0x%02x\n", info.hardware.subtype);
        printf("    Version:              %d.%d\n", info.hardware.version_major, info.hardware.version_minor);
        printf("    Storage size:         0x%02x (%s%d bytes)\n", info.hardware.storage_size,
               (info.hardware.storage_size & 1) ? ">" : "=", 1 << (info.hardware.storage_size >> 1));
        printf("    Protocol:             0x%02x\n", info.hardware.protocol);
        printf("Software Information:\n");
        printf("    Vendor ID:            0x%02x\n", info.software.vendor_id);
        printf("    Type:                 0x%02x\n", info.software.type);
        printf("    Subtype:              0x%02x\n", info.software.subtype);
        printf("    Version:              %d.%d\n", info.software.version_major, info.software.version_minor);
        printf("    Storage size:         0x%02x (%s%d bytes)\n", info.software.storage_size,
               (info.software.storage_size & 1) ? ">" : "=", 1 << (info.software.storage_size >> 1));
        printf("    Protocol:             0x%02x\n", info.software.protocol);

        uint8_t settings;
        uint8_t max_keys;
        res = mifare_desfire_get_key_settings(tag, &settings, &max_keys);
        if (res == 0) {
            printf("Master Key settings (0x%02x):\n", settings);
            printf("    0x%02x configuration changeable;\n", settings & 0x08);
            printf("    0x%02x PICC Master Key not required for create / delete;\n", settings & 0x04);
            printf("    0x%02x Free directory list access without PICC Master Key;\n", settings & 0x02);
            printf("    0x%02x Allow changing the Master Key;\n", settings & 0x01);
        } else if (AUTHENTICATION_ERROR == mifare_desfire_last_picc_error(tag)) {
            printf("Master Key settings: LOCKED\n");
        } else {
            freefare_perror(tag, "mifare_desfire_get_key_settings");
            throw ExitException(EXIT_FAILURE, "Failed to get Master Key settings.");
        }

        uint8_t version;
        mifare_desfire_get_key_version(tag, 0, &version);
        printf("Master Key version: %d (0x%02x)\n", version, version);

        uint32_t size;
        res = mifare_desfire_free_mem(tag, &size);
        printf("Free memory: ");
        if (0 == res) {
            printf("%d bytes\n", size);
        } else {
            printf("unknown\n");
        }

        printf("Use random UID: %s\n", (strlen(tag_uid) / 2 == 4) ? "yes" : "no");

        // --- Print all applications and their files ---
        std::cout << "\nApplications on card:\n";
        std::vector<uint32_t> aids;
        {
            size_t num_apps = 0;
            MifareDESFireAID *raw_aids;
            if (print_error_code(mifare_desfire_get_application_ids(tag, &raw_aids, &num_apps), tag)<0) {
                std::cout << "  (none or failed to list applications)\n";
            } else {
                auto app_ids_guard = ScopeGuard([&]() { mifare_desfire_free_application_ids(raw_aids); });
                for (size_t i = 0; i < num_apps; ++i) {
                    uint32_t aid = mifare_desfire_aid_get_aid(raw_aids[i]);
                    aids.push_back(aid);
                    std::cout << "  AID: " << std::hex << std::uppercase << std::setw(6) << std::setfill('0') << aid << std::dec << std::nouppercase << std::endl;

                    // Select application
                    if (print_error_code(mifare_desfire_select_application(tag, raw_aids[i]), tag) < 0) {
                        std::cout << "    (failed to select application)\n";
                        continue;
                    }
/*
                    // Authenticate with app1 rw key
                    auto app1_rw_key_vector = read_key_file(app1_rw_key_file, 16);
                    MifareDESFireKey app1_rw_key = mifare_desfire_aes_key_new_with_version(app1_rw_key_vector.data(), 0);
                    auto app1_rw_key_guard = ScopeGuard([&]() { mifare_desfire_key_free(app1_rw_key); });
                    if (print_error_code(mifare_desfire_authenticate(tag, 1, app1_rw_key), tag) < 0) {
                        std::cout << "    (failed to authenticate with app1 rw key)\n";
                        continue;
                    }
*/
                    // List files in application
                    size_t num_files = 0;
                    uint8_t *file_ids;
                    if (print_error_code(mifare_desfire_get_file_ids(tag, &file_ids, &num_files), tag)<0) {
                        std::cout << "    (no files or failed to list files)\n";
                    } else {
                        auto file_ids_guard = ScopeGuard([&]() { free(file_ids); });
                        for (size_t j = 0; j < num_files; ++j) {
                            std::cout << "    File ID: " << static_cast<int>(file_ids[j]) << std::endl;
                        }
                    }
                }
            }
        }
        // Reselect PICC (root) application for further operations
        mifare_desfire_select_application(tag, 0);


        return EXIT_SUCCESS;
    } catch (ExitException &e) {
        std::cerr << e.what() << std::endl;
        return e.exit_code();
    }
}
