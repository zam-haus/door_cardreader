//
// Created by phi1010 on 6/25/25.
//

#ifndef FREEFARE_ERRORCODES_H
#define FREEFARE_ERRORCODES_H
#include <freefare.h>
#include <iostream>

template<class T>
T print_error_code(T code, FreefareTag tag) {
    switch (mifare_desfire_last_picc_error(tag)) {
        case OPERATION_OK: std::cerr << "OPERATION_OK";
            break;
        case NO_CHANGES: std::cerr << "NO_CHANGES";
            break;
        case OUT_OF_EEPROM_ERROR: std::cerr << "OUT_OF_EEPROM_ERROR";
            break;
        case ILLEGAL_COMMAND_CODE: std::cerr << "ILLEGAL_COMMAND_CODE";
            break;
        case INTEGRITY_ERROR: std::cerr << "INTEGRITY_ERROR";
            break;
        case NO_SUCH_KEY: std::cerr << "NO_SUCH_KEY";
            break;
        case LENGTH_ERROR: std::cerr << "LENGTH_ERROR";
            break;
        case PERMISSION_ERROR: std::cerr << "PERMISSION_ERROR";
            break;
        case PARAMETER_ERROR: std::cerr << "PARAMETER_ERROR";
            break;
        case APPLICATION_NOT_FOUND: std::cerr << "APPLICATION_NOT_FOUND";
            break;
        case APPL_INTEGRITY_ERROR: std::cerr << "APPL_INTEGRITY_ERROR";
            break;
        case AUTHENTICATION_ERROR: std::cerr << "AUTHENTICATION_ERROR";
            break;
        case ADDITIONAL_FRAME: std::cerr << "ADDITIONAL_FRAME";
            break;
        case BOUNDARY_ERROR: std::cerr << "BOUNDARY_ERROR";
            break;
        case PICC_INTEGRITY_ERROR: std::cerr << "PICC_INTEGRITY_ERROR";
            break;
        case COMMAND_ABORTED: std::cerr << "COMMAND_ABORTED";
            break;
        case PICC_DISABLED_ERROR: std::cerr << "PICC_DISABLED_ERROR";
            break;
        case COUNT_ERROR: std::cerr << "COUNT_ERROR";
            break;
        case DUPLICATE_ERROR: std::cerr << "DUPLICATE_ERROR";
            break;
        case EEPROM_ERROR: std::cerr << "EEPROM_ERROR";
            break;
        case FILE_NOT_FOUND: std::cerr << "FILE_NOT_FOUND";
            break;
        case FILE_INTEGRITY_ERROR: std::cerr << "FILE_INTEGRITY_ERROR";
            break;
        case CRYPTO_ERROR: std::cerr << "CRYPTO_ERROR";
            break;
        case TAG_INFO_MISSING_ERROR: std::cerr << "TAG_INFO_MISSING_ERROR";
            break;
        case UNKNOWN_TAG_TYPE_ERROR: std::cerr << "UNKNOWN_TAG_TYPE_ERROR";
            break;
        default: std::cerr << "UNKNOWN_ERROR_CODE (0x" << std::hex << code << ")";
            break;
    }
    std::cerr << std::endl;
    return code;
}

#endif //FREEFARE_ERRORCODES_H
