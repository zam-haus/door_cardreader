//
// Created by phi1010 on 6/25/25.
//

#include "exceptions.h"
#include <cstdarg>
#include <stdexcept>
#include <vector>

ExitException::ExitException(int code, const char *fmt, ...) : exit_code_(code) {
    va_list args1;
    va_start(args1, fmt);
    int size = vsnprintf(nullptr, 0, fmt, args1);
    va_end(args1);

    if (size < 0) {
        throw std::runtime_error("Formatting error in ExitException");
        return;
    }

    std::vector<char> buf(size + 1);
    va_list args2;
    va_start(args2, fmt);
    vsnprintf(buf.data(), buf.size(), fmt, args2);
    va_end(args2);

    message_ = std::string(buf.data(), size);
}

int ExitException::exit_code() const noexcept {
    return exit_code_;
}

const char *ExitException::what() const noexcept {
    return message_.c_str();
}
