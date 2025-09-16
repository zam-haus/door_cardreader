//
// Created by phi1010 on 6/25/25.
//

#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <cstdarg>
#include <cstdio>
#include <exception>
#include <string>
#include <vector>

class ExitException : public std::exception {
public:
    ExitException(int code, const char *fmt, ...);

    [[nodiscard]] int exit_code() const noexcept;

    [[nodiscard]] const char *what() const noexcept override;

private:
    int exit_code_;
    std::string message_;
};

#endif //EXCEPTIONS_H
