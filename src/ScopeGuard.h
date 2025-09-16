//
// Created by phi1010 on 6/25/25.
//

#ifndef SCOPEGUARD_H
#define SCOPEGUARD_H

#include <functional>

class ScopeGuard {
public:
    explicit ScopeGuard(std::function<void()> fn);

    ~ScopeGuard();

    // Disable copy
    ScopeGuard(const ScopeGuard &) = delete;
    ScopeGuard &operator=(const ScopeGuard &) = delete;

    // Allow move
    ScopeGuard(ScopeGuard &&other) noexcept;
    ScopeGuard &operator=(ScopeGuard &&other) noexcept;

    void dismiss();

private:
    std::function<void()> fn_;
    bool active_;
};


#endif //SCOPEGUARD_H
