//
// Created by phi1010 on 6/25/25.
//

#include "ScopeGuard.h"
#include <utility>

ScopeGuard::ScopeGuard(std::function<void()> fn)
    : fn_(std::move(fn)), active_(true) {}

ScopeGuard::~ScopeGuard() {
    if (active_ && fn_) fn_();
}

ScopeGuard::ScopeGuard(ScopeGuard &&other) noexcept
    : fn_(std::move(other.fn_)), active_(other.active_) {
    other.active_ = false;
}

ScopeGuard &ScopeGuard::operator=(ScopeGuard &&other) noexcept {
    if (this != &other) {
        fn_ = std::move(other.fn_);
        active_ = other.active_;
        other.active_ = false;
    }
    return *this;
}

void ScopeGuard::dismiss() {
    active_ = false;
}
