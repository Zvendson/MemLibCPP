#pragma once
#include <memlib/inline_hook.hpp>
#include <expected>
#include <array>
#include <atomic>

namespace memlib
{
    struct hook_error
    {
        enum Type
        {
            InvalidTarget, InvalidDestination, DecodeFailed, UnsupportedInstruction,
            AllocationFailed, RelocationOutOfRange, InvalidBranchTarget, AlreadyHooked,
            ProtectionFailed, ThreadFreezeFailed, ThreadContextFailed, TargetChanged,
            InvalidHook, ProtectionRestoreFailed
        } type;
        uintptr_t address{};
        bool patch_applied{};
    };
}

namespace memlib::detail
{
    struct instruction_boundary { uintptr_t source; uintptr_t relocated; };
    struct pending_protection { void* address{}; size_t size{}; uint32_t protection{}; };
    struct patch_view
    {
        uint8_t* target;
        size_t size;
        const uint8_t* expected;
        const uint8_t* replacement;
        const instruction_boundary* boundaries;
        size_t boundary_count;
        bool enabling;
        pending_protection* pending;
    };

    // No heap allocation, CRT locks, or logging after peer threads are stopped.
    std::expected<void, hook_error> patch_code(const patch_view& patch);
    uint8_t* allocate_trampoline(uintptr_t target, size_t& size) noexcept;
    void release_trampoline(uint8_t* address, size_t size) noexcept;
    bool seal_trampoline(uint8_t* address, size_t size) noexcept;
    std::expected<void, hook_error> recover_protections(std::array<pending_protection, 2>& pending) noexcept;

    inline bool bytes_equal(const uint8_t* target, const uint8_t* expected, size_t size) noexcept
    {
        // Volatile access prevents the compiler from introducing a lazy-bound
        // libc memcmp/memcpy call while a peer may own the dynamic loader lock.
        const volatile uint8_t* source = target;
        for (size_t i = 0; i < size; ++i) if (source[i] != expected[i]) return false;
        return true;
    }
    inline void write_bytes(uint8_t* target, const uint8_t* replacement, size_t size) noexcept
    {
        volatile uint8_t* destination = target;
        for (size_t i = 0; i < size; ++i) destination[i] = replacement[i];
    }

    inline std::expected<uintptr_t, hook_error> redirect_ip(uintptr_t ip, const patch_view& patch)
    {
        const auto start = reinterpret_cast<uintptr_t>(patch.target);
        if (ip < start || ip >= start + patch.size) return ip;
        if (!patch.enabling)
        {
            // Installed entry is a single five-byte jump. No other entry into
            // the overwritten prologue is supported.
            if (ip == start) return ip;
        }
        else
        {
            for (size_t i = 0; i < patch.boundary_count; ++i)
                if (patch.boundaries[i].source == ip) return patch.boundaries[i].relocated;
        }
        return std::unexpected(hook_error{hook_error::ThreadContextFailed, ip});
    }
}
