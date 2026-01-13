#pragma once

#include <cstdint>

namespace memlib
{
    enum class prot : uint32_t
    {
        none = 0,
        r = 1u << 0,
        w = 1u << 1,
        x = 1u << 2,
    };
    constexpr inline prot operator|(prot a, prot b) noexcept
    {
        return static_cast<prot>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
    }
    constexpr inline bool has(prot p, prot f) noexcept
    {
        return (static_cast<uint32_t>(p) & static_cast<uint32_t>(f)) != 0;
    }
}
