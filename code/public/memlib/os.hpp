#pragma once

#include "macros.hpp"
#include <cstdint>


#if MEMLIB_IS_WINDOWS
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif

    #ifndef NOMINMAX
        #define NOMINMAX
    #endif

    #include <windows.h>
#elif MEMLIB_IS_LINUX
#endif

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

#if MEMLIB_IS_WINDOWS
    using module_handle = HMODULE;
#elif MEMLIB_IS_LINUX
    using module_handle = void*;
#endif
}
