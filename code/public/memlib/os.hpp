#pragma once

#include "macros.hpp"
#include "types.hpp"


#if MEMLIB_IS_WINDOWS
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif

    #ifndef NOMINMAX
        #define NOMINMAX
    #endif

    #include <windows.h>
    #include <psapi.h>
#elif MEMLIB_IS_LINUX
    #include <dlfcn.h>
#endif

namespace memlib
{
    /* Memory protection */
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
    constexpr inline bool prot_has(prot p, prot f) noexcept
    {
        return (static_cast<uint32_t>(p) & static_cast<uint32_t>(f)) != 0;
    }



    enum class section : uint8_t
    {
        code,           // executable code (e.g. ".text")
        ro_data,        // read-only data
        rw_data,        // writable data
        zero_data,      // bss / tbss
        imports,        // iat / plt+got
        exports,        // edata / dynsym
        relocations,
        tls,
        debug,
        resources,      // Windows only
        max,
        unknown = uint8_t(-1)
    };



#if MEMLIB_IS_WINDOWS
    using module_handle = HMODULE;

    prot  win_to_prot(DWORD protect) noexcept;
    DWORD prot_to_win(prot  protect) noexcept;

    section get_section_from_name(const uint8_t name8[8]) noexcept;

    std::string to_string(const wchar_t* str);

    uint32_t get_pid();

    module_handle get_module_handle(const char* name);

    IMAGE_NT_HEADERS* get_nt_headers_from_module(HMODULE mod) noexcept;

    bool is_readable_protect_win(DWORD protect) noexcept;
#elif MEMLIB_IS_LINUX
    using module_handle = void*;

    module_handle get_module_handle(const char* name);
#endif



    struct section_info
    {
        /* the name of the section, e.g. ".text" */
        std::string name{};

        /* enum representation of the section name */
        section type = section::unknown;

        /* start address of the secton. */
        void* start = nullptr;

        /* the real size of the section - no paddings */
        size_t size = 0;

        /* padded size of the section */
        size_t size_padded = 0;

        /* r (read), w (write) or x (execution). maybe sounds misleading, but if 'w' is not specified then you cannot write to it. */
        prot protection = prot::none;

        /* module reference */
        module_handle module = nullptr;

        explicit operator bool() const noexcept
        {
            return module != nullptr
                and start != nullptr
                and size != 0;
        }
    };



    struct region_info
    {
        void*       start      = nullptr;
        void*       end        = nullptr;
        prot        protection = prot::none;
        std::string mapped_path{};

        explicit operator bool() const noexcept { return start != nullptr && end != nullptr && start < end; }
    };



    struct module_info
    {
        void*       base = nullptr;
        size_t      size = 0;
        std::string path{};
        std::string name{};

        explicit operator bool() const noexcept { return base != nullptr; }
    };



    struct scan_pattern
    {
        size_t  length = 0;
        uint8_t bytes[MEMLIB_MAX_PATTERN_LEN]{};
        char    mask[MEMLIB_MAX_PATTERN_LEN]{}; // 'x' = match, '?' = wildcard
    };



    struct span_pattern
    {
        const char* combo = nullptr; // e.g. "E8 ?? ?? ?? ?? 86"
        section     sec   = section::code;
    };

}
