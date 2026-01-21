#pragma once

#include "macros.hpp"
#include "os.hpp"

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <mutex>
#include <algorithm>
#include <type_traits>

#if MEMLIB_IS_WINDOWS
    #include <psapi.h>
#elif MEMLIB_IS_LINUX
#endif
#include <functional>

namespace memlib
{
    class address;

    template <class T>
    constexpr bool is_trivially_memcpyable_v =
        std::is_trivially_copyable_v<T> && std::is_standard_layout_v<T>;



    enum class section : uint8_t
    {
        text,
        rdata,
        data,
        bss,
        edata,
        idata,
        reloc,
        rsrc,
        tls,
        pdata,
        debug,
        max,
        none = uint8_t(-1),
    };



    struct section_info
    {
        /* the name of the section, e.g. ".text" */
        std::string name{};

        /* enum representation of the section name */
        section type = section::none;

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
        uint8_t bytes[256]{};
        char    mask[256]{}; // 'x' = match, '?' = wildcard
    };

    struct span_pattern
    {
        const char* combo   = nullptr;
        section     section = section::text;
    };

    std::optional<region_info> query(void* p) noexcept;

    bool  protect(void* p, size_t size, prot new_prot, prot* old_prot_out = nullptr) noexcept;
    void* alloc(size_t size, prot p = prot::r | prot::w) noexcept;
    bool  free(void* p, size_t size = 0) noexcept;
    void  flush_icache(void* p, size_t size) noexcept;

    std::optional<module_info>  module_from_address(void* p) noexcept;
    std::optional<section_info> section_from_address(void* p) noexcept;

    bool is_readable(void* p, size_t bytes = 1) noexcept;
    bool is_writable(void* p, size_t bytes = 1) noexcept;
    bool is_executable(void* p, size_t bytes = 1) noexcept;

    bool is_readable_protect(DWORD protect) noexcept;

    bool parse_combo_pattern(const char* combo, scan_pattern& out) noexcept;

    [[nodiscard]] address find(const scan_pattern& pattern, void* start, size_t length, int32_t offset = 0x0000) noexcept;
    [[nodiscard]] address find(const char* combo, void* start, size_t length, int32_t offset = 0x0000) noexcept;

}
