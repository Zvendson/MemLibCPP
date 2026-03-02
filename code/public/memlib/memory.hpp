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
#include <span>
#include <functional>


namespace memlib
{
    class address;

    using scan_callback = memlib::address(*)(memlib::address addr);

    std::optional<region_info> query(void* p) noexcept;

    bool  protect(void* p, size_t size, prot new_prot, prot* old_prot_out = nullptr) noexcept;
    void* alloc(size_t size, prot p = prot::r | prot::w) noexcept;
    bool  free(void* p) noexcept;
    void  flush_icache(void* p, size_t size) noexcept;

    std::optional<module_info>  module_from_address(void* p) noexcept;
    std::optional<section_info> section_from_address(void* p) noexcept;

    bool is_readable(void* p, size_t bytes = 1) noexcept;
    bool is_writable(void* p, size_t bytes = 1) noexcept;
    bool is_executable(void* p, size_t bytes = 1) noexcept;

    bool parse_combo_pattern(const char* combo, scan_pattern& out) noexcept;

    [[nodiscard]] address find(const scan_pattern& pattern, uintptr_t start, uintptr_t end, int32_t offset = 0x0000) noexcept;
    [[nodiscard]] address find(const char* combo, uintptr_t start, uintptr_t end, int32_t offset = 0x0000) noexcept;

    [[nodiscard]] std::vector<address> find_all(const scan_pattern& pattern, uintptr_t start, uintptr_t end, scan_callback scan_cb = nullptr) noexcept;
    [[nodiscard]] std::vector<address> find_all(const char* combo, uintptr_t start, uintptr_t end, scan_callback scan_cb = nullptr) noexcept;
}
