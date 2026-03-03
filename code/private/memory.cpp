#include "memlib/macros.hpp"
#include "memlib/os.hpp"
#include "memlib/memory.hpp"
#include "memlib/address.hpp"

#include <array>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cstddef>
#include <cinttypes>

#if MEMLIB_IS_WINDOWS
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#elif MEMLIB_IS_LINUX
#include <cstdio>
#endif

#include "internal.hpp"

namespace
{
	using namespace memlib;

    static inline constexpr uintptr_t invalid_addr = uintptr_t(-1);

    struct run
    {
        uint16_t off = 0;
        uint16_t len = 0;
    };

    inline std::string to_string(std::string_view s) { return std::string(s); }

    inline bool contains_range(uintptr_t start, uintptr_t end, uintptr_t p, size_t n) noexcept
    {
        if (n == 0)
            return (p >= start && p < end);

        if (p < start)
            return false;

        const uintptr_t p2 = p + (n - 1);

        // overflow-safe
        return p2 >= p && p2 < end;
    }

    static bool region_has(void* p, size_t bytes, prot need) noexcept
    {
        auto r = query(p);
        if (!r)
            return false;

        const auto start = reinterpret_cast<uintptr_t>(r->start);
        const auto end   = reinterpret_cast<uintptr_t>(r->end);
        const auto addr  = reinterpret_cast<uintptr_t>(p);

        if (!contains_range(start, end, addr, bytes))
            return false;

        if (prot_has(need, prot::r) && !prot_has(r->protection, prot::r)) return false;
        if (prot_has(need, prot::w) && !prot_has(r->protection, prot::w)) return false;
        if (prot_has(need, prot::x) && !prot_has(r->protection, prot::x)) return false;

        return true;
    }



    static inline int to_hexval(char c) noexcept
    {
        if ('0' <= c && c <= '9') return c - '0';
        if ('a' <= c && c <= 'f') return 10 + (c - 'a');
        if ('A' <= c && c <= 'F') return 10 + (c - 'A');
        return -1;
    }



    static inline bool pattern_matches_at(const scan_pattern& pat, uintptr_t addr) noexcept
    {
        const uint8_t* mem = reinterpret_cast<const uint8_t*>(addr);
        const size_t len = pat.length;
        if (len == 0)
            return false;

        if (pat.mask[0] == 'x' && mem[0] != pat.bytes[0])
            return false;

        for (size_t i = 1; i < len; ++i)
        {
            if (pat.mask[i] != 'x')
                continue;

            if (mem[i] != pat.bytes[i])
                return false;
        }
        return true;
    }



    static inline address make_result(uintptr_t found, int32_t offset) noexcept
    {
        const intptr_t res = static_cast<intptr_t>(found) + static_cast<intptr_t>(offset);
        return address(static_cast<uintptr_t>(res));
    }



    static inline address scan_range(const scan_pattern& pat, uintptr_t lo, uintptr_t hi, int32_t offset, bool backwards) noexcept
    {
        const size_t pat_len = pat.length;
        if (pat_len == 0 || hi <= lo)
            return {};

        const size_t span = static_cast<size_t>(hi - lo);
        if (span < pat_len)
            return {};

        const uintptr_t last = hi - pat_len;

        if (!backwards)
        {
            for (uintptr_t p = lo; p <= last; ++p)
            {
                if (pattern_matches_at(pat, p))
                    return make_result(p, offset);
            }
        }
        else
        {
            for (uintptr_t p = last;; --p)
            {
                if (pattern_matches_at(pat, p))
                    return make_result(p, offset);

                if (p == lo)
                    break;
            }
        }

        return {};
    }
}

namespace memlib
{
    bool is_readable(void* p, size_t bytes)   noexcept { return region_has(p, bytes, prot::r); }
    bool is_writable(void* p, size_t bytes)   noexcept { return region_has(p, bytes, prot::w); }
    bool is_executable(void* p, size_t bytes) noexcept { return region_has(p, bytes, prot::x); }

    bool parse_combo_pattern(const char* combo, scan_pattern& out) noexcept
    {
        out = {};
        if (!combo)
            return false;

        const size_t max_len = std::strlen(combo);
        size_t off = 0;
        size_t len = 0;

        auto skip_spaces = [&]() noexcept {
            while (off < max_len && combo[off] == ' ') ++off;
            };

        skip_spaces();

        while (off < max_len)
        {
            if (len >= sizeof(out.bytes))
                return false;

            if (combo[off] == '?')
            {
                if (off + 1 < max_len && combo[off + 1] == '?')
                    off += 2;
                else
                    ++off;

                out.bytes[len] = 0;
                out.mask[len] = '?';
                ++len;

                skip_spaces();
                continue;
            }

            if (off + 1 >= max_len)
                return false;

            const int hi = to_hexval(combo[off + 0]);
            const int lo = to_hexval(combo[off + 1]);
            if (hi < 0 || lo < 0)
                return false;

            out.bytes[len] = uint8_t((hi << 4) | lo);
            out.mask[len] = 'x';
            ++len;

            off += 2;
            skip_spaces();
        }

        out.length = len;
        return (len != 0);
    }

    address find(const scan_pattern& pattern, uintptr_t start, uintptr_t end, int32_t offset) noexcept
    {
        MEMLIB_DEBUG("Scanning 0x{:x} to 0x{:x}.", start, end);

        if (start == 0 || end == 0)
            return {};

        if (pattern.length == 0)
            return {};

        const bool backwards = (start > end);
        const uintptr_t lo_req = backwards ? end : start;
        const uintptr_t hi_req = backwards ? start : end;

        uintptr_t cursor = lo_req;

        while (cursor < hi_req)
        {
            auto r = query(reinterpret_cast<void*>(cursor));
            if (!r)
                break;

            uintptr_t r_lo = reinterpret_cast<uintptr_t>(r->start);
            uintptr_t r_hi = reinterpret_cast<uintptr_t>(r->end);

            if (r_hi <= cursor)
                break;

            if (r_lo < lo_req) r_lo = lo_req;
            if (r_hi > hi_req) r_hi = hi_req;

            if (r_hi > r_lo)
            {
                if (prot_has(r->protection, prot::r))
                {
                    if (region_has(reinterpret_cast<void*>(r_lo), pattern.length, prot::r))
                    {
                        address hit = scan_range(pattern, r_lo, r_hi, offset, backwards);
                        if (hit)
                            return hit;
                    }
                }
            }

            // next region
            cursor = reinterpret_cast<uintptr_t>(r->end);
        }

        return {};
    }

    address find(const char* combo, uintptr_t start, uintptr_t end, int32_t offset) noexcept
    {
        scan_pattern pattern{};
        if (!parse_combo_pattern(combo, pattern))
            return {};

        return find(pattern, start, end, offset);
    }



    std::vector<address> find_all(const scan_pattern& pattern, uintptr_t start, uintptr_t end, scan_callback scan_cb) noexcept
    {
        std::vector<address> results;
        MEMLIB_DEBUG("Scanning 0x{:x} to 0x{:x}.", start, end);

        if (start == 0 || end == 0)
            return {};

        if (pattern.length == 0)
            return {};

        const bool backwards = (start > end);
        const uintptr_t lo_req = backwards ? end : start;
        const uintptr_t hi_req = backwards ? start : end;

        uintptr_t cursor = lo_req;

        while (cursor < hi_req)
        {
            auto r = query(reinterpret_cast<void*>(cursor));
            if (!r)
                break;

            uintptr_t r_lo = reinterpret_cast<uintptr_t>(r->start);
            uintptr_t r_hi = reinterpret_cast<uintptr_t>(r->end);

            if (r_hi <= cursor)
                break;

            if (r_lo < lo_req) r_lo = lo_req;
            if (r_hi > hi_req) r_hi = hi_req;

            if (r_hi > r_lo)
            {
                if (prot_has(r->protection, prot::r))
                {
                    if (region_has(reinterpret_cast<void*>(r_lo), pattern.length, prot::r))
                    {
                        address hit = scan_range(pattern, r_lo, r_hi, 0, backwards);
                        if (!hit)
                            continue;

                        if (scan_cb)
                        {
                            hit = scan_cb(hit);
                            if (!hit)
                                continue;
                        }

                        results.push_back(hit);                        
                    }
                }
            }

            // next region
            cursor = reinterpret_cast<uintptr_t>(r->end);
        }

        return {};
    }



    std::vector<address> find_all(const char* combo, uintptr_t start, uintptr_t end, scan_callback scan_cb) noexcept
    {
        scan_pattern pattern{};
        if (!parse_combo_pattern(combo, pattern))
            return {};

        return find_all(pattern, start, end, scan_cb);
    }
    
}