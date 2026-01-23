#include "memlib/macros.hpp"
#include "memlib/os.hpp"
#include "memlib/memory.hpp"
#include "memlib/address.hpp"

#include <array>
#include <algorithm>
#include <cstdint>
#include <cstring>

#if MEMLIB_IS_WINDOWS
#elif MEMLIB_IS_LINUX
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



    static inline size_t build_runs(const scan_pattern& pat, run out[MEMLIB_MAX_PATTERN_LEN]) noexcept
    {
        size_t count = 0;
        size_t i = 0;

        while (i < pat.length)
        {
            while (i < pat.length && pat.mask[i] != 'x')
                ++i;

            if (i >= pat.length)
                break;

            const size_t start = i;
            while (i < pat.length && pat.mask[i] == 'x')
                ++i;

            const size_t len = i - start;
            out[count].off = static_cast<uint16_t>(start);
            out[count].len = static_cast<uint16_t>(len);
            ++count;
        }

        return count;
    }



    static inline bool runs_equal(const uint8_t* mem, const scan_pattern& pat, const run* runs, size_t run_count) noexcept
    {
        for (size_t i = 0; i < run_count; ++i)
        {
            const size_t off = runs[i].off;
            const size_t len = runs[i].len;
            if (std::memcmp(mem + off, pat.bytes + off, len) != 0)
                return false;
        }
        return true;
    }



    static inline bool add_signed_checked(uintptr_t base, int32_t off, uintptr_t& out) noexcept
    {
        if (off >= 0)
        {
            const uintptr_t u = uintptr_t(off);
            if (u > uintptr_t(-1) - base)
                return false;

            out = base + u;
            return true;
        }
        else
        {
            const uintptr_t u = uintptr_t(-(int64_t)off); // safe for INT32_MIN
            if (u > base)
                return false;

            out = base - u;
            return true;
        }
    }



    static inline bool build_bmh_table(const scan_pattern& pat, size_t& key_idx, uint8_t skip[MEMLIB_MAX_PATTERN_LEN]) noexcept
    {
        key_idx = size_t(-1);
        for (size_t i = pat.length; i-- > 0; )
        {
            if (pat.mask[i] == 'x')
            {
                key_idx = i;
                break;
            }
        }

        if (key_idx == size_t(-1))
            return false;

        const uint8_t def = static_cast<uint8_t>((key_idx + 1) > 255 ? 255 : (key_idx + 1));
        for (size_t i = 0; i < MEMLIB_MAX_PATTERN_LEN; ++i)
            skip[i] = def;

        for (size_t i = 0; i < key_idx; ++i)
        {
            if (pat.mask[i] != 'x')
                continue;

            const uint8_t b = pat.bytes[i];
            const size_t dist = key_idx - i;
            skip[b] = static_cast<uint8_t>(dist > 255 ? 255 : dist);
        }

        return true;
    }



    static inline uintptr_t scan_range_bmh(uintptr_t begin, uintptr_t end_exclusive, const scan_pattern& pat) noexcept
    {
        const size_t pat_len = pat.length;
        if (pat_len == 0)
            return invalid_addr;

        if (end_exclusive <= begin)
            return invalid_addr;

        if (end_exclusive - begin < uintptr_t(pat_len))
            return invalid_addr;

        const uintptr_t max_pos = end_exclusive - uintptr_t(pat_len);

        run runs[MEMLIB_MAX_PATTERN_LEN]{};
        const size_t run_count = build_runs(pat, runs);

        // pattern is all wildcards -> first position matches
        if (run_count == 0)
            return begin;

        size_t key_idx = 0;
        uint8_t skip[MEMLIB_MAX_PATTERN_LEN]{};
        if (!build_bmh_table(pat, key_idx, skip))
        {
            for (uintptr_t cur = begin; cur <= max_pos; ++cur)
            {
                const uint8_t* mem = reinterpret_cast<const uint8_t*>(cur);
                if (runs_equal(mem, pat, runs, run_count))
                    return cur;
            }
            return invalid_addr;
        }

        const size_t k = key_idx;
        const uint8_t key_byte = pat.bytes[k];

        uintptr_t cur = begin;
        while (cur <= max_pos)
        {
            const uint8_t* mem = reinterpret_cast<const uint8_t*>(cur);
            const uint8_t v = mem[k];

            if (v == key_byte)
            {
                if (runs_equal(mem, pat, runs, run_count))
                    return cur;

                ++cur;
            }
            else
            {
                cur += skip[v];
            }
        }

        return invalid_addr;
    }



    static inline bool add_range_intersection(uintptr_t r_start, uintptr_t r_end,
        uintptr_t scan_start, uintptr_t scan_end,
        uintptr_t& out_start, uintptr_t& out_end) noexcept
    {
        if (r_end <= scan_start || r_start >= scan_end)
            return false;

        out_start = (r_start < scan_start) ? scan_start : r_start;
        out_end = (r_end > scan_end) ? scan_end : r_end;
        return out_end > out_start;
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

    address find(const scan_pattern& pattern, void* start, size_t length, int32_t offset) noexcept
    {
        MEMLIB_DEBUG("Scanning {} to {}.", start, (void*)(((uintptr_t)start) + length));
        if (!start || length == 0 || pattern.length == 0)
            return {};

        const size_t pat_len = pattern.length;
        if (length < pat_len)
            return {};

        const uintptr_t first = uintptr_t(start);
        if (uintptr_t(length) > uintptr_t(-1) - first)
            return {};

        const uintptr_t scan_end = first + uintptr_t(length);

#if MEMLIB_IS_WINDOWS
        uintptr_t cur = first;
        while (cur < scan_end)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (::VirtualQuery(reinterpret_cast<void*>(cur), &mbi, sizeof(mbi)) == 0)
                break;

            const uintptr_t r_start = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            const uintptr_t r_end = r_start + uintptr_t(mbi.RegionSize);

            if (cur < r_start)
                cur = r_start;

            uintptr_t seg_start = 0, seg_end = 0;
            if (!add_range_intersection(r_start, r_end, first, scan_end, seg_start, seg_end))
            {
                cur = r_end;
                continue;
            }

            const bool committed = (mbi.State == MEM_COMMIT);
            const bool readable = committed && is_readable_protect_win(mbi.Protect);

            if (readable && (seg_end - seg_start >= uintptr_t(pat_len)))
            {
                const uintptr_t found = scan_range_bmh(seg_start, seg_end, pattern);
                if (found != invalid_addr)
                {
                    uintptr_t out = 0;
                    if (!add_signed_checked(found, offset, out))
                        return {};

                    return address(out);
                }
            }

            cur = r_end;
        }

        return {};

#elif MEMLIB_IS_LINUX
        FILE* f = std::fopen("/proc/self/maps", "r");
        if (!f)
            return {};

        char line[512];
        while (std::fgets(line, sizeof(line), f))
        {
            uintptr_t r_start = 0, r_end = 0;
            char perm[5]{};

            if (std::sscanf(line, "%lx-%lx %4s", &r_start, &r_end, perm) != 3)
                continue;

            if (perm[0] != 'r')
                continue;

            uintptr_t seg_start = 0, seg_end = 0;
            if (!add_range_intersection(r_start, r_end, first, scan_end, seg_start, seg_end))
                continue;

            if (seg_end - seg_start < uintptr_t(pat_len))
                continue;

            const uintptr_t found = scan_range_bmh(seg_start, seg_end, pattern);
            if (found != invalid_addr)
            {
                uintptr_t out = 0;
                if (!add_signed_checked(found, offset, out))
                {
                    std::fclose(f);
                    return {};
                }

                std::fclose(f);
                return address(out);
            }
        }

        std::fclose(f);
        return {};
#endif
    }

    address find(const char* combo, void* start, size_t length, int32_t offset) noexcept
    {
        scan_pattern pattern{};
        if (!parse_combo_pattern(combo, pattern))
            return {};

        return find(pattern, start, length, offset);
    }
}