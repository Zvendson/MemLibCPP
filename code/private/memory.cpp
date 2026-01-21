#include "memlib/macros.hpp"
#include "memlib/os.hpp"
#include "memlib/memory.hpp"
#include "memlib/address.hpp"

#include <array>
#include <algorithm>
#include <cstdint>
#include <cstring>

#include "internal.hpp"

namespace
{
	using namespace memlib;

    constexpr uint32_t MAX_PATH_BUFFER_SIZE = 4096;
    static inline constexpr uintptr_t invalid_addr = uintptr_t(-1);

    struct sec_map_entry
    {
        const char* name;
        uint8_t     id;
        uint8_t     len;
    };

    struct run
    {
        uint16_t off = 0;
        uint16_t len = 0;
    };

#if MEMLIB_IS_WINDOWS
    static prot win_to_prot(DWORD protect) noexcept
    {
        // Ignore PAGE_GUARD/PAGE_NOCACHE/etc for now; we care about R/W/X.
        const DWORD p = protect & 0xFF;
        switch (p)
        {
            case PAGE_NOACCESS:          return prot::none;
            case PAGE_READONLY:          return prot::r;
            case PAGE_READWRITE:         return prot::r | prot::w;
            case PAGE_WRITECOPY:         return prot::r | prot::w;
            case PAGE_EXECUTE:           return prot::x;
            case PAGE_EXECUTE_READ:      return prot::r | prot::x;
            case PAGE_EXECUTE_READWRITE: return prot::r | prot::w | prot::x;
            case PAGE_EXECUTE_WRITECOPY: return prot::r | prot::w | prot::x;
            default:                     return prot::none;
        }
    }

    static DWORD prot_to_win(prot p) noexcept
    {
        const bool r = has(p, prot::r);
        const bool w = has(p, prot::w);
        const bool x = has(p, prot::x);

        if (!r && !w && !x) return PAGE_NOACCESS;
        if ( x &&  w)       return PAGE_EXECUTE_READWRITE;
        if ( x && !w &&  r) return PAGE_EXECUTE_READ;
        if ( x && !w && !r) return PAGE_EXECUTE;
        if (!x &&  w)       return PAGE_READWRITE;
        if (!x && !w && r)  return PAGE_READONLY;

        return PAGE_NOACCESS;
    }

    std::string ToMultiByteString(const wchar_t* str)
    {
        if (str == nullptr)
            return "";

        size_t length = wcslen(str);
        const auto sz = WideCharToMultiByte(CP_UTF8, 0, str, static_cast<int>(length), nullptr, 0, nullptr, nullptr);
        if (sz <= 0)
            return "";

        std::string result(sz, 0);
        WideCharToMultiByte(CP_UTF8, 0, str, static_cast<int>(length), &result.at(0), sz, nullptr, nullptr);
        return result;
    }

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

        if (has(need, prot::r) && !has(r->protection, prot::r)) return false;
        if (has(need, prot::w) && !has(r->protection, prot::w)) return false;
        if (has(need, prot::x) && !has(r->protection, prot::x)) return false;

        return true;
    }

    static inline bool is_readable_protect_win(DWORD protect) noexcept
    {
        if (protect & PAGE_GUARD)     return false;
        if (protect & PAGE_NOACCESS)  return false;

        const DWORD p = protect & 0xFF;
        switch (p)
        {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

#elif MEMLIB_IS_LINUX
#endif



    static inline int to_hexval(char c) noexcept
    {
        if ('0' <= c && c <= '9') return c - '0';
        if ('a' <= c && c <= 'f') return 10 + (c - 'a');
        if ('A' <= c && c <= 'F') return 10 + (c - 'A');
        return -1;
    }



    static inline size_t build_runs(const scan_pattern& pat, run out[256]) noexcept
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



    static inline bool build_bmh_table(const scan_pattern& pat, size_t& key_idx, uint8_t skip[256]) noexcept
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
        for (size_t i = 0; i < 256; ++i)
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

        run runs[256]{};
        const size_t run_count = build_runs(pat, runs);

        // pattern is all wildcards -> first position matches
        if (run_count == 0)
            return begin;

        size_t key_idx = 0;
        uint8_t skip[256]{};
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
    std::optional<region_info> query(void* p) noexcept
    {
#if MEMLIB_IS_WINDOWS
        MEMORY_BASIC_INFORMATION mbi{};
        if (::VirtualQuery(p, &mbi, sizeof(mbi)) == 0)
            return std::nullopt;

        region_info r{};

        r.start      = mbi.BaseAddress;
        r.end        = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
        r.protection = (mbi.State == MEM_COMMIT) ? win_to_prot(mbi.Protect) : prot::none;

        if (mbi.Type == MEM_IMAGE)
        {
            if (auto m = module_from_address(p))
                r.mapped_path = m->path;
        }

        return r;
#elif MEMLIB_IS_LINUX
#endif
    }



    bool protect(void* p, size_t size, prot new_prot, prot* old_prot_out) noexcept
    {
#if MEMLIB_IS_WINDOWS
        DWORD oldp = 0;
        if (!::VirtualProtect(p, size, prot_to_win(new_prot), &oldp))
            return false;

        if (old_prot_out)
            *old_prot_out = win_to_prot(oldp);

        return true;
#elif MEMLIB_IS_LINUX
#endif
    }



    void* alloc(size_t size, prot p) noexcept
    {
#if MEMLIB_IS_WINDOWS
        return ::VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, prot_to_win(p));
#elif MEMLIB_IS_LINUX
#endif
    }



    bool free(void* p, size_t size) noexcept
    {
#if MEMLIB_IS_WINDOWS
        UNREFERENCED_PARAMETER(size);
        return ::VirtualFree(p, 0, MEM_RELEASE) != 0;
#elif MEMLIB_IS_LINUX
#endif
    }



    void flush_icache(void* p, size_t size) noexcept
    {
#if MEMLIB_IS_WINDOWS
        ::FlushInstructionCache(::GetCurrentProcess(), p, size);
#elif MEMLIB_IS_LINUX
#endif
    }



    std::optional<module_info> module_from_address(void* p) noexcept
    {
#if MEMLIB_IS_WINDOWS
        constexpr DWORD flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                              | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;

        HMODULE hmod = nullptr;
        if (!::GetModuleHandleExA(flags, reinterpret_cast<LPCSTR>(p), &hmod))
            return std::nullopt;

        MODULEINFO mi{};
        if (!::GetModuleInformation(::GetCurrentProcess(), hmod, &mi, sizeof(mi)))
            return std::nullopt;

        wchar_t path[MAX_PATH_BUFFER_SIZE]{};
        ::GetModuleFileNameW(hmod, path, MAX_PATH_BUFFER_SIZE);

        module_info out{};
        out.base = mi.lpBaseOfDll;
        out.size = static_cast<size_t>(mi.SizeOfImage);
        out.path = ToMultiByteString(path);

        const std::string s = out.path;
        const auto pos = s.find_last_of("\\/");
        out.name = (pos == std::string::npos) ? s : s.substr(pos + 1);

        return out;
#elif MEMLIB_IS_LINUX
#endif
    }



    std::optional<section_info> section_from_address(void* p) noexcept
    {
#if MEMLIB_IS_WINDOWS
        auto mod = module_from_address(p);
        if (!mod)
            return std::nullopt;

        auto* base = static_cast<uint8_t*>(mod->base);
        auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
            return std::nullopt;

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
            return std::nullopt;

        auto* sec        = IMAGE_FIRST_SECTION(nt);
        const auto count = nt->FileHeader.NumberOfSections;

        const uintptr_t addr = reinterpret_cast<uintptr_t>(p);

        for (uint16_t i = 0; i < count; ++i)
        {
            const uintptr_t start = reinterpret_cast<uintptr_t>(base + sec[i].VirtualAddress);
            const size_t    sz    = static_cast<size_t>(std::max(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData));
            const uintptr_t end   = start + sz;

            if (addr >= start && addr < end)
            {
                section_info s{};
                char name[IMAGE_SIZEOF_SHORT_NAME + 1]{};
                std::memcpy(name, sec[i].Name, 8);

                s.name  = name;
                s.start = reinterpret_cast<void*>(start);
                s.size  = sz;

                prot pr = prot::none;
                if (sec[i].Characteristics & IMAGE_SCN_MEM_READ)    pr = pr | prot::r;
                if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)   pr = pr | prot::w;
                if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) pr = pr | prot::x;

                s.protection = pr;

                return s;
            }
        }

        return std::nullopt;

#elif MEMLIB_IS_LINUX
#endif
    }

    bool is_readable(void* p, size_t bytes)   noexcept { return region_has(p, bytes, prot::r); }
    bool is_writable(void* p, size_t bytes)   noexcept { return region_has(p, bytes, prot::w); }
    bool is_executable(void* p, size_t bytes) noexcept { return region_has(p, bytes, prot::x); }

    bool is_readable_protect(DWORD protect) noexcept
    {
        if (protect & PAGE_GUARD)    return false;
        if (protect & PAGE_NOACCESS) return false;

        const prot p = win_to_prot(protect);
        return has(p, prot::r);
    }

#pragma region scanner

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

            const uintptr_t found = scan_range_bmh(seg_start, seg_end, pat);
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

#pragma endregion
}