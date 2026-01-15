#include "memlib/macros.hpp"
#include "memlib/memory.hpp"

#include <Zydis/Zydis.h>
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

    constexpr std::array<sec_map_entry, uint8_t(section::max)> k_sec_map{ {
        { ".text",  uint8_t(section::text),  5 },
        { ".rdata", uint8_t(section::rdata), 6 },
        { ".data",  uint8_t(section::data),  5 },
        { ".idata", uint8_t(section::idata), 6 },
        { ".reloc", uint8_t(section::reloc), 6 },
        { ".pdata", uint8_t(section::pdata), 6 },
        { ".bss",   uint8_t(section::bss),   4 },
        { ".edata", uint8_t(section::edata), 6 },
        { ".rsrc",  uint8_t(section::rsrc),  5 },
        { ".tls",   uint8_t(section::tls),   4 },
        { ".debug", uint8_t(section::debug), 6 },
    } };

    // Compare IMAGE_SECTION_HEADER::Name (8 bytes, not necessarily 0-terminated) to ASCII literal.
    inline bool sec_name_equals_ci(const uint8_t name8[8], const char* s, size_t n) noexcept
    {
        if (!s || n == 0 || n > 8) return false;

        for (size_t i = 0; i < n; ++i)
        {
            const uint8_t a = name8[i];
            const uint8_t b = static_cast<uint8_t>(s[i]);

            // ASCII case-fold
            const uint8_t af = (a >= 'A' && a <= 'Z') ? (a | 0x20) : a;
            const uint8_t bf = (b >= 'A' && b <= 'Z') ? (b | 0x20) : b;

            if (af != bf)
                return false;
        }

        // Optional: ensure the next byte isn't an extra letter (so ".textX" doesn't match ".text")
        // For PE section names, this is rare but harmless to guard.
        if (n < 8)
        {
            const uint8_t next = name8[n];
            if (next != 0 && next != ' ') // PE names sometimes padded with zeros/spaces
                return false;
        }

        return true;
    }

    inline uint8_t section_id_from_name(const uint8_t name8[8]) noexcept
    {
        for (const auto& e : k_sec_map)
        {
            if (sec_name_equals_ci(name8, e.name, e.len))
                return e.id;
        }
        return 0xFF;
    }

    inline const IMAGE_NT_HEADERS* nt_headers_from_module(HMODULE mod) noexcept
    {
        if (!mod)
            return nullptr;

        const auto* base = reinterpret_cast<const uint8_t*>(mod);
        const auto* dos  = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        return nt;
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

    ZydisDecoder& get_decoder()
    {
        static bool init = false;
        static ZydisDecoder decoder;

        if (!init)
        {
            #if MEMLIB_IS_64
                ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
            #else
                ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
            #endif
        }

        return decoder;
    }



    bool zydis_decode(void* p, ZydisDecodedInstruction& inst, ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]) noexcept
    {
        if (!p)
            return false;

        if (!is_readable(p, ZYDIS_MAX_INSTRUCTION_LENGTH))
            return false;

        auto& decoder = get_decoder();
        return ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, p, 16, &inst, ops));
    }



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

#pragma region address
    bool address::is_valid() const noexcept
    {
        if (!m_value)
            return false;

        return query(ptr()).has_value();
    }



    bool address::is_readable(size_t bytes) const noexcept
    {
        if (!m_value)
            return false;

        return memlib::is_readable(ptr(), bytes);
    }



    bool address::is_writable(size_t bytes) const noexcept
    {
        if (!m_value)
            return false;

        return memlib::is_writable(ptr(), bytes);
    }



    bool address::is_executable(size_t bytes) const noexcept
    {
        if (!m_value)
            return false;

        return memlib::is_executable(ptr(), bytes);
    }



    std::optional<module_info> address::module() const noexcept
    {
        if (!m_value)
            return std::nullopt;

        return module_from_address(ptr());
    }



    std::optional<section_info> address::section() const noexcept
    {
        if (!m_value)
            return std::nullopt;

        return section_from_address(ptr());
    }



    std::optional<region_info> address::region() const noexcept
    {
        if (!m_value)
            return std::nullopt;

        return query(ptr());
    }



    address address::dereference_pointer(size_t count) const noexcept
    {
        address cur = *this;

        for (size_t i = 0; i < count; ++i)
        {
            if (!cur.is_readable(sizeof(void*)))
                return address{};

            value_type next{};
            if constexpr (MEMLIB_IS_64)
            {
                uint64_t v{};
                if (!cur.read(v))
                    return address{};

                next = static_cast<value_type>(v);
            }
            else
            {
                uint32_t v{};
                if (!cur.read(v))
                    return address{};

                next = static_cast<value_type>(v);
            }

            cur = address(next);
            if (!cur)
                return address{};
        }

        return cur;
    }



    address address::follow(std::initializer_list<value_type> offsets) const noexcept
    {
        if (!m_value)
            return {};

        address cur = *this;

        bool first = true;
        for (auto off : offsets)
        {
            if (first)
            {
                cur = cur + off;
                first = false;
                continue;
            }

            cur = cur.dereference_pointer(1);
            if (!cur)
                return {};

            cur = cur + off;
        }

        return cur;
    }



    address address::dereference_call() const noexcept
    {
        ZydisDecodedInstruction inst{};
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!zydis_decode(ptr(), inst, ops))
            return {};

        if (inst.mnemonic != ZYDIS_MNEMONIC_CALL)
            return {};

        for (uint8_t i = 0; i < inst.operand_count_visible; ++i)
        {
            const auto& op = ops[i];
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative)
            {
                const int64_t disp = op.imm.value.s;
                return resolve_relative(disp, inst.length);
            }
        }

        return {};
    }



    address address::dereference_branch() const noexcept
    {
        ZydisDecodedInstruction inst{};
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!zydis_decode(ptr(), inst, ops))
            return {};

        const bool is_jmp = (inst.mnemonic == ZYDIS_MNEMONIC_JMP);

        const bool is_jcc =
            (inst.mnemonic >= ZYDIS_MNEMONIC_JB    && inst.mnemonic <= ZYDIS_MNEMONIC_JZ) ||
             inst.mnemonic == ZYDIS_MNEMONIC_JECXZ || inst.mnemonic == ZYDIS_MNEMONIC_JRCXZ;

        if (!is_jmp && !is_jcc)
            return {};

        for (uint8_t i = 0; i < inst.operand_count_visible; ++i)
        {
            const auto& op = ops[i];
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative)
            {
                const int64_t disp = op.imm.value.s;
                return resolve_relative(disp, inst.length);
            }
        }

        return {};
    }



#if MEMLIB_IS_64
    address address::resolve_rip_relative() const noexcept
    {
        ZydisDecodedInstruction inst{};
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT_VISIBLE]{};
        if (!zydis_decode(ptr(), inst, ops))
            return {};

        // Look for memory operand with base = RIP
        for (uint8_t i = 0; i < inst.operand_count_visible; ++i)
        {
            const auto& op = ops[i];
            if (op.type != ZYDIS_OPERAND_TYPE_MEMORY)
                continue;

            if (op.mem.base != ZYDIS_REGISTER_RIP)
                continue;

            // Effective address: next_ip + disp
            const int64_t    disp    = op.mem.disp.value;
            const value_type next_ip = m_value + inst.length;

            return address(static_cast<value_type>(next_ip + disp));
        }

        return {};
    }
#endif

#pragma endregion

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



    scanner::scanner(const char* modulename)
    {
#if MEMLIB_IS_WINDOWS
        m_module = ::GetModuleHandleA(modulename); // modulename==nullptr => current module
        if (!m_module)
        {
            const char* label = modulename ? modulename : "<current module>";
            MEMLIB_ERROR("Could not find module handle of {}", label);
            return;
        }

        const auto* nt = nt_headers_from_module(m_module);
        if (!nt)
        {
            m_module = nullptr;
            MEMLIB_ERROR("Invalid PE headers (DOS/NT signature check failed).");
            return;
        }

        const uintptr_t module_base = reinterpret_cast<uintptr_t>(m_module);
        const uintptr_t image_size = nt->OptionalHeader.SizeOfImage;

        auto* section     = IMAGE_FIRST_SECTION(nt);
        const WORD nsects = nt->FileHeader.NumberOfSections;

        size_t sections_found = 0;
        for (WORD i = 0; i < nsects; ++i, ++section)
        {
            uintptr_t va   = section->VirtualAddress;
            size_t    vlen = static_cast<size_t>(std::max(section->Misc.VirtualSize, section->SizeOfRawData));

            if (va >= image_size)
                continue;

            char name[IMAGE_SIZEOF_SHORT_NAME + 1]{};
            std::memcpy(name, section->Name, 8);

            const uint8_t id = section_id_from_name(section->Name);
            if (id == 0xFF)
                continue;

            prot pr = prot::none;
            if (section->Characteristics & IMAGE_SCN_MEM_READ)    pr = pr | prot::r;
            if (section->Characteristics & IMAGE_SCN_MEM_WRITE)   pr = pr | prot::w;
            if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) pr = pr | prot::x;

            void* start = reinterpret_cast<void*>(module_base + va);
            size_t size = std::min<size_t>(vlen, image_size - va);

            m_sections[id] = { name, start, size, pr };
            MEMLIB_DEBUG(
                "[Scanner] Found section \"{}\" at {} and size 0x{:X} ({}{}{}).",
                name,
                start,
                size,
                has(pr, prot::r) ? "r" : "",
                has(pr, prot::w) ? "w" : "",
                has(pr, prot::x) ? "x" : ""
            );

            ++sections_found;
        }

        if (!sections_found)
        {
            m_module = nullptr;
            MEMLIB_ERROR("Target module has no sections. (bug?)");
        }
#elif MEMLIB_IS_LINUX
#endif
    }



    address scanner::find(const scan_pattern& pattern, void* start, size_t length, int32_t offset) const noexcept
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

    address scanner::find(const char* combo, void* start, size_t length, int32_t offset) const noexcept
    {
        scan_pattern pattern{};
        if (!parse_combo_pattern(combo, pattern))
            return {};

        return find(pattern, start, length, offset);
    }

    address scanner::find(const scan_pattern& pattern, section sec, int32_t offset) const noexcept
    {
        auto s = m_sections[uint8_t(sec)];
        if (!s.start || !s.size)
            return {};

        return find(pattern, s.start, s.size, offset);
    }

    address scanner::find(const char* combo, section sec, int32_t offset) const noexcept
    {
        scan_pattern pattern{};
        if (!parse_combo_pattern(combo, pattern))
            return {};

        return find(pattern, sec, offset);
    }

#pragma endregion
}