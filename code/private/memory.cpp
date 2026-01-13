#include "memlib/macros.hpp"
#include "memlib/memory.hpp"

#include <Zydis/Zydis.h>

namespace
{
	using namespace memlib;

    constexpr uint32_t MAX_PATH_BUFFER_SIZE = 4096;

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

}