#include "memlib/os.hpp"
#include "memlib/memory.hpp"

#include <array>

namespace memlib
{
    prot win_to_prot(DWORD protect) noexcept
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



    DWORD prot_to_win(prot protect) noexcept
    {
        const bool r = prot_has(protect, prot::r);
        const bool w = prot_has(protect, prot::w);
        const bool x = prot_has(protect, prot::x);

        if (!r && !w && !x) return PAGE_NOACCESS;
        if ( x &&  w)       return PAGE_EXECUTE_READWRITE;
        if ( x && !w &&  r) return PAGE_EXECUTE_READ;
        if ( x && !w && !r) return PAGE_EXECUTE;
        if (!x &&  w)       return PAGE_READWRITE;
        if (!x && !w && r)  return PAGE_READONLY;

        return PAGE_NOACCESS;
    }



    struct sec_map_entry
    {
        const char* name;
        section     sec;
        uint8_t     len;
    };
    constexpr std::array<sec_map_entry, uint8_t(section::max)> SECTIONS_MAP{ {
        sec_map_entry(".text",  section::code       , 5 ),
        sec_map_entry(".rdata", section::ro_data    , 6 ),
        sec_map_entry(".data",  section::rw_data    , 5 ),
        sec_map_entry(".idata", section::imports    , 6 ),
        sec_map_entry(".reloc", section::relocations, 6 ),
        sec_map_entry(".bss",   section::zero_data  , 4 ),
        sec_map_entry(".edata", section::exports    , 6 ),
        sec_map_entry(".rsrc",  section::resources  , 5 ),
        sec_map_entry(".tls",   section::tls        , 4 ),
        sec_map_entry(".debug", section::debug      , 6 ),
    }};



    // helper function to compare IMAGE_SECTION_HEADER.Name not always 0-terminated
    inline bool get_section_name_equals(const uint8_t name8[8], const char* s, size_t n) noexcept
    {
        if (!s || n == 0 || n > 8) 
            return false;

        for (size_t i = 0; i < n; ++i)
        {
            const uint8_t a = name8[i];
            const uint8_t b = static_cast<uint8_t>(s[i]);

            const uint8_t af = (a >= 'A' && a <= 'Z') ? (a | 0x20) : a;
            const uint8_t bf = (b >= 'A' && b <= 'Z') ? (b | 0x20) : b;

            if (af != bf)
                return false;
        }

        if (n < 8)
        {
            const uint8_t next = name8[n];
            if (next != 0 && next != ' ')
                return false;
        }

        return true;
    }



    section get_section_from_name(const uint8_t name8[8]) noexcept
    {
        for (const auto& e : SECTIONS_MAP)
        {
            if (get_section_name_equals(name8, e.name, e.len))
                return e.sec;
        }

        return section::unknown;
    }



    std::string to_string(const wchar_t* str)
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



    uint32_t get_pid()
    {
        return ::GetCurrentProcessId();
    }



    module_handle get_module_handle(const char* name)
    {
        return ::GetModuleHandleA(name);
    }



    IMAGE_NT_HEADERS* get_nt_headers_from_module(HMODULE mod) noexcept
    {
        if (!mod)
            return nullptr;

        const uintptr_t         base = reinterpret_cast<const uintptr_t>(mod);
        const IMAGE_DOS_HEADER* dos  = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);

        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        return nt;
    }

    bool is_readable_protect_win(DWORD protect) noexcept
    {
        if (protect & PAGE_GUARD)
            return false;

        if (protect & PAGE_NOACCESS)
            return false;

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



    std::optional<region_info> query(void* p) noexcept
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (::VirtualQuery(p, &mbi, sizeof(mbi)) == 0)
            return std::nullopt;

        region_info r{};

        r.start = mbi.BaseAddress;
        r.end = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
        r.protection = (mbi.State == MEM_COMMIT) ? win_to_prot(mbi.Protect) : prot::none;

        if (mbi.Type == MEM_IMAGE)
        {
            if (auto m = module_from_address(p))
                r.mapped_path = m->path;
        }

        return r;
    }



    bool protect(void* p, size_t size, prot new_prot, prot* old_prot_out) noexcept
    {
        DWORD oldp = 0;
        if (!::VirtualProtect(p, size, prot_to_win(new_prot), &oldp))
            return false;

        if (old_prot_out)
            *old_prot_out = win_to_prot(oldp);

        return true;
    }



    void* alloc(size_t size, prot p) noexcept
    {
        return ::VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, prot_to_win(p));
    }



    bool free(void* p, size_t size) noexcept
    {
        return ::VirtualFree(p, size, MEM_RELEASE) != 0;
    }



    void flush_icache(void* p, size_t size) noexcept
    {
        ::FlushInstructionCache(::GetCurrentProcess(), p, size);
    }



    std::optional<section_info> section_from_address(void* p) noexcept
    {
        auto mod = module_from_address(p);
        if (!mod)
            return std::nullopt;

        auto* base = static_cast<uint8_t*>(mod->base);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
            return std::nullopt;

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
            return std::nullopt;

        auto* sec = IMAGE_FIRST_SECTION(nt);
        const auto count = nt->FileHeader.NumberOfSections;

        const uintptr_t addr = reinterpret_cast<uintptr_t>(p);

        for (uint16_t i = 0; i < count; ++i)
        {
            const uintptr_t start = reinterpret_cast<uintptr_t>(base + sec[i].VirtualAddress);
            const size_t    sz = static_cast<size_t>(std::max(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData));
            const uintptr_t end = start + sz;

            if (addr >= start && addr < end)
            {
                section_info s{};
                char name[IMAGE_SIZEOF_SHORT_NAME + 1]{};
                std::memcpy(name, sec[i].Name, 8);

                s.name = name;
                s.start = reinterpret_cast<void*>(start);
                s.size = sz;

                prot pr = prot::none;
                if (sec[i].Characteristics & IMAGE_SCN_MEM_READ)    pr = pr | prot::r;
                if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE)   pr = pr | prot::w;
                if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) pr = pr | prot::x;

                s.protection = pr;

                return s;
            }
        }

        return std::nullopt;
    }



    std::optional<module_info> module_from_address(void* p) noexcept
    {
        constexpr DWORD flags = GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
            | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;

        HMODULE hmod = nullptr;
        if (!::GetModuleHandleExA(flags, reinterpret_cast<LPCSTR>(p), &hmod))
            return std::nullopt;

        MODULEINFO mi{};
        if (!::GetModuleInformation(::GetCurrentProcess(), hmod, &mi, sizeof(mi)))
            return std::nullopt;

        wchar_t path[MEMLIB_MAX_PATH]{};
        ::GetModuleFileNameW(hmod, path, MEMLIB_MAX_PATH);

        module_info out{};
        out.base = mi.lpBaseOfDll;
        out.size = static_cast<size_t>(mi.SizeOfImage);
        out.path = to_string(path);

        const std::string s = out.path;
        const auto pos = s.find_last_of("\\/");
        out.name = (pos == std::string::npos) ? s : s.substr(pos + 1);

        return out;
    }
}
