#include "memlib/module.hpp"

#include "internal.hpp"

#include <array>

namespace
{
    using namespace memlib;

#if MEMLIB_IS_WINDOWS
    struct sec_map_entry
    {
        const char* name;
        section     sec;
        uint8_t     len;
    };

    constexpr std::array<sec_map_entry, uint8_t(section::max)> SECTIONS_MAP{{
        { ".text",  section::text,  5 },
        { ".rdata", section::rdata, 6 },
        { ".data",  section::data,  5 },
        { ".idata", section::idata, 6 },
        { ".reloc", section::reloc, 6 },
        { ".pdata", section::pdata, 6 },
        { ".bss",   section::bss,   4 },
        { ".edata", section::edata, 6 },
        { ".rsrc",  section::rsrc,  5 },
        { ".tls",   section::tls,   4 },
        { ".debug", section::debug, 6 },
    }};

    inline const IMAGE_NT_HEADERS* nt_headers_from_module(HMODULE mod) noexcept
    {
        if (!mod)
            return nullptr;

        const uintptr_t         base = reinterpret_cast<const uintptr_t>(mod);
        const IMAGE_DOS_HEADER* dos  = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);

        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        return nt;
    }



    // Compare IMAGE_SECTION_HEADER::Name (8 bytes, not necessarily 0-terminated) to ASCII literal.
    inline bool get_section_name_equals(const uint8_t name8[8], const char* s, size_t n) noexcept
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

        if (n < 8)
        {
            const uint8_t next = name8[n];
            if (next != 0 && next != ' ') // PE names sometimes padded with zeros/spaces
                return false;
        }

        return true;
    }

    inline section section_from_name(const uint8_t name8[8]) noexcept
    {
        for (const auto& e : SECTIONS_MAP)
        {
            if (get_section_name_equals(name8, e.name, e.len))
                return e.sec;
        }

        return section::none;
    }
#elif MEMLIB_IS_LINUX
#endif

}

namespace memlib
{
	module::module(const char* modulename)
	{
#if MEMLIB_IS_WINDOWS
        m_handle = ::GetModuleHandleA(modulename); // modulename==nullptr => current module
        if (!m_handle)
        {
            const char* label = modulename ? modulename : "<current module>";
            MEMLIB_ERROR("Could not find module handle of {}", label);
            return;
        }

        const auto* nt = nt_headers_from_module(m_handle);
        if (!nt)
        {
            m_handle = nullptr;
            MEMLIB_ERROR("Invalid PE headers (DOS/NT signature check failed).");
            return;
        }

        const uintptr_t module_base = reinterpret_cast<uintptr_t>(m_handle);
        const uintptr_t image_size  = nt->OptionalHeader.SizeOfImage;

        auto*      sec    = IMAGE_FIRST_SECTION(nt);
        const WORD nsects = nt->FileHeader.NumberOfSections;

        size_t sections_found = 0;

        for (WORD i = 0; i < nsects; ++i, ++sec)
        {
            uintptr_t va   = sec->VirtualAddress;
            size_t    vlen = static_cast<size_t>(std::max(sec->Misc.VirtualSize, sec->SizeOfRawData));

            if (va >= image_size)
                continue;

            char section_name[IMAGE_SIZEOF_SHORT_NAME + 1]{};
            std::memcpy(section_name, sec->Name, 8);

            const section secid = section_from_name(sec->Name);
            if (secid == section::none)
                continue;

            prot pr = prot::none;
            if (sec->Characteristics & IMAGE_SCN_MEM_READ)    pr = pr | prot::r;
            if (sec->Characteristics & IMAGE_SCN_MEM_WRITE)   pr = pr | prot::w;
            if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) pr = pr | prot::x;

            void* section_start = reinterpret_cast<void*>(module_base + va);
            size_t section_size = std::min<size_t>(vlen, image_size - va);

            m_sections[uint8_t(secid)] = { section_name, secid, section_start, section_size, section_size /* todo: size_padded */, pr};
            MEMLIB_DEBUG(
                "[Scanner] Found section \"{}\" at {} and size 0x{:X} ({}{}{}).",
                section_name,
                section_start,
                section_size,
                has(pr, prot::r) ? "r" : "",
                has(pr, prot::w) ? "w" : "",
                has(pr, prot::x) ? "x" : ""
            );

            ++sections_found;
        }

        if (!sections_found)
        {
            m_handle = nullptr;
            MEMLIB_ERROR("Target module has no sections. (bug?)");
        }
#elif MEMLIB_IS_LINUX
#endif
	}
    
    
    address module::find(const scan_pattern& pattern, section sec, int32_t offset) noexcept
    {
        const auto section = m_sections[uint8_t(sec)];        
        return memlib::find(pattern, section.start, section.size, offset);
    }

    address module::find(const char* combo, section sec, int32_t offset) noexcept
    {
        const auto section = m_sections[uint8_t(sec)];
        return memlib::find(combo, section.start, section.size, offset);
    }
}
