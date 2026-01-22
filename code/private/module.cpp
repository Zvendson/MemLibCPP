#include "memlib/module.hpp"

#include "internal.hpp"


namespace memlib
{
	module::module(const char* modulename)
	{
        m_handle = get_module_handle(modulename);
        if (!m_handle)
        {
            const char* label = modulename ? modulename : "<current module>";
            MEMLIB_ERROR("Could not find module handle of {}", label);
            return;
        }

#if MEMLIB_IS_WINDOWS
        auto* nt = get_nt_headers_from_module(m_handle);
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

            const section secid = get_section_from_name(sec->Name);
            if (secid == section::unknown)
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
                prot_has(pr, prot::r) ? "r" : "",
                prot_has(pr, prot::w) ? "w" : "",
                prot_has(pr, prot::x) ? "x" : ""
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
