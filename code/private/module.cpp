#include "memlib/module.hpp"

#include "internal.hpp"

#if MEMLIB_IS_LINUX
#include <link.h>
#include <elf.h>
#include <unistd.h>
#include <algorithm>
#include <string_view>
#include <cstring>
#include <limits.h>
#include <limits>

namespace
{
    inline bool match_name(std::string_view candidate_path, const char* requested)
    {
        if (!requested || !*requested)
            return candidate_path.empty();

        std::string_view req = requested;

        // If requested contains '/', match full path.
        if (req.find('/') != std::string_view::npos)
            return candidate_path == req;

        // Compare basename only
        const auto pos = candidate_path.find_last_of('/');
        const std::string_view base = (pos == std::string_view::npos) ? candidate_path : candidate_path.substr(pos + 1);

        if (base == req)
            return true;

        // Allow "foo" to match "libfoo.so"
        std::string tmp;
        tmp.reserve(3 + req.size() + 3);
        tmp.append("lib").append(req).append(".so");
        return base == tmp;
    }

    inline memlib::prot phdr_to_prot(uint32_t flags) noexcept
    {
        memlib::prot p = memlib::prot::none;
        if (flags & PF_R) p = p | memlib::prot::r;
        if (flags & PF_W) p = p | memlib::prot::w;
        if (flags & PF_X) p = p | memlib::prot::x;
        return p;
    }

    inline void set_if_empty(memlib::section_info& dst, const memlib::section_info& src)
    {
        if (!dst)
            dst = src;
    }

    inline std::string self_exe_path()
    {
        char buf[PATH_MAX]{};
        const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (n <= 0)
            return {};
        buf[n] = '\0';
        return std::string(buf);
    }
} // anonymous namespace
#endif

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

        m_base = reinterpret_cast<void*>(module_base);
        m_size = static_cast<size_t>(image_size);
        m_path = get_module_path(m_handle);

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
        // Discover module base/path/segments using dl_iterate_phdr.
        // This gives us PT_LOAD segments which we map to our coarse section categories.
        struct ctx
        {
            const char* requested = nullptr;   // nullptr => main program
            module_handle handle = nullptr;

            void* base = nullptr;
            size_t size = 0;
            std::string path{};
            std::string name{};

            section_info sections[uint8_t(section::max)]{};
            bool found = false;
        } c;

        c.requested = modulename;
        c.handle = m_handle;

        auto cb = [](dl_phdr_info* info, size_t, void* data) -> int
        {
            auto* c = static_cast<ctx*>(data);

            const std::string_view path = (info->dlpi_name && *info->dlpi_name) ? info->dlpi_name : "";

            if (!match_name(path, c->requested))
            {
                return 0;
            }

            c->found = true;

            // On Linux, dlpi_addr can be 0 for the main executable (non-PIE). Do NOT treat it as the base.
            // Compute base/size from PT_LOAD segments instead (these are the actually mapped ranges).
            uintptr_t min_addr = std::numeric_limits<uintptr_t>::max();
            uintptr_t max_addr = 0;

            // Path/name
            c->path = path.empty() ? self_exe_path() : std::string(path);
            MEMLIB_DEBUG("Path: {}", c->path);
            const auto pos = c->path.find_last_of('/');
            c->name = (pos == std::string::npos) ? c->path : c->path.substr(pos + 1);

            // Compute base/size and fill coarse "sections" based on PT_LOAD segments.

            for (int i = 0; i < info->dlpi_phnum; ++i)
            {
                const auto& ph = info->dlpi_phdr[i];
                if (ph.p_type != PT_LOAD)
                    continue;

                const uintptr_t seg_start = (info->dlpi_addr == 0)
                    ? static_cast<uintptr_t>(ph.p_vaddr)
                    : static_cast<uintptr_t>(info->dlpi_addr) + static_cast<uintptr_t>(ph.p_vaddr);
                const uintptr_t seg_end   = seg_start + static_cast<uintptr_t>(ph.p_memsz);

                min_addr = std::min(min_addr, seg_start);
                max_addr = std::max(max_addr, seg_end);

                const prot pr = phdr_to_prot(ph.p_flags);

                section st = section::unknown;
                const char* sname = "PT_LOAD";

                if (prot_has(pr, prot::x))
                {
                    st = section::code;
                    sname = ".text";
                }
                else if (prot_has(pr, prot::w))
                {
                    st = section::rw_data;
                    sname = ".data";
                }
                else
                {
                    st = section::ro_data;
                    sname = ".rodata";
                }

                section_info si{};
                si.name = sname;
                si.type = st;
                si.start = reinterpret_cast<void*>(seg_start);
                si.size = static_cast<size_t>(seg_end - seg_start);
                si.size_padded = si.size;
                si.protection = pr;
                si.module = c->handle;

                // Keep the first segment for each category (good enough for scanning).
                set_if_empty(c->sections[uint8_t(st)], si);
            }

            if (min_addr != std::numeric_limits<uintptr_t>::max() && max_addr > min_addr)
            {
                c->base = reinterpret_cast<void*>(min_addr);
                c->size = static_cast<size_t>(max_addr - min_addr);
            }
            else
            {
                c->base = nullptr;
                c->size = 0;
            }
            return 1; // stop iteration
        };

        ::dl_iterate_phdr(cb, &c);

        if (!c.found || !c.base || c.size == 0)
        {
            m_handle = nullptr;
            const char* label = modulename ? modulename : "<main program>";
            MEMLIB_ERROR("Could not resolve module info for {}", label);
            return;
        }

        m_base = c.base;
        m_size = c.size;
        m_path = c.path;
        m_name = c.name;

        for (uint8_t i = 0; i < uint8_t(section::max); ++i)
            m_sections[i] = c.sections[i];

        // Require at least a code section to scan.
        if (!m_sections[uint8_t(section::code)])
        {
            MEMLIB_ERROR("Target module has no executable segment. (bug?)");
            m_handle = nullptr;
            return;
        }
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

    section_info module::get_section(section sec) const noexcept
    {
        size_t secid = size_t(sec);
        if (secid >= size_t(section::max))
            return {};

        return m_sections[secid];
    }



    std::vector<section_info> module::get_sections() const noexcept
    {
        std::vector<section_info> out;
        if (!m_handle)
            return out;

        constexpr size_t size = size_t(section::max);
        out.reserve(size);

        for (size_t i = 0 ; i < size; ++i)
        {
            auto& section = m_sections[i];
            if (section.module == nullptr)
                continue;

            out.push_back(section);
        }

        return out;
    }
}
