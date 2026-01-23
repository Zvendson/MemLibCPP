
#include "memlib/os.hpp"
#include "memlib/memory.hpp"

#if MEMLIB_IS_LINUX

#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <string>
#include <string_view>
#include <optional>
#include <utility>
#include <algorithm>

namespace
{
    using namespace memlib;

    inline prot phdr_flags_to_prot(uint32_t flags) noexcept
    {
        prot p = prot::none;
        if (flags & PF_R) p = p | prot::r;
        if (flags & PF_W) p = p | prot::w;
        if (flags & PF_X) p = p | prot::x;
        return p;
    }

    inline std::string basename_of(std::string_view path)
    {
        const auto pos = path.find_last_of('/');
        return (pos == std::string_view::npos) ? std::string(path) : std::string(path.substr(pos + 1));
    }

    inline bool parse_maps_line(const char* line, uintptr_t& start, uintptr_t& end, char perm[5], std::string& path_out)
    {
        // Typical /proc/self/maps:
        // start-end perms offset dev inode pathname...
        unsigned long s = 0, e = 0;
        char p[5] = {};
        int n = 0;

        // Read the first 3 fields; then capture the rest as path (optional)
        // Use %n to find where the path starts.
        int matched = std::sscanf(line, "%lx-%lx %4s %*s %*s %*s %n", &s, &e, p, &n);
        if (matched < 3)
            return false;

        start = static_cast<uintptr_t>(s);
        end   = static_cast<uintptr_t>(e);
        std::memcpy(perm, p, 5);

        path_out.clear();
        if (n > 0)
        {
            const char* rest = line + n;
            while (*rest == ' ' || *rest == '\t') ++rest;
            // Trim trailing newline
            size_t len = std::strlen(rest);
            while (len && (rest[len - 1] == '\n' || rest[len - 1] == '\r')) --len;
            if (len)
                path_out.assign(rest, len);
        }
        return true;
    }

    inline prot perms_to_prot(const char perm[5]) noexcept
    {
        prot p = prot::none;
        if (perm[0] == 'r') p = p | prot::r;
        if (perm[1] == 'w') p = p | prot::w;
        if (perm[2] == 'x') p = p | prot::x;
        return p;
    }

    inline std::string self_exe_path()
    {
        char buf[4096]{};
        const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (n <= 0)
            return {};
        buf[n] = '\0';
        return std::string(buf);
    }

    inline std::optional<std::pair<uintptr_t, uintptr_t>> module_range_from_maps(std::string_view path, uintptr_t base_hint = 0)
    {
        FILE* f = std::fopen("/proc/self/maps", "r");
        if (!f)
            return std::nullopt;

        uintptr_t min_s = 0, max_e = 0;
        bool any = false;

        char line[4096]{};
        while (std::fgets(line, sizeof(line), f))
        {
            uintptr_t s = 0, e = 0;
            char perm[5]{};
            std::string mapped{};
            if (!parse_maps_line(line, s, e, perm, mapped))
                continue;

            if (mapped.empty())
                continue;

            // For the main executable, maps path is the full path to /proc/self/exe target.
            if (mapped != path)
                continue;

            // If we have a base hint, ignore stray mappings below it.
            if (base_hint && s < base_hint)
                continue;

            if (!any)
            {
                min_s = s;
                max_e = e;
                any = true;
            }
            else
            {
                min_s = std::min(min_s, s);
                max_e = std::max(max_e, e);
            }
        }

        std::fclose(f);
        if (!any)
            return std::nullopt;

        return std::make_pair(min_s, max_e);
    }
}

namespace memlib
{
    module_handle get_module_handle(const char* name)
    {
        if (!name || !*name)
            return ::dlopen(nullptr, RTLD_NOW);

        void* h = ::dlopen(name, RTLD_NOLOAD | RTLD_NOW);
        if (h)
            return h;

        std::string alt;
        alt.reserve(std::strlen(name) + 6);
        if (std::strchr(name, '/'))
            return nullptr;

        alt = "lib";
        alt += name;
        if (alt.rfind(".so") == std::string::npos)
            alt += ".so";

        return ::dlopen(alt.c_str(), RTLD_NOLOAD | RTLD_NOW);
    }



    std::optional<region_info> query(void* p) noexcept
    {
        const uintptr_t addr = reinterpret_cast<uintptr_t>(p);

        FILE* f = std::fopen("/proc/self/maps", "r");
        if (!f)
            return std::nullopt;

        char line[4096]{};
        while (std::fgets(line, sizeof(line), f))
        {
            uintptr_t s = 0, e = 0;
            char perm[5]{};
            std::string mapped{};
            if (!parse_maps_line(line, s, e, perm, mapped))
                continue;

            if (addr < s || addr >= e)
                continue;

            region_info r{};
            r.start = reinterpret_cast<void*>(s);
            r.end   = reinterpret_cast<void*>(e);
            r.protection = perms_to_prot(perm);
            r.mapped_path = mapped;

            std::fclose(f);
            return r;
        }

        std::fclose(f);
        return std::nullopt;
    }



    bool protect(void* p, size_t size, prot new_prot, prot* old_prot_out) noexcept
    {
        if (size == 0)
            return true;

        if (old_prot_out)
        {
            auto r = query(p);
            *old_prot_out = r ? r->protection : prot::none;
        }

        int mp = 0;
        if (prot_has(new_prot, prot::r)) mp |= PROT_READ;
        if (prot_has(new_prot, prot::w)) mp |= PROT_WRITE;
        if (prot_has(new_prot, prot::x)) mp |= PROT_EXEC;

        // mprotect wants page-aligned address
        const long page = ::sysconf(_SC_PAGESIZE);
        const uintptr_t addr = reinterpret_cast<uintptr_t>(p);
        const uintptr_t aligned = addr & ~(uintptr_t(page) - 1);
        const size_t delta = static_cast<size_t>(addr - aligned);
        const size_t len = size + delta;

        return ::mprotect(reinterpret_cast<void*>(aligned), len, mp) == 0;
    }



    void* alloc(size_t size, prot p) noexcept
    {
        int mp = 0;
        if (prot_has(p, prot::r)) mp |= PROT_READ;
        if (prot_has(p, prot::w)) mp |= PROT_WRITE;
        if (prot_has(p, prot::x)) mp |= PROT_EXEC;

        void* out = ::mmap(nullptr, size, mp, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return (out == MAP_FAILED) ? nullptr : out;
    }



    bool free(void* p, size_t size) noexcept
    {
        if (!p)
            return true;

        // On Linux, munmap needs the original length. If size==0, try to infer it from /proc/self/maps,
        // but only if p equals the region start (safe).
        if (size == 0)
        {
            if (auto r = query(p); r && r->start == p)
                size = static_cast<size_t>(reinterpret_cast<uintptr_t>(r->end) - reinterpret_cast<uintptr_t>(r->start));
            else
                return false;
        }

        return ::munmap(p, size) == 0;
    }



    void flush_icache(void* p, size_t size) noexcept
    {
        // GCC/Clang builtin. Works across architectures.
        auto* b = static_cast<char*>(p);
        __builtin___clear_cache(b, b + size);
    }



    std::optional<module_info> module_from_address(void* p) noexcept
    {
        Dl_info di{};
        if (::dladdr(p, &di) == 0 || !di.dli_fbase)
            return std::nullopt;

        module_info out{};
        out.base = di.dli_fbase;
        out.path = di.dli_fname ? std::string(di.dli_fname) : std::string{};
        if (out.path.empty())
            out.path = self_exe_path();

        out.name = basename_of(out.path);

        const uintptr_t base = reinterpret_cast<uintptr_t>(out.base);

        if (auto range = module_range_from_maps(out.path, base))
        {
            out.base = reinterpret_cast<void*>(range->first); // more trustworthy than dladdr for main exe sometimes
            out.size = static_cast<size_t>(range->second - range->first);
        }
        else
        {
            // Fallback: compute size from program headers via dl_iterate_phdr
            struct ctx { uintptr_t base; size_t size; std::string path; bool found; } c{base, 0, out.path, false};

            auto cb = [](dl_phdr_info* info, size_t, void* data) -> int
            {
                auto* c = static_cast<ctx*>(data);

                std::string_view name = (info->dlpi_name && *info->dlpi_name) ? info->dlpi_name : "";
                std::string path = name.empty() ? self_exe_path() : std::string(name);

                if (path != c->path)
                    return 0;

                uintptr_t max_end = 0;
                for (int i = 0; i < info->dlpi_phnum; ++i)
                {
                    const auto& ph = info->dlpi_phdr[i];
                    if (ph.p_type != PT_LOAD)
                        continue;
                    const uintptr_t seg_end = info->dlpi_addr + ph.p_vaddr + ph.p_memsz;
                    max_end = std::max(max_end, seg_end);
                }
                c->size = (max_end > info->dlpi_addr) ? static_cast<size_t>(max_end - info->dlpi_addr) : 0;
                c->base = info->dlpi_addr;
                c->found = true;
                return 1;
            };

            ::dl_iterate_phdr(cb, &c);

            out.base = reinterpret_cast<void*>(c.base);
            out.size = c.size;
        }

        return out;
    }



    std::optional<section_info> section_from_address(void* p) noexcept
    {
        auto mod = module_from_address(p);
        if (!mod)
            return std::nullopt;

        const uintptr_t addr = reinterpret_cast<uintptr_t>(p);
        const uintptr_t base = reinterpret_cast<uintptr_t>(mod->base);

        // Find the PT_LOAD segment that contains this address.
        struct ctx
        {
            uintptr_t base = 0;
            uintptr_t addr = 0;
            std::string path{};
            section_info out{};
            bool found = false;
        } c;

        c.base = base;
        c.addr = addr;
        c.path = mod->path;

        auto cb = [](dl_phdr_info* info, size_t, void* data) -> int
        {
            auto* c = static_cast<ctx*>(data);

            std::string_view name = (info->dlpi_name && *info->dlpi_name) ? info->dlpi_name : "";
            std::string path = name.empty() ? self_exe_path() : std::string(name);

            if (path != c->path)
                return 0;

            for (int i = 0; i < info->dlpi_phnum; ++i)
            {
                const auto& ph = info->dlpi_phdr[i];
                if (ph.p_type != PT_LOAD)
                    continue;

                const uintptr_t seg_start = info->dlpi_addr + ph.p_vaddr;
                const uintptr_t seg_end   = seg_start + ph.p_memsz;

                if (c->addr < seg_start || c->addr >= seg_end)
                    continue;

                const prot pr = phdr_flags_to_prot(ph.p_flags);

                section type = section::unknown;
                std::string sname;

                if (prot_has(pr, prot::x))
                {
                    type = section::code;
                    sname = ".text";
                }
                else if (prot_has(pr, prot::w))
                {
                    type = section::rw_data;
                    sname = ".data";
                }
                else
                {
                    type = section::ro_data;
                    sname = ".rodata";
                }

                // module handle for reference: NOLOAD only if already loaded
                module_handle mh = get_module_handle(path.c_str());

                c->out = { sname, type, reinterpret_cast<void*>(seg_start),
                           static_cast<size_t>(seg_end - seg_start),
                           static_cast<size_t>(seg_end - seg_start),
                           pr, mh };

                c->found = true;
                return 1;
            }

            return 0;
        };

        ::dl_iterate_phdr(cb, &c);

        if (!c.found)
            return std::nullopt;

        return c.out;
    }
}

#endif // MEMLIB_IS_LINUX
