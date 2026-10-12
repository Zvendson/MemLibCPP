#include <memlib/c_api.h>

#include <memlib/address.hpp>
#include <memlib/memory.hpp>
#include <memlib/module.hpp>
#include <memlib/os.hpp>

#include <algorithm>
#include <cstring>
#include <new>
#include <string>
#include <vector>

struct memlib_module
{
    memlib::module value;
    explicit memlib_module(const char* name) : value(name) {}
    explicit memlib_module(const memlib::module& source) : value(source) {}
};

namespace
{
    uint32_t protection(memlib::prot value) { return static_cast<uint32_t>(value); }

    memlib::prot protection(uint32_t value) { return static_cast<memlib::prot>(value); }

    memlib_section_kind section_kind(memlib::section value)
    {
        const auto raw = static_cast<uint8_t>(value);
        return raw < static_cast<uint8_t>(memlib::section::max)
            ? static_cast<memlib_section_kind>(raw)
            : MEMLIB_SECTION_UNKNOWN;
    }

    template <size_t N>
    void copy_text(char (&destination)[N], const std::string& source)
    {
        const auto count = std::min(source.size(), N - 1);
        std::memcpy(destination, source.data(), count);
        destination[count] = '\0';
    }

    template <size_t N>
    void copy_text(char (&destination)[N], const std::filesystem::path& source)
    { copy_text(destination, source.string()); }

    void copy_region(const memlib::region_info& source, memlib_region_info& destination)
    {
        destination.start = source.start;
        destination.end = source.end;
        destination.protection = protection(source.protection);
    }

    void copy_section(const memlib::section_info& source, memlib_section_info& destination)
    {
        std::memset(&destination, 0, sizeof(destination));
        copy_text(destination.name, source.name);
        destination.type = section_kind(source.type);
        destination.start = source.start;
        destination.size = source.size;
        destination.size_padded = source.size_padded;
        destination.protection = protection(source.protection);
        destination.module = source.module;
    }

    void copy_module(const memlib::module_info& source, memlib_module_info& destination)
    {
        std::memset(&destination, 0, sizeof(destination));
        destination.base = source.base;
        destination.size = source.size;
        copy_text(destination.name, source.name);
        copy_text(destination.path, source.path);
    }

    memlib::scan_pattern to_cpp_pattern(const memlib_scan_pattern& source)
    {
        memlib::scan_pattern destination{};
        destination.length = std::min(source.length, sizeof(destination.bytes));
        std::memcpy(destination.bytes, source.bytes, destination.length);
        std::memcpy(destination.mask, source.mask, destination.length);
        return destination;
    }

    uintptr_t value(memlib::address address) { return address.value(); }
}

extern "C"
{
    int memlib_query(void* address, memlib_region_info* out)
    {
        if (!address || !out) return 0;
        const auto result = memlib::query(address);
        if (!result) return 0;
        copy_region(*result, *out);
        return 1;
    }

    int memlib_protect(void* address, size_t size, uint32_t protection_value, uint32_t* old_protection)
    {
        memlib::prot old{};
        const auto result = memlib::protect(address, size, protection(protection_value), old_protection ? &old : nullptr);
        if (old_protection) *old_protection = protection(old);
        return result ? 1 : 0;
    }

    void* memlib_alloc(size_t size, uint32_t protection_value)
    { return memlib::alloc(size, protection(protection_value)); }

    int memlib_free(void* address) { return memlib::free(address) ? 1 : 0; }

    void memlib_flush_icache(void* address, size_t size) { memlib::flush_icache(address, size); }
    int memlib_is_readable(void* address, size_t bytes) { return memlib::is_readable(address, bytes) ? 1 : 0; }
    int memlib_is_writable(void* address, size_t bytes) { return memlib::is_writable(address, bytes) ? 1 : 0; }
    int memlib_is_executable(void* address, size_t bytes) { return memlib::is_executable(address, bytes) ? 1 : 0; }
    int memlib_read(void* address, void* output, size_t size)
    {
        if (!address || !output || !memlib::is_readable(address, size)) return 0;
        std::memcpy(output, address, size);
        return 1;
    }
    int memlib_write(void* address, const void* input, size_t size)
    {
        if (!address || !input || !memlib::is_writable(address, size)) return 0;
        std::memcpy(address, input, size);
        return 1;
    }

    int memlib_parse_pattern(const char* text, memlib_scan_pattern* out)
    {
        if (!text || !out) return 0;
        memlib::scan_pattern pattern{};
        if (!memlib::parse_combo_pattern(text, pattern)) return 0;
        out->length = pattern.length;
        std::memcpy(out->bytes, pattern.bytes, sizeof(out->bytes));
        std::memcpy(out->mask, pattern.mask, sizeof(out->mask));
        return 1;
    }

    uintptr_t memlib_find(const memlib_scan_pattern* pattern, uintptr_t start, uintptr_t end, int32_t offset)
    { return pattern ? value(memlib::find(to_cpp_pattern(*pattern), start, end, offset)) : 0; }
    uintptr_t memlib_find_combo(const char* pattern, uintptr_t start, uintptr_t end, int32_t offset)
    { return pattern ? value(memlib::find(pattern, start, end, offset)) : 0; }
    uintptr_t memlib_find_xref(const memlib_scan_pattern* pattern, uintptr_t start, uintptr_t end, int32_t offset)
    { return pattern ? value(memlib::find_xref(to_cpp_pattern(*pattern), start, end, offset)) : 0; }
    uintptr_t memlib_find_combo_xref(const char* pattern, uintptr_t start, uintptr_t end, int32_t offset)
    { return pattern ? value(memlib::find_xref(pattern, start, end, offset)) : 0; }

    uintptr_t memlib_find_xrefs(const char* const* patterns, size_t count, uintptr_t start, uintptr_t end, int32_t offset)
    {
        if (!patterns || count == 0) return 0;
        return value(memlib::find_xrefs(std::span<const char* const>(patterns, count), start, end, offset));
    }

    uintptr_t memlib_find_xrefs_secure(const char* const* patterns, size_t count, uintptr_t start, uintptr_t end, int32_t offset)
    {
        if (!patterns || count == 0) return 0;
        return value(memlib::find_xrefs_secure(std::span<const char* const>(patterns, count), start, end, offset));
    }

    size_t memlib_find_all(const memlib_scan_pattern* pattern, uintptr_t start, uintptr_t end, uintptr_t* output, size_t capacity)
    {
        if (!pattern || (capacity != 0 && !output)) return 0;
        const auto values = memlib::find_all(to_cpp_pattern(*pattern), start, end);
        const auto count = std::min(values.size(), capacity);
        for (size_t i = 0; i < count; ++i) output[i] = values[i].value();
        return values.size();
    }
    size_t memlib_find_all_combo(const char* pattern, uintptr_t start, uintptr_t end, uintptr_t* output, size_t capacity)
    {
        if (!pattern || (capacity != 0 && !output)) return 0;
        const auto values = memlib::find_all(pattern, start, end);
        const auto count = std::min(values.size(), capacity);
        for (size_t i = 0; i < count; ++i) output[i] = values[i].value();
        return values.size();
    }

    int memlib_address_valid(uintptr_t address) { return memlib::address(address).is_valid() ? 1 : 0; }
    int memlib_address_readable(uintptr_t address, size_t bytes) { return memlib::address(address).is_readable(bytes) ? 1 : 0; }
    int memlib_address_writable(uintptr_t address, size_t bytes) { return memlib::address(address).is_writable(bytes) ? 1 : 0; }
    int memlib_address_executable(uintptr_t address, size_t bytes) { return memlib::address(address).is_executable(bytes) ? 1 : 0; }
    int memlib_address_read(uintptr_t address, void* output, size_t size) { return memlib_read(reinterpret_cast<void*>(address), output, size); }
    int memlib_address_write(uintptr_t address, const void* input, size_t size) { return memlib_write(reinterpret_cast<void*>(address), input, size); }
    uintptr_t memlib_address_dereference_pointer(uintptr_t address) { return value(memlib::address(address).dereference_pointer()); }
    uintptr_t memlib_address_dereference_call(uintptr_t address) { return value(memlib::address(address).dereference_call()); }
    uintptr_t memlib_address_resolve_relative(uintptr_t address, int64_t displacement, size_t instruction_length)
    { return value(memlib::address(address).resolve_relative(displacement, instruction_length)); }

    int memlib_address_region(uintptr_t address, memlib_region_info* out)
    {
        return memlib_query(reinterpret_cast<void*>(address), out);
    }

    int memlib_address_section(uintptr_t address, memlib_section_info* out)
    {
        if (!out) return 0;
        const auto result = memlib::address(address).section();
        if (!result) return 0;
        copy_section(*result, *out);
        return 1;
    }

    int memlib_address_module(uintptr_t address, memlib_module_info* out)
    {
        if (!out) return 0;
        const auto result = memlib::address(address).module();
        if (!result) return 0;
        copy_module(*result, *out);
        return 1;
    }

    memlib_module* memlib_module_open(const char* name)
    { return new (std::nothrow) memlib_module(name); }

    memlib_module* memlib_module_from_address(uintptr_t address)
    {
        const auto result = memlib::address(address).module();
        if (!result) return nullptr;
        return new (std::nothrow) memlib_module(result->name.c_str());
    }

    void memlib_module_close(memlib_module* module) { delete module; }
    int memlib_module_valid(const memlib_module* module) { return module && module->value.is_valid() ? 1 : 0; }
    uintptr_t memlib_module_base(const memlib_module* module) { return module ? module->value.get_base() : 0; }
    size_t memlib_module_size(const memlib_module* module) { return module ? module->value.get_size() : 0; }

    int memlib_module_get_info(const memlib_module* module, memlib_module_info* out)
    {
        if (!module || !out || !module->value.is_valid()) return 0;
        memlib_module_info value_out{};
        value_out.base = module->value.get_base();
        value_out.size = module->value.get_size();
        copy_text(value_out.name, module->value.get_name());
        copy_text(value_out.path, module->value.get_path());
        *out = value_out;
        return 1;
    }

    int memlib_module_section(const memlib_module* module, int section_value, memlib_section_info* out)
    {
        if (!module || !out || section_value < 0 || section_value >= static_cast<int>(memlib::section::max)) return 0;
        const auto result = module->value.get_section(static_cast<memlib::section>(section_value));
        if (!result) return 0;
        copy_section(result, *out);
        return 1;
    }

    int memlib_module_contains(const memlib_module* module, uintptr_t address, int section_value)
    {
        if (!module) return 0;
        const auto target = memlib::address(address);
        if (section_value < 0) return module->value.is_valid_address(target) ? 1 : 0;
        if (section_value >= static_cast<int>(memlib::section::max)) return 0;
        return module->value.is_valid_address(target, static_cast<memlib::section>(section_value)) ? 1 : 0;
    }

    uintptr_t memlib_module_find(const memlib_module* module, const char* pattern, int section_value, int32_t offset)
    {
        if (!module || !pattern || section_value < 0 || section_value >= static_cast<int>(memlib::section::max)) return 0;
        return value(module->value.find(pattern, static_cast<memlib::section>(section_value), offset));
    }

    size_t memlib_module_find_all(const memlib_module* module, const char* pattern, int section_value, uintptr_t* output, size_t capacity)
    {
        if (!module || !pattern || (capacity != 0 && !output) || section_value < 0 || section_value >= static_cast<int>(memlib::section::max)) return 0;
        const auto values = module->value.find_all(pattern, static_cast<memlib::section>(section_value));
        const auto count = std::min(values.size(), capacity);
        for (size_t i = 0; i < count; ++i) output[i] = values[i].value();
        return values.size();
    }

    uint32_t memlib_get_pid(void) { return memlib::get_pid(); }
}
