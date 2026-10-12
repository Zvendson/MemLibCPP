#pragma once

#include "hook.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum memlib_section_kind {
    MEMLIB_SECTION_CODE, MEMLIB_SECTION_RO_DATA, MEMLIB_SECTION_RW_DATA,
    MEMLIB_SECTION_ZERO_DATA, MEMLIB_SECTION_IMPORTS, MEMLIB_SECTION_EXPORTS,
    MEMLIB_SECTION_RELOCATIONS, MEMLIB_SECTION_TLS, MEMLIB_SECTION_DEBUG,
    MEMLIB_SECTION_RESOURCES, MEMLIB_SECTION_UNKNOWN = 255
} memlib_section_kind;

typedef struct memlib_section_info {
    char name[64];
    memlib_section_kind type;
    uintptr_t start;
    size_t size;
    size_t size_padded;
    uint32_t protection;
    void* module;
} memlib_section_info;

typedef struct memlib_region_info {
    uintptr_t start;
    uintptr_t end;
    uint32_t protection;
} memlib_region_info;

typedef struct memlib_module_info {
    uintptr_t base;
    size_t size;
    char name[256];
    char path[4096];
} memlib_module_info;

typedef struct memlib_scan_pattern {
    size_t length;
    uint8_t bytes[512];
    char mask[512];
} memlib_scan_pattern;

typedef struct memlib_module memlib_module;

MEMLIB_API int memlib_query(void* address, memlib_region_info* out);
MEMLIB_API int memlib_protect(void* address, size_t size, uint32_t protection, uint32_t* old_protection);
MEMLIB_API void* memlib_alloc(size_t size, uint32_t protection);
MEMLIB_API int memlib_free(void* address);
MEMLIB_API void memlib_flush_icache(void* address, size_t size);
MEMLIB_API int memlib_is_readable(void* address, size_t bytes);
MEMLIB_API int memlib_is_writable(void* address, size_t bytes);
MEMLIB_API int memlib_is_executable(void* address, size_t bytes);
MEMLIB_API int memlib_read(void* address, void* output, size_t size);
MEMLIB_API int memlib_write(void* address, const void* input, size_t size);

MEMLIB_API int memlib_parse_pattern(const char* text, memlib_scan_pattern* out);
MEMLIB_API uintptr_t memlib_find(const memlib_scan_pattern* pattern, uintptr_t start, uintptr_t end, int32_t offset);
MEMLIB_API uintptr_t memlib_find_combo(const char* pattern, uintptr_t start, uintptr_t end, int32_t offset);
MEMLIB_API uintptr_t memlib_find_xref(const memlib_scan_pattern* pattern, uintptr_t start, uintptr_t end, int32_t offset);
MEMLIB_API uintptr_t memlib_find_combo_xref(const char* pattern, uintptr_t start, uintptr_t end, int32_t offset);
MEMLIB_API uintptr_t memlib_find_xrefs(const char* const* patterns, size_t count, uintptr_t start, uintptr_t end, int32_t offset);
MEMLIB_API uintptr_t memlib_find_xrefs_secure(const char* const* patterns, size_t count, uintptr_t start, uintptr_t end, int32_t offset);
MEMLIB_API size_t memlib_find_all(const memlib_scan_pattern* pattern, uintptr_t start, uintptr_t end, uintptr_t* output, size_t capacity);
MEMLIB_API size_t memlib_find_all_combo(const char* pattern, uintptr_t start, uintptr_t end, uintptr_t* output, size_t capacity);

MEMLIB_API int memlib_address_valid(uintptr_t address);
MEMLIB_API int memlib_address_readable(uintptr_t address, size_t bytes);
MEMLIB_API int memlib_address_writable(uintptr_t address, size_t bytes);
MEMLIB_API int memlib_address_executable(uintptr_t address, size_t bytes);
MEMLIB_API int memlib_address_read(uintptr_t address, void* output, size_t size);
MEMLIB_API int memlib_address_write(uintptr_t address, const void* input, size_t size);
MEMLIB_API uintptr_t memlib_address_dereference_pointer(uintptr_t address);
MEMLIB_API uintptr_t memlib_address_dereference_call(uintptr_t address);
MEMLIB_API uintptr_t memlib_address_resolve_relative(uintptr_t address, int64_t displacement, size_t instruction_length);
MEMLIB_API int memlib_address_region(uintptr_t address, memlib_region_info* out);
MEMLIB_API int memlib_address_section(uintptr_t address, memlib_section_info* out);
MEMLIB_API int memlib_address_module(uintptr_t address, memlib_module_info* out);

MEMLIB_API memlib_module* memlib_module_open(const char* name);
MEMLIB_API memlib_module* memlib_module_from_address(uintptr_t address);
MEMLIB_API void memlib_module_close(memlib_module* module);
MEMLIB_API int memlib_module_valid(const memlib_module* module);
MEMLIB_API uintptr_t memlib_module_base(const memlib_module* module);
MEMLIB_API size_t memlib_module_size(const memlib_module* module);
MEMLIB_API int memlib_module_get_info(const memlib_module* module, memlib_module_info* out);
MEMLIB_API int memlib_module_section(const memlib_module* module, int section, memlib_section_info* out);
MEMLIB_API int memlib_module_contains(const memlib_module* module, uintptr_t address, int section);
MEMLIB_API uintptr_t memlib_module_find(const memlib_module* module, const char* pattern, int section, int32_t offset);
MEMLIB_API size_t memlib_module_find_all(const memlib_module* module, const char* pattern, int section, uintptr_t* output, size_t capacity);

MEMLIB_API uint32_t memlib_get_pid(void);

#ifdef __cplusplus
}
#endif
