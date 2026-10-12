#include <memlib/hook.h>
#include <memlib/memory.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace
{
    extern "C" int detour() { return 99; }

    bool check(bool value, const char* message)
    {
        if (!value) std::fprintf(stderr, "check failed: %s\n", message);
        return value;
    }
}

int main()
{
    auto* code = static_cast<std::uint8_t*>(memlib::alloc(64, memlib::prot::r | memlib::prot::w | memlib::prot::x));
    if (!check(code != nullptr, "allocation")) return 1;

#if INTPTR_MAX == INT64_MAX
    const std::uint8_t body[] = { 0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3 };
#else
    const std::uint8_t body[] = { 0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3 };
#endif
    std::memcpy(code, body, sizeof(body));
    memlib::flush_icache(code, sizeof(body));
    using function_type = int (*)();
    auto function = reinterpret_cast<function_type>(code);
    if (!check(function() == 7, "original call")) return 1;

    memlib_inline_hook* hook = nullptr;
    auto status = memlib_inline_hook_create(code, reinterpret_cast<void*>(&detour), MEMLIB_HOOK_START_DISABLED, &hook);
    if (!check(status == MEMLIB_HOOK_OK && hook != nullptr, "create")) return 1;
    if (!check(memlib_inline_hook_target(hook) == code, "target")) return 1;
    if (!check(!memlib_inline_hook_enabled(hook), "disabled state")) return 1;

    status = memlib_inline_hook_enable(hook);
    if (!check(status == MEMLIB_HOOK_OK && function() == 99, "enable")) return 1;
    status = memlib_inline_hook_disable(hook);
    if (!check(status == MEMLIB_HOOK_OK && function() == 7, "disable")) return 1;
    status = memlib_inline_hook_reset(hook);
    if (!check(status == MEMLIB_HOOK_OK && function() == 7, "reset")) return 1;

    memlib_mid_hook* mid = nullptr;
    status = memlib_mid_hook_create(code, reinterpret_cast<void*>(&detour), MEMLIB_HOOK_START_DISABLED, &mid);
    if (!check(status == MEMLIB_HOOK_OK && mid != nullptr, "mid create")) return 1;
    status = memlib_mid_hook_enable(mid);
    if (!check(status == MEMLIB_HOOK_OK && function() == 99, "mid enable")) return 1;
    status = memlib_mid_hook_reset(mid);
    if (!check(status == MEMLIB_HOOK_OK && function() == 7, "mid reset")) return 1;

    memlib::free(code);
    return 0;
}
