#include <memlib/hook.h>
#include <memlib/c_api.h>

static void verify_api(void)
{
    memlib_inline_hook* inline_hook = 0;
    memlib_mid_hook* mid_hook = 0;
    memlib_hook_allocation allocation = {0};
    memlib_hook_status (*create_inline)(void*, void*, uint32_t, memlib_inline_hook**) = memlib_inline_hook_create;
    memlib_hook_status (*create_mid)(void*, void*, uint32_t, memlib_mid_hook**) = memlib_mid_hook_create;
    memlib_module_info module_info = {0};
    memlib_scan_pattern pattern = {0};
    (void)inline_hook;
    (void)mid_hook;
    (void)allocation;
    (void)create_inline;
    (void)create_mid;
    (void)module_info;
    (void)pattern;
}

int main(void)
{
    verify_api();
    return MEMLIB_HOOK_OK;
}
