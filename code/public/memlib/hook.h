#pragma once
#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER) && defined(_M_IX86)
#define MEMLIB_CDECL __cdecl
#define MEMLIB_STDCALL __stdcall
#define MEMLIB_THISCALL __thiscall
#define MEMLIB_FASTCALL __fastcall
#elif defined(__i386__)
#define MEMLIB_CDECL __attribute__((cdecl))
#define MEMLIB_STDCALL __attribute__((stdcall))
#define MEMLIB_THISCALL __attribute__((thiscall))
#define MEMLIB_FASTCALL __attribute__((fastcall))
#else
#define MEMLIB_CDECL
#define MEMLIB_STDCALL
#define MEMLIB_THISCALL
#define MEMLIB_FASTCALL
#endif

#ifdef __cplusplus
extern "C" {
#endif
typedef enum memlib_hook_status
{
    MEMLIB_HOOK_OK = 0, MEMLIB_HOOK_INVALID_TARGET, MEMLIB_HOOK_INVALID_DESTINATION,
    MEMLIB_HOOK_DECODE_FAILED, MEMLIB_HOOK_UNSUPPORTED_INSTRUCTION, MEMLIB_HOOK_ALLOCATION_FAILED,
    MEMLIB_HOOK_RELOCATION_OUT_OF_RANGE, MEMLIB_HOOK_INVALID_BRANCH_TARGET, MEMLIB_HOOK_ALREADY_HOOKED,
    MEMLIB_HOOK_PROTECTION_FAILED, MEMLIB_HOOK_THREAD_FREEZE_FAILED, MEMLIB_HOOK_THREAD_CONTEXT_FAILED,
    MEMLIB_HOOK_TARGET_CHANGED, MEMLIB_HOOK_INVALID_HOOK, MEMLIB_HOOK_PROTECTION_RESTORE_FAILED,
    MEMLIB_HOOK_UNSUPPORTED
} memlib_hook_status;
enum { MEMLIB_HOOK_START_DISABLED = 1u };
typedef struct memlib_inline_hook memlib_inline_hook;
typedef struct memlib_mid_hook memlib_mid_hook;
typedef struct memlib_hook_allocation { void* address; size_t size; } memlib_hook_allocation;

memlib_hook_status memlib_inline_hook_create(void*, void*, uint32_t, memlib_inline_hook**);
memlib_hook_status memlib_inline_hook_enable(memlib_inline_hook*);
memlib_hook_status memlib_inline_hook_disable(memlib_inline_hook*);
memlib_hook_status memlib_inline_hook_reset(memlib_inline_hook*);
int memlib_inline_hook_enabled(const memlib_inline_hook*);
void* memlib_inline_hook_target(const memlib_inline_hook*);
void* memlib_inline_hook_destination(const memlib_inline_hook*);
memlib_hook_status memlib_inline_hook_trampoline(const memlib_inline_hook*, memlib_hook_allocation*);

memlib_hook_status memlib_mid_hook_create(void* address, void* destination, uint32_t flags, memlib_mid_hook** out_hook);
memlib_hook_status memlib_mid_hook_enable(memlib_mid_hook*);
memlib_hook_status memlib_mid_hook_disable(memlib_mid_hook*);
memlib_hook_status memlib_mid_hook_reset(memlib_mid_hook*);
int memlib_mid_hook_enabled(const memlib_mid_hook*);
#ifdef __cplusplus
}
#endif
