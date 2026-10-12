#pragma once

#include <memlib/hook.h>
#include <cstdint>
#include <vector>

namespace memlib
{
    enum class hook_status : uint32_t
    {
        ok = MEMLIB_HOOK_OK, invalid_target = MEMLIB_HOOK_INVALID_TARGET,
        invalid_destination = MEMLIB_HOOK_INVALID_DESTINATION, decode_failed = MEMLIB_HOOK_DECODE_FAILED,
        unsupported_instruction = MEMLIB_HOOK_UNSUPPORTED_INSTRUCTION, allocation_failed = MEMLIB_HOOK_ALLOCATION_FAILED,
        relocation_out_of_range = MEMLIB_HOOK_RELOCATION_OUT_OF_RANGE, invalid_branch_target = MEMLIB_HOOK_INVALID_BRANCH_TARGET,
        already_hooked = MEMLIB_HOOK_ALREADY_HOOKED, protection_failed = MEMLIB_HOOK_PROTECTION_FAILED,
        thread_freeze_failed = MEMLIB_HOOK_THREAD_FREEZE_FAILED, thread_context_failed = MEMLIB_HOOK_THREAD_CONTEXT_FAILED,
        target_changed = MEMLIB_HOOK_TARGET_CHANGED, invalid_hook = MEMLIB_HOOK_INVALID_HOOK,
        protection_restore_failed = MEMLIB_HOOK_PROTECTION_RESTORE_FAILED, unsupported = MEMLIB_HOOK_UNSUPPORTED
    };

    class inl_hook
    {
    public:
        enum Flags : uint32_t { Default = 0, StartDisabled = MEMLIB_HOOK_START_DISABLED };
        struct allocation { uint8_t* data{}; size_t length{}; uint8_t* address() const noexcept { return data; } size_t size() const noexcept { return length; } explicit operator bool() const noexcept { return data != nullptr; } };
        inl_hook() noexcept = default;
        ~inl_hook() { reset(); }
        inl_hook(inl_hook&& other) noexcept : m_handle(other.m_handle) { other.m_handle = nullptr; }
        inl_hook& operator=(inl_hook&& other) noexcept { if (this != &other && reset() == hook_status::ok) { m_handle = other.m_handle; other.m_handle = nullptr; } return *this; }
        inl_hook(const inl_hook&) = delete;
        inl_hook& operator=(const inl_hook&) = delete;
        static hook_status create(void* target, void* destination, Flags flags, inl_hook* out) noexcept { return static_cast<hook_status>(memlib_inline_hook_create(target, destination, static_cast<uint32_t>(flags), out ? &out->m_handle : nullptr)); }
        hook_status enable() noexcept { return static_cast<hook_status>(memlib_inline_hook_enable(m_handle)); }
        hook_status disable() noexcept { return static_cast<hook_status>(memlib_inline_hook_disable(m_handle)); }
        hook_status reset() noexcept { if (!m_handle) return hook_status::ok; const auto result = static_cast<hook_status>(memlib_inline_hook_reset(m_handle)); if (result == hook_status::ok) m_handle = nullptr; return result; }
        bool enabled() const noexcept { return memlib_inline_hook_enabled(m_handle) != 0; }
        explicit operator bool() const noexcept { return m_handle != nullptr; }
        uint8_t* target() const noexcept { return static_cast<uint8_t*>(memlib_inline_hook_target(m_handle)); }
        uintptr_t target_address() const noexcept { return reinterpret_cast<uintptr_t>(target()); }
        uint8_t* destination() const noexcept { return static_cast<uint8_t*>(memlib_inline_hook_destination(m_handle)); }
        uintptr_t destination_address() const noexcept { return reinterpret_cast<uintptr_t>(destination()); }
        allocation trampoline() const noexcept { memlib_hook_allocation value{}; memlib_inline_hook_trampoline(m_handle, &value); return {static_cast<uint8_t*>(value.address), value.size}; }
        const auto& original_bytes() const noexcept { static const std::vector<uint8_t> empty; return empty; }
        template<class T> T original() const noexcept { return reinterpret_cast<T>(trampoline().address()); }
#define MEMLIB_HOOK_CALL(name, convention) template<class Ret = void, class... Args> Ret name(Args... args) const { return original<Ret (convention *)(Args...)>()(static_cast<Args&&>(args)...); }
        MEMLIB_HOOK_CALL(call, MEMLIB_CDECL)
        MEMLIB_HOOK_CALL(ccall, MEMLIB_CDECL)
        MEMLIB_HOOK_CALL(stdcall, MEMLIB_STDCALL)
        MEMLIB_HOOK_CALL(fastcall, MEMLIB_FASTCALL)
        MEMLIB_HOOK_CALL(unsafe_call, MEMLIB_CDECL)
        MEMLIB_HOOK_CALL(unsafe_ccall, MEMLIB_CDECL)
        MEMLIB_HOOK_CALL(unsafe_stdcall, MEMLIB_STDCALL)
        MEMLIB_HOOK_CALL(unsafe_fastcall, MEMLIB_FASTCALL)
#undef MEMLIB_HOOK_CALL
        template<class Ret = void, class This, class... Args> Ret thiscall(This self, Args... args) const { using fn = Ret (MEMLIB_THISCALL *)(This, Args...); return original<fn>()(self, static_cast<Args&&>(args)...); }
        template<class Ret = void, class This, class... Args> Ret unsafe_thiscall(This self, Args... args) const { return thiscall<Ret, This, Args...>(self, static_cast<Args&&>(args)...); }
    private:
        memlib_inline_hook* m_handle{};
    };
}
