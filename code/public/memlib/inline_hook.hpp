#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <utility>
#include <vector>

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

namespace memlib
{
    struct hook_error
    {
        enum Type
        {
            InvalidTarget, InvalidDestination, DecodeFailed, UnsupportedInstruction,
            AllocationFailed, RelocationOutOfRange, InvalidBranchTarget,
            AlreadyHooked, ProtectionFailed, ThreadFreezeFailed, ThreadContextFailed,
            TargetChanged, InvalidHook, ProtectionRestoreFailed
        } type;
        uintptr_t address{};
        // The requested bytes were installed, but final protection restoration
        // failed. enabled() still reflects the actual code state on this error.
        bool patch_applied{};
    };

    // Move-only ownership. Lifecycle changes are serialized across all hooks.
    // The target and destination must remain mapped until reset succeeds.
    class inl_hook
    {
    public:
        enum Flags : uint32_t { Default = 0, StartDisabled = 1 };
        struct allocation
        {
            uint8_t* data{};
            size_t length{};
            [[nodiscard]] uint8_t* address() const noexcept { return data; }
            [[nodiscard]] size_t size() const noexcept { return length; }
            explicit operator bool() const noexcept { return data != nullptr; }
        };
        using Error = hook_error;
        struct state;

        inl_hook() noexcept;
        ~inl_hook();
        inl_hook(inl_hook&& other) noexcept;
        inl_hook& operator=(inl_hook&& other) noexcept;
        inl_hook(const inl_hook&) = delete;
        inl_hook& operator=(const inl_hook&) = delete;

        [[nodiscard]] static std::expected<inl_hook, Error> create(
            void* target, void* destination, Flags flags = Default);
        [[nodiscard]] std::expected<void, Error> enable();
        [[nodiscard]] std::expected<void, Error> disable();
        // On failure ownership and the trampoline are preserved; inspect the error.
        [[nodiscard]] std::expected<void, Error> reset();
        [[nodiscard]] bool enabled() const noexcept;
        explicit operator bool() const noexcept;
        [[nodiscard]] uint8_t* target() const noexcept;
        [[nodiscard]] uintptr_t target_address() const noexcept;
        [[nodiscard]] uint8_t* destination() const noexcept;
        [[nodiscard]] uintptr_t destination_address() const noexcept;
        [[nodiscard]] const allocation& trampoline() const noexcept;
        [[nodiscard]] const std::vector<uint8_t>& original_bytes() const noexcept;

        template<class T> [[nodiscard]] T original() const noexcept
        {
            return reinterpret_cast<T>(trampoline().address());
        }

        // Specify argument types explicitly when the ABI requires references or
        // narrow types. These helpers do not synchronize with reset/destruction.
#define MEMLIB_HOOK_CALL(name, convention) \
        template<class Ret = void, class... Args> Ret name(Args... args) const \
        { return original<Ret (convention *)(Args...)>()(std::forward<Args>(args)...); }
        MEMLIB_HOOK_CALL(call, MEMLIB_CDECL)
        MEMLIB_HOOK_CALL(ccall, MEMLIB_CDECL)
        MEMLIB_HOOK_CALL(stdcall, MEMLIB_STDCALL)
        MEMLIB_HOOK_CALL(fastcall, MEMLIB_FASTCALL)
        MEMLIB_HOOK_CALL(unsafe_call, MEMLIB_CDECL)
        MEMLIB_HOOK_CALL(unsafe_ccall, MEMLIB_CDECL)
        MEMLIB_HOOK_CALL(unsafe_stdcall, MEMLIB_STDCALL)
        MEMLIB_HOOK_CALL(unsafe_fastcall, MEMLIB_FASTCALL)
#undef MEMLIB_HOOK_CALL
#if defined(__GNUC__) && !defined(__clang__) && defined(__i386__)
        // GCC warns while parsing this dependent free-function pointer, even
        // though the first instantiated argument supplies the this register.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattributes"
#endif
        template<class Ret = void, class This, class... Args> Ret thiscall(This self, Args... args) const
        {
            using target_function = Ret (MEMLIB_THISCALL *)(This, Args...);
            return original<target_function>()(self, std::forward<Args>(args)...);
        }
        template<class Ret = void, class This, class... Args> Ret unsafe_thiscall(This self, Args... args) const
        { return thiscall<Ret, This, Args...>(self, std::forward<Args>(args)...); }
#if defined(__GNUC__) && !defined(__clang__) && defined(__i386__)
#pragma GCC diagnostic pop
#endif

    private:
        std::unique_ptr<state> m_state;
    };
}
