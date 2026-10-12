#include "../hook_internal.hpp"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <memory>

namespace memlib::detail
{
    uint8_t* allocate_trampoline(uintptr_t target, size_t& size) noexcept
    {
        SYSTEM_INFO info;
        GetSystemInfo(&info);
        size = info.dwPageSize;
        if constexpr (sizeof(uintptr_t) == 4)
        {
            return static_cast<uint8_t*>(VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        }
        else
        {
            const uintptr_t step = info.dwAllocationGranularity;
            const uintptr_t base = target & ~(step - 1);
            for (uintptr_t distance = step; distance < 0x40000000; distance += step)
            {
                const uintptr_t candidates[] = {base >= distance ? base - distance : 0, base + distance};
                for (const auto candidate : candidates)
                {
                    if (candidate < reinterpret_cast<uintptr_t>(info.lpMinimumApplicationAddress) ||
                        candidate > reinterpret_cast<uintptr_t>(info.lpMaximumApplicationAddress) - size) continue;
                    MEMORY_BASIC_INFORMATION region;
                    if (!VirtualQuery(reinterpret_cast<void*>(candidate), &region, sizeof(region)) || region.State != MEM_FREE) continue;
                    if (auto* result = VirtualAlloc(reinterpret_cast<void*>(candidate), size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))
                        return static_cast<uint8_t*>(result);
                }
            }
            return nullptr;
        }
    }
    void release_trampoline(uint8_t* address, size_t) noexcept
    { if (address) VirtualFree(address, 0, MEM_RELEASE); }
    bool seal_trampoline(uint8_t* address, size_t size) noexcept
    {
        DWORD previous;
        return VirtualProtect(address, size, PAGE_EXECUTE_READ, &previous) &&
            FlushInstructionCache(GetCurrentProcess(), address, size);
    }

    std::expected<void, hook_error> recover_protections(std::array<pending_protection, 2>& pending) noexcept
    {
        for (auto& page : pending)
        {
            if (!page.address) continue;
            DWORD ignored;
            if (!VirtualProtect(page.address, page.size, page.protection, &ignored))
                return std::unexpected(hook_error{hook_error::ProtectionRestoreFailed, reinterpret_cast<uintptr_t>(page.address)});
            page = {};
        }
        return {};
    }

    namespace
    {
        using next_thread_fn = LONG (NTAPI*)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
        constexpr size_t max_threads = 2048;
        struct thread_record
        {
            HANDLE handle{};
            DWORD id{};
            CONTEXT context{};
            uintptr_t original_ip{};
            bool changed{};
        };
        uintptr_t get_ip(const CONTEXT& context)
        {
#if defined(_M_X64) || defined(__x86_64__)
            return context.Rip;
#else
            return context.Eip;
#endif
        }
        void set_ip(CONTEXT& context, uintptr_t ip)
        {
#if defined(_M_X64) || defined(__x86_64__)
            context.Rip = ip;
#else
            context.Eip = ip;
#endif
        }
        struct frozen_threads
        {
            std::unique_ptr<thread_record[]> records{new thread_record[max_threads]};
            size_t count{};
            ~frozen_threads()
            {
                for (size_t i = count; i > 0; --i)
                {
                    ResumeThread(records[i - 1].handle);
                    CloseHandle(records[i - 1].handle);
                }
            }
            bool freeze(next_thread_fn next)
            {
                const auto self = GetCurrentThreadId();
                for (size_t pass = 0; pass < 4; ++pass)
                {
                    size_t added = 0;
                    HANDLE cursor = nullptr;
                    for (;;)
                    {
                        HANDLE handle = nullptr;
                        const auto status = next(GetCurrentProcess(), cursor,
                            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION,
                            0, 0, &handle);
                        if (cursor) CloseHandle(cursor);
                        cursor = nullptr;
                        if (status == static_cast<LONG>(0x8000001AUL)) break;
                        if (status < 0 || !handle) return false;
                        cursor = handle;
                        const auto id = GetThreadId(handle);
                        if (!id) { CloseHandle(cursor); return false; }
                        if (id == self) continue;
                        bool found = false;
                        for (size_t i = 0; i < count; ++i) found |= records[i].id == id;
                        if (found) continue;
                        HANDLE owned = nullptr;
                        if (count == max_threads || !DuplicateHandle(GetCurrentProcess(), handle,
                            GetCurrentProcess(), &owned, 0, FALSE, DUPLICATE_SAME_ACCESS))
                        { CloseHandle(cursor); return false; }
                        if (SuspendThread(owned) == DWORD(-1))
                        { CloseHandle(owned); CloseHandle(cursor); return false; }
                        auto& record = records[count++];
                        record.handle = owned;
                        record.id = id;
                        record.context.ContextFlags = CONTEXT_CONTROL;
                        if (!GetThreadContext(owned, &record.context))
                        { CloseHandle(cursor); return false; }
                        record.original_ip = get_ip(record.context);
                        ++added;
                    }
                    if (!added) return true;
                }
                return false;
            }
            bool restore_contexts()
            {
                bool success = true;
                for (size_t i = 0; i < count; ++i)
                {
                    auto& record = records[i];
                    if (!record.changed) continue;
                    set_ip(record.context, record.original_ip);
                    success &= SetThreadContext(record.handle, &record.context) != 0;
                }
                return success;
            }
        };
        struct page_record { void* address; size_t size; DWORD protection; };
    }

    std::expected<void, hook_error> patch_code(const patch_view& patch)
    {
        using enum hook_error::Type;
        const auto address = reinterpret_cast<uintptr_t>(patch.target);
        const auto failure = [address](hook_error::Type type)
        { return std::unexpected(hook_error{type, address}); };
        auto next = reinterpret_cast<next_thread_fn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtGetNextThread"));
        if (!next) return failure(ThreadFreezeFailed);
        SYSTEM_INFO info;
        GetSystemInfo(&info);
        // A prologue is at most 19 bytes, and can span at most two pages.
        std::array<page_record, 2> pages{};
        size_t page_count = 0;
        const auto end = address + patch.size;
        for (auto cursor = address & ~(uintptr_t(info.dwPageSize) - 1); cursor < end; cursor += info.dwPageSize)
        {
            MEMORY_BASIC_INFORMATION region;
            if (page_count == pages.size() || !VirtualQuery(reinterpret_cast<void*>(cursor), &region, sizeof(region)) ||
                region.State != MEM_COMMIT || (region.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return failure(ProtectionFailed);
            pages[page_count++] = {reinterpret_cast<void*>(cursor), info.dwPageSize, region.Protect};
        }
        frozen_threads threads;
        if (!threads.freeze(next)) return failure(ThreadFreezeFailed);
        for (size_t i = 0; i < threads.count; ++i)
        {
            auto& record = threads.records[i];
            auto translated = redirect_ip(record.original_ip, patch);
            if (!translated) return std::unexpected(translated.error());
            set_ip(record.context, *translated);
        }
        if (!bytes_equal(patch.target, patch.expected, patch.size)) return failure(TargetChanged);
        size_t writable = 0;
        for (; writable < page_count; ++writable)
        {
            DWORD previous;
            if (!VirtualProtect(pages[writable].address, pages[writable].size, PAGE_EXECUTE_READWRITE, &previous)) break;
        }
        if (writable != page_count)
        {
            for (size_t i = 0; i < writable; ++i)
            {
                DWORD ignored;
                if (!VirtualProtect(pages[i].address, pages[i].size, pages[i].protection, &ignored))
                    patch.pending[i] = {pages[i].address, pages[i].size, pages[i].protection};
            }
            return failure(ProtectionFailed);
        }
        // Apply contexts before changing bytes; a failed context update leaves
        // the original program intact and previously changed contexts roll back.
        bool contexts_ok = true;
        for (size_t i = 0; i < threads.count; ++i)
        {
            auto& record = threads.records[i];
            if (get_ip(record.context) == record.original_ip) continue;
            if (!SetThreadContext(record.handle, &record.context)) { contexts_ok = false; break; }
            record.changed = true;
        }
        if (contexts_ok)
        {
            write_bytes(patch.target, patch.replacement, patch.size);
            if (!FlushInstructionCache(GetCurrentProcess(), patch.target, patch.size))
            {
                write_bytes(patch.target, patch.expected, patch.size);
                FlushInstructionCache(GetCurrentProcess(), patch.target, patch.size);
                contexts_ok = false;
            }
        }
        if (!contexts_ok)
        {
            // A failed rollback can leave a peer executing the relocated
            // original. Every enable attempt retains its trampoline mapping.
            (void)threads.restore_contexts();
        }
        bool restored = true;
        for (size_t i = 0; i < page_count; ++i)
        {
            DWORD ignored;
            if (!VirtualProtect(pages[i].address, pages[i].size, pages[i].protection, &ignored))
            {
                restored = false;
                patch.pending[i] = {pages[i].address, pages[i].size, pages[i].protection};
            }
        }
        // Code installation must be reported as installed even if the final
        // protection restoration failed. Retrying it must not discard ownership.
        if (contexts_ok && !restored) return std::unexpected(hook_error{ProtectionRestoreFailed, address, true});
        if (contexts_ok) return {};
        return failure(ThreadContextFailed);
    }
}
