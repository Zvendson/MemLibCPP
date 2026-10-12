#include "../hook_internal.hpp"
#include <memlib/memory.hpp>
#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <linux/futex.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

namespace memlib::detail
{
    uint8_t* allocate_trampoline(uintptr_t target, size_t& size) noexcept
    {
        size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
        if constexpr (sizeof(uintptr_t) == 4)
        {
            auto* result = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            return result == MAP_FAILED ? nullptr : static_cast<uint8_t*>(result);
        }
        else
        {
            constexpr uintptr_t step = 0x10000;
            const auto base = target & ~(step - 1);
            for (uintptr_t distance = step; distance < 0x40000000; distance += step)
            {
                const uintptr_t candidates[] = {base > distance ? base - distance : 0, base + distance};
                for (const auto candidate : candidates)
                {
                    if (candidate < size) continue;
                    // A hint cannot replace existing mappings, even on old kernels.
                    auto* result = mmap(reinterpret_cast<void*>(candidate), size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                    if (result == MAP_FAILED) continue;
                    const auto actual = reinterpret_cast<uintptr_t>(result);
                    const auto delta = actual > target ? actual - target : target - actual;
                    if (delta < 0x40000000) return static_cast<uint8_t*>(result);
                    munmap(result, size);
                }
            }
            return nullptr;
        }
    }
    void release_trampoline(uint8_t* address, size_t size) noexcept
    { if (address) munmap(address, size); }
    bool seal_trampoline(uint8_t* address, size_t size) noexcept
    {
        __builtin___clear_cache(reinterpret_cast<char*>(address), reinterpret_cast<char*>(address + size));
        return mprotect(address, size, PROT_READ | PROT_EXEC) == 0;
    }

    std::expected<void, hook_error> recover_protections(std::array<pending_protection, 2>& pending) noexcept
    {
        for (auto& page : pending)
        {
            if (!page.address) continue;
            if (syscall(SYS_mprotect, page.address, page.size, page.protection))
                return std::unexpected(hook_error{hook_error::ProtectionRestoreFailed, reinterpret_cast<uintptr_t>(page.address)});
            page = {};
        }
        return {};
    }

    namespace
    {
        constexpr size_t max_threads = 2048;
        struct thread_slot
        {
            std::atomic<int> tid{};
            // 1: sent, 2: parked, 3: released, 4: handler completed/dead.
            std::atomic<int> phase{};
            std::atomic<ucontext_t*> context{};
        };
        static_assert(std::atomic<int>::is_always_lock_free);
        static_assert(sizeof(std::atomic<int>) == sizeof(int));
        static_assert(std::atomic<ucontext_t*>::is_always_lock_free);
        // Static lifetime: delayed/blocked signals must never reference a stack
        // transaction or a trampoline that was freed on an error path.
        std::array<thread_slot, max_threads> slots;
        std::atomic<int> round{};
        std::atomic<int> active_handlers{};
        int signal_number{};
        int next_round{};

        void park_thread(int, siginfo_t* info, void* raw_context)
        {
            const int saved_errno = errno;
            active_handlers.fetch_add(1);
            const int generation = round.load();
            if (generation && info && info->si_code == SI_QUEUE && info->si_pid == getpid() &&
                info->si_value.sival_int == generation)
            {
                const int tid = static_cast<int>(syscall(SYS_gettid));
                for (auto& slot : slots)
                {
                    if (slot.tid.load() != tid) continue;
                    slot.context.store(static_cast<ucontext_t*>(raw_context));
                    int expected = 1;
                    if (slot.phase.compare_exchange_strong(expected, 2))
                    {
                        while (slot.phase.load() == 2)
                            syscall(SYS_futex, reinterpret_cast<int*>(&slot.phase), FUTEX_WAIT_PRIVATE, 2, nullptr, nullptr, 0);
                        slot.context.store(nullptr);
                        slot.phase.store(4);
                    }
                    break;
                }
            }
            active_handlers.fetch_sub(1);
            errno = saved_errno;
        }
        bool install_handler()
        {
            if (signal_number)
            {
                struct sigaction current{};
                return sigaction(signal_number, nullptr, &current) == 0 &&
                    (current.sa_flags & SA_SIGINFO) && current.sa_sigaction == park_thread;
            }
            const int candidate = SIGRTMIN + 6;
            if (candidate > SIGRTMAX) return false;
            struct sigaction previous{};
            if (sigaction(candidate, nullptr, &previous) || previous.sa_handler != SIG_DFL) return false;
            struct sigaction action{};
            action.sa_sigaction = park_thread;
            action.sa_flags = SA_SIGINFO | SA_RESTART;
            sigfillset(&action.sa_mask);
            if (sigaction(candidate, &action, nullptr)) return false;
            signal_number = candidate;
            return true;
        }
        uintptr_t get_ip(const ucontext_t& context)
        {
#if defined(__x86_64__)
            return static_cast<uintptr_t>(context.uc_mcontext.gregs[REG_RIP]);
#else
            return static_cast<uintptr_t>(context.uc_mcontext.gregs[REG_EIP]);
#endif
        }
        void set_ip(ucontext_t& context, uintptr_t ip)
        {
#if defined(__x86_64__)
            context.uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(ip);
#else
            context.uc_mcontext.gregs[REG_EIP] = static_cast<greg_t>(ip);
#endif
        }
        uint64_t monotonic_ns()
        {
            timespec now{};
            syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now);
            return uint64_t(now.tv_sec) * 1000000000 + static_cast<uint64_t>(now.tv_nsec);
        }
        void pause_poll()
        {
            const timespec delay{0, 1000000};
            syscall(SYS_nanosleep, &delay, nullptr);
        }
        struct linux_dirent64
        {
            uint64_t ino;
            int64_t offset;
            unsigned short record_size;
            unsigned char type;
            char name[1];
        };
        struct frozen_threads
        {
            size_t count{};
            int generation{};
            ~frozen_threads()
            {
                // Close admission before releasing any accepted handler. A late
                // signal sees round==0 (or the next generation) and is ignored.
                round.store(0);
                for (size_t i = 0; i < count; ++i)
                {
                    slots[i].phase.exchange(3);
                    syscall(SYS_futex, reinterpret_cast<int*>(&slots[i].phase), FUTEX_WAKE_PRIVATE, INT_MAX, nullptr, nullptr, 0);
                }
                while (active_handlers.load()) pause_poll();
            }
            bool scan(int self, size_t& added)
            {
                const int fd = static_cast<int>(syscall(SYS_openat, AT_FDCWD, "/proc/self/task", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0));
                if (fd < 0) return false;
                alignas(uint64_t) std::array<char, 8192> buffer{};
                bool success = true;
                for (;;)
                {
                    const auto bytes = syscall(SYS_getdents64, fd, buffer.data(), buffer.size());
                    if (!bytes) break;
                    if (bytes < 0) { success = false; break; }
                    for (long offset = 0; offset < bytes;)
                    {
                        const auto* entry = reinterpret_cast<const linux_dirent64*>(buffer.data() + offset);
                        if (entry->record_size < 20 || offset + entry->record_size > bytes)
                        { success = false; break; }
                        int tid = 0;
                        for (size_t j = 0; j < static_cast<size_t>(entry->record_size) - 19 && entry->name[j] >= '0' && entry->name[j] <= '9'; ++j)
                            tid = tid * 10 + entry->name[j] - '0';
                        offset += entry->record_size;
                        if (!tid || tid == self) continue;
                        bool found = false;
                        for (size_t i = 0; i < count; ++i) found |= slots[i].tid.load() == tid;
                        if (found) continue;
                        if (count == slots.size()) { success = false; break; }
                        auto& slot = slots[count++];
                        slot.context.store(nullptr);
                        slot.phase.store(1);
                        slot.tid.store(tid);
                        siginfo_t info{};
                        info.si_signo = signal_number;
                        info.si_code = SI_QUEUE;
                        info.si_pid = getpid();
                        info.si_uid = getuid();
                        info.si_value.sival_int = generation;
                        if (syscall(SYS_rt_tgsigqueueinfo, getpid(), tid, signal_number, &info))
                        {
                            if (errno == ESRCH) slot.phase.store(4);
                            else { success = false; break; }
                        }
                        ++added;
                    }
                    if (!success) break;
                }
                syscall(SYS_close, fd);
                return success;
            }
            bool freeze()
            {
                if (!install_handler()) return false;
                if (next_round == INT_MAX) return false; // Never reuse signal tokens.
                generation = ++next_round;
                // Resolve errno's TLS accessor before any signal handler needs
                // it. No lazy PLT binding may occur with peer threads parked.
                errno = 0;
                // Old queued tokens cannot match the new generation.
                for (auto& slot : slots) slot.tid.store(0);
                round.store(generation);
                const int self = static_cast<int>(syscall(SYS_gettid));
                const auto deadline = monotonic_ns() + 250000000;
                for (size_t pass = 0; pass < 4; ++pass)
                {
                    size_t added = 0;
                    if (!scan(self, added)) return false;
                    for (;;)
                    {
                        bool parked = true;
                        for (size_t i = 0; i < count; ++i)
                        {
                            auto& slot = slots[i];
                            if (slot.phase.load() != 1) continue;
                            if (syscall(SYS_tgkill, getpid(), slot.tid.load(), 0) && errno == ESRCH)
                                slot.phase.store(4);
                            else parked = false;
                        }
                        if (parked) break;
                        if (monotonic_ns() >= deadline) return false;
                        pause_poll();
                    }
                    if (!added) return true;
                }
                return false;
            }
        };
        struct page_record { void* address; size_t size; int protection; };
    }

    std::expected<void, hook_error> patch_code(const patch_view& patch)
    {
        using enum hook_error::Type;
        const auto address = reinterpret_cast<uintptr_t>(patch.target);
        const auto failure = [address](hook_error::Type type) { return std::unexpected(hook_error{type, address}); };
        const auto page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
        std::array<page_record, 2> pages{};
        size_t page_count = 0;
        for (auto cursor = address & ~(uintptr_t(page_size) - 1); cursor < address + patch.size; cursor += page_size)
        {
            auto region = memlib::query(reinterpret_cast<void*>(cursor));
            if (!region || page_count == pages.size() || !prot_has(region->protection, prot::r) || !prot_has(region->protection, prot::x))
                return failure(ProtectionFailed);
            int native = PROT_READ | PROT_EXEC;
            if (prot_has(region->protection, prot::w)) native |= PROT_WRITE;
            pages[page_count++] = {reinterpret_cast<void*>(cursor), page_size, native};
        }
        // query() reads /proc using libc. Finish that work before parking peers.
        frozen_threads threads;
        if (!threads.freeze()) return failure(ThreadFreezeFailed);
        std::array<uintptr_t, max_threads> translated{};
        for (size_t i = 0; i < threads.count; ++i)
        {
            if (slots[i].phase.load() != 2) continue;
            const auto context = slots[i].context.load();
            if (!context) return failure(ThreadContextFailed);
            const auto result = redirect_ip(get_ip(*context), patch);
            if (!result) return std::unexpected(result.error());
            translated[i] = *result;
        }
        if (!bytes_equal(patch.target, patch.expected, patch.size)) return failure(TargetChanged);
        size_t writable = 0;
        for (; writable < page_count; ++writable)
            if (syscall(SYS_mprotect, pages[writable].address, pages[writable].size, PROT_READ | PROT_WRITE | PROT_EXEC)) break;
        if (writable != page_count)
        {
            for (size_t i = 0; i < writable; ++i)
                if (syscall(SYS_mprotect, pages[i].address, pages[i].size, pages[i].protection))
                    patch.pending[i] = {pages[i].address, pages[i].size, static_cast<uint32_t>(pages[i].protection)};
            return failure(ProtectionFailed);
        }
        write_bytes(patch.target, patch.replacement, patch.size);
        __builtin___clear_cache(reinterpret_cast<char*>(patch.target), reinterpret_cast<char*>(patch.target + patch.size));
        for (size_t i = 0; i < threads.count; ++i)
            if (slots[i].phase.load() == 2) set_ip(*slots[i].context.load(), translated[i]);
        bool restored = true;
        for (size_t i = 0; i < page_count; ++i)
        {
            if (syscall(SYS_mprotect, pages[i].address, pages[i].size, pages[i].protection))
            {
                restored = false;
                patch.pending[i] = {pages[i].address, pages[i].size, static_cast<uint32_t>(pages[i].protection)};
            }
        }
        if (!restored) return std::unexpected(hook_error{ProtectionRestoreFailed, address, true});
        return {};
    }
}
