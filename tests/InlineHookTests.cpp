#include <memlib/hook.hpp>
#include <memlib/memory.hpp>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#if defined(_WIN32)
#include <Windows.h>
#else
#include <sys/mman.h>
#include <signal.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

#define CHECK(expression) do { if (!(expression)) throw std::runtime_error(std::string(#expression) + " at line " + std::to_string(__LINE__)); } while (false)

namespace
{
    using function = int (*)();
    int detour() { return 99; }
    struct code_buffer
    {
        uint8_t* data;
        size_t page_size;
        bool keep_mapping{};
        code_buffer()
        {
#if defined(_WIN32)
            SYSTEM_INFO info; GetSystemInfo(&info); page_size = info.dwPageSize;
            data = static_cast<uint8_t*>(VirtualAlloc(nullptr, page_size * 2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
#else
            page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
            data = static_cast<uint8_t*>(mmap(nullptr, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
            if (data == MAP_FAILED) data = nullptr;
#endif
            CHECK(data);
            std::memset(data, 0x90, page_size * 2);
            constant(0, 7);
            constant(32, 8);
        }
        ~code_buffer()
        {
            if (keep_mapping) return;
#if defined(_WIN32)
            VirtualFree(data, 0, MEM_RELEASE);
#else
            munmap(data, page_size * 2);
#endif
        }
        void constant(size_t offset, int value)
        { data[offset] = 0xB8; std::memcpy(data + offset + 1, &value, 4); data[offset + 5] = 0xC3; }
        void bytes(std::initializer_list<uint8_t> bytes) { std::memcpy(data, bytes.begin(), bytes.size()); }
        void relative(size_t offset, uint8_t opcode, size_t destination)
        { data[offset] = opcode; const auto delta = static_cast<int32_t>(destination - offset - 5); std::memcpy(data + offset + 1, &delta, 4); }
        void seal()
        { memlib::flush_icache(data, page_size * 2); CHECK(memlib::protect(data, page_size * 2, memlib::prot::r | memlib::prot::x)); }
        function fn(size_t offset = 0) { return reinterpret_cast<function>(data + offset); }
        auto create(size_t offset = 0, memlib::inl_hook::Flags flags = memlib::inl_hook::StartDisabled)
        { return memlib::inl_hook::create(data + offset, reinterpret_cast<void*>(&detour), flags); }
    };

    void check_relocation(code_buffer& buffer, int expected)
    {
        buffer.seal();
        CHECK(buffer.fn()() == expected);
        auto hook = buffer.create(); CHECK(hook);
        CHECK(hook->original<function>()() == expected);
        CHECK(hook->enable()); CHECK(buffer.fn()() == 99);
        CHECK(hook->original<function>()() == expected);
        CHECK(hook->disable()); CHECK(buffer.fn()() == expected);
        CHECK(!memlib::is_writable(buffer.data));
    }

    void run(const std::string& name)
    {
        if (name == "linux_signal_conflict")
        {
#if !defined(_WIN32)
            const auto signal = SIGRTMIN + 6;
            struct sigaction previous{}, ignored{};
            ignored.sa_handler = SIG_IGN;
            sigemptyset(&ignored.sa_mask);
            CHECK(sigaction(signal, &ignored, &previous) == 0);
            code_buffer buffer; buffer.seal(); auto hook = buffer.create(); CHECK(hook);
            auto result = hook->enable(); CHECK(!result); CHECK(result.error().type == memlib::hook_error::ThreadFreezeFailed);
            CHECK(!hook->enabled()); CHECK(buffer.fn()() == 7);
            struct sigaction current{}; CHECK(sigaction(signal, nullptr, &current) == 0); CHECK(current.sa_handler == SIG_IGN);
            CHECK(sigaction(signal, &previous, nullptr) == 0);
#endif
            return;
        }
        code_buffer buffer;
        if (name == "lifecycle")
        {
            buffer.seal(); auto hook = buffer.create(); CHECK(hook); CHECK(!hook->enabled());
            CHECK(hook->target() == buffer.data); CHECK(hook->destination() == reinterpret_cast<void*>(&detour));
            CHECK(hook->original_bytes().size() == 5); CHECK(hook->call<int>() == 7);
            CHECK(hook->enable()); CHECK(hook->enable()); CHECK(hook->enabled()); CHECK(buffer.fn()() == 99);
            CHECK(hook->disable()); CHECK(hook->disable()); CHECK(buffer.fn()() == 7);
            CHECK(hook->reset()); CHECK(!*hook); CHECK(hook->reset()); CHECK(!hook->enable());
            { auto automatic = buffer.create(0, memlib::inl_hook::Default); CHECK(automatic); CHECK(automatic->enabled()); CHECK(buffer.fn()() == 99); }
            CHECK(buffer.fn()() == 7);
        }
        else if (name == "manager")
        {
            buffer.seal(); memlib::hook_manager manager;
            auto hook = manager.create_inline(buffer.data, reinterpret_cast<void*>(&detour), memlib::inl_hook::Default);
            CHECK(hook); CHECK(hook->is_hook_enabled()); CHECK(buffer.fn()() == 99);
            CHECK(manager.disable_all()); CHECK(!hook->is_hook_enabled()); CHECK(buffer.fn()() == 7);
            CHECK(manager.enable_all()); CHECK(hook->is_hook_enabled()); CHECK(buffer.fn()() == 99);
            CHECK(manager.reset_all()); CHECK(!*hook); CHECK(buffer.fn()() == 7);
        }
        else if (name == "relative_call")
        { buffer.relative(0, 0xE8, 32); buffer.data[5] = 0x83; buffer.data[6] = 0xC0; buffer.data[7] = 1; buffer.data[8] = 0xC3; check_relocation(buffer, 9); }
        else if (name == "relative_jump")
        { buffer.relative(0, 0xE9, 32); check_relocation(buffer, 8); }
        else if (name == "conditional")
        {
            for (const auto opcode : {0x74, 0x75})
            {
                CHECK(memlib::protect(buffer.data, buffer.page_size * 2, memlib::prot::r | memlib::prot::w | memlib::prot::x));
                buffer.bytes({0x31, 0xC0, static_cast<uint8_t>(opcode), 28, 0x90}); buffer.constant(5, 7);
                check_relocation(buffer, opcode == 0x74 ? 8 : 7);
            }
        }
        else if (name == "internal_branch")
        {
            buffer.bytes({0x31, 0xC0, 0x74, 0, 0x90}); buffer.constant(5, 7); check_relocation(buffer, 7);
            CHECK(memlib::protect(buffer.data, buffer.page_size * 2, memlib::prot::r | memlib::prot::w | memlib::prot::x));
            buffer.data[3] = 0xFD; buffer.seal(); auto invalid = buffer.create(); CHECK(!invalid);
            CHECK(invalid.error().type == memlib::hook_error::InvalidBranchTarget);
        }
        else if (name == "loop")
        {
            buffer.bytes({0x31, 0xC9, 0xE3, 28, 0x90}); buffer.constant(5, 7); check_relocation(buffer, 8);
            CHECK(memlib::protect(buffer.data, buffer.page_size * 2, memlib::prot::r | memlib::prot::w | memlib::prot::x));
            buffer.bytes({0x6A, 1, 0x59, 0xE2, 27}); buffer.constant(5, 7); check_relocation(buffer, 7);
        }
        else if (name == "rip_relative")
        {
            const int value = 12; std::memcpy(buffer.data + 128, &value, 4);
            if constexpr (sizeof(uintptr_t) == 8)
            { buffer.bytes({0x8B, 0x05}); const int32_t displacement = 122; std::memcpy(buffer.data + 2, &displacement, 4); buffer.data[6] = 0xC3; }
            else
            { buffer.data[0] = 0xA1; const auto address = reinterpret_cast<uintptr_t>(buffer.data + 128); std::memcpy(buffer.data + 1, &address, 4); buffer.data[5] = 0xC3; }
            check_relocation(buffer, value);
        }
        else if (name == "long_instruction")
        {
            if constexpr (sizeof(uintptr_t) == 8)
            { buffer.bytes({0x48, 0xB8}); const uint64_t value = 7; std::memcpy(buffer.data + 2, &value, 8); buffer.data[10] = 0xC3; }
            else { buffer.bytes({0x66, 0x0F, 0x1F, 0x84, 0, 0, 0, 0, 0}); buffer.constant(9, 7); }
            check_relocation(buffer, 7);
        }
        else if (name == "endbr")
        {
            buffer.bytes({0xF3, 0x0F, 0x1E, sizeof(uintptr_t) == 8 ? uint8_t(0xFA) : uint8_t(0xFB)});
            buffer.constant(4, 7); buffer.seal(); auto hook = buffer.create(); CHECK(hook); CHECK(hook->enable());
            CHECK(buffer.data[0] == 0xF3); CHECK(buffer.fn()() == 99); CHECK(hook->call<int>() == 7); CHECK(hook->reset()); CHECK(buffer.fn()() == 7);
        }
        else if (name == "page_boundary")
        {
            const auto offset = buffer.page_size - 2; buffer.constant(offset, 7);
            CHECK(memlib::protect(buffer.data, buffer.page_size, memlib::prot::r | memlib::prot::x));
            auto hook = buffer.create(offset); CHECK(hook); CHECK(hook->enable()); CHECK(buffer.fn(offset)() == 99);
            CHECK(!memlib::is_writable(buffer.data)); CHECK(memlib::is_writable(buffer.data + buffer.page_size));
            CHECK(hook->call<int>() == 7); CHECK(hook->reset()); CHECK(buffer.fn(offset)() == 7);
            CHECK(!memlib::is_writable(buffer.data)); CHECK(memlib::is_writable(buffer.data + buffer.page_size));
        }
        else if (name == "decode_boundary")
        {
            buffer.data[buffer.page_size - 1] = 0x0F;
            CHECK(memlib::protect(buffer.data + buffer.page_size, buffer.page_size, memlib::prot::none));
            auto hook = buffer.create(buffer.page_size - 1); CHECK(!hook); CHECK(hook.error().type == memlib::hook_error::DecodeFailed);
        }
        else if (name == "invalid_target")
        {
            CHECK(!memlib::inl_hook::create(nullptr, reinterpret_cast<void*>(&detour)));
            CHECK(!memlib::inl_hook::create(buffer.data, nullptr));
            CHECK(!memlib::inl_hook::create(buffer.data, buffer.data));
            buffer.data[0] = 0xC3; auto short_function = buffer.create(); CHECK(!short_function);
            CHECK(short_function.error().type == memlib::hook_error::UnsupportedInstruction);
            CHECK(memlib::protect(buffer.data, buffer.page_size, memlib::prot::r)); CHECK(!buffer.create());
        }
        else if (name == "duplicate")
        {
            buffer.seal(); auto hook = buffer.create(); CHECK(hook);
            auto duplicate = buffer.create(); CHECK(!duplicate); CHECK(duplicate.error().type == memlib::hook_error::AlreadyHooked);
            CHECK(hook->enable()); duplicate = buffer.create(); CHECK(!duplicate); CHECK(duplicate.error().type == memlib::hook_error::AlreadyHooked);
            auto overlap = buffer.create(1); CHECK(!overlap); CHECK(overlap.error().type == memlib::hook_error::AlreadyHooked);
        }
        else if (name == "target_changed")
        {
            buffer.seal(); auto hook = buffer.create(); CHECK(hook);
            CHECK(memlib::protect(buffer.data, buffer.page_size, memlib::prot::r | memlib::prot::w | memlib::prot::x));
            buffer.data[0] = 0x90; auto enabled = hook->enable(); CHECK(!enabled); CHECK(enabled.error().type == memlib::hook_error::TargetChanged); CHECK(!hook->enabled());
            buffer.data[0] = 0xB8; CHECK(hook->enable()); const auto patched = buffer.data[0]; buffer.data[0] = 0x90;
            CHECK(!hook->disable()); CHECK(hook->enabled()); CHECK(!hook->reset()); CHECK(*hook);
            buffer.data[0] = patched; CHECK(hook->reset()); CHECK(buffer.fn()() == 7);
        }
        else if (name == "move")
        {
            buffer.seal(); auto hook = buffer.create(); CHECK(hook); CHECK(hook->enable());
            memlib::inl_hook moved = std::move(*hook); CHECK(!*hook); CHECK(moved.enabled());
            auto second = buffer.create(32); CHECK(second); CHECK(second->enable());
            moved = std::move(*second); CHECK(buffer.fn()() == 7); CHECK(buffer.fn(32)() == 99); CHECK(moved.reset()); CHECK(buffer.fn(32)() == 8);
        }
        else if (name == "concurrent")
        {
            buffer.seal(); auto hook = buffer.create(); CHECK(hook);
            std::atomic<bool> running{true}; std::atomic<int> invalid{}, calls{};
            std::vector<std::jthread> workers;
            for (int i = 0; i < 4; ++i) workers.emplace_back([&] { while (running.load()) { const int value = buffer.fn()(); if (value != 7 && value != 99) ++invalid; ++calls; } });
            // Never throw with joinable workers still waiting for running=false.
            bool success = true;
            for (int i = 0; i < 100; ++i)
                if (!hook->enable() || !hook->disable()) { success = false; break; }
            running.store(false); workers.clear();
            CHECK(success); CHECK(invalid.load() == 0); CHECK(calls.load() > 0); CHECK(buffer.fn()() == 7);
        }
        else if (name == "retained_original")
        {
            buffer.seal(); auto hook = buffer.create(); CHECK(hook); auto original = hook->original<function>();
            CHECK(hook->enable()); CHECK(hook->reset()); CHECK(original() == 7);
            CHECK(memlib::is_executable(reinterpret_cast<void*>(original))); CHECK(!memlib::is_writable(reinterpret_cast<void*>(original)));
        }
        else if (name == "active_original")
        {
            // A peer waits inside a callee whose return address is in the
            // trampoline. Reset must not free that mapping beneath the return.
            static_assert(sizeof(std::atomic<uint8_t>) == 1);
            std::atomic<uint8_t> flags[2]{};
            buffer.relative(0, 0xE8, 32); buffer.data[5] = 0xC3;
            size_t cursor = 32;
            if constexpr (sizeof(uintptr_t) == 8) buffer.data[cursor++] = 0x48;
            buffer.data[cursor++] = 0xB8;
            const auto address = reinterpret_cast<uintptr_t>(flags);
            std::memcpy(buffer.data + cursor, &address, sizeof(address)); cursor += sizeof(address);
            const uint8_t wait[] = {0xC6, 0x00, 1, 0x80, 0x78, 1, 0, 0x74, 0xFA};
            std::memcpy(buffer.data + cursor, wait, sizeof(wait)); cursor += sizeof(wait);
            buffer.constant(cursor, 7); buffer.seal();
            auto hook = buffer.create(); CHECK(hook); CHECK(hook->enable());
            auto original = hook->original<function>(); std::atomic<int> result{};
            std::jthread worker([&] { result.store(original()); });
            while (!flags[0].load()) std::this_thread::yield();
            const bool reset = static_cast<bool>(hook->reset());
            flags[1].store(1); worker.join();
            CHECK(reset); CHECK(result.load() == 7); CHECK(buffer.fn()() == 7);
        }
        else if (name == "getpc")
        {
            if constexpr (sizeof(uintptr_t) == 4)
            {
                // Test a GCC PIC thunk using EAX; the original return address
                // is the value, rather than the trampoline's return address.
                buffer.relative(0, 0xE8, 32); buffer.data[5] = 0xC3;
                const uint8_t thunk[] = {0x8B, 0x04, 0x24, 0xC3}; std::memcpy(buffer.data + 32, thunk, 4);
                buffer.seal(); auto hook = buffer.create(); CHECK(hook);
                CHECK(hook->original<uintptr_t (*)()>()() == reinterpret_cast<uintptr_t>(buffer.data + 5));
                CHECK(hook->reset());
                CHECK(memlib::protect(buffer.data, buffer.page_size * 2, memlib::prot::r | memlib::prot::w | memlib::prot::x));
                buffer.relative(0, 0xE8, 5); buffer.data[5] = 0x58; buffer.data[6] = 0xC3;
                buffer.seal(); hook = buffer.create(); CHECK(hook);
                CHECK(hook->original<uintptr_t (*)()>()() == reinterpret_cast<uintptr_t>(buffer.data + 5));
            }
        }
        else if (name == "calling_conventions")
        {
            // Test actual x86 register and callee-cleanup conventions. On x64
            // these names intentionally use the platform's single standard ABI.
            if constexpr (sizeof(uintptr_t) == 4)
            {
                buffer.bytes({0x8B, 0x44, 0x24, 4, 0x03, 0x44, 0x24, 8, 0xC3});
                buffer.seal(); auto hook = buffer.create(); CHECK(hook); CHECK((hook->ccall<int, int, int>(3, 4) == 7)); CHECK(hook->reset());
                CHECK(memlib::protect(buffer.data, buffer.page_size * 2, memlib::prot::r | memlib::prot::w | memlib::prot::x));
                buffer.data[8] = 0xC2; buffer.data[9] = 8; buffer.data[10] = 0;
                buffer.seal(); hook = buffer.create(); CHECK(hook); CHECK((hook->stdcall<int, int, int>(3, 4) == 7)); CHECK(hook->reset());
                CHECK(memlib::protect(buffer.data, buffer.page_size * 2, memlib::prot::r | memlib::prot::w | memlib::prot::x));
                buffer.bytes({0x89, 0xC8, 0x01, 0xD0, 0x90, 0xC3});
                buffer.seal(); hook = buffer.create(); CHECK(hook); CHECK((hook->fastcall<int, int, int>(3, 4) == 7)); CHECK(hook->reset());
                CHECK(memlib::protect(buffer.data, buffer.page_size * 2, memlib::prot::r | memlib::prot::w | memlib::prot::x));
                buffer.bytes({0x8B, 0x01, 0x03, 0x44, 0x24, 4, 0xC2, 4, 0});
                buffer.seal(); hook = buffer.create(); CHECK(hook); int self = 3;
                CHECK((hook->thiscall<int, int*, int>(&self, 4) == 7));
            }
            else { buffer.seal(); auto hook = buffer.create(); CHECK(hook); CHECK(hook->ccall<int>() == 7); CHECK(hook->stdcall<int>() == 7); CHECK(hook->fastcall<int>() == 7); int self = 0; CHECK(hook->thiscall<int>(&self) == 7); }
        }
        else if (name == "linux_protection_failure")
        {
#if !defined(_WIN32)
            buffer.seal(); auto hook = buffer.create(); CHECK(hook);
            // Deny only mprotect after preparing executable code. This tests a
            // real OS protection failure, not an implementation stub.
            sock_filter filter[] = {
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mprotect, 0, 1),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
            };
            sock_fprog program{static_cast<unsigned short>(std::size(filter)), filter};
            CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
            CHECK(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0);
            auto result = hook->enable(); CHECK(!result); CHECK(result.error().type == memlib::hook_error::ProtectionFailed);
            CHECK(!hook->enabled()); CHECK(buffer.fn()() == 7); CHECK(!memlib::is_writable(buffer.data));
#endif
        }
        else if (name == "linux_protection_restore_failure")
        {
#if !defined(_WIN32)
            buffer.seal(); auto hook = buffer.create(); CHECK(hook);
            sock_filter filter[] = {
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mprotect, 0, 3),
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args) + 2 * sizeof(uint64_t)),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PROT_READ | PROT_EXEC, 0, 1),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
            };
            sock_fprog program{static_cast<unsigned short>(std::size(filter)), filter};
            CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
            CHECK(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0);
            // This policy cannot be removed in-process. Preserve the target
            // until process exit, just as the host must on an unrecoverable error.
            buffer.keep_mapping = true;
            auto result = hook->enable(); CHECK(!result);
            CHECK(result.error().type == memlib::hook_error::ProtectionRestoreFailed);
            CHECK(result.error().patch_applied); CHECK(hook->enabled()); CHECK(buffer.fn()() == 99);
            CHECK(!hook->reset()); CHECK(*hook); CHECK(hook->enabled()); CHECK(buffer.fn()() == 99);
            CHECK(hook->call<int>() == 7);
#endif
        }
        else if (name == "linux_blocked_signal")
        {
#if !defined(_WIN32)
            buffer.seal(); auto hook = buffer.create(); CHECK(hook);
            std::atomic<bool> ready{}, finish{};
            std::jthread worker([&] {
                sigset_t mask; sigemptyset(&mask); sigaddset(&mask, SIGRTMIN + 6);
                pthread_sigmask(SIG_BLOCK, &mask, nullptr); ready.store(true);
                while (!finish.load()) std::this_thread::yield();
                pthread_sigmask(SIG_UNBLOCK, &mask, nullptr);
            });
            while (!ready.load()) std::this_thread::yield();
            auto result = hook->enable(); finish.store(true); worker.join();
            CHECK(!result); CHECK(result.error().type == memlib::hook_error::ThreadFreezeFailed); CHECK(!hook->enabled()); CHECK(buffer.fn()() == 7);
            CHECK(hook->enable()); CHECK(hook->disable());
#endif
        }
        else throw std::runtime_error("Unknown test: " + name);
    }
}
int main(int argc, char** argv)
{
    try { CHECK(argc == 2); if (std::string(argv[1]) == "getpc" && sizeof(uintptr_t) == 8) return 77; run(argv[1]); std::cout << argv[1] << " passed\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
