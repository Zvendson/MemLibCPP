#include <memlib/inline_hook.hpp>
#include <memlib/memory.hpp>
#include "hook_internal.hpp"
#include <Zydis/Zydis.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>

#if !defined(_M_IX86) && !defined(_M_X64) && !defined(__i386__) && !defined(__x86_64__)
#error "MemLib inline hooks support x86 and x64 only"
#endif

namespace memlib
{
    struct hook_state
    {
        struct allocation { uint8_t* data{}; size_t length{}; explicit operator bool() const noexcept { return data != nullptr; } };
        uint8_t* target{};
        uint8_t* destination{};
        uint8_t* patch_target{};
        allocation trampoline;
        std::vector<uint8_t> saved;
        std::vector<uint8_t> patch;
        std::array<detail::instruction_boundary, 32> boundaries{};
        std::array<detail::pending_protection, 2> pending{};
        size_t boundary_count{};
        std::atomic<bool> enabled{};
        bool ever_enabled{};
        ~hook_state()
        {
            // A suspended thread can be inside a callee with a return address
            // in the trampoline. Keep published code mapped until process exit.
            if (!ever_enabled) detail::release_trampoline(trampoline.data, trampoline.length);
        }
    };
}

namespace
{
    using memlib::hook_error;
    using memlib::hook_state;
    std::mutex& lifecycle_mutex();
    std::vector<hook_state*>& hooks();
    std::expected<void, hook_error> prepare(hook_state&);
    std::expected<void, hook_error> toggle(hook_state&, bool);
    memlib_hook_status to_c_status(hook_error::Type);
    memlib_hook_status result_status(const std::expected<void, hook_error>&);
}

struct memlib_inline_hook
{
    memlib::hook_state* state{};
};

struct memlib_mid_hook
{
    memlib_inline_hook* inner{};
};

namespace
{
    memlib_hook_status create_inline_state(void* target, void* destination, uint32_t flags, memlib_inline_hook* handle)
    {
        if (!handle) return MEMLIB_HOOK_INVALID_HOOK;
        std::scoped_lock lock(lifecycle_mutex());
        if (!target) return MEMLIB_HOOK_INVALID_TARGET;
        if (!destination || target == destination) return MEMLIB_HOOK_INVALID_DESTINATION;
        auto* state = new (std::nothrow) memlib::hook_state;
        if (!state) return MEMLIB_HOOK_ALLOCATION_FAILED;
        state->target = static_cast<uint8_t*>(target);
        state->destination = static_cast<uint8_t*>(destination);
        for (const auto* existing : hooks())
        {
            const auto address = reinterpret_cast<uintptr_t>(target);
            const auto begin = reinterpret_cast<uintptr_t>(existing->patch_target);
            if (existing->target == target || (address >= begin && address < begin + existing->saved.size()))
            { delete state; return MEMLIB_HOOK_ALREADY_HOOKED; }
        }
        if (auto prepared = prepare(*state); !prepared)
        { const auto status = to_c_status(prepared.error().type); delete state; return status; }
        const auto begin = reinterpret_cast<uintptr_t>(state->patch_target);
        for (const auto* existing : hooks())
        {
            const auto other = reinterpret_cast<uintptr_t>(existing->patch_target);
            if (begin < other + existing->saved.size() && other < begin + state->saved.size())
            { delete state; return MEMLIB_HOOK_ALREADY_HOOKED; }
        }
        hooks().push_back(state);
        handle->state = state;
        if ((flags & MEMLIB_HOOK_START_DISABLED) == 0)
        {
            const auto result = toggle(*state, true);
            if (!result)
            {
                const auto status = to_c_status(result.error().type);
                if (state->enabled.load()) return status;
                std::erase(hooks(), state); handle->state = nullptr; delete state; return status;
            }
        }
        return MEMLIB_HOOK_OK;
    }
}

extern "C"
{
    memlib_hook_status memlib_inline_hook_create(void* target, void* destination, uint32_t flags, memlib_inline_hook** out_hook)
    {
        if (out_hook) *out_hook = nullptr;
        if (!out_hook) return MEMLIB_HOOK_INVALID_HOOK;
        auto* handle = new (std::nothrow) memlib_inline_hook;
        if (!handle) return MEMLIB_HOOK_ALLOCATION_FAILED;
        const auto result = create_inline_state(target, destination, flags, handle);
        if (result != MEMLIB_HOOK_OK && !handle->state) delete handle;
        else *out_hook = handle;
        return result;
    }

    memlib_hook_status memlib_inline_hook_enable(memlib_inline_hook* hook)
    {
        if (!hook || !hook->state) return MEMLIB_HOOK_INVALID_HOOK;
        std::scoped_lock lock(lifecycle_mutex());
        return result_status(toggle(*hook->state, true));
    }
    memlib_hook_status memlib_inline_hook_disable(memlib_inline_hook* hook)
    {
        if (!hook || !hook->state) return MEMLIB_HOOK_INVALID_HOOK;
        std::scoped_lock lock(lifecycle_mutex());
        return result_status(toggle(*hook->state, false));
    }
    memlib_hook_status memlib_inline_hook_reset(memlib_inline_hook* hook)
    {
        if (!hook || !hook->state) return MEMLIB_HOOK_OK;
        std::scoped_lock lock(lifecycle_mutex());
        const auto result = toggle(*hook->state, false);
        if (!result) return to_c_status(result.error().type);
        std::erase(hooks(), hook->state);
        delete hook->state;
        hook->state = nullptr;
        delete hook;
        return MEMLIB_HOOK_OK;
    }
    int memlib_inline_hook_enabled(const memlib_inline_hook* hook)
    { return hook && hook->state && hook->state->enabled.load() ? 1 : 0; }
    void* memlib_inline_hook_target(const memlib_inline_hook* hook)
    { return hook && hook->state ? hook->state->target : nullptr; }
    void* memlib_inline_hook_destination(const memlib_inline_hook* hook)
    { return hook && hook->state ? hook->state->destination : nullptr; }
    memlib_hook_status memlib_inline_hook_trampoline(const memlib_inline_hook* hook, memlib_hook_allocation* out)
    {
        if (!hook || !hook->state || !out) return MEMLIB_HOOK_INVALID_HOOK;
        out->address = hook->state->trampoline.data; out->size = hook->state->trampoline.length;
        return MEMLIB_HOOK_OK;
    }

    memlib_hook_status memlib_mid_hook_create(void* address, void* destination, uint32_t flags, memlib_mid_hook** out_hook)
    {
        if (out_hook) *out_hook = nullptr;
        if (!out_hook) return MEMLIB_HOOK_INVALID_HOOK;
        auto* handle = new (std::nothrow) memlib_mid_hook;
        if (!handle) return MEMLIB_HOOK_ALLOCATION_FAILED;
        const auto status = memlib_inline_hook_create(address, destination, flags, &handle->inner);
        if (status != MEMLIB_HOOK_OK)
        {
            delete handle;
            return status;
        }
        *out_hook = handle;
        return MEMLIB_HOOK_OK;
    }
    memlib_hook_status memlib_mid_hook_enable(memlib_mid_hook* hook)
    { return hook ? memlib_inline_hook_enable(hook->inner) : MEMLIB_HOOK_INVALID_HOOK; }
    memlib_hook_status memlib_mid_hook_disable(memlib_mid_hook* hook)
    { return hook ? memlib_inline_hook_disable(hook->inner) : MEMLIB_HOOK_INVALID_HOOK; }
    memlib_hook_status memlib_mid_hook_reset(memlib_mid_hook* hook)
    {
        if (!hook) return MEMLIB_HOOK_INVALID_HOOK;
        const auto status = memlib_inline_hook_reset(hook->inner);
        if (status == MEMLIB_HOOK_OK) delete hook;
        return status;
    }
    int memlib_mid_hook_enabled(const memlib_mid_hook* hook)
    { return hook ? memlib_inline_hook_enabled(hook->inner) : 0; }
}

namespace
{
    using memlib::hook_error;
    using memlib::hook_state;
    std::mutex& lifecycle_mutex();
    std::vector<hook_state*>& hooks();
    std::expected<void, hook_error> prepare(hook_state&);
    std::expected<void, hook_error> toggle(hook_state&, bool);
    memlib_hook_status to_c_status(hook_error::Type);
    memlib_hook_status result_status(const std::expected<void, hook_error>&);
    constexpr bool x64 = sizeof(uintptr_t) == 8;
    // Intentionally process-lifetime storage: DLL static destruction order must
    // not invalidate bookkeeping while a hook is still installed.
    std::mutex& lifecycle_mutex() { static auto* value = new std::mutex; return *value; }
    std::vector<hook_state*>& hooks()
    { static auto* value = new std::vector<hook_state*>; return *value; }

    memlib_hook_status to_c_status(hook_error::Type type)
    {
        using T = hook_error::Type;
        switch (type)
        {
        case T::InvalidTarget: return MEMLIB_HOOK_INVALID_TARGET;
        case T::InvalidDestination: return MEMLIB_HOOK_INVALID_DESTINATION;
        case T::DecodeFailed: return MEMLIB_HOOK_DECODE_FAILED;
        case T::UnsupportedInstruction: return MEMLIB_HOOK_UNSUPPORTED_INSTRUCTION;
        case T::AllocationFailed: return MEMLIB_HOOK_ALLOCATION_FAILED;
        case T::RelocationOutOfRange: return MEMLIB_HOOK_RELOCATION_OUT_OF_RANGE;
        case T::InvalidBranchTarget: return MEMLIB_HOOK_INVALID_BRANCH_TARGET;
        case T::AlreadyHooked: return MEMLIB_HOOK_ALREADY_HOOKED;
        case T::ProtectionFailed: return MEMLIB_HOOK_PROTECTION_FAILED;
        case T::ThreadFreezeFailed: return MEMLIB_HOOK_THREAD_FREEZE_FAILED;
        case T::ThreadContextFailed: return MEMLIB_HOOK_THREAD_CONTEXT_FAILED;
        case T::TargetChanged: return MEMLIB_HOOK_TARGET_CHANGED;
        case T::InvalidHook: return MEMLIB_HOOK_INVALID_HOOK;
        case T::ProtectionRestoreFailed: return MEMLIB_HOOK_PROTECTION_RESTORE_FAILED;
        }
        return MEMLIB_HOOK_UNSUPPORTED;
    }

    memlib_hook_status result_status(const std::expected<void, hook_error>& result)
    { return result ? MEMLIB_HOOK_OK : to_c_status(result.error().type); }

    bool rel32(uintptr_t from, uintptr_t to, int32_t& result)
    {
        if constexpr (x64)
        {
            if (to >= from && to - from > INT32_MAX) return false;
            if (to < from && from - to > uint64_t(INT32_MAX) + 1) return false;
        }
        // In 32-bit mode relative arithmetic wraps at the address-space boundary.
        const uint32_t bits = static_cast<uint32_t>(to - from);
        std::memcpy(&result, &bits, sizeof(result));
        return true;
    }

    void put32(uint8_t* output, int32_t value) { std::memcpy(output, &value, 4); }
    bool jump(uint8_t* output, uintptr_t destination, bool call = false)
    {
        int32_t displacement;
        if (!rel32(reinterpret_cast<uintptr_t>(output) + 5, destination, displacement)) return false;
        output[0] = call ? 0xE8 : 0xE9;
        put32(output + 1, displacement);
        return true;
    }
    void absolute_jump(uint8_t* output, uintptr_t destination)
    {
        const uint8_t opcode[] = {0xFF, 0x25, 0, 0, 0, 0};
        std::memcpy(output, opcode, 6);
        const uint64_t pointer = destination;
        std::memcpy(output + 6, &pointer, 8);
    }

    enum class branch { none, call, jump, conditional, loop, getpc_mov, getpc_push };
    struct instruction
    {
        ZydisDecodedInstruction decoded{};
        std::array<uint8_t, 15> bytes{};
        size_t source_offset{};
        size_t output_offset{};
        size_t output_size{};
        branch kind{};
        uintptr_t branch_target{};
        uintptr_t memory_target{};
        bool rip_relative{};
        uint8_t pc_register{};
    };

    std::expected<void, hook_error> prepare(hook_state& state)
    {
        using enum hook_error::Type;
        const auto target = reinterpret_cast<uintptr_t>(state.target);
        if (!memlib::is_executable(state.target) || !memlib::is_readable(state.target))
            return std::unexpected(hook_error{InvalidTarget, target});
        if (!memlib::is_executable(state.destination))
            return std::unexpected(hook_error{InvalidDestination, reinterpret_cast<uintptr_t>(state.destination)});

        state.patch_target = state.target;
        if (memlib::is_readable(state.target, 4) && state.target[0] == 0xF3 &&
            state.target[1] == 0x0F && state.target[2] == 0x1E &&
            state.target[3] == (x64 ? 0xFA : 0xFB)) state.patch_target += 4;
        const auto start = reinterpret_cast<uintptr_t>(state.patch_target);
        ZydisDecoder decoder;
        ZydisDecoderInit(&decoder, x64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
            x64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);
        std::array<instruction, 32> instructions{};
        size_t stolen = 0, output_size = 4;
        while (stolen < 5)
        {
            auto& item = instructions[state.boundary_count];
            item.source_offset = stolen;
            item.output_offset = output_size;
            size_t readable = 0;
            // Bound every read, including targets at the end of a mapping.
            while (readable < item.bytes.size() &&
                memlib::is_readable(state.patch_target + stolen + readable) &&
                memlib::is_executable(state.patch_target + stolen + readable))
            {
                item.bytes[readable] = state.patch_target[stolen + readable];
                ++readable;
            }
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, item.bytes.data(), readable, &item.decoded, operands)))
                return std::unexpected(hook_error{DecodeFailed, start + stolen});
            const auto& decoded = item.decoded;
            item.output_size = decoded.length;
            for (size_t i = 0; i < decoded.operand_count; ++i)
            {
                const auto& operand = operands[i];
                if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.is_relative)
                {
                    // 16-bit branches and XBEGIN need different semantics.
                    if ((decoded.raw.imm[0].size != 8 && decoded.raw.imm[0].size != 32) ||
                        decoded.mnemonic == ZYDIS_MNEMONIC_XBEGIN)
                        return std::unexpected(hook_error{UnsupportedInstruction, start + stolen});
                    item.branch_target = start + stolen + decoded.length + static_cast<uintptr_t>(operand.imm.value.s);
                    if (decoded.meta.category == ZYDIS_CATEGORY_CALL)
                    {
                        item.kind = branch::call;
                        item.output_size = x64 ? 16 : 5;
                        if constexpr (!x64)
                        {
                            const auto return_address = start + stolen + decoded.length;
                            if (item.branch_target == return_address)
                                item.kind = branch::getpc_push;
                            else
                            {
                                auto* thunk = reinterpret_cast<uint8_t*>(item.branch_target);
                                if (memlib::is_readable(thunk, 4) && thunk[0] == 0xF3 && thunk[1] == 0x0F && thunk[2] == 0x1E && thunk[3] == 0xFB) thunk += 4;
                                // GCC's __x86.get_pc_thunk.<register>: mov reg,[esp]; ret.
                                if (memlib::is_readable(thunk, 4) && memlib::is_executable(thunk, 4) &&
                                    thunk[0] == 0x8B && (thunk[1] & 0xC7) == 0x04 && thunk[2] == 0x24 && thunk[3] == 0xC3)
                                {
                                    item.pc_register = (thunk[1] >> 3) & 7;
                                    if (item.pc_register == 4) return std::unexpected(hook_error{UnsupportedInstruction, item.branch_target});
                                    item.kind = branch::getpc_mov;
                                }
                            }
                        }
                    }
                    else if (decoded.meta.category == ZYDIS_CATEGORY_UNCOND_BR)
                    {
                        item.kind = branch::jump;
                        item.output_size = x64 ? 14 : 5;
                    }
                    else if (decoded.opcode >= 0xE0 && decoded.opcode <= 0xE3)
                    {
                        item.kind = branch::loop;
                        item.output_size = decoded.length + 2 + (x64 ? 14 : 5);
                    }
                    else if (decoded.meta.category == ZYDIS_CATEGORY_COND_BR &&
                        ((decoded.opcode >= 0x70 && decoded.opcode <= 0x7F) ||
                         (decoded.opcode >= 0x80 && decoded.opcode <= 0x8F)))
                    {
                        item.kind = branch::conditional;
                        item.output_size = x64 ? 16 : 6;
                    }
                    else return std::unexpected(hook_error{UnsupportedInstruction, start + stolen});
                }
                if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    (operand.mem.base == ZYDIS_REGISTER_RIP || operand.mem.base == ZYDIS_REGISTER_EIP))
                {
                    // Address-size-overridden EIP addressing is not RIP addressing.
                    if (operand.mem.base != ZYDIS_REGISTER_RIP || decoded.raw.disp.size != 32)
                        return std::unexpected(hook_error{UnsupportedInstruction, start + stolen});
                    item.rip_relative = true;
                    item.memory_target = start + stolen + decoded.length + static_cast<uintptr_t>(operand.mem.disp.value);
                }
            }
            stolen += decoded.length;
            output_size += item.output_size;
            ++state.boundary_count;
            // Never read padding after a terminal instruction to make a short
            // function appear hookable; external entries cannot be discovered.
            if (stolen < 5 && (decoded.meta.category == ZYDIS_CATEGORY_RET ||
                decoded.meta.category == ZYDIS_CATEGORY_UNCOND_BR || decoded.meta.category == ZYDIS_CATEGORY_CALL))
                return std::unexpected(hook_error{UnsupportedInstruction, start + item.source_offset});
        }

        state.trampoline.data = memlib::detail::allocate_trampoline(start, state.trampoline.length);
        if (!state.trampoline) return std::unexpected(hook_error{AllocationFailed, start});
        auto* code = state.trampoline.data;
        std::memset(code, 0x90, state.trampoline.length);
        // A callable trampoline retains the indirect branch landing instruction.
        const uint8_t endbr[] = {0xF3, 0x0F, 0x1E, static_cast<uint8_t>(x64 ? 0xFA : 0xFB)};
        std::memcpy(code, endbr, 4);
        for (size_t i = 0; i < state.boundary_count; ++i)
        {
            auto& item = instructions[i];
            state.boundaries[i] = {start + item.source_offset, reinterpret_cast<uintptr_t>(code + item.output_offset)};
        }
        for (size_t i = 0; i < state.boundary_count; ++i)
        {
            const auto& item = instructions[i];
            const auto& decoded = item.decoded;
            auto* output = code + item.output_offset;
            auto destination = item.branch_target;
            if (item.kind != branch::none && item.kind != branch::getpc_mov && item.kind != branch::getpc_push &&
                destination >= start && destination < start + stolen)
            {
                auto found = std::find_if(state.boundaries.begin(), state.boundaries.begin() + state.boundary_count,
                    [destination](const auto& boundary) { return boundary.source == destination; });
                if (found == state.boundaries.begin() + state.boundary_count)
                    return std::unexpected(hook_error{InvalidBranchTarget, destination});
                destination = found->relocated;
            }
            switch (item.kind)
            {
            case branch::none:
                std::memcpy(output, item.bytes.data(), decoded.length);
                if (item.rip_relative)
                {
                    if (item.memory_target >= start && item.memory_target < start + stolen)
                        return std::unexpected(hook_error{UnsupportedInstruction, item.memory_target});
                    int32_t displacement;
                    if (!rel32(reinterpret_cast<uintptr_t>(output) + decoded.length, item.memory_target, displacement))
                        return std::unexpected(hook_error{RelocationOutOfRange, item.memory_target});
                    put32(output + decoded.raw.disp.offset, displacement);
                }
                break;
            case branch::call:
                if (!jump(output, destination, true))
                {
                    if constexpr (x64)
                    {
                        // call [rip+2]; jmp over the embedded 64-bit pointer.
                        const uint8_t bytes[] = {0xFF, 0x15, 2, 0, 0, 0, 0xEB, 8};
                        std::memcpy(output, bytes, 8);
                        std::memcpy(output + 8, &destination, 8);
                    }
                }
                break;
            case branch::jump:
                if (!jump(output, destination)) absolute_jump(output, destination);
                break;
            case branch::conditional:
                if constexpr (x64)
                {
                    output[0] = static_cast<uint8_t>(0x70 | ((decoded.opcode & 0xF) ^ 1));
                    output[1] = 14;
                    if (!jump(output + 2, destination)) absolute_jump(output + 2, destination);
                }
                else
                {
                    output[0] = 0x0F;
                    output[1] = static_cast<uint8_t>(0x80 | (decoded.opcode & 0xF));
                    int32_t displacement;
                    (void)rel32(reinterpret_cast<uintptr_t>(output) + 6, destination, displacement);
                    put32(output + 2, displacement);
                }
                break;
            case branch::loop:
                std::memcpy(output, item.bytes.data(), decoded.length);
                output[decoded.raw.imm[0].offset] = 2;
                output[decoded.length] = 0xEB;
                output[decoded.length + 1] = x64 ? 14 : 5;
                if (!jump(output + decoded.length + 2, destination))
                    absolute_jump(output + decoded.length + 2, destination);
                break;
            case branch::getpc_mov:
            case branch::getpc_push:
                output[0] = item.kind == branch::getpc_push ? 0x68 : static_cast<uint8_t>(0xB8 + item.pc_register);
                put32(output + 1, static_cast<int32_t>(start + item.source_offset + decoded.length));
                break;
            }
        }
        if (!jump(code + output_size, start + stolen))
            return std::unexpected(hook_error{RelocationOutOfRange, start + stolen});
        auto* relay = code + output_size + 5;
        if constexpr (x64) absolute_jump(relay, reinterpret_cast<uintptr_t>(state.destination));
        else (void)jump(relay, reinterpret_cast<uintptr_t>(state.destination));
        state.saved.assign(state.patch_target, state.patch_target + stolen);
        state.patch.assign(stolen, 0x90);
        // Encode using the target address, rather than the vector's address.
        int32_t displacement;
        if (!rel32(start + 5, reinterpret_cast<uintptr_t>(relay), displacement))
            return std::unexpected(hook_error{RelocationOutOfRange, start});
        state.patch[0] = 0xE9;
        put32(state.patch.data() + 1, displacement);
        if (!memlib::detail::seal_trampoline(code, state.trampoline.length))
            return std::unexpected(hook_error{ProtectionFailed, reinterpret_cast<uintptr_t>(code)});
        return {};
    }

    std::expected<void, hook_error> toggle(hook_state& state, bool enabling)
    {
        if (auto recovered = memlib::detail::recover_protections(state.pending); !recovered) return recovered;
        if (state.enabled.load() == enabling) return {};
        const memlib::detail::patch_view patch{state.patch_target, state.saved.size(),
            enabling ? state.saved.data() : state.patch.data(), enabling ? state.patch.data() : state.saved.data(),
            state.boundaries.data(), state.boundary_count, enabling, state.pending.data()};
        // A failed context rollback can still publish relocated code to a peer.
        // Retain the mapping even when no target bytes ultimately changed.
        state.ever_enabled |= enabling;
        auto result = memlib::detail::patch_code(patch);
        if (result || result.error().patch_applied) state.enabled.store(enabling);
        return result;
    }
}

