#include <memlib/inline_hook.hpp>
#include <memlib/memory.hpp>
#include "hook_internal.hpp"
#include <Zydis/Zydis.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <mutex>

#if !defined(_M_IX86) && !defined(_M_X64) && !defined(__i386__) && !defined(__x86_64__)
#error "MemLib inline hooks support x86 and x64 only"
#endif

namespace memlib
{
    struct inl_hook::state
    {
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
        ~state()
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
    constexpr bool x64 = sizeof(uintptr_t) == 8;
    // Intentionally process-lifetime storage: DLL static destruction order must
    // not invalidate bookkeeping while a hook is still installed.
    std::mutex& lifecycle_mutex() { static auto* value = new std::mutex; return *value; }
    std::vector<memlib::inl_hook::state*>& hooks()
    { static auto* value = new std::vector<memlib::inl_hook::state*>; return *value; }

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

    std::expected<void, hook_error> prepare(memlib::inl_hook::state& state)
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

    std::expected<void, hook_error> toggle(memlib::inl_hook::state& state, bool enabling)
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

namespace memlib
{
    inl_hook::inl_hook() noexcept = default;
    inl_hook::~inl_hook()
    {
        // If restoring the target failed, keep the owner/registry alive. Freeing
        // it would leave an installed jump pointing to destroyed storage.
        if (auto result = reset(); !result) (void)m_state.release();
    }
    inl_hook::inl_hook(inl_hook&& other) noexcept = default;
    inl_hook& inl_hook::operator=(inl_hook&& other) noexcept
    {
        if (this == &other) return *this;
        if (reset()) m_state = std::move(other.m_state);
        return *this;
    }
    std::expected<inl_hook, inl_hook::Error> inl_hook::create(void* target, void* destination, Flags flags)
    {
        inl_hook result;
        std::scoped_lock lock(lifecycle_mutex());
        if (!target) return std::unexpected(Error{Error::InvalidTarget, 0});
        if (!destination || target == destination) return std::unexpected(Error{Error::InvalidDestination, reinterpret_cast<uintptr_t>(destination)});
        result.m_state = std::make_unique<state>();
        auto& state = *result.m_state;
        state.target = static_cast<uint8_t*>(target);
        state.destination = static_cast<uint8_t*>(destination);
        // Check exact duplicates before decoding an already-installed jump.
        for (const auto* existing : hooks())
            if (existing->target == target || (reinterpret_cast<uintptr_t>(target) >= reinterpret_cast<uintptr_t>(existing->patch_target) &&
                reinterpret_cast<uintptr_t>(target) < reinterpret_cast<uintptr_t>(existing->patch_target) + existing->saved.size()))
            {
                result.m_state.reset();
                return std::unexpected(Error{Error::AlreadyHooked, reinterpret_cast<uintptr_t>(target)});
            }
        if (auto prepared = prepare(state); !prepared)
        {
            const auto error = prepared.error();
            result.m_state.reset();
            return std::unexpected(error);
        }
        const auto begin = reinterpret_cast<uintptr_t>(state.patch_target);
        for (const auto* existing : hooks())
        {
            const auto other = reinterpret_cast<uintptr_t>(existing->patch_target);
            if (begin < other + existing->saved.size() && other < begin + state.saved.size())
            {
                result.m_state.reset();
                return std::unexpected(Error{Error::AlreadyHooked, begin});
            }
        }
        hooks().push_back(&state);
        if (!(flags & StartDisabled))
        {
            if (auto enabled = toggle(state, true); !enabled)
            {
                auto error = enabled.error();
                if (!toggle(state, false))
                {
                    error.patch_applied = state.enabled.load();
                    (void)result.m_state.release();
                    return std::unexpected(error);
                }
                error.patch_applied = false;
                std::erase(hooks(), &state);
                result.m_state.reset();
                return std::unexpected(error);
            }
        }
        return result;
    }
    std::expected<void, inl_hook::Error> inl_hook::enable()
    {
        std::scoped_lock lock(lifecycle_mutex());
        if (!m_state) return std::unexpected(Error{Error::InvalidHook, 0});
        return toggle(*m_state, true);
    }
    std::expected<void, inl_hook::Error> inl_hook::disable()
    {
        std::scoped_lock lock(lifecycle_mutex());
        if (!m_state) return std::unexpected(Error{Error::InvalidHook, 0});
        return toggle(*m_state, false);
    }
    std::expected<void, inl_hook::Error> inl_hook::reset()
    {
        if (!m_state) return {};
        std::scoped_lock lock(lifecycle_mutex());
        if (auto result = toggle(*m_state, false); !result) return result;
        std::erase(hooks(), m_state.get());
        m_state.reset();
        return {};
    }
    bool inl_hook::enabled() const noexcept { return m_state && m_state->enabled.load(); }
    inl_hook::operator bool() const noexcept { return m_state != nullptr; }
    uint8_t* inl_hook::target() const noexcept { return m_state ? m_state->target : nullptr; }
    uintptr_t inl_hook::target_address() const noexcept { return reinterpret_cast<uintptr_t>(target()); }
    uint8_t* inl_hook::destination() const noexcept { return m_state ? m_state->destination : nullptr; }
    uintptr_t inl_hook::destination_address() const noexcept { return reinterpret_cast<uintptr_t>(destination()); }
    const inl_hook::allocation& inl_hook::trampoline() const noexcept
    { static const allocation empty; return m_state ? m_state->trampoline : empty; }
    const std::vector<uint8_t>& inl_hook::original_bytes() const noexcept
    { static const std::vector<uint8_t> empty; return m_state ? m_state->saved : empty; }
}
