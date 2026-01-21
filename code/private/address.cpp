#include "memlib/address.hpp"


#include <Zydis/Zydis.h>

namespace
{
    using namespace memlib;

#if MEMLIB_IS_64
    #define ZYDIS_MACHINE_MODE ZYDIS_MACHINE_MODE_LONG_64
    #define ZYDIS_STACK_WIDTH ZYDIS_STACK_WIDTH_64
#else
    #define ZYDIS_MACHINE_MODE ZYDIS_MACHINE_MODE_LEGACY_32
    #define ZYDIS_STACK_WIDTH ZYDIS_STACK_WIDTH_32
#endif

    ZydisDecoder& get_decoder()
    {
        static bool init = false;
        static ZydisDecoder decoder;

        if (!init)
        {
            ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE, ZYDIS_STACK_WIDTH);
            init = true;
        }

        return decoder;
    }



    bool zydis_decode(void* p, ZydisDecodedInstruction& inst, ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]) noexcept
    {
        /* this should probably be handled by the caller.
        if (!is_readable(p, ZYDIS_MAX_INSTRUCTION_LENGTH))
            return false;
        */

        auto& decoder = get_decoder();
        return ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, p, 16, &inst, ops));
    }

}

namespace memlib
{

    bool address::is_valid() const noexcept
    {
        if (!m_value)
            return false;

        return query(ptr()).has_value();
    }

    bool address::is_readable(size_t bytes) const noexcept
    {
        if (!m_value)
            return false;

        return memlib::is_readable(ptr(), bytes);
    }

    bool address::is_writable(size_t bytes) const noexcept
    {
        if (!m_value)
            return false;

        return memlib::is_writable(ptr(), bytes);
    }

    bool address::is_executable(size_t bytes) const noexcept
    {
        if (!m_value)
            return false;

        return memlib::is_executable(ptr(), bytes);
    }

    std::optional<module_info> address::module() const noexcept
    {
        if (!m_value)
            return std::nullopt;

        return module_from_address(ptr());
    }

    std::optional<section_info> address::section() const noexcept
    {
        if (!m_value)
            return std::nullopt;

        return section_from_address(ptr());
    }

    std::optional<region_info> address::region() const noexcept
    {
        if (!m_value)
            return std::nullopt;

        return query(ptr());
    }

    address address::dereference_pointer(size_t count) const noexcept
    {
        address cur = *this;

        for (size_t i = 0; i < count; ++i)
        {
            if (!cur.is_readable(sizeof(void*)))
                return address{};

            value_type next{};
            if constexpr (MEMLIB_IS_64)
            {
                uint64_t v{};
                if (!cur.read(v))
                    return address{};

                next = static_cast<value_type>(v);
            }
            else
            {
                uint32_t v{};
                if (!cur.read(v))
                    return address{};

                next = static_cast<value_type>(v);
            }

            cur = address(next);
            if (!cur)
                return address{};
        }

        return cur;
    }

    address address::follow(std::initializer_list<value_type> offsets) const noexcept
    {
        if (!m_value)
            return {};

        address cur = *this;

        bool first = true;
        for (auto off : offsets)
        {
            if (first)
            {
                cur = cur + off;
                first = false;
                continue;
            }

            cur = cur.dereference_pointer(1);
            if (!cur)
                return {};

            cur = cur + off;
        }

        return cur;
    }

    address address::dereference_call() const noexcept
    {
        ZydisDecodedInstruction inst{};
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!zydis_decode(ptr(), inst, ops))
            return {};

        if (inst.mnemonic != ZYDIS_MNEMONIC_CALL)
            return {};

        for (uint8_t i = 0; i < inst.operand_count_visible; ++i)
        {
            const auto& op = ops[i];
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative)
            {
                const int64_t disp = op.imm.value.s;
                return resolve_relative(disp, inst.length);
            }
        }

        return {};
    }

    address address::dereference_branch() const noexcept
    {
        ZydisDecodedInstruction inst{};
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!zydis_decode(ptr(), inst, ops))
            return {};

        const bool is_jmp = (inst.mnemonic == ZYDIS_MNEMONIC_JMP);

        const bool is_jcc =
            (inst.mnemonic >= ZYDIS_MNEMONIC_JB && inst.mnemonic <= ZYDIS_MNEMONIC_JZ) ||
            inst.mnemonic == ZYDIS_MNEMONIC_JECXZ || inst.mnemonic == ZYDIS_MNEMONIC_JRCXZ;

        if (!is_jmp && !is_jcc)
            return {};

        for (uint8_t i = 0; i < inst.operand_count_visible; ++i)
        {
            const auto& op = ops[i];
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative)
            {
                const int64_t disp = op.imm.value.s;
                return resolve_relative(disp, inst.length);
            }
        }

        return {};
    }

#if MEMLIB_IS_64
    address address::resolve_rip_relative() const noexcept
    {
        ZydisDecodedInstruction inst{};
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT_VISIBLE]{};
        if (!zydis_decode(ptr(), inst, ops))
            return {};

        // Look for memory operand with base = RIP
        for (uint8_t i = 0; i < inst.operand_count_visible; ++i)
        {
            const auto& op = ops[i];
            if (op.type != ZYDIS_OPERAND_TYPE_MEMORY)
                continue;

            if (op.mem.base != ZYDIS_REGISTER_RIP)
                continue;

            // Effective address: next_ip + disp
            const int64_t    disp = op.mem.disp.value;
            const value_type next_ip = m_value + inst.length;

            return address(static_cast<value_type>(next_ip + disp));
        }

        return {};
    }
#endif
}