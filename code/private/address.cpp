#include "memlib/address.hpp"


#include <Zydis/Zydis.h>
#include "internal.hpp"

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
        static ZydisDecoder decoder = []()
        {
            ZydisDecoder d{};
            ZydisDecoderInit(&d, ZYDIS_MACHINE_MODE, ZYDIS_STACK_WIDTH);
            return d;
        }();

        return decoder;
    }



    bool zydis_decode(
        void* p,
        ZydisDecodedInstruction& inst,
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]
    ) noexcept
    {
        auto& decoder = get_decoder();
        return ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, p, ZYDIS_MAX_INSTRUCTION_LENGTH, &inst, ops));
    }



    memlib::address resolve_memory_operand_storage(
        const memlib::address instr_addr,
        const ZydisDecodedInstruction& inst,
        const ZydisDecodedOperand& op) noexcept
    {
        if (op.type != ZYDIS_OPERAND_TYPE_MEMORY)
            return {};

#if MEMLIB_IS_64
        if (op.mem.base == ZYDIS_REGISTER_RIP)
        {
            const auto next_ip = static_cast<memlib::address::value_type>(instr_addr.value() + inst.length);
            const auto disp = static_cast<int64_t>(op.mem.disp.value);
            return memlib::address(static_cast<memlib::address::value_type>(next_ip + disp));
        }
#else
        UNREFERENCED_PARAMETER(inst);
        UNREFERENCED_PARAMETER(instr_addr);
#endif

        if (op.mem.base == ZYDIS_REGISTER_NONE && op.mem.index == ZYDIS_REGISTER_NONE)
        {
            if (!op.mem.disp.has_displacement)
                return {};

#if MEMLIB_IS_64
            return memlib::address(static_cast<memlib::address::value_type>(op.mem.disp.value));
#else
            return memlib::address(static_cast<memlib::address::value_type>(static_cast<uint32_t>(op.mem.disp.value)));
#endif
        }

        return {};
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



    rva_t address::rva() const noexcept
    {
        const auto mod = this->module();
        if (!mod || !mod->base)
        {
            MEMLIB_DEBUG("Cannot compute RVA for address {} because it does not belong to a known module.", ptr());
            return std::nullopt;
        }

        const size_t base = static_cast<size_t>(mod->base);
        if (m_value < base)
        {
            MEMLIB_DEBUG("Cannot compute RVA for address {} because it is below the module base 0x{:x}.", ptr(), mod->base);
            return std::nullopt;
        }

        const size_t rva = m_value - base;
        if (rva >= mod->size)
        {
            MEMLIB_DEBUG("Cannot compute RVA for address {} because it is outside the module range [0x{:x}, 0x{:x}).", ptr(), mod->base, (mod->base + mod->size));
            return std::nullopt;
        }

        return rva;
    }



    address address::dereference_pointer() const noexcept
    {
        if (!is_readable(ZYDIS_MAX_INSTRUCTION_LENGTH))
            return {};

        ZydisDecodedInstruction inst{};
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!zydis_decode(ptr(), inst, ops))
            return {};

        // 1) Prefer statically resolvable memory operands.
        for (uint8_t i = 0; i < inst.operand_count_visible; ++i)
        {
            const auto& op = ops[i];
            if (op.type != ZYDIS_OPERAND_TYPE_MEMORY)
                continue;

            const address addr = resolve_memory_operand_storage(*this, inst, op);
            if (addr)
                return addr;
        }

        // 2) Handle reliable immediate-address forms.
        switch (inst.mnemonic)
        {
            case ZYDIS_MNEMONIC_MOV:
            case ZYDIS_MNEMONIC_PUSH:
            {
                for (uint8_t i = 0; i < inst.operand_count_visible; ++i)
                {
                    const auto& op = ops[i];
                    if (op.type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
                        continue;

                    if (op.imm.is_relative)
                        continue;

                #if MEMLIB_IS_64
                    return address(static_cast<value_type>(op.imm.value.u));
                #else
                    return address(static_cast<value_type>(static_cast<uint32_t>(op.imm.value.u)));
                #endif
                }

                break;
            }

            default:
                break;
        }

        return {};
    }

    address address::dereference_call() const noexcept
    {
        if (!is_readable(ZYDIS_MAX_INSTRUCTION_LENGTH))
            return {};

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

}