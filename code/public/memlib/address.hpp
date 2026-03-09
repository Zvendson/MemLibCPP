#pragma once

#include "memory.hpp"

namespace memlib
{
	using rva_t = std::optional<size_t>;

    /**
     * @brief Wrapper around a raw process address.
     *
     * Provides:
     * - raw address conversion utilities
     * - address arithmetic
     * - checked memory/property queries
     * - unchecked and checked typed memory access
     * - common reverse-engineering helpers for instruction-based pointer/call resolution
     *
     * This class does not own memory. It is only a typed utility around a uintptr_t.
     */
    class address
    {
    public: /* Ctor and similar */
        using value_type = uintptr_t;

        /** @brief Constructs a null address. */
        constexpr address() noexcept = default;

        /** @brief Constructs a null address from nullptr. */
        constexpr address(nullptr_t) noexcept : m_value(0) {}

        /**
         * @brief Constructs an address from an integer value.
         * @param v Raw address value.
         */
        constexpr explicit address(value_type v) noexcept : m_value(v) {}

        /**
         * @brief Constructs an address from a raw pointer.
         * @param p Raw pointer to convert.
         */
        explicit address(const void* p) noexcept
            : m_value(reinterpret_cast<value_type>(p)) {
        }

        /**
         * @brief Returns the raw integer address.
         * @return Stored address as uintptr_t.
         */
        constexpr value_type value() const noexcept { return m_value; }

        /**
         * @brief Returns the address as void*.
         * @return Stored address as void*.
         */
        void* ptr() const noexcept { return reinterpret_cast<void*>(m_value); }

        /**
         * @brief Checks whether the address is non-null.
         * @return true if the stored address is not zero.
         */
        explicit operator bool() const noexcept { return m_value != 0; }


        /**
         * @brief Reinterprets the stored address as another type.
         * @tparam T Target type, typically a pointer type.
         * @return Address reinterpreted as T.
         *
         * @code
         * auto p = addr.as<uint32_t*>();
         * @endcode
         */
        template <class T>
        T as() const noexcept { return reinterpret_cast<T>(m_value); }

    public: /* operators */

        /** @brief Adds a byte offset to this address. */
        constexpr address& operator+=(value_type off) noexcept { m_value += off; return *this; }

        /** @brief Subtracts a byte offset from this address. */
        constexpr address& operator-=(value_type off) noexcept { m_value -= off; return *this; }

        /** @brief Returns a new address advanced by @p off bytes. */
        constexpr address operator+(value_type off) const noexcept { return address(m_value + off); }

        /** @brief Returns a new address moved back by @p off bytes. */
        constexpr address operator-(value_type off) const noexcept { return address(m_value - off); }

        /** @brief Returns the byte distance between two addresses. */
        constexpr value_type operator-(address rhs) const noexcept { return m_value - rhs.m_value; }

        /** @brief Prefix increment by one byte. */
        constexpr address& operator++() noexcept { ++m_value; return *this; }

        /** @brief Prefix decrement by one byte. */
        constexpr address& operator--() noexcept { --m_value; return *this; }

        /** @brief Postfix increment by one byte. */
        constexpr address operator++(int) noexcept { address tmp = *this; ++m_value; return tmp; }

        /** @brief Postfix decrement by one byte. */
        constexpr address operator--(int) noexcept { address tmp = *this; --m_value; return tmp; }



        /** @brief Compares two addresses for equality. */
        constexpr bool operator==(address rhs) const noexcept { return m_value == rhs.m_value; }

        /** @brief Compares two addresses for inequality. */
        constexpr bool operator!=(address rhs) const noexcept { return m_value != rhs.m_value; }

        /** @brief Less-than comparison between two addresses. */
        constexpr bool operator<(address rhs) const noexcept { return m_value < rhs.m_value; }

        /** @brief Less-or-equal comparison between two addresses. */
        constexpr bool operator<=(address rhs) const noexcept { return m_value <= rhs.m_value; }

        /** @brief Greater-than comparison between two addresses. */
        constexpr bool operator>(address rhs) const noexcept { return m_value > rhs.m_value; }

        /** @brief Greater-or-equal comparison between two addresses. */
        constexpr bool operator>=(address rhs) const noexcept { return m_value >= rhs.m_value; }



        /** @brief Compares the address against a raw integer value. */
        constexpr bool operator==(value_type rhs) const noexcept { return m_value == rhs; }
        constexpr bool operator!=(value_type rhs) const noexcept { return m_value != rhs; }
        constexpr bool operator<(value_type rhs) const noexcept { return m_value < rhs; }
        constexpr bool operator<=(value_type rhs) const noexcept { return m_value <= rhs; }
        constexpr bool operator>(value_type rhs) const noexcept { return m_value > rhs; }
        constexpr bool operator>=(value_type rhs) const noexcept { return m_value >= rhs; }



        /** @brief Symmetric comparisons for raw integer values on the left-hand side. */
        friend constexpr bool operator==(value_type lhs, address rhs) noexcept { return lhs == rhs.m_value; }
        friend constexpr bool operator!=(value_type lhs, address rhs) noexcept { return lhs != rhs.m_value; }
        friend constexpr bool operator< (value_type lhs, address rhs) noexcept { return lhs < rhs.m_value; }
        friend constexpr bool operator<=(value_type lhs, address rhs) noexcept { return lhs <= rhs.m_value; }
        friend constexpr bool operator> (value_type lhs, address rhs) noexcept { return lhs > rhs.m_value; }
        friend constexpr bool operator>=(value_type lhs, address rhs) noexcept { return lhs >= rhs.m_value; }

    public: /* methods */
        /**
         * @brief Checks whether the address belongs to a valid mapped region.
         * @return true if the address resolves to a known memory region.
         */
        [[nodiscard]] bool is_valid() const noexcept;

        /**
         * @brief Checks whether the address range is readable.
         * @param bytes Number of bytes that must be readable.
         * @return true if the range is readable.
         */
        [[nodiscard]] bool is_readable(size_t bytes = 1) const noexcept;

        /**
         * @brief Checks whether the address range is writable.
         * @param bytes Number of bytes that must be writable.
         * @return true if the range is writable.
         */
        [[nodiscard]] bool is_writable(size_t bytes = 1) const noexcept;

        /**
         * @brief Checks whether the address range is executable.
         * @param bytes Number of bytes that must be executable.
         * @return true if the range is executable.
         */
        [[nodiscard]] bool is_executable(size_t bytes = 1) const noexcept;

        /**
         * @brief Checks whether the address is aligned to a given boundary.
         * @param alignment Alignment in bytes.
         * @return true if the address is aligned to @p alignment.
         */
        [[nodiscard]] bool is_aligned(size_t alignment) const noexcept
        {
            return alignment != 0 && (m_value % alignment) == 0;
        }

        /**
         * @brief Resolves the module containing this address.
         * @return Module metadata on success, std::nullopt otherwise.
         */
        [[nodiscard]] std::optional<module_info> module()  const noexcept;

        /**
         * @brief Resolves the section containing this address.
         * @return Section metadata on success, std::nullopt otherwise.
         */
        [[nodiscard]] std::optional<section_info> section() const noexcept;

        /**
         * @brief Resolves the memory region containing this address.
         * @return Region metadata on success, std::nullopt otherwise.
         */
        [[nodiscard]] std::optional<region_info> region()  const noexcept;

        /**
         * @brief Computes the relative virtual address inside the owning module.
         * @return RVA on success, std::nullopt if the address is not inside a known module.
         *
         * Note that RVA 0 is valid, so std::optional is used to distinguish failure.
         */
        [[nodiscard]] rva_t rva() const noexcept;

        /**
         * @brief Returns a new address offset by a signed byte displacement.
         * @param off Signed byte offset.
         * @return New shifted address.
         */
        [[nodiscard]] constexpr address offset(ptrdiff_t off) const noexcept
        {
            return address(static_cast<value_type>(m_value + off));
        }

        /**
         * @brief Decodes the instruction at this address and extracts a referenced pointer.
         * @return Decoded runtime pointer on success, null address otherwise.
         *
         * This is an instruction-based helper for reverse engineering.
         * (!) It does not perform a plain raw pointer dereference.
         *
         * Supported forms are statically resolvable memory operands such as:
         * - x64 RIP-relative memory references
         * - absolute memory references without register context
         *
         * Register-based operands such as [rcx], [rax+10], call rax, etc. are not resolved.
         */
        [[nodiscard]] address dereference_pointer() const noexcept;

        /**
         * @brief Decodes a call instruction and resolves its destination.
         * @return Final resolved call target on success, null address otherwise.
         *
         * Supported forms include:
         * - direct relative calls (call rel32 / rel16)
         * - memory-based calls with statically resolvable operands
         *
         * Implementations may follow simple jump thunks automatically.
         */
        [[nodiscard]] address dereference_call() const noexcept;

        /**
         * @brief Resolves a relative target using instruction length and displacement.
         * @param disp Signed relative displacement.
         * @param instr_len Length of the instruction in bytes.
         * @return Absolute target address.
         *
         * Computes:
         * target = this + instr_len + disp
         */
        [[nodiscard]] address resolve_relative(int64_t disp, size_t instr_len) const noexcept
        {
            const auto base = static_cast<int64_t>(m_value);
            const auto len = static_cast<int64_t>(instr_len);
            return address(static_cast<value_type>(base + len + disp));
        }

        /**
         * @brief Reads a trivially copyable object from this address without safety checks.
         * @tparam T Type to read.
         * @param out Destination object.
         * @return Always true.
         *
         * This is an unchecked raw memory read. The caller must ensure the address is valid.
         */
        template <class T>
        bool read(T& out) const noexcept
        {
            static_assert(is_trivially_memcpyable_v<T>, "read<T> requires trivially copyable T");
            std::memcpy(&out, ptr(), sizeof(T));
            return true;
        }

        /**
         * @brief Safely reads a trivially copyable object from this address.
         * @tparam T Type to read.
         * @return The read value on success, std::nullopt on failure.
         */
        template <class T>
        [[nodiscard]] std::optional<T> try_read() const noexcept
        {
            static_assert(is_trivially_memcpyable_v<T>, "try_read<T> requires trivially copyable T");

            if (!is_readable(sizeof(T)))
                return std::nullopt;

            T out{};
            std::memcpy(&out, ptr(), sizeof(T));
            return out;
        }

        /**
         * @brief Writes a trivially copyable object to this address without safety checks.
         * @tparam T Type to write.
         * @param in Value to write.
         *
         * This is an unchecked raw memory write. The caller must ensure the address is valid.
         */
        template <class T>
        void write(const T& in) const noexcept
        {
            static_assert(is_trivially_memcpyable_v<T>, "write<T> requires trivially copyable T");
            std::memcpy(ptr(), &in, sizeof(T));
        }

        /**
         * @brief Safely writes a trivially copyable object to this address.
         * @tparam T Type to write.
         * @param in Value to write.
         * @return true on success, false if the target range is not writable.
         */
        template <class T>
        [[nodiscard]] bool try_write(const T& in) const noexcept
        {
            static_assert(is_trivially_memcpyable_v<T>, "try_write<T> requires trivially copyable T");

            if (!is_writable(sizeof(T)))
                return false;

            std::memcpy(ptr(), &in, sizeof(T));
            return true;
        }

    protected:
        /** @brief Stored raw address value. */
        value_type m_value = 0;
    };
}

#if MEMLIB_HAS_STD_FORMAT
namespace std
{
    template <>
    struct formatter<memlib::address, char>
    {
        constexpr auto parse(std::format_parse_context& ctx) -> std::format_parse_context::iterator
        {
            auto it = ctx.begin();
            if (it != ctx.end() && *it != '}')
                throw std::format_error("invalid format for memlib::address");
            return it;
        }

        auto format(const memlib::address& value, std::format_context& ctx) const -> std::format_context::iterator
        {
            return std::format_to(ctx.out(), "0x{:X}", static_cast<std::uintptr_t>(value.value()));
        }
    };

    template <>
    struct formatter<memlib::rva_t, char>
    {
        constexpr auto parse(std::format_parse_context& ctx) -> std::format_parse_context::iterator
        {
            auto it = ctx.begin();
            const auto end = ctx.end();

            if (it != end && *it != '}')
                throw std::format_error("invalid format for memlib::rva_t");

            return it;
        }

        auto format(const memlib::rva_t& value, std::format_context& ctx) const -> std::format_context::iterator
        {
            if (!value.has_value())
                return std::format_to(ctx.out(), "n/a");

            return std::format_to(ctx.out(), "0x{:X}", static_cast<std::size_t>(*value));
        }
    };
}
#endif

#if MEMLIB_HAS_FMT
template <>
struct fmt::formatter<memlib::address>
{
    constexpr auto parse(fmt::format_parse_context& ctx) -> fmt::format_parse_context::iterator
    {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const memlib::address& value, FormatContext& ctx) const -> typename FormatContext::iterator
    {
        return fmt::format_to(ctx.out(), "{}", value.ptr());
    }
};

template <>
struct fmt::formatter<memlib::rva_t>
{
    constexpr auto parse(fmt::format_parse_context& ctx) -> fmt::format_parse_context::iterator
    {
        auto it = ctx.begin();
        const auto end = ctx.end();

        if (it != end && *it != '}')
            throw fmt::format_error("invalid format for memlib::rva_t");

        return it;
    }

    template <typename FormatContext>
    auto format(const memlib::rva_t& value, FormatContext& ctx) const -> typename FormatContext::iterator
    {
        if (!value.has_value())
            return fmt::format_to(ctx.out(), "n/a");

        return fmt::format_to(ctx.out(), "0x{:X}", *value);
    }
};
#endif