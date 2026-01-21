#pragma once

#include "memory.hpp"

namespace memlib
{
    class address
    {
    public:
        using value_type = uintptr_t;

        constexpr address() noexcept = default;
        constexpr address(nullptr_t) noexcept : m_value(0) {}
        constexpr explicit address(value_type v) noexcept : m_value(v) {}

        explicit address(const void* p) noexcept
            : m_value(reinterpret_cast<value_type>(p)) {
        }

        constexpr value_type value() const noexcept { return m_value; }

        void* ptr() const noexcept { return reinterpret_cast<void*>(m_value); }

        explicit operator bool() const noexcept { return m_value != 0; }

        template <class T>
        T as() const noexcept { return reinterpret_cast<T>(m_value); }

    public:
        constexpr address& operator+=(value_type off) noexcept { m_value += off; return *this; }
        constexpr address& operator-=(value_type off) noexcept { m_value -= off; return *this; }
        constexpr address operator+(value_type off) const noexcept { return address(m_value + off); }
        constexpr address operator-(value_type off) const noexcept { return address(m_value - off); }
        constexpr value_type operator-(address rhs) const noexcept { return m_value - rhs.m_value; }
        constexpr address& operator++() noexcept { ++m_value; return *this; }
        constexpr address& operator--() noexcept { --m_value; return *this; }
        constexpr address operator++(int) noexcept { address tmp = *this; ++m_value; return tmp; }
        constexpr address operator--(int) noexcept { address tmp = *this; --m_value; return tmp; }

        constexpr bool operator==(address rhs) const noexcept { return m_value == rhs.m_value; }
        constexpr bool operator!=(address rhs) const noexcept { return m_value != rhs.m_value; }
        constexpr bool operator< (address rhs) const noexcept { return m_value < rhs.m_value; }
        constexpr bool operator<=(address rhs) const noexcept { return m_value <= rhs.m_value; }
        constexpr bool operator> (address rhs) const noexcept { return m_value > rhs.m_value; }
        constexpr bool operator>=(address rhs) const noexcept { return m_value >= rhs.m_value; }

        constexpr bool operator==(value_type rhs) const noexcept { return m_value == rhs; }
        constexpr bool operator!=(value_type rhs) const noexcept { return m_value != rhs; }
        constexpr bool operator< (value_type rhs) const noexcept { return m_value < rhs; }
        constexpr bool operator<=(value_type rhs) const noexcept { return m_value <= rhs; }
        constexpr bool operator> (value_type rhs) const noexcept { return m_value > rhs; }
        constexpr bool operator>=(value_type rhs) const noexcept { return m_value >= rhs; }

        friend constexpr bool operator==(value_type lhs, address rhs) noexcept { return lhs == rhs.m_value; }
        friend constexpr bool operator!=(value_type lhs, address rhs) noexcept { return lhs != rhs.m_value; }
        friend constexpr bool operator< (value_type lhs, address rhs) noexcept { return lhs < rhs.m_value; }
        friend constexpr bool operator<=(value_type lhs, address rhs) noexcept { return lhs <= rhs.m_value; }
        friend constexpr bool operator> (value_type lhs, address rhs) noexcept { return lhs > rhs.m_value; }
        friend constexpr bool operator>=(value_type lhs, address rhs) noexcept { return lhs >= rhs.m_value; }

    public:
        bool is_valid() const noexcept;
        bool is_readable(size_t bytes = 1) const noexcept;
        bool is_writable(size_t bytes = 1) const noexcept;
        bool is_executable(size_t bytes = 1) const noexcept;

    public:
        std::optional<module_info>  module()  const noexcept;
        std::optional<section_info> section() const noexcept;
        std::optional<region_info>  region()  const noexcept;

    public:
        template <class T>
        bool read(T& out) const noexcept
        {
            static_assert(is_trivially_memcpyable_v<T>, "read<T> requires trivially copyable T");
            if (!is_readable(sizeof(T)))
                return false;

            std::memcpy(&out, ptr(), sizeof(T));
            return true;
        }

        template <class T>
        T read_or(T fallback = {}) const noexcept
        {
            T v{};
            return read(v) ? v : fallback;
        }

        template <class T>
        bool write(const T& in) const noexcept
        {
            static_assert(is_trivially_memcpyable_v<T>, "write<T> requires trivially copyable T");
            if (!is_writable(sizeof(T)))
                return false;

            std::memcpy(ptr(), &in, sizeof(T));
            return true;
        }

    public:
        address dereference_pointer(size_t count = 1) const noexcept; // *(...*(this))
        address follow(std::initializer_list<value_type> offsets) const noexcept; // *(base+o0)->... + on

        // Resolve common RE patterns
        // - call rel32 / jmp rel32: returns target, else returns 0
        address dereference_call() const noexcept;
        address dereference_branch() const noexcept; // jmp + jcc rel

#if MEMLIB_IS_64
        // Resolve RIP-relative memory operand target address for x64 instructions like:
        //   mov rax, [rip+disp32]
        // returns absolute address if found, else 0.
        address resolve_rip_relative() const noexcept;
#endif

        // Manual relative resolver:
        // target = this + instr_len + disp
        address resolve_relative(int64_t disp, size_t instr_len) const noexcept
        {
            return address(static_cast<value_type>(m_value + instr_len + disp));
        }

    private:
        value_type m_value = 0;
    };

}