#pragma once

#include "macros.hpp"
#include "os.hpp"

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <mutex>
#include <algorithm>
#include <type_traits>

#if MEMLIB_IS_WINDOWS
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif

    #ifndef NOMINMAX
        #define NOMINMAX
    #endif

    #include <windows.h>
    #include <psapi.h>
#elif MEMLIB_IS_LINUX
#endif
#include <functional>

namespace memlib
{
    template <class T>
    constexpr bool is_trivially_memcpyable_v =
        std::is_trivially_copyable_v<T> && std::is_standard_layout_v<T>;

    enum class section : uint8_t
    {
        text,
        rdata,
        data,
        bss,
        edata,
        idata,
        reloc,
        rsrc,
        tls,
        pdata,
        debug,
        max
    };

    struct section_info
    {
        std::string name{};
        void*       start      = nullptr;
        size_t      size       = 0;
        prot        protection = prot::none;

        explicit operator bool() const noexcept { return start != nullptr && size != 0; }
    };

    struct region_info
    {
        void*       start      = nullptr;
        void*       end        = nullptr;
        prot        protection = prot::none;
        std::string mapped_path{};

        explicit operator bool() const noexcept { return start != nullptr && end != nullptr && start < end; }
    };

    struct module_info
    {
        void*       base = nullptr;
        size_t      size = 0;
        std::string path{};
        std::string name{};

        explicit operator bool() const noexcept { return base != nullptr; }
    };

    struct scan_pattern
    {
        size_t  length = 0;
        uint8_t bytes[256]{};
        char    mask[256]{}; // 'x' = match, '?' = wildcard
    };

    struct span_pattern
    {
        const char* combo = nullptr;
        section     section = section::text;
    };

    std::optional<region_info> query(void* p) noexcept;

    bool  protect(void* p, size_t size, prot new_prot, prot* old_prot_out = nullptr) noexcept;
    void* alloc(size_t size, prot p = prot::r | prot::w) noexcept;
    bool  free(void* p, size_t size = 0) noexcept;
    void  flush_icache(void* p, size_t size) noexcept;

    std::optional<module_info>  module_from_address(void* p) noexcept;
    std::optional<section_info> section_from_address(void* p) noexcept;

    bool is_readable(void* p, size_t bytes = 1) noexcept;
    bool is_writable(void* p, size_t bytes = 1) noexcept;
    bool is_executable(void* p, size_t bytes = 1) noexcept;

    bool is_readable_protect(DWORD protect) noexcept;

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
        constexpr address add(value_type off) const noexcept { return address(m_value + off); }
        constexpr address sub(value_type off) const noexcept { return address(m_value - off); }
        constexpr address& operator+=(value_type off) noexcept { m_value += off; return *this; }
        constexpr address& operator-=(value_type off) noexcept { m_value -= off; return *this; }
        constexpr address operator+(value_type off) const noexcept { return add(off); }
        constexpr address operator-(value_type off) const noexcept { return sub(off); }
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

    bool parse_combo_pattern(const char* combo, scan_pattern& out) noexcept;

    class scanner
    {
    public:
        using callback = std::function<address (address addr)>;
        using callback_any = std::function<address(size_t index, address addr)>;

        scanner(const char* modulename = nullptr);

        [[nodiscard]] inline bool is_valid() const noexcept { return m_module != nullptr; }
        explicit operator bool() const noexcept { return m_module != nullptr; }

        [[nodiscard]] address find(const scan_pattern& pattern, void* start, size_t length, int32_t offset = 0x0000) const noexcept;
        [[nodiscard]] address find(const char*         combo  , void* start, size_t length, int32_t offset = 0x0000) const noexcept;

        [[nodiscard]] address find(const scan_pattern& pattern, section sec, int32_t offset = 0x0000) const noexcept;
        [[nodiscard]] address find(const char*         combo  , section sec, int32_t offset = 0x0000) const noexcept;

    protected:
        section_info m_sections[uint8_t(section::max)] = {};
#if MEMLIB_IS_WINDOWS
        HMODULE      m_module                          = nullptr;
#elif MEMLIB_IS_LINUX
        void*        m_module                          = nullptr;
#endif
    };
}
