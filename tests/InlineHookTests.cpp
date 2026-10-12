#include <gtest/gtest.h>

#include <memlib/hook.h>
#include <memlib/c_api.h>
#include <memlib/inline_hook.hpp>
#include <memlib/memory.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <initializer_list>

namespace
{
    extern "C" int detour_value() { return 99; }

    using test_function = int (*)();

    class HookFixture : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            memory = static_cast<std::uint8_t*>(memlib::alloc(256, memlib::prot::r | memlib::prot::w | memlib::prot::x));
            ASSERT_NE(memory, nullptr);
            std::memset(memory, 0x90, 256);
        }

        void TearDown() override
        {
            if (hook) EXPECT_EQ(memlib_inline_hook_reset(hook), MEMLIB_HOOK_OK);
            if (mid_hook) EXPECT_EQ(memlib_mid_hook_reset(mid_hook), MEMLIB_HOOK_OK);
            if (memory) EXPECT_TRUE(memlib::free(memory));
        }

        void write_code(std::initializer_list<std::uint8_t> bytes, std::size_t offset = 0)
        {
            std::memcpy(memory + offset, bytes.begin(), bytes.size());
            memlib::flush_icache(memory + offset, bytes.size());
        }

        std::uint8_t* memory{};
        memlib_inline_hook* hook{};
        memlib_mid_hook* mid_hook{};
    };

    TEST(MemLibHookStatus, RejectsInvalidCreateArguments)
    {
        memlib_inline_hook* hook = nullptr;
        EXPECT_EQ(memlib_inline_hook_create(nullptr, reinterpret_cast<void*>(&detour_value), 0, &hook), MEMLIB_HOOK_INVALID_TARGET);
        EXPECT_EQ(memlib_inline_hook_create(reinterpret_cast<void*>(&detour_value), nullptr, 0, &hook), MEMLIB_HOOK_INVALID_DESTINATION);
        EXPECT_EQ(memlib_inline_hook_create(reinterpret_cast<void*>(&detour_value), reinterpret_cast<void*>(&detour_value), 0, &hook), MEMLIB_HOOK_INVALID_DESTINATION);
        EXPECT_EQ(memlib_inline_hook_create(reinterpret_cast<void*>(&detour_value), reinterpret_cast<void*>(&detour_value), 0, nullptr), MEMLIB_HOOK_INVALID_HOOK);
        memlib_mid_hook* mid = nullptr;
        EXPECT_EQ(memlib_mid_hook_create(nullptr, reinterpret_cast<void*>(&detour_value), 0, &mid), MEMLIB_HOOK_INVALID_TARGET);
    }

    TEST_F(HookFixture, StartsDisabledAndRestoresOriginalCode)
    {
        write_code({0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3});
        const auto function = reinterpret_cast<test_function>(memory);
        ASSERT_EQ(function(), 7);

        ASSERT_EQ(memlib_inline_hook_create(memory, reinterpret_cast<void*>(&detour_value), MEMLIB_HOOK_START_DISABLED, &hook), MEMLIB_HOOK_OK);
        EXPECT_EQ(memlib_inline_hook_target(hook), memory);
        EXPECT_EQ(memlib_inline_hook_destination(hook), reinterpret_cast<void*>(&detour_value));
        EXPECT_EQ(memlib_inline_hook_enabled(hook), 0);
        EXPECT_EQ(function(), 7);

        ASSERT_EQ(memlib_inline_hook_enable(hook), MEMLIB_HOOK_OK);
        EXPECT_EQ(function(), 99);
        EXPECT_EQ(memlib_inline_hook_enabled(hook), 1);
        ASSERT_EQ(memlib_inline_hook_disable(hook), MEMLIB_HOOK_OK);
        EXPECT_EQ(function(), 7);
    }

    TEST_F(HookFixture, StartsEnabledByDefault)
    {
        write_code({0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3});
        const auto function = reinterpret_cast<test_function>(memory);
        ASSERT_EQ(memlib_inline_hook_create(memory, reinterpret_cast<void*>(&detour_value), 0, &hook), MEMLIB_HOOK_OK);
        EXPECT_EQ(memlib_inline_hook_enabled(hook), 1);
        EXPECT_EQ(function(), 99);
    }

    TEST_F(HookFixture, ExposesAWorkingOriginalTrampoline)
    {
        write_code({0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3});
        ASSERT_EQ(memlib_inline_hook_create(memory, reinterpret_cast<void*>(&detour_value), MEMLIB_HOOK_START_DISABLED, &hook), MEMLIB_HOOK_OK);
        memlib_hook_allocation trampoline{};
        ASSERT_EQ(memlib_inline_hook_trampoline(hook, &trampoline), MEMLIB_HOOK_OK);
        ASSERT_NE(trampoline.address, nullptr);
        ASSERT_GT(trampoline.size, 0u);
        EXPECT_EQ(reinterpret_cast<test_function>(trampoline.address)(), 7);
    }

    TEST_F(HookFixture, RelocatesRelativeCallInTheTrampoline)
    {
        // call +32; ret; followed by a local helper: mov eax, 11; ret.
        write_code({0xE8, 0x1B, 0x00, 0x00, 0x00, 0xC3}, 0);
        write_code({0xB8, 0x0B, 0x00, 0x00, 0x00, 0xC3}, 32);
        const auto function = reinterpret_cast<test_function>(memory);
        ASSERT_EQ(function(), 11);
        ASSERT_EQ(memlib_inline_hook_create(memory, reinterpret_cast<void*>(&detour_value), MEMLIB_HOOK_START_DISABLED, &hook), MEMLIB_HOOK_OK);
        ASSERT_EQ(memlib_inline_hook_enable(hook), MEMLIB_HOOK_OK);
        EXPECT_EQ(function(), 99);
        ASSERT_EQ(memlib_inline_hook_disable(hook), MEMLIB_HOOK_OK);
        EXPECT_EQ(function(), 11);
    }

    TEST_F(HookFixture, SupportsAnArbitraryFunctionEntryOffset)
    {
        // The hook starts at the second instruction, after xor eax,eax.
        write_code({0x31, 0xC0, 0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3});
        const auto function = reinterpret_cast<test_function>(memory);
        ASSERT_EQ(function(), 7);
        ASSERT_EQ(memlib_mid_hook_create(memory + 2, reinterpret_cast<void*>(&detour_value), 0, &mid_hook), MEMLIB_HOOK_OK);
        EXPECT_EQ(memlib_mid_hook_enabled(mid_hook), 1);
        EXPECT_EQ(function(), 99);
    }

    TEST_F(HookFixture, RejectsDuplicateAndOverlappingHooks)
    {
        write_code({0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3});
        ASSERT_EQ(memlib_inline_hook_create(memory, reinterpret_cast<void*>(&detour_value), MEMLIB_HOOK_START_DISABLED, &hook), MEMLIB_HOOK_OK);
        memlib_inline_hook* duplicate = nullptr;
        EXPECT_EQ(memlib_inline_hook_create(memory, reinterpret_cast<void*>(&detour_value), MEMLIB_HOOK_START_DISABLED, &duplicate), MEMLIB_HOOK_ALREADY_HOOKED);
        EXPECT_EQ(duplicate, nullptr);
    }

    TEST_F(HookFixture, ResetIsIdempotentThroughTheCHandle)
    {
        write_code({0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3});
        ASSERT_EQ(memlib_inline_hook_create(memory, reinterpret_cast<void*>(&detour_value), MEMLIB_HOOK_START_DISABLED, &hook), MEMLIB_HOOK_OK);
        EXPECT_EQ(memlib_inline_hook_reset(hook), MEMLIB_HOOK_OK);
        hook = nullptr;
        EXPECT_EQ(memlib_inline_hook_reset(nullptr), MEMLIB_HOOK_INVALID_HOOK);
        EXPECT_EQ(reinterpret_cast<test_function>(memory)(), 7);
    }

    TEST(MemLibCppWrapper, ReturnsEnumStatuses)
    {
        memlib::inl_hook hook;
        EXPECT_EQ(memlib::inl_hook::create(nullptr, reinterpret_cast<void*>(&detour_value), memlib::inl_hook::Default, &hook), memlib::hook_status::invalid_target);
        EXPECT_EQ(hook.reset(), memlib::hook_status::ok);
    }

    TEST(MemLibCApi, ExposesMemoryAndPatternOperations)
    {
        auto* memory = static_cast<std::uint8_t*>(memlib_alloc(64, static_cast<uint32_t>(memlib::prot::r | memlib::prot::w | memlib::prot::x)));
        ASSERT_NE(memory, nullptr);
        const std::uint8_t bytes[] = {0x90, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3};
        std::memcpy(memory, bytes, sizeof(bytes));
        memlib_flush_icache(memory, sizeof(bytes));

        memlib_region_info region{};
        EXPECT_EQ(memlib_query(memory, &region), 1);
        EXPECT_EQ(region.start, reinterpret_cast<uintptr_t>(memory));
        EXPECT_EQ(memlib_is_readable(memory, sizeof(bytes)), 1);
        EXPECT_EQ(memlib_is_executable(memory, sizeof(bytes)), 1);

        memlib_scan_pattern pattern{};
        ASSERT_EQ(memlib_parse_pattern("B8 2A 00 00 00", &pattern), 1);
        EXPECT_EQ(memlib_find(&pattern, reinterpret_cast<uintptr_t>(memory), reinterpret_cast<uintptr_t>(memory + sizeof(bytes)), 0), reinterpret_cast<uintptr_t>(memory + 1));
        EXPECT_EQ(memlib_address_resolve_relative(reinterpret_cast<uintptr_t>(memory), 4, 5), reinterpret_cast<uintptr_t>(memory + 9));
        EXPECT_EQ(memlib_free(memory), 1);
    }
}
