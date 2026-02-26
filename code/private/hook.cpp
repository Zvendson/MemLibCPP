#include "memlib/hook.hpp"

#include <atomic>
#include <cassert>

#include <memlib/macros.hpp>

namespace memlib
{
    static std::atomic<int> g_active_guards{ 0 };

    void memlib::enter_hookguard()
    {
        g_active_guards.fetch_add(1, std::memory_order_acq_rel);
    }

    void memlib::leave_hookguard()
    {
        const int prev = g_active_guards.fetch_sub(1, std::memory_order_acq_rel);
        MEMLIB_ASSERT(prev > 0, "memlib::leave_hookguard() called more often than memlib::enter_hookguard()");
    }

    bool is_guarded()
    {
        return g_active_guards.load(std::memory_order_acquire) != 0;
    }
}
