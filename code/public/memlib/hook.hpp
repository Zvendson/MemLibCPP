#pragma once

#include <safetyhook.hpp>

#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>


namespace memlib
{
	using hook_context = safetyhook::Context;
	using inl_hook = safetyhook::InlineHook;
	using mid_hook = safetyhook::MidHook;
	using vmt_hook = safetyhook::VmtHook;
	using vm_hook = safetyhook::VmHook;

	void enter_hookguard();
	void leave_hookguard();
	bool is_guarded();

	class hook_guard
	{
	public:
		hook_guard() noexcept { enter_hookguard(); }
		~hook_guard() noexcept { leave_hookguard(); }

		hook_guard(const hook_guard&) = delete;
		hook_guard& operator=(const hook_guard&) = delete;
	};

    class hook_entry
    { // NOTE: Wrapper for safetyhook, in case i decide to change the backend (safetyhook).
    public:
        explicit hook_entry(inl_hook&& in) : m_hook(std::move(in)) {}

        inline void enable_hook()
        {
            if (!m_enabled)
            {
                (void)m_hook.enable();
                m_enabled = true;
            }
        }

        inline void disable_hook()
        {
            if (m_enabled)
            {
                (void)m_hook.disable();
                m_enabled = false;
            }
        }

        [[nodiscard]] inline bool is_hook_enabled() const noexcept { return m_enabled; }

        inline void reset_hook() noexcept
        {
            try 
            {
                disable_hook(); 
            }
            catch (...)
            {
            }

            m_hook.reset();
            m_enabled = false;
        }

        /// @brief Get a pointer to the target.
        [[nodiscard]] inline uint8_t* target() const noexcept { return m_hook.target(); }

        /// @brief Get the target address.
        [[nodiscard]] inline uintptr_t target_address() const noexcept { return m_hook.target_address(); }

        /// @brief Get a pointer to the destination.
        [[nodiscard]] inline uint8_t* destination() const noexcept { return m_hook.destination(); }

        /// @brief Get the destination address.
        [[nodiscard]] inline uintptr_t destination_address() const noexcept { return m_hook.destination_address(); }

        /// @brief Get the trampoline allocation.
        [[nodiscard]] inline const auto& trampoline() const noexcept { return m_hook.trampoline(); }

        /// @brief Tests if the hook is valid.
        explicit operator bool() const noexcept { return static_cast<bool>(m_hook); }

        /// @brief Returns the address of the trampoline to call the original function.
        template <typename T>
        [[nodiscard]] inline T original() const noexcept
        {
            return m_hook.template original<T>();
        }

        /// @brief Returns a vector containing the original bytes of the target function.
        [[nodiscard]] inline const auto& original_bytes() const noexcept
        {
            return m_hook.original_bytes();
        }

        template <typename RetT = void, typename... Args>
        RetT inline call(Args... args)
        {
            return m_hook.template call<RetT>(args...);
        }

        template <typename RetT = void, typename... Args>
        RetT inline ccall(Args... args)
        {
            return m_hook.template ccall<RetT>(args...);
        }

        template <typename RetT = void, typename... Args>
        RetT inline thiscall(Args... args)
        {
            return m_hook.template thiscall<RetT>(args...);
        }

        template <typename RetT = void, typename... Args>
        RetT inline stdcall(Args... args)
        {
            return m_hook.template stdcall<RetT>(args...);
        }

        template <typename RetT = void, typename... Args>
        RetT inline fastcall(Args... args)
        {
            return m_hook.template fastcall<RetT>(args...);
        }

        template <typename RetT = void, typename... Args>
        RetT inline unsafe_call(Args... args)
        {
            return m_hook.template unsafe_call<RetT>(args...);
        }

        template <typename RetT = void, typename... Args>
        RetT inline unsafe_ccall(Args... args)
        {
            return m_hook.template unsafe_ccall<RetT>(args...);
        }

        template <typename RetT = void, typename... Args>
        RetT inline unsafe_thiscall(Args... args)
        {
            return m_hook.template unsafe_thiscall<RetT>(args...);
        }

        template <typename RetT = void, typename... Args>
        RetT inline unsafe_stdcall(Args... args)
        {
            return m_hook.template unsafe_stdcall<RetT>(args...);
        }

        template <typename RetT = void, typename... Args>
        RetT inline unsafe_fastcall(Args... args)
        {
            return m_hook.template unsafe_fastcall<RetT>(args...);
        }

    protected:
        inl_hook m_hook;
        bool     m_enabled { false };
    };
    using hook = std::shared_ptr<hook_entry>;



    class hook_manager
    {
    public:
        hook create_inline(void* target, void* detour, inl_hook::Flags flags = inl_hook::Flags::StartDisabled)
        {
            auto res = inl_hook::create(target, detour, flags);
            if (!res) return {};

            auto entry = std::make_shared<hook_entry>(std::move(res.value()));

            {
                std::scoped_lock lk(m_mutex);
                m_hooks.emplace_back(entry);
            }

            return entry;
        }

        void disable_all()
        {
            std::scoped_lock lk(m_mutex);
            auto it = m_hooks.begin();
            while (it != m_hooks.end())
            {
                if (auto& sp = *it)
                {
                    sp->enable_hook();
                    ++it;
                }
                else
                {
                    it = m_hooks.erase(it);
                }
            }
        }

        void enable_all()
        {
            std::scoped_lock lk(m_mutex);
            auto it = m_hooks.begin();
            while (it != m_hooks.end())
            {
                if (auto& sp = *it)
                {
                    sp->enable_hook();
                    ++it;
                }
                else
                {
                    it = m_hooks.erase(it);
                }
            }
        }

        void reset_all()
        {
            std::scoped_lock lk(m_mutex);
            auto it = m_hooks.begin();
            while (it != m_hooks.end())
            {
                if (auto& sp = *it)
                {
                    sp->reset_hook();
                    ++it;
                }
                else
                {
                    it = m_hooks.erase(it);
                }
            }
        }

    protected:
        std::mutex        m_mutex;
        std::vector<hook> m_hooks;
    };
}
