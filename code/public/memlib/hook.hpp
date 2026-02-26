#pragma once

#include <safetyhook.hpp>



namespace memlib
{
	using hook_context = safetyhook::Context;
	using hook = safetyhook::InlineHook;
	using mid_hook = safetyhook::MidHook;
	using vmt_hook = safetyhook::VmtHook;
	using vm_hook = safetyhook::VmHook;

	void enter_hookguard();
	void leave_hookguard();
	bool is_guarded();

	class hook_guard
	{
	public:
		hook_guard() { enter_hookguard(); }
		~hook_guard() { leave_hookguard(); }

		hook_guard(const hook_guard&) = delete;
		hook_guard& operator=(const hook_guard&) = delete;
	};
}
