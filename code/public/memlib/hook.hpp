#pragma once

#include <safetyhook.hpp>



namespace memlib
{
	using hook_context = safetyhook::Context;
	using hook = safetyhook::InlineHook;
	using mid_hook = safetyhook::MidHook;
	using vmt_hook = safetyhook::VmtHook;
	using vm_hook = safetyhook::VmHook;
}
