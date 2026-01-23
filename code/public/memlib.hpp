#pragma once

#include "memlib/macros.hpp"
#include "memlib/types.hpp"
#include "memlib/os.hpp"
#include "memlib/memory.hpp"
#include "memlib/address.hpp"
#include "memlib/module.hpp"
#include "memlib/thread.hpp"
#include "memlib/hook.hpp"

#include <cstdint>
#include <functional>
#include <string>

namespace memlib
{
	enum class log_level : uint8_t
	{
		trace, debug, info, warn, error, fatal
	};

	using log_callback = void(*)(log_level, const std::string&);
	void set_log_callback(const log_callback& cb);
}