#pragma once

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