#pragma once

#include "memlib.hpp"

#include <atomic>
#include <format>
#include <string>
#include <string_view>
#include <utility>

namespace memlib
{
	inline std::atomic<log_callback> g_log_func{ nullptr };

	inline log_callback get_log_callback() noexcept
	{
		return g_log_func.load(std::memory_order_acquire);
	}

	template <typename... Args>
	void log(log_level level, const std::format_string<Args...> fmt, Args &&...args)
	{
		auto log_func = get_log_callback();
		if (!log_func)
			return;

		std::string msg = std::format(fmt, std::forward<Args>(args)...);
		log_func(level, msg);
	}
}

#if MEMLIB_IS_DEBUG
	#define MEMLIB_TRACE(...) ::memlib::log(::memlib::log_level::trace, __VA_ARGS__)
	#define MEMLIB_DEBUG(...) ::memlib::log(::memlib::log_level::debug, __VA_ARGS__)
#else
	#define MEMLIB_TRACE(...)
	#define MEMLIB_DEBUG(...)
#endif

#define MEMLIB_INFO(...)  ::memlib::log(::memlib::log_level::info,  __VA_ARGS__)
#define MEMLIB_WARN(...)  ::memlib::log(::memlib::log_level::warn,  __VA_ARGS__)
#define MEMLIB_ERROR(...) ::memlib::log(::memlib::log_level::error, __VA_ARGS__)
#define MEMLIB_FATAL(...) ::memlib::log(::memlib::log_level::fatal, __VA_ARGS__)