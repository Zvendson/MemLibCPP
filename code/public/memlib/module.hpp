#pragma once

#include "macros.hpp"
#include "os.hpp"
#include "memory.hpp"
#include "address.hpp"

#include <string>


namespace memlib
{
	class module
	{
	public:
		module(const char* modulename = nullptr);
		module(module_handle module);
		module(const section_info& section) : module(section.module) {}

	public:
		explicit operator bool() const noexcept
		{
			return m_handle != nullptr;
		}

	public:
		[[nodiscard]] address find(const scan_pattern& pattern, section sec, int32_t offset = 0x0000) noexcept;
		[[nodiscard]] address find(const char* combo, section sec, int32_t offset) noexcept;

	protected:
		void*         m_base = nullptr;
		size_t        m_size = 0;
		std::string   m_path{};
		std::string   m_name{};

		section_info  m_sections[uint8_t(section::max)] = {};
		module_handle m_handle                          = nullptr;
	};
}