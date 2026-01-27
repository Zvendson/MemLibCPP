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
		module(const module_handle& module);
		module(const section_info& section) : module(section.module) {}

	public:
		explicit operator bool() const noexcept
		{
			return m_handle != nullptr;
		}

	public:
		inline void*                 get_base() const noexcept { return m_base; }
		inline size_t                get_size() const noexcept { return m_size; }
		inline void*                 get_end()  const noexcept { return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(m_base) + m_size); }
		inline std::string           get_name() const noexcept { return get_module_name(m_path);; }
		inline std::filesystem::path get_path() const noexcept { return m_path; }

		section_info get_section(section sec) const noexcept;
		std::vector<section_info> get_sections() const noexcept;

	public:
		[[nodiscard]] address find(const scan_pattern& pattern, section sec, int32_t offset = 0x0000) noexcept;
		[[nodiscard]] address find(const char* combo, section sec, int32_t offset = 0x0000) noexcept;

	protected:
		void*                 m_base = nullptr;
		size_t                m_size = 0;
		std::filesystem::path m_path{};
		section_info          m_sections[uint8_t(section::max)] = {};
		module_handle         m_handle                          = nullptr;
	};
}