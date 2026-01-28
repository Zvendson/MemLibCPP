#pragma once

#include "macros.hpp"

#include <cstdint>
#include <type_traits>
#include <string>

namespace memlib
{
    template <class T>
    constexpr bool is_trivially_memcpyable_v = std::is_trivially_copyable_v<T> 
                                            && std::is_standard_layout_v<T>;
}