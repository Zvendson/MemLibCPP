#pragma once
#include <cstdint>

#if defined(_WIN32) || defined(_WIN64)
    #define MEMLIB_IS_WINDOWS 1
#else
    #define MEMLIB_IS_WINDOWS 0
#endif

#if defined(__linux__)
    #define MEMLIB_IS_LINUX 1
#else
    #define MEMLIB_IS_LINUX 0
#endif

#if INTPTR_MAX == INT64_MAX
    #define MEMLIB_IS_64 1
    #define MEMLIB_IS_32 0
#elif INTPTR_MAX == INT32_MAX
    #define MEMLIB_IS_64 0
    #define MEMLIB_IS_32 1
#else
    #error "MEMLIB: unsupported pointer size"
#endif
