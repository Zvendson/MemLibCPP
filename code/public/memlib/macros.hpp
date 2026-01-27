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

#if defined(NDEBUG)
    #define MEMLIB_IS_DEBUG   0
    #define MEMLIB_IS_RELEASE 1
#else
    #define MEMLIB_IS_DEBUG   1
    #define MEMLIB_IS_RELEASE 0
#endif


/*
Helper macros for your reversed structs or w/e.
*/

#ifndef MEMLIB_BYTE_TYPE
    // just in case you want to use a namespaced type.
	#define MEMLIB_BYTE_TYPE uint8_t
#endif

#ifndef PAD
	#define __MEMLIB_CONCAT_IMPL(a, b) a##b
	#define __MEMLIB_CONCAT(a, b) __MEMLIB_CONCAT_IMPL(a, b)
	#define PAD(bytes) MEMLIB_BYTE_TYPE __MEMLIB_CONCAT(pad_, __COUNTER__)[bytes]
#endif

#ifndef ASSERT_SIZE
	#define ASSERT_SIZE(type_, size_) \
		static_assert(sizeof(type_) == size_, #type_ " has incorrect size.")
#endif

#ifndef ASSERT_OFFSET
	#define ASSERT_OFFSET(struct_, field_, offset_)                        \
		static_assert(                                                     \
			offsetof(struct_, field_) == offset_,                          \
            #struct_ " has incorrect offset: " #field_ " at " # offset_ "." \
        )
#endif



#ifndef MEMLIB_MAX_PATH
    #define MEMLIB_MAX_PATH 4096
#endif


#ifndef MEMLIB_MAX_PATTERN_LEN
    #define MEMLIB_MAX_PATTERN_LEN 512
#endif
