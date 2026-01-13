#pragma once
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
