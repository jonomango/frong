#pragma once

#ifdef FRONG_DEBUG

// for assert()
#undef NDEBUG

// debug messages
#include <stdio.h>
#define FRONG_DEBUG_RAW(format, ...) printf(format, __VA_ARGS__)

#else

// do nothing looool
#define FRONG_DEBUG_RAW(format, ...) ((void)0)
#define FRONG_DEBUG_ASSERT(condition) ((void)0)

#endif

// assert()
#include <assert.h>
#define FRONG_ASSERT(x) assert(x)

// pretty print debug messages
#define FRONG_DEBUG_MSG(format, ...) FRONG_DEBUG_RAW("[frong-msg]: " format "\n", __VA_ARGS__)
#define FRONG_DEBUG_ERROR(format, ...) FRONG_DEBUG_RAW("[frong-error]: " format "\n", __VA_ARGS__)
#define FRONG_DEBUG_WARNING(format, ...) FRONG_DEBUG_RAW("[frong-warning]: " format "\n", __VA_ARGS__)