/**
 * vaulting_core.c — Thin combined shared-library entry point
 *
 * This file includes the individual C modules so the whole native library
 * is compiled and linked as a single translation unit.  The resulting
 * libvaulting_core.so (or .dylib) exposes the combined public API.
 */

/* Must come before ANY system headers (needed for memset_s on macOS/C11). */
#if defined(__APPLE__) || defined(__STDC_LIB_EXT1__)
#  ifndef __STDC_WANT_LIB_EXT1__
#    define __STDC_WANT_LIB_EXT1__ 1
#  endif
#endif

#include "scanner.c"
#include "secure_mem.c"
#include "shamir.c"
