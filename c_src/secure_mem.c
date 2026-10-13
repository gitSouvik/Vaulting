/**
 * secure_mem.c — Cryptographic memory safety primitives
 *
 * Design notes
 * ─────────────
 * • On POSIX we use mmap(MAP_ANONYMOUS | MAP_PRIVATE) so pages are managed
 *   independently of the libc heap, then mlock() to prevent swapping.
 * • On Windows we use VirtualAlloc + VirtualLock (compiled if _WIN32).
 * • vlt_explicit_zero uses a volatile write loop plus a compiler memory
 *   barrier (asm volatile("" ::: "memory")) so that optimisers cannot
 *   eliminate the zeroing.  On platforms where explicit_bzero() is
 *   available we delegate to that, which is guaranteed to not be elided.
 *
 * Copyright 2026 — MIT Licence
 */
/* Feature test macros must precede ALL system headers. */
#if defined(__APPLE__) || defined(__STDC_LIB_EXT1__)
#  ifndef __STDC_WANT_LIB_EXT1__
#    define __STDC_WANT_LIB_EXT1__ 1
#  endif
#endif

#include "secure_mem.h"

#include <string.h>   /* brings in memset_s when __STDC_WANT_LIB_EXT1__ is 1 */
#include <stdlib.h>
#include <stdint.h>

#if defined(_WIN32)
#  include <windows.h>
#else
#  include <sys/mman.h>
#  include <unistd.h>
#  include <errno.h>
#endif

/* ---------------------------------------------------------- zero helpers */

#if defined(__APPLE__) || defined(__STDC_LIB_EXT1__)
#  define VLT_ZERO(p, n) ((void)memset_s((void*)(p), (size_t)(n), 0, (size_t)(n)))
#elif defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
   extern void explicit_bzero(void *, size_t);
#  define VLT_ZERO(p, n) explicit_bzero((p), (n))
#else
static void _vlt_zero_fallback(void *buf, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)buf;
    while (len--) *p++ = 0;
#  if defined(__GNUC__)
    __asm__ volatile("" ::: "memory");
#  endif
}
#  define VLT_ZERO(p, n) _vlt_zero_fallback((p), (n))
#endif

void vlt_explicit_zero(void *buf, size_t len) {
    VLT_ZERO(buf, len);
}

/* ---------------------------------------------------------- secure alloc */

#if defined(_WIN32)

int vlt_secure_alloc(SecureBuffer *sb, size_t len) {
    if (!sb || len == 0) return -1;
    size_t page = 4096;
    size_t alloc = ((len + page - 1) / page) * page;
    void *p = VirtualAlloc(NULL, alloc, MEM_COMMIT | MEM_RESERVE,
                           PAGE_READWRITE);
    if (!p) return -1;
    if (!VirtualLock(p, alloc)) {
        VirtualFree(p, 0, MEM_RELEASE);
        return -1;
    }
    memset(p, 0, alloc);
    sb->data       = (uint8_t *)p;
    sb->len        = len;
    sb->_alloc_size = alloc;
    return 0;
}

void vlt_secure_free(SecureBuffer *sb) {
    if (!sb || !sb->data) return;
    vlt_explicit_zero(sb->data, sb->_alloc_size);
    VirtualUnlock(sb->data, sb->_alloc_size);
    VirtualFree(sb->data, 0, MEM_RELEASE);
    sb->data = NULL;
    sb->len  = 0;
    sb->_alloc_size = 0;
}

#else /* POSIX */

int vlt_secure_alloc(SecureBuffer *sb, size_t len) {
    if (!sb || len == 0) return -1;
    long ps = sysconf(_SC_PAGESIZE);
    if (ps < 0) ps = 4096;
    size_t page = (size_t)ps;
    size_t alloc = ((len + page - 1) / page) * page;

    void *p = mmap(NULL, alloc,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return -1;

    /* Best-effort: RLIMIT_MEMLOCK might be 0 on some systems */
    if (mlock(p, alloc) != 0) {
        /* Not fatal: the allocation still works; keys just might be swapped */
    }
    /* Advise kernel not to include in core dumps */
#ifdef MADV_DONTDUMP
    madvise(p, alloc, MADV_DONTDUMP);
#endif

    memset(p, 0, alloc);
    sb->data        = (uint8_t *)p;
    sb->len         = len;
    sb->_alloc_size = alloc;
    return 0;
}

void vlt_secure_free(SecureBuffer *sb) {
    if (!sb || !sb->data) return;
    vlt_explicit_zero(sb->data, sb->_alloc_size);
    munlock(sb->data, sb->_alloc_size);
    munmap(sb->data, sb->_alloc_size);
    sb->data        = NULL;
    sb->len         = 0;
    sb->_alloc_size = 0;
}

#endif /* _WIN32 / POSIX */

/* ------------------------------------------------ constant-time compare */

int vlt_consttime_memcmp(const void *a, const void *b, size_t len) {
    const volatile uint8_t *va = (const volatile uint8_t *)a;
    const volatile uint8_t *vb = (const volatile uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= va[i] ^ vb[i];
    return (int)diff;
}
