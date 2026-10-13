/**
 * secure_mem.h — Cryptographic memory safety primitives
 *
 * Provides:
 *  • vlt_secure_alloc / vlt_secure_free  — mlock()d, mmap'd allocations that
 *    are zeroed with explicit_bzero before munmap.
 *  • vlt_explicit_zero    — compiler-barrier-resistant zeroing (no elimination).
 *  • SecureBuffer         — length-prefixed secure byte buffer.
 */
#ifndef VAULTING_SECURE_MEM_H
#define VAULTING_SECURE_MEM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque secure memory region: mlock'd and zeroed on free. */
typedef struct SecureBuffer {
    uint8_t *data;
    size_t   len;
    size_t   _alloc_size;   /* internal: actual mmap'd length (page-rounded) */
} SecureBuffer;

/**
 * Allocate len bytes of secure memory.
 * The pages are locked (mlock) so they are never swapped to disk.
 * @return 0 on success, -1 on failure (e.g. RLIMIT_MEMLOCK exceeded).
 */
int vlt_secure_alloc(SecureBuffer *sb, size_t len);

/**
 * Zero and free a secure buffer.
 * Uses explicit_bzero (or equivalent) to prevent compiler from
 * optimising away the zeroing.
 */
void vlt_secure_free(SecureBuffer *sb);

/**
 * Constant-time comparison of two byte strings.
 * Returns 0 iff a[0..len-1] == b[0..len-1], non-zero otherwise.
 * Not short-circuiting: always reads all bytes.
 */
int vlt_consttime_memcmp(const void *a, const void *b, size_t len);

/**
 * Unconditional byte-level memory zeroing that will not be eliminated
 * by any standard-conforming C optimiser.
 */
void vlt_explicit_zero(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* VAULTING_SECURE_MEM_H */
