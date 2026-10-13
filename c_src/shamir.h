/**
 * shamir.h — Shamir's Secret Sharing over GF(2^8)
 *
 * Splits an arbitrary-length secret into N shares such that any K of them
 * reconstruct the original.  All arithmetic is performed byte-by-byte in
 * GF(2^8) (the same field used by AES) so the implementation is
 * constant-time (no data-dependent branches or table indices that vary).
 *
 * API:
 *   shamir_split   — secret → N shares
 *   shamir_combine — any K shares → secret
 *
 * Format of a share (opaque bytes returned by shamir_split):
 *   [1 byte: x-coordinate (1..255)] [secret_len bytes: y-coordinates]
 */
#ifndef VAULTING_SHAMIR_H
#define VAULTING_SHAMIR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Split `secret_len` bytes into `n` shares, any `k` of which reconstruct
 * the secret.
 *
 * @param secret       Input secret bytes.
 * @param secret_len   Number of bytes in the secret (> 0).
 * @param k            Threshold: minimum shares needed to reconstruct.
 * @param n            Total shares to produce.  k ≤ n ≤ 255.
 * @param shares_out   Output buffer.  Caller must allocate
 *                     n * (1 + secret_len) bytes.
 *                     Share i starts at shares_out + i*(1+secret_len).
 *                     First byte is the x-coordinate; remaining bytes are y.
 * @return 0 on success, -1 on invalid arguments or OOM.
 */
int shamir_split(const uint8_t *secret,
                 size_t         secret_len,
                 uint8_t        k,
                 uint8_t        n,
                 uint8_t       *shares_out);

/**
 * Reconstruct a secret from exactly `k` shares.
 *
 * @param shares      Array of k pointers, each pointing to a share buffer
 *                    of (1 + secret_len) bytes.
 * @param k           Number of shares provided (≥ threshold).
 * @param secret_len  Length of the original secret.
 * @param secret_out  Caller-allocated buffer of secret_len bytes.
 * @return 0 on success, -1 on invalid arguments.
 */
int shamir_combine(const uint8_t * const *shares,
                   uint8_t                k,
                   size_t                 secret_len,
                   uint8_t               *secret_out);

#ifdef __cplusplus
}
#endif

#endif /* VAULTING_SHAMIR_H */
