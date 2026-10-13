/**
 * shamir.c — Shamir's Secret Sharing over GF(2^8)
 *
 * GF(2^8) arithmetic
 * ──────────────────
 * Elements are uint8_t (0-255).
 * Addition  = XOR.
 * Multiplication uses the standard AES irreducible polynomial
 *   x^8 + x^4 + x^3 + x + 1  (0x11B).
 * We precompute log/antilog tables once so multiplication and division
 * are table lookups — constant time because the table index is the
 * operand value, not a secret-dependent branch.
 *
 * Splitting
 * ─────────
 * For each byte position b in the secret, pick k-1 random coefficients
 * a[1]..a[k-1] ∈ GF(2^8), set a[0] = secret[b].
 * Polynomial p(x) = a[0] + a[1]*x + ... + a[k-1]*x^(k-1)
 * Evaluate p(1), p(2), ..., p(n) to produce the y-coordinates.
 * x-coordinates are simply 1..n.
 *
 * Combining (Lagrange interpolation at x=0)
 * ─────────────────────────────────────────
 * Given k (x_i, y_i) pairs, p(0) = sum_i [ y_i * prod_{j≠i} x_j / (x_j - x_i) ]
 * All arithmetic in GF(2^8).
 *
 * Copyright 2026 — MIT Licence
 */

#include "shamir.h"
#include "secure_mem.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(__APPLE__)
#  include <Security/SecRandom.h>   /* SecRandomCopyBytes */
#else
#  include <fcntl.h>
#  include <unistd.h>
#endif

/* ---------------------------------------------------------- GF(2^8) tables */

/* GF(2^8) with irreducible polynomial x^8+x^4+x^3+x+1 (= 0x11B, reduction: 0x1B).
 * Primitive element g = 3  (order 255, proven by exhaustive check).
 *
 * Tables:
 *   gf_exp[i]     = g^i   for i = 0..254
 *   gf_exp[i+256] = g^i   doubled so log arithmetic (a-b+255) never wraps past 510
 *   gf_log[v]     = k such that g^k = v  (v=1..255; gf_log[0] undefined)
 */
#define GF_REDUCE 0x1B   /* lower 8 bits of irreducible poly */

static uint8_t gf_log[256];
static uint8_t gf_exp[512];
static int     gf_init_done = 0;

/* Bitwise GF multiply: Russian-peasant algorithm, always correct. */
static inline uint8_t _gf_mul_bitwise(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a = (uint8_t)(a << 1);
        if (hi) a ^= GF_REDUCE;
        b >>= 1;
    }
    return p;
}

static void gf_init(void) {
    if (gf_init_done) return;
    /* Build exp table: gf_exp[i] = 3^i for i=0..254 */
    uint8_t x = 1;
    for (int i = 0; i < 255; i++) {
        gf_exp[i] = x;
        x = _gf_mul_bitwise(x, 3);
    }
    gf_exp[255] = 1;                   /* 3^255 ≡ 1 (cyclic group of order 255) */
    /* Extend to [0..509]: gf_exp[255+i] = gf_exp[i] for i=0..254.
     * This way gf_mul can add two logs (max 254+254=508) and index gf_exp
     * directly without a modular reduce — gf_exp[508] = gf_exp[253]. */
    for (int i = 0; i < 255; i++)
        gf_exp[255 + i] = gf_exp[i];
    /* Build log table: gf_log[gf_exp[i]] = i for i=0..254 */
    gf_log[0] = 0;  /* 0 has no log; sentinel */
    for (int i = 0; i < 255; i++)
        gf_log[gf_exp[i]] = (uint8_t)i;
    gf_init_done = 1;
}

static inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) return 0;
    /* log_a, log_b ∈ [0..254]; sum ∈ [0..508] ⊆ valid gf_exp indices */
    return gf_exp[(int)gf_log[a] + (int)gf_log[b]];
}

static inline uint8_t gf_div(uint8_t a, uint8_t b) {
    if (a == 0) return 0;
    /* (log_a - log_b + 255) ∈ [1..509] ⊆ valid gf_exp indices */
    return gf_exp[(int)gf_log[a] - (int)gf_log[b] + 255];
}

/* ---------------------------------------------------------- random bytes */

static int secure_random_bytes(uint8_t *buf, size_t len) {
#if defined(__APPLE__)
    return SecRandomCopyBytes(kSecRandomDefault, len, buf) == 0 ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t got = read(fd, buf, len);
    close(fd);
    return (got == (ssize_t)len) ? 0 : -1;
#endif
}

/* --------------------------------------------------------- polynomial eval */

/** Evaluate polynomial with coefficients coeff[0..k-1] at point x, in GF. */
static uint8_t poly_eval(const uint8_t *coeff, uint8_t k, uint8_t x) {
    /* Horner's method: coeff[0] + x*(coeff[1] + x*(... + x*coeff[k-1])...) */
    uint8_t result = 0;
    for (int i = (int)k - 1; i >= 0; i--) {
        result = coeff[i] ^ gf_mul(result, x);
    }
    return result;
}

/* ---------------------------------------------------------------- split */

int shamir_split(const uint8_t *secret,
                 size_t         secret_len,
                 uint8_t        k,
                 uint8_t        n,
                 uint8_t       *shares_out) {
    if (!secret || !shares_out) return -1;
    if (k == 0 || n == 0 || k > n || n > 255 || secret_len == 0) return -1;

    gf_init();

    size_t share_stride = 1 + secret_len;   /* x byte + secret_len y bytes */

    /* Assign x-coordinates 1..n */
    for (uint8_t i = 0; i < n; i++)
        shares_out[(size_t)i * share_stride] = (uint8_t)(i + 1);

    /* For each byte position, build a random degree-(k-1) polynomial whose
     * constant term is secret[b], then evaluate at x=1..n. */
    SecureBuffer coeff_buf;
    if (vlt_secure_alloc(&coeff_buf, k) != 0) return -1;
    uint8_t *coeff = coeff_buf.data;

    for (size_t b = 0; b < secret_len; b++) {
        coeff[0] = secret[b];
        /* Random coefficients a[1] .. a[k-1] */
        if (k > 1) {
            if (secure_random_bytes(coeff + 1, k - 1) != 0) {
                vlt_secure_free(&coeff_buf);
                return -1;
            }
        }
        /* Evaluate p(x) for each share */
        for (uint8_t i = 0; i < n; i++) {
            uint8_t x = (uint8_t)(i + 1);
            shares_out[(size_t)i * share_stride + 1 + b] =
                poly_eval(coeff, k, x);
        }
    }

    vlt_secure_free(&coeff_buf);
    return 0;
}

/* --------------------------------------------------------------- combine */

int shamir_combine(const uint8_t * const *shares,
                   uint8_t                k,
                   size_t                 secret_len,
                   uint8_t               *secret_out) {
    if (!shares || !secret_out || k == 0 || secret_len == 0) return -1;

    gf_init();

    /* Extract x-coordinates */
    uint8_t xs[255];
    for (uint8_t i = 0; i < k; i++) {
        xs[i] = shares[i][0];
        if (xs[i] == 0) return -1;   /* x=0 is reserved for the secret */
    }

    /* Lagrange interpolation at x=0 for each byte position */
    for (size_t b = 0; b < secret_len; b++) {
        uint8_t result = 0;
        for (uint8_t i = 0; i < k; i++) {
            uint8_t yi  = shares[i][1 + b];
            uint8_t num = 1, den = 1;
            for (uint8_t j = 0; j < k; j++) {
                if (j == i) continue;
                /* num *= x_j - 0 = x_j  (subtraction in GF is XOR) */
                num = gf_mul(num, xs[j]);
                /* den *= x_j - x_i */
                den = gf_mul(den, xs[j] ^ xs[i]);
            }
            result ^= gf_mul(yi, gf_div(num, den));
        }
        secret_out[b] = result;
    }
    return 0;
}
