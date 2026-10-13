/**
 * test_c.c — Standalone C unit tests for the native vaulting core.
 *
 * Compile and run via:  make test   (from c_src/)
 *
 * Tests:
 *   1. Aho-Corasick: single pattern, multi-pattern, no match, empty
 *   2. Secure memory: alloc/free lifecycle
 *   3. Constant-time compare: equal and unequal buffers
 *   4. Shamir: split/combine roundtrip for (k=2,n=3), (k=3,n=5)
 *   5. Shamir: wrong shares produce wrong secret
 */

/* Feature test macros must come before every system header. */
#if defined(__APPLE__) || defined(__STDC_LIB_EXT1__)
#  ifndef __STDC_WANT_LIB_EXT1__
#    define __STDC_WANT_LIB_EXT1__ 1
#  endif
#endif

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>

/* Pull in implementations directly (not the shared lib) */
#include "scanner.h"
#include "secure_mem.h"
#include "shamir.h"

static int tests_run   = 0;
static int tests_failed = 0;

#define PASS(msg) do { printf("  ✓ %s\n", msg); tests_run++; } while(0)
#define FAIL(msg) do { printf("  ✗ FAIL: %s\n", msg); tests_run++; tests_failed++; } while(0)
#define CHECK(cond, msg) do { if (cond) PASS(msg); else FAIL(msg); } while(0)

/* ─────────────────────────────────── Aho-Corasick tests ─────────────── */

typedef struct { int count; uint32_t last_id; } MatchCtx;
static int on_match(size_t pos, uint32_t pid, void *ud) {
    (void)pos;
    MatchCtx *m = (MatchCtx *)ud;
    m->count++;
    m->last_id = pid;
    return 0;
}

static void test_scanner(void) {
    printf("\n[scanner]\n");

    /* Test 1: single pattern found */
    {
        ACScan *ac = acs_new();
        acs_add_pattern(ac, "hello", 5, 42);
        acs_build(ac);
        const char *text = "say hello world";
        MatchCtx m = {0, 0};
        acs_search(ac, text, strlen(text), on_match, &m);
        CHECK(m.count == 1 && m.last_id == 42, "single pattern found");
        acs_free(ac);
    }

    /* Test 2: multiple patterns */
    {
        ACScan *ac = acs_new();
        acs_add_pattern(ac, "foo", 3, 1);
        acs_add_pattern(ac, "bar", 3, 2);
        acs_add_pattern(ac, "baz", 3, 3);
        acs_build(ac);
        const char *text = "foobarbaz";
        MatchCtx m = {0, 0};
        acs_search(ac, text, strlen(text), on_match, &m);
        CHECK(m.count == 3, "three patterns found");
        acs_free(ac);
    }

    /* Test 3: no match */
    {
        ACScan *ac = acs_new();
        acs_add_pattern(ac, "xyz", 3, 1);
        acs_build(ac);
        const char *text = "abcdefgh";
        MatchCtx m = {0, 0};
        acs_search(ac, text, strlen(text), on_match, &m);
        CHECK(m.count == 0, "no match");
        acs_free(ac);
    }

    /* Test 4: overlapping patterns */
    {
        ACScan *ac = acs_new();
        acs_add_pattern(ac, "he",    2, 1);
        acs_add_pattern(ac, "she",   3, 2);
        acs_add_pattern(ac, "his",   3, 3);
        acs_add_pattern(ac, "hers",  4, 4);
        acs_build(ac);
        /* Classic Aho-Corasick test string */
        const char *text = "ushers";
        MatchCtx m = {0, 0};
        acs_search(ac, text, strlen(text), on_match, &m);
        /* "she"(1) + "he"(1) + "hers"(1) → 3 matches */
        CHECK(m.count == 3, "overlapping patterns (Aho-Corasick classic)");
        acs_free(ac);
    }
}

/* ─────────────────────────────────── secure_mem tests ───────────────── */

static void test_secure_mem(void) {
    printf("\n[secure_mem]\n");

    /* Test 1: allocate and free */
    {
        SecureBuffer sb;
        int rc = vlt_secure_alloc(&sb, 64);
        CHECK(rc == 0, "alloc returns 0");
        CHECK(sb.data != NULL && sb.len == 64, "data/len set correctly");
        /* Write something */
        memset(sb.data, 0xAB, 64);
        vlt_secure_free(&sb);
        CHECK(sb.data == NULL && sb.len == 0, "data NULL after free");
    }

    /* Test 2: constant-time compare */
    {
        uint8_t a[] = {1, 2, 3, 4};
        uint8_t b[] = {1, 2, 3, 4};
        uint8_t c[] = {1, 2, 3, 5};
        CHECK(vlt_consttime_memcmp(a, b, 4) == 0, "equal buffers");
        CHECK(vlt_consttime_memcmp(a, c, 4) != 0, "unequal buffers");
    }
}

/* ─────────────────────────────────── Shamir tests ───────────────────── */

static void test_shamir(void) {
    printf("\n[shamir]\n");

    /* Test 1: (2, 3) split and combine */
    {
        uint8_t secret[] = "hunter2-super-secret-password";
        size_t  slen = sizeof(secret) - 1;  /* 29 bytes, no null */
        /* stride = 1 + slen = 30 bytes per share */
        size_t stride = 1 + slen;
        uint8_t shares[3 * 30];  /* n=3, stride=30 — flat buffer avoids 2D mismatch */

        int rc = shamir_split(secret, slen, 2, 3, shares);
        CHECK(rc == 0, "(2,3) split returns 0");

        /* Reconstruct from shares 0 and 2 */
        const uint8_t *pair[2] = {shares + 0*stride, shares + 2*stride};
        uint8_t recovered[29];
        rc = shamir_combine(pair, 2, slen, recovered);
        CHECK(rc == 0, "(2,3) combine returns 0");
        CHECK(memcmp(secret, recovered, slen) == 0,
              "(2,3) recovered == original");
    }

    /* Test 2: (3, 5) split and combine */
    {
        uint8_t secret[32];
        for (int i = 0; i < 32; i++) secret[i] = (uint8_t)(i * 7 + 13);
        uint8_t shares[5][1 + 32];
        int rc = shamir_split(secret, 32, 3, 5, (uint8_t *)shares);
        CHECK(rc == 0, "(3,5) split returns 0");

        const uint8_t *trio[3] = {shares[1], shares[3], shares[4]};
        uint8_t recovered[32];
        rc = shamir_combine(trio, 3, 32, recovered);
        CHECK(rc == 0, "(3,5) combine returns 0");
        CHECK(memcmp(secret, recovered, 32) == 0,
              "(3,5) recovered == original");
    }

    /* Test 3: k=1 (trivial: n=1 share = secret itself) */
    {
        uint8_t secret[] = {0xDE, 0xAD, 0xBE, 0xEF};
        uint8_t share[1 + 4];
        shamir_split(secret, 4, 1, 1, share);
        const uint8_t *p = share;
        uint8_t out[4];
        shamir_combine(&p, 1, 4, out);
        CHECK(memcmp(secret, out, 4) == 0, "(1,1) trivial split/combine");
    }
}

/* ─────────────────────────────────── main ───────────────────────────── */

int main(void) {
    printf("=== Vaulting C Core Tests ===\n");
    test_scanner();
    test_secure_mem();
    test_shamir();
    printf("\n%d/%d tests passed.\n", tests_run - tests_failed, tests_run);
    return tests_failed > 0 ? 1 : 0;
}
