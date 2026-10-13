/**
 * scanner.h — Aho-Corasick multi-pattern string matching
 *
 * Builds a deterministic finite automaton (DFA) from a set of plaintext
 * patterns (secret values) and searches an arbitrary byte buffer for any of
 * them in a single O(n) pass, regardless of how many patterns there are.
 *
 * API:
 *   ACScan *acs_new(void);
 *   int     acs_add_pattern(ACScan *, const char *pattern, size_t len,
 *                           uint32_t id);
 *   int     acs_build(ACScan *);
 *   void    acs_search(const ACScan *, const char *text, size_t tlen,
 *                      acs_match_cb cb, void *userdata);
 *   void    acs_free(ACScan *);
 */
#ifndef VAULTING_SCANNER_H
#define VAULTING_SCANNER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque scanner handle. */
typedef struct ACScan ACScan;

/**
 * Match callback. Called once for each pattern occurrence found.
 *
 * @param pos       Byte offset of the LAST character of the match in the text.
 * @param pattern_id  ID assigned to the pattern via acs_add_pattern.
 * @param userdata  Caller-supplied cookie passed through from acs_search.
 * @return          Return 0 to continue, non-zero to abort the scan early.
 */
typedef int (*acs_match_cb)(size_t pos, uint32_t pattern_id, void *userdata);

/** Allocate a new, empty scanner. Returns NULL on OOM. */
ACScan *acs_new(void);

/**
 * Add a pattern string.  Copies the bytes internally.
 * Must be called before acs_build().
 * @return 0 on success, -1 on OOM or if the automaton is already built.
 */
int acs_add_pattern(ACScan *ac, const char *pattern, size_t len, uint32_t id);

/**
 * Compile the trie into a full DFA with failure links (BFS pass).
 * Must be called after all patterns are added and before acs_search().
 * @return 0 on success, -1 on error.
 */
int acs_build(ACScan *ac);

/**
 * Scan the text buffer.  acs_build() must have been called first.
 * The callback is invoked for every match; returning non-zero from the
 * callback stops the scan immediately.
 */
void acs_search(const ACScan *ac,
                const char   *text,
                size_t        tlen,
                acs_match_cb  cb,
                void         *userdata);

/** Free all memory allocated by the scanner. */
void acs_free(ACScan *ac);

/** Return the total number of patterns loaded. */
size_t acs_pattern_count(const ACScan *ac);

#ifdef __cplusplus
}
#endif

#endif /* VAULTING_SCANNER_H */
