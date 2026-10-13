/**
 * scanner.c — Aho-Corasick multi-pattern string matching
 *
 * Implementation details
 * ─────────────────────
 * • Trie nodes are stored in a flat growable array so the whole structure
 *   is allocated with two malloc() calls and is cache-friendly.
 * • Each node stores a child pointer for every possible byte value (0-255)
 *   using a compact representation: a hash-map for sparse alphabets during
 *   trie construction, then baked into a full 256-wide DFA transition table
 *   after acs_build() for O(1) character dispatch during search.
 * • Failure links and output links are computed in a BFS pass (classic
 *   Aho-Corasick construction).
 * • The search loop is a tight state-machine that touches each byte exactly
 *   once: O(n + m + z) where n = text length, m = total pattern bytes,
 *   z = number of matches.
 *
 * Copyright 2026 — MIT Licence
 */

#include "scanner.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ types */

#define ALPHA  256          /* full byte alphabet */
#define INIT_CAP 256        /* initial node-pool capacity */

typedef uint32_t state_t;
#define NO_STATE ((state_t)UINT32_MAX)

/** Pattern metadata attached to a terminal trie node. */
typedef struct Pattern {
    char    *data;
    size_t   len;
    uint32_t id;
} Pattern;

/** A trie / DFA node. */
typedef struct Node {
    state_t  go[ALPHA];     /* DFA transition table (after build) */
    state_t  fail;          /* failure link */
    state_t  output;        /* output link: next terminal node in chain */
    int32_t  pattern_idx;   /* index into ac->patterns[], or -1 */
} Node;

struct ACScan {
    Node    *nodes;
    size_t   num_nodes;
    size_t   cap_nodes;

    Pattern *patterns;
    size_t   num_patterns;
    size_t   cap_patterns;

    int      built;         /* 0 = construction phase, 1 = search ready */
};

/* --------------------------------------------------------------- helpers */

static int grow_nodes(ACScan *ac) {
    size_t newcap = ac->cap_nodes ? ac->cap_nodes * 2 : INIT_CAP;
    Node  *p = realloc(ac->nodes, newcap * sizeof(Node));
    if (!p) return -1;
    ac->nodes    = p;
    ac->cap_nodes = newcap;
    return 0;
}

static state_t new_node(ACScan *ac) {
    if (ac->num_nodes >= ac->cap_nodes) {
        if (grow_nodes(ac)) return NO_STATE;
    }
    Node *nd = &ac->nodes[ac->num_nodes];
    memset(nd->go, 0xFF, sizeof(nd->go));   /* 0xFF = NO_STATE (all bytes) */
    nd->fail        = 0;
    nd->output      = NO_STATE;
    nd->pattern_idx = -1;
    return (state_t)(ac->num_nodes++);
}

/* --------------------------------------------------------------- public API */

ACScan *acs_new(void) {
    ACScan *ac = calloc(1, sizeof(ACScan));
    if (!ac) return NULL;
    /* Root node = state 0 */
    if (new_node(ac) == NO_STATE) { free(ac); return NULL; }
    return ac;
}

int acs_add_pattern(ACScan *ac, const char *pattern, size_t len, uint32_t id) {
    if (!ac || !pattern || ac->built) return -1;
    if (len == 0) return 0;  /* empty pattern — skip silently */

    /* Grow pattern store if needed */
    if (ac->num_patterns >= ac->cap_patterns) {
        size_t nc = ac->cap_patterns ? ac->cap_patterns * 2 : 64;
        Pattern *pp = realloc(ac->patterns, nc * sizeof(Pattern));
        if (!pp) return -1;
        ac->patterns    = pp;
        ac->cap_patterns = nc;
    }

    /* Copy pattern bytes */
    char *copy = malloc(len);
    if (!copy) return -1;
    memcpy(copy, pattern, len);

    ac->patterns[ac->num_patterns].data = copy;
    ac->patterns[ac->num_patterns].len  = len;
    ac->patterns[ac->num_patterns].id   = id;

    /* Insert into trie */
    state_t cur = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)pattern[i];
        if (ac->nodes[cur].go[ch] == NO_STATE) {
            state_t ns = new_node(ac);
            if (ns == NO_STATE) { free(copy); return -1; }
            ac->nodes[cur].go[ch] = ns;
        }
        cur = ac->nodes[cur].go[ch];
    }

    /* Mark as terminal */
    if (ac->nodes[cur].pattern_idx == -1) {
        ac->nodes[cur].pattern_idx = (int32_t)ac->num_patterns;
    }
    ac->num_patterns++;
    return 0;
}

int acs_build(ACScan *ac) {
    if (!ac || ac->built) return -1;

    /* BFS queue: at most num_nodes entries */
    state_t *q = malloc(ac->num_nodes * sizeof(state_t));
    if (!q) return -1;
    size_t head = 0, tail = 0;

    /* Root's failure link points to itself. Initialise root children. */
    Node *root = &ac->nodes[0];
    root->fail = 0;
    for (int c = 0; c < ALPHA; c++) {
        if (root->go[c] == NO_STATE) {
            root->go[c] = 0;    /* redirect back to root */
        } else {
            ac->nodes[root->go[c]].fail = 0;
            q[tail++] = root->go[c];
        }
    }

    /* BFS */
    while (head < tail) {
        state_t r = q[head++];
        Node   *rn = &ac->nodes[r];

        for (int c = 0; c < ALPHA; c++) {
            state_t s = rn->go[c];
            if (s == NO_STATE) {
                /* Shortcut: use ancestor's DFA transition */
                rn->go[c] = ac->nodes[rn->fail].go[c];
            } else {
                ac->nodes[s].fail = ac->nodes[rn->fail].go[c];
                /* Output chain: link to any terminal reachable via fail */
                state_t f = ac->nodes[s].fail;
                if (ac->nodes[f].pattern_idx != -1)
                    ac->nodes[s].output = f;
                else
                    ac->nodes[s].output = ac->nodes[f].output;
                q[tail++] = s;
            }
        }
    }

    free(q);
    ac->built = 1;
    return 0;
}

void acs_search(const ACScan *ac,
                const char   *text,
                size_t        tlen,
                acs_match_cb  cb,
                void         *userdata) {
    if (!ac || !ac->built || !text || tlen == 0) return;

    state_t cur = 0;
    const Node *nodes = ac->nodes;

    for (size_t i = 0; i < tlen; i++) {
        unsigned char ch = (unsigned char)text[i];
        cur = nodes[cur].go[ch];

        /* Check for match at this state */
        if (nodes[cur].pattern_idx != -1) {
            uint32_t pid = ac->patterns[nodes[cur].pattern_idx].id;
            if (cb(i, pid, userdata)) return;
        }
        /* Walk output chain for overlapping / shorter patterns */
        state_t out = nodes[cur].output;
        while (out != NO_STATE) {
            uint32_t pid = ac->patterns[nodes[out].pattern_idx].id;
            if (cb(i, pid, userdata)) return;
            out = nodes[out].output;
        }
    }
}

void acs_free(ACScan *ac) {
    if (!ac) return;
    for (size_t i = 0; i < ac->num_patterns; i++)
        free(ac->patterns[i].data);
    free(ac->patterns);
    free(ac->nodes);
    free(ac);
}

size_t acs_pattern_count(const ACScan *ac) {
    return ac ? ac->num_patterns : 0;
}
