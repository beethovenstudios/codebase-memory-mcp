/*
 * ref_bloom.c — the reference bloom codec. See ref_bloom.h for the blob layout.
 *
 * Three pieces: a tokenizer that interns identifier-like runs into a set, a
 * builder that turns a set into a bloom blob, and a lookup that validates the
 * blob before reading any bit. A fourth function gathers a file's tokens from
 * its extraction result.
 */
#include "ref_bloom.h"
#include "pipeline/pass_lsp_cross.h" /* cbm_pxc_has_cross_lsp */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum {
    REF_BLOOM_HEADER_BYTES = 4,
    /* Runs shorter than this are checked against the set on the stack, so a
     * token already interned costs no allocation. */
    REF_TOKEN_STACK = 256,
};

/* 64-bit FNV-1a. h1 uses the standard offset basis; h2 starts from a second
 * basis so the two hashes of one name are independent. */
#define REF_FNV_PRIME 0x100000001b3ULL
#define REF_FNV_BASIS_1 0xcbf29ce484222325ULL
#define REF_FNV_BASIS_2 0x9e3779b97f4a7c15ULL

static uint64_t fnv1a(const char *s, uint64_t basis) {
    uint64_t h = basis;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h ^= (uint64_t)*p;
        h *= REF_FNV_PRIME;
    }
    return h;
}

/* Bit position of the i-th probe: h1 + i*h2 over m bits. h2 is forced odd by
 * the callers so the probe sequence cannot collapse onto one value. */
static uint64_t probe_bit(uint64_t h1, uint64_t h2, uint32_t i, uint64_t m) {
    return (h1 + ((uint64_t)i * h2)) % m;
}

/* ── Tokenizer ─────────────────────────────────────────────────── */

static bool is_token_byte(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '_' || c == '$' || c >= 0x80;
}

/* Adds the n bytes at text as one token. The set borrows key pointers, so a
 * token seen for the first time is copied to the heap and the set owns it. */
static void intern_token(CBMHashTable *set, const char *text, size_t n) {
    char stack[REF_TOKEN_STACK];
    char *probe = n < sizeof(stack) ? stack : (char *)malloc(n + 1);
    if (!probe) {
        return;
    }
    memcpy(probe, text, n);
    probe[n] = '\0';
    if (cbm_ht_has(set, probe)) {
        if (probe != stack) {
            free(probe);
        }
        return;
    }
    char *owned = probe;
    if (probe == stack) {
        owned = (char *)malloc(n + 1);
        if (!owned) {
            return;
        }
        memcpy(owned, probe, n + 1);
    }
    cbm_ht_set(set, owned, owned);
}

void cbm_ref_tokens_add_text(CBMHashTable *set, const char *text, size_t len) {
    if (!set || !text) {
        return;
    }
    size_t i = 0;
    while (i < len) {
        if (!is_token_byte((unsigned char)text[i])) {
            i++;
            continue;
        }
        size_t start = i;
        while (i < len && is_token_byte((unsigned char)text[i])) {
            i++;
        }
        intern_token(set, text + start, i - start);
    }
}

/* ── Build ─────────────────────────────────────────────────────── */

typedef struct {
    unsigned char *bits; /* first bit byte, after the header */
    uint64_t m;          /* number of bits */
} BloomFill;

static void fill_one(const char *key, void *value, void *userdata) {
    (void)value;
    BloomFill *f = (BloomFill *)userdata;
    uint64_t h1 = fnv1a(key, REF_FNV_BASIS_1);
    uint64_t h2 = fnv1a(key, REF_FNV_BASIS_2) | 1ULL;
    for (uint32_t i = 0; i < CBM_REF_BLOOM_K; i++) {
        uint64_t bit = probe_bit(h1, h2, i, f->m);
        f->bits[bit >> 3] |= (unsigned char)(1u << (bit & 7u));
    }
}

const unsigned char *cbm_ref_bloom_from_tokens(CBMArena *arena, CBMHashTable *set, int *out_len) {
    if (out_len) {
        *out_len = 0;
    }
    if (!arena || !set) {
        return NULL;
    }
    uint64_t bits = (uint64_t)cbm_ht_count(set) * CBM_REF_BLOOM_BITS_PER_TOKEN;
    if (bits < CBM_REF_BLOOM_MIN_BITS) {
        bits = CBM_REF_BLOOM_MIN_BITS;
    }
    uint64_t bytes = (bits + 7u) / 8u;
    if (bytes > (uint64_t)INT_MAX - REF_BLOOM_HEADER_BYTES) {
        return NULL;
    }
    size_t total = REF_BLOOM_HEADER_BYTES + (size_t)bytes;
    unsigned char *blob = (unsigned char *)cbm_arena_calloc(arena, total);
    if (!blob) {
        return NULL;
    }
    blob[0] = (unsigned char)CBM_REF_BLOOM_MAGIC;
    blob[1] = (unsigned char)CBM_REF_BLOOM_VERSION;
    blob[2] = (unsigned char)CBM_REF_BLOOM_K;
    blob[3] = 0;
    /* Probes run over the whole bytes actually stored, so a reader that
     * derives m from the length indexes the same bits. */
    BloomFill fill = {.bits = blob + REF_BLOOM_HEADER_BYTES, .m = bytes * 8u};
    cbm_ht_foreach(set, fill_one, &fill);
    if (out_len) {
        *out_len = (int)total;
    }
    return blob;
}

/* ── Lookup ────────────────────────────────────────────────────── */

int cbm_ref_bloom_may_contain(const void *blob, int len, const char *name) {
    /* The length is checked before any byte is read. A header with fewer than
     * the minimum bit count behind it is not a bloom this build wrote. */
    if (!blob || !name || len < REF_BLOOM_HEADER_BYTES + (int)(CBM_REF_BLOOM_MIN_BITS / 8u)) {
        return -1;
    }
    const unsigned char *b = (const unsigned char *)blob;
    /* A different hash count would be probed at the wrong bits and answer 0
     * for names that are present, so it is unreadable, never a false "no". */
    if (b[0] != CBM_REF_BLOOM_MAGIC || b[1] != CBM_REF_BLOOM_VERSION || b[2] != CBM_REF_BLOOM_K) {
        return -1;
    }
    const unsigned char *bits = b + REF_BLOOM_HEADER_BYTES;
    uint64_t m = (uint64_t)(len - REF_BLOOM_HEADER_BYTES) * 8u;
    uint64_t h1 = fnv1a(name, REF_FNV_BASIS_1);
    uint64_t h2 = fnv1a(name, REF_FNV_BASIS_2) | 1ULL;
    for (uint32_t i = 0; i < CBM_REF_BLOOM_K; i++) {
        uint64_t bit = probe_bit(h1, h2, i, m);
        if (!(bits[bit >> 3] & (1u << (bit & 7u)))) {
            return 0;
        }
    }
    return 1;
}

/* ── Gathering a file's tokens ─────────────────────────────────── */

static void add_str(CBMHashTable *set, const char *s) {
    if (s && *s) {
        cbm_ref_tokens_add_text(set, s, strlen(s));
    }
}

/* Every leaf of the syntax tree except comments. A node whose type names a
 * comment is stepped over with everything under it; strings are kept because
 * handler and dependency references are read from string arguments. Keyword
 * leaves are kept too: filtering them would depend on every grammar marking
 * its contextual keywords the same way. */
static void add_tree_tokens(CBMHashTable *set, TSTree *tree, const char *source, int source_len) {
    TSTreeCursor cur = ts_tree_cursor_new(ts_tree_root_node(tree));
    bool done = false;
    while (!done) {
        TSNode node = ts_tree_cursor_current_node(&cur);
        bool descend = false;
        if (strstr(ts_node_type(node), "comment") != NULL) {
            descend = false;
        } else if (ts_node_child_count(node) == 0) {
            uint32_t start = ts_node_start_byte(node);
            uint32_t end = ts_node_end_byte(node);
            if (end > (uint32_t)source_len) {
                end = (uint32_t)source_len;
            }
            if (start < end) {
                cbm_ref_tokens_add_text(set, source + start, (size_t)(end - start));
            }
        } else {
            descend = true;
        }
        if (descend && ts_tree_cursor_goto_first_child(&cur)) {
            continue;
        }
        while (!ts_tree_cursor_goto_next_sibling(&cur)) {
            if (!ts_tree_cursor_goto_parent(&cur)) {
                done = true;
                break;
            }
        }
    }
    ts_tree_cursor_delete(&cur);
}

static void add_str_list(CBMHashTable *set, const char **list) {
    for (int i = 0; list && list[i]; i++) {
        add_str(set, list[i]);
    }
}

/* Every string the extraction result's reference arrays hold. For a language
 * with no cross-file resolver these are exactly the names that can bind. */
static void add_result_tokens(CBMHashTable *set, const CBMFileResult *r) {
    for (int i = 0; i < r->calls.count; i++) {
        add_str(set, r->calls.items[i].callee_name);
        add_str(set, r->calls.items[i].first_string_arg);
        add_str(set, r->calls.items[i].second_arg_name);
    }
    for (int i = 0; i < r->usages.count; i++) {
        add_str(set, r->usages.items[i].ref_name);
    }
    for (int i = 0; i < r->imports.count; i++) {
        add_str(set, r->imports.items[i].local_name);
        add_str(set, r->imports.items[i].module_path);
    }
    for (int i = 0; i < r->throws.count; i++) {
        add_str(set, r->throws.items[i].exception_name);
    }
    for (int i = 0; i < r->rw.count; i++) {
        add_str(set, r->rw.items[i].var_name);
    }
    for (int i = 0; i < r->type_refs.count; i++) {
        add_str(set, r->type_refs.items[i].type_name);
    }
    for (int i = 0; i < r->type_assigns.count; i++) {
        add_str(set, r->type_assigns.items[i].var_name);
        add_str(set, r->type_assigns.items[i].type_name);
    }
    for (int i = 0; i < r->impl_traits.count; i++) {
        add_str(set, r->impl_traits.items[i].trait_name);
        add_str(set, r->impl_traits.items[i].struct_name);
    }
    for (int i = 0; i < r->defs.count; i++) {
        add_str_list(set, r->defs.items[i].base_classes);
        add_str_list(set, r->defs.items[i].decorators);
        add_str(set, r->defs.items[i].signature);
    }
}

static void free_key(const char *key, void *value, void *userdata) {
    (void)value;
    (void)userdata;
    free((void *)key);
}

void cbm_ref_bloom_of_result(CBMFileResult *result, const char *source, int source_len) {
    if (!result) {
        return;
    }
    result->ref_bloom = NULL;
    result->ref_bloom_len = 0;

    bool from_tree = cbm_pxc_has_cross_lsp(result->cached_lang);
    if (from_tree && (!result->cached_tree || !source || source_len <= 0)) {
        return; /* the tree the tokens come from is gone: no bloom */
    }
    CBMHashTable *set = cbm_ht_create(0);
    if (!set) {
        return;
    }
    if (from_tree) {
        add_tree_tokens(set, result->cached_tree, source, source_len);
    } else {
        add_result_tokens(set, result);
    }
    int len = 0;
    const unsigned char *blob = cbm_ref_bloom_from_tokens(&result->arena, set, &len);
    if (blob) {
        result->ref_bloom = blob;
        result->ref_bloom_len = len;
    }
    cbm_ht_foreach(set, free_key, NULL);
    cbm_ht_free(set);
}
