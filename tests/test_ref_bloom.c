/*
 * test_ref_bloom.c — the reference bloom codec: tokenizer, build, lookup and
 * rejection of blobs the build cannot read.
 */
#include "test_framework.h"
#include "ref_bloom.h"
#include "foundation/hash_table.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Helpers ───────────────────────────────────────────────────── */

/* Token sets own heap copies of their keys; this releases one. */
static void free_key(const char *key, void *value, void *userdata) {
    (void)value;
    (void)userdata;
    free((void *)key);
}

static void release_set(CBMHashTable *set) {
    cbm_ht_foreach(set, free_key, NULL);
    cbm_ht_free(set);
}

/* A fixed-seed generator so a run is repeatable. */
static uint32_t next_rand(uint32_t *state) {
    *state = (*state * 1664525u) + 1013904223u;
    return *state >> 8;
}

/* Writes TOKEN_COUNT distinct names of the form tok_<i>, space separated. They
 * hold digits and an underscore, so no letters-only name can equal one. */
#define TOKEN_COUNT 500
static void make_token_text(char *buf, size_t cap) {
    size_t used = 0;
    for (int i = 0; i < TOKEN_COUNT; i++) {
        used += (size_t)snprintf(buf + used, cap - used, "tok_%d ", i);
    }
}

/* Builds the 500-token set from make_token_text. */
static CBMHashTable *build_token_set(void) {
    static char text[TOKEN_COUNT * 12];
    make_token_text(text, sizeof(text));
    CBMHashTable *set = cbm_ht_create(0);
    cbm_ref_tokens_add_text(set, text, strlen(text));
    return set;
}

/* ── Tokenizer ─────────────────────────────────────────────────── */

TEST(ref_tokens_split_identifiers) {
    const char *text = "pkg.Func(a::b, \"handler_x\") /* gone */";
    CBMHashTable *set = cbm_ht_create(0);
    cbm_ref_tokens_add_text(set, text, strlen(text));

    uint32_t count = cbm_ht_count(set);
    int has_pkg = cbm_ht_has(set, "pkg");
    int has_func = cbm_ht_has(set, "Func");
    int has_a = cbm_ht_has(set, "a");
    int has_b = cbm_ht_has(set, "b");
    int has_handler = cbm_ht_has(set, "handler_x");
    int has_gone = cbm_ht_has(set, "gone");
    release_set(set);

    /* The tokenizer sees text, not syntax: the comment's word is a token here
     * and is dropped by the tree walk instead. */
    ASSERT_EQ(count, 6);
    ASSERT_TRUE(has_pkg);
    ASSERT_TRUE(has_func);
    ASSERT_TRUE(has_a);
    ASSERT_TRUE(has_b);
    ASSERT_TRUE(has_handler);
    ASSERT_TRUE(has_gone);
    PASS();
}

/* ── Build and lookup ──────────────────────────────────────────── */

TEST(ref_bloom_holds_what_was_put_in) {
    CBMHashTable *set = build_token_set();
    CBMArena arena;
    cbm_arena_init(&arena);
    int len = 0;
    const unsigned char *blob = cbm_ref_bloom_from_tokens(&arena, set, &len);

    ASSERT_NOT_NULL(blob);
    /* 500 tokens x 20 bits = 10,000 bits = 1,250 bytes, after 4 header bytes. */
    ASSERT_EQ(len, 4 + 1250);
    ASSERT_EQ(blob[0], CBM_REF_BLOOM_MAGIC);
    ASSERT_EQ(blob[1], CBM_REF_BLOOM_VERSION);
    ASSERT_EQ(blob[2], CBM_REF_BLOOM_K);

    int missing = 0;
    char name[32];
    for (int i = 0; i < TOKEN_COUNT; i++) {
        snprintf(name, sizeof(name), "tok_%d", i);
        if (cbm_ref_bloom_may_contain(blob, len, name) != 1) {
            missing++;
        }
    }
    cbm_arena_destroy(&arena);
    release_set(set);
    ASSERT_EQ(missing, 0);
    PASS();
}

TEST(ref_bloom_false_positives_are_rare) {
    CBMHashTable *set = build_token_set();
    CBMArena arena;
    cbm_arena_init(&arena);
    int len = 0;
    const unsigned char *blob = cbm_ref_bloom_from_tokens(&arena, set, &len);

    ASSERT_NOT_NULL(blob);
    /* A filter that answers 0 to everything would also have no false
     * positives, so the same blob must still hold a member. */
    ASSERT_EQ(cbm_ref_bloom_may_contain(blob, len, "tok_0"), 1);

    uint32_t state = 12345u;
    int false_positives = 0;
    char name[9];
    for (int i = 0; i < 10000; i++) {
        for (int c = 0; c < 8; c++) {
            name[c] = (char)('a' + (next_rand(&state) % 26u));
        }
        name[8] = '\0';
        if (cbm_ref_bloom_may_contain(blob, len, name) == 1) {
            false_positives++;
        }
    }
    cbm_arena_destroy(&arena);
    release_set(set);
    /* 0.05% of 10,000 is 5. */
    ASSERT_LT(false_positives, 5);
    PASS();
}

TEST(ref_bloom_empty_set_holds_nothing) {
    CBMHashTable *set = cbm_ht_create(0);
    CBMArena arena;
    cbm_arena_init(&arena);
    int len = 0;
    const unsigned char *blob = cbm_ref_bloom_from_tokens(&arena, set, &len);

    ASSERT_NOT_NULL(blob);
    /* The header plus the 64-bit minimum, no bit set. */
    ASSERT_EQ(len, 12);
    ASSERT_EQ(cbm_ref_bloom_may_contain(blob, len, "anything"), 0);
    ASSERT_EQ(cbm_ref_bloom_may_contain(blob, len, "x"), 0);
    cbm_arena_destroy(&arena);
    release_set(set);
    PASS();
}

/* ── Rejection ─────────────────────────────────────────────────── */

TEST(ref_bloom_rejects_what_it_cannot_read) {
    /* A header this build reads, followed by the 64-bit minimum. */
    unsigned char good[12] = {CBM_REF_BLOOM_MAGIC, CBM_REF_BLOOM_VERSION, CBM_REF_BLOOM_K, 0,
                              0,                   0,                     0,                0,
                              0,                   0,                     0,                0};
    unsigned char bad_magic[12];
    unsigned char old_version[12];
    memcpy(bad_magic, good, sizeof(good));
    memcpy(old_version, good, sizeof(good));
    bad_magic[0] = 0xB0u;
    old_version[1] = 1u;

    ASSERT_EQ(cbm_ref_bloom_may_contain(bad_magic, 12, "name"), -1);
    ASSERT_EQ(cbm_ref_bloom_may_contain(old_version, 12, "name"), -1);
    /* Shorter than the header. */
    ASSERT_EQ(cbm_ref_bloom_may_contain(good, 3, "name"), -1);
    /* A header with fewer than 64 bits behind it. */
    ASSERT_EQ(cbm_ref_bloom_may_contain(good, 11, "name"), -1);
    /* No blob at all. */
    ASSERT_EQ(cbm_ref_bloom_may_contain(NULL, 0, "name"), -1);
    /* The same bytes with an honest header and length are readable. */
    ASSERT_EQ(cbm_ref_bloom_may_contain(good, 12, "name"), 0);
    PASS();
}

SUITE(ref_bloom) {
    RUN_TEST(ref_tokens_split_identifiers);
    RUN_TEST(ref_bloom_holds_what_was_put_in);
    RUN_TEST(ref_bloom_false_positives_are_rare);
    RUN_TEST(ref_bloom_empty_set_holds_nothing);
    RUN_TEST(ref_bloom_rejects_what_it_cannot_read);
}
