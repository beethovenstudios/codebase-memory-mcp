#ifndef CBM_REF_BLOOM_H
#define CBM_REF_BLOOM_H

/*
 * ref_bloom.h — a small bloom filter over the names a source file mentions.
 *
 * A file's definitions are stored with a "surface" row. When a definition or a
 * file is added, the files whose references might now bind differently are the
 * ones that spell the added name. The bloom is how that question is asked of a
 * stored row without re-reading the file: "may this file mention NAME?"
 * answers 0 only when it certainly does not.
 *
 * Blob layout (all multi-byte values are bit positions, not stored):
 *   byte 0  magic    CBM_REF_BLOOM_MAGIC
 *   byte 1  version  CBM_REF_BLOOM_VERSION
 *   byte 2  k        CBM_REF_BLOOM_K hash functions
 *   byte 3  reserved 0
 *   bytes 4..  m bits, m = max(64, 20 x distinct tokens) rounded up to bytes.
 * A reader derives m from the blob length, so a blob is only readable when its
 * length leaves at least CBM_REF_BLOOM_MIN_BITS bits after the header.
 *
 * Hashing is 64-bit FNV-1a with double hashing, h_i = h1 + i*h2, where h2 comes
 * from a second offset basis and is forced odd.
 */

#include <stddef.h>
#include "cbm.h"
#include "../../src/foundation/hash_table.h" /* relative: the lsp_all unit has no -Isrc */

#ifdef __cplusplus
extern "C" {
#endif

#define CBM_REF_BLOOM_MAGIC 0xB1u
#define CBM_REF_BLOOM_VERSION 2u
#define CBM_REF_BLOOM_K 14u
#define CBM_REF_BLOOM_BITS_PER_TOKEN 20u
#define CBM_REF_BLOOM_MIN_BITS 64u

/* Split text into identifier-like tokens and add each to set. A token is a
 * maximal run of [A-Za-z0-9_$] or bytes >= 0x80. Each distinct token is
 * interned once: the set owns a heap copy of the key (the value is the same
 * pointer, so cbm_ht_get answers non-NULL). The text is not a syntax tree, so
 * comments are not recognised here. To release a set, free each key with
 * cbm_ht_foreach and then call cbm_ht_free. */
void cbm_ref_tokens_add_text(CBMHashTable *set, const char *text, size_t len);

/* The bloom of a token set, allocated in arena; its length in *out_len.
 * NULL only on allocation failure. */
const unsigned char *cbm_ref_bloom_from_tokens(CBMArena *arena, CBMHashTable *set, int *out_len);

/* 1: name may be among the tokens. 0: certainly not. -1: not a bloom this
 * build reads (wrong magic, version or length); the caller declines. Checks
 * the length before every read. */
int cbm_ref_bloom_may_contain(const void *blob, int len, const char *name);

/* Builds result->ref_bloom by the rule: the leaves of result->cached_tree for
 * a language cbm_pxc_has_cross_lsp names, the result's reference strings
 * otherwise. Leaves ref_bloom NULL when the tree it needs is gone. */
void cbm_ref_bloom_of_result(CBMFileResult *result, const char *source, int source_len);

#ifdef __cplusplus
}
#endif

#endif /* CBM_REF_BLOOM_H */
