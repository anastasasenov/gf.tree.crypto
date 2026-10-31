/** gf_tree_crypto: demo Dynamic Cryptographic Tree */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "gf_crypto_tree.h"


static const uint32_t K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    size_t datalen;
} sha256_ctx;

static uint32_t rotr32(uint32_t x, unsigned int n)
{
    return (x >> n) | (x << (32u - n));
}

static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void store_be64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)v;
}

static void secure_wipe(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len-- > 0) {
        *p++ = 0;
    }
}

static void sha256_transform(sha256_ctx *ctx, const uint8_t data[64])
{
    uint32_t w[64];

    for (size_t i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)data[4 * i] << 24) |
               ((uint32_t)data[4 * i + 1] << 16) |
               ((uint32_t)data[4 * i + 2] << 8) |
               ((uint32_t)data[4 * i + 3]);
    }

    for (size_t i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];

    for (size_t i = 0; i < 64; ++i) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + s1 + ch + K256[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx)
{
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->bitlen = 0;
    ctx->datalen = 0;
}

static void sha256_update(sha256_ctx *ctx, const void *data, size_t len)
{
    if (len == 0) {
        return;
    }

    const uint8_t *p = (const uint8_t *)data;

    ctx->bitlen += (uint64_t)len * 8u;

    while (len > 0) {
        size_t space = 64 - ctx->datalen;
        size_t take = (len < space) ? len : space;

        memcpy(ctx->data + ctx->datalen, p, take);
        ctx->datalen += take;
        p += take;
        len -= take;

        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t out[SHA256_DIGEST_SIZE])
{
    uint64_t bitlen = ctx->bitlen;
    uint8_t pad = 0x80;
    uint8_t zero = 0x00;
    uint8_t lenbuf[8];

    sha256_update(ctx, &pad, 1);
    while (ctx->datalen != 56) {
        sha256_update(ctx, &zero, 1);
    }

    store_be64(lenbuf, bitlen);
    sha256_update(ctx, lenbuf, sizeof lenbuf);

    for (size_t i = 0; i < 8; ++i) {
        store_be32(out + 4 * i, ctx->state[i]);
    }

    secure_wipe(ctx, sizeof *ctx);
}

void sha256(const void *data, size_t len,
            uint8_t out[SHA256_DIGEST_SIZE])
{
    sha256_ctx ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

void hmac_sha256(const uint8_t *key, size_t keylen,
                 const void *data, size_t datalen,
                 uint8_t out[SHA256_DIGEST_SIZE])
{
    uint8_t k[64];
    uint8_t ipad[64];
    uint8_t opad[64];
    uint8_t inner[SHA256_DIGEST_SIZE];
    sha256_ctx ctx;

    memset(k, 0, sizeof k);

    if (keylen > sizeof k) {
        sha256(key, keylen, k);
    } else if (keylen > 0) {
        memcpy(k, key, keylen);
    }

    for (size_t i = 0; i < sizeof k; ++i) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36u);
        opad[i] = (uint8_t)(k[i] ^ 0x5cu);
    }

    sha256_init(&ctx);
    sha256_update(&ctx, ipad, sizeof ipad);
    sha256_update(&ctx, data, datalen);
    sha256_final(&ctx, inner);

    sha256_init(&ctx);
    sha256_update(&ctx, opad, sizeof opad);
    sha256_update(&ctx, inner, sizeof inner);
    sha256_final(&ctx, out);

    secure_wipe(k, sizeof k);
    secure_wipe(ipad, sizeof ipad);
    secure_wipe(opad, sizeof opad);
    secure_wipe(inner, sizeof inner);
}

uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;

    for (unsigned int i = 0; i < 8; ++i) {

        uint8_t add_mask = (uint8_t)(-(int)(b & 1u));
        p ^= (uint8_t)(a & add_mask);

        uint8_t hi_mask = (uint8_t)(-(int)(a >> 7));
        a = (uint8_t)(a << 1);
        a ^= (uint8_t)(0x1Bu & hi_mask);

        b >>= 1;
    }

    return p;
}

uint8_t gf_inv(uint8_t a)
{
    if (a == 0) {
        return 0;
    }

    uint8_t result = 1;
    uint8_t base = a;
    unsigned int exponent = 254;

    while (exponent != 0) {
        if (exponent & 1u) {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }

    return result;
}

uint8_t gf_key_byte(const uint8_t *key, size_t index)
{
    uint8_t k = key[index % KEY_SIZE];
    return (k == 0) ? (uint8_t)0x01 : k;
}

void gf_mul_block_enc(uint8_t *out,
                      const uint8_t *in,
                      const uint8_t *key,
                      size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        out[i] = gf_mul(in[i], gf_key_byte(key, i));
    }
}

void gf_mul_block_dec(uint8_t *out,
                      const uint8_t *in,
                      const uint8_t *key,
                      size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        out[i] = gf_mul(in[i], gf_inv(gf_key_byte(key, i)));
    }
}

void rotl_key(uint8_t key[KEY_SIZE], unsigned int shift)
{
    const unsigned int total_bits = (unsigned int)(KEY_SIZE * 8);

    shift %= total_bits;
    if (shift == 0) {
        return;
    }

    unsigned int byte_shift = (shift / 8) % KEY_SIZE;
    unsigned int bit_shift = shift % 8;

    uint8_t tmp[KEY_SIZE];

    for (size_t i = 0; i < KEY_SIZE; ++i) {
        size_t idx = (i + byte_shift) % KEY_SIZE;
        uint8_t lo = key[idx];
        uint8_t hi = key[(idx + 1) % KEY_SIZE];

        if (bit_shift == 0) {
            tmp[i] = lo;
        } else {
            tmp[i] = (uint8_t)((lo << bit_shift) |
                               (hi >> (8u - bit_shift)));
        }
    }

    for (size_t i = 0; i < KEY_SIZE; ++i) {
        key[i] = tmp[i];
    }
}

static bool ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static void keystream_chunk(const CryptoNode *node, uint64_t counter,
                            uint8_t out[SHA256_DIGEST_SIZE])
{
    uint8_t msg[4 + 4 + NONCE_SIZE + 8];
    size_t off = 0;

    memcpy(msg + off, "STRM", 4);
    off += 4;
    store_be32(msg + off, (uint32_t)node->id);
    off += 4;
    memcpy(msg + off, node->nonce, NONCE_SIZE);
    off += NONCE_SIZE;
    store_be64(msg + off, counter);
    off += 8;

    hmac_sha256(node->node_key, KEY_SIZE, msg, off, out);
}

static void content_transform(uint8_t *out, const uint8_t *in,
                              const CryptoNode *node, bool decrypt)
{
    uint8_t digest[SHA256_DIGEST_SIZE];
    uint64_t counter = 0;
    size_t off = 0;

    while (off < node->block_size) {
        keystream_chunk(node, counter, digest);

        size_t chunk = node->block_size - off;
        if (chunk > SHA256_DIGEST_SIZE) {
            chunk = SHA256_DIGEST_SIZE;
        }

        for (size_t j = 0; j < chunk; ++j) {
            size_t i = off + j;
            uint8_t key_byte = gf_key_byte(node->node_key, i);

            if (decrypt) {
                uint8_t x = gf_mul(in[i], gf_inv(key_byte));
                out[i] = (uint8_t)(x ^ digest[j]);
            } else {
                uint8_t x = (uint8_t)(in[i] ^ digest[j]);
                out[i] = gf_mul(x, key_byte);
            }
        }

        off += chunk;
        ++counter;
    }

    secure_wipe(digest, sizeof digest);
}

static bool compute_tag(const CryptoNode *node, uint8_t out[TAG_SIZE])
{
    size_t msglen = 4 + 4 + 4 + 8 + 8 + 8 + NONCE_SIZE + node->block_size;
    uint8_t *msg = malloc(msglen);
    if (!msg) {
        return false;
    }

    size_t off = 0;

    memcpy(msg + off, "TAG1", 4);
    off += 4;
    store_be32(msg + off, (uint32_t)node->id);
    off += 4;
    store_be32(msg + off, node->is_leaf ? 1u : 0u);
    off += 4;
    store_be64(msg + off, (uint64_t)node->children_count);
    off += 8;
    store_be64(msg + off, (uint64_t)node->leaf_token_len);
    off += 8;
    store_be64(msg + off, (uint64_t)node->block_size);
    off += 8;
    memcpy(msg + off, node->nonce, NONCE_SIZE);
    off += NONCE_SIZE;
    memcpy(msg + off, node->encrypted_content, node->block_size);
    off += node->block_size;

    hmac_sha256(node->node_key, KEY_SIZE, msg, msglen, out);
    secure_wipe(msg, msglen);
    free(msg);
    return true;
}

CryptoNode *create_node(int id, bool is_leaf, size_t block_size)
{
    if (block_size == 0 || block_size > MAX_BLOCK_SIZE) {
        return NULL;
    }

    CryptoNode *node = calloc(1, sizeof *node);
    if (!node) {
        return NULL;
    }

    node->encrypted_content = calloc(1, block_size);
    if (!node->encrypted_content) {
        free(node);
        return NULL;
    }

    node->id = id;
    node->is_leaf = is_leaf;
    node->block_size = block_size;
    node->content_ready = false;
    node->children = NULL;
    node->children_count = 0;
    node->children_capacity = 0;
    return node;
}

void free_node(CryptoNode *node)
{
    if (!node) {
        return;
    }

    for (size_t i = 0; i < node->children_count; ++i) {
        free_node(node->children[i]);
    }
    free(node->children);

    if (node->leaf_token) {
        secure_wipe(node->leaf_token, node->leaf_token_len);
        free(node->leaf_token);
    }
    if (node->encrypted_content) {
        secure_wipe(node->encrypted_content, node->block_size);
        free(node->encrypted_content);
    }

    secure_wipe(node->node_key, sizeof node->node_key);
    secure_wipe(node->tag, sizeof node->tag);
    free(node);
}

bool node_set_key(CryptoNode *node, const uint8_t key[KEY_SIZE])
{
    if (!node || !key) {
        return false;
    }

    memcpy(node->node_key, key, KEY_SIZE);
    node->content_ready = false;
    return true;
}

bool node_set_nonce(CryptoNode *node, const uint8_t nonce[NONCE_SIZE])
{
    if (!node || !nonce) {
        return false;
    }

    memcpy(node->nonce, nonce, NONCE_SIZE);
    node->content_ready = false;
    return true;
}

bool leaf_set_token(CryptoNode *leaf, const char *token, size_t len)
{
    if (!leaf || !leaf->is_leaf) {
        return false;
    }
    if (token == NULL && len != 0) {
        return false;
    }
    if (len > leaf->block_size) {
        return false;
    }

    char *copy = malloc(len + 1);
    if (!copy) {
        return false;
    }
    if (len > 0) {
        memcpy(copy, token, len);
    }
    copy[len] = '\0';

    if (leaf->leaf_token) {
        secure_wipe(leaf->leaf_token, leaf->leaf_token_len);
        free(leaf->leaf_token);
    }

    leaf->leaf_token = copy;
    leaf->leaf_token_len = len;
    leaf->content_ready = false;
    return true;
}

bool add_child(CryptoNode *parent, CryptoNode *child)
{
    if (!parent || !child || parent == child || parent->is_leaf) {
        return false;
    }
    if (parent->block_size != child->block_size) {
        return false;
    }

    if (parent->children_count == parent->children_capacity) {
        size_t new_capacity = parent->children_capacity == 0
                                  ? 4
                                  : parent->children_capacity * 2;

        if (new_capacity < parent->children_capacity ||
            new_capacity > ((size_t)-1) / sizeof(CryptoNode *)) {
            return false;
        }

        CryptoNode **grown = realloc(parent->children,
                                     new_capacity * sizeof *grown);
        if (!grown) {
            return false;
        }

        parent->children = grown;
        parent->children_capacity = new_capacity;
    }

    parent->children[parent->children_count++] = child;
    return true;
}

void derive_child_key(const uint8_t parent_key[KEY_SIZE],
                      uint8_t child_key[KEY_SIZE],
                      uint32_t parent_id,
                      uint32_t child_index)
{
    uint8_t msg[12];
    uint8_t digest[SHA256_DIGEST_SIZE];

    memcpy(msg, "CTK1", 4);
    store_be32(msg + 4, parent_id);
    store_be32(msg + 8, child_index);

    hmac_sha256(parent_key, KEY_SIZE, msg, sizeof msg, digest);
    memcpy(child_key, digest, KEY_SIZE);

    secure_wipe(digest, sizeof digest);
    secure_wipe(msg, sizeof msg);
}

bool encrypt_leaf(CryptoNode *leaf)
{
    if (!leaf || !leaf->is_leaf) {
        return false;
    }
    if (leaf->leaf_token_len > leaf->block_size) {
        return false;
    }
    if (leaf->leaf_token == NULL && leaf->leaf_token_len != 0) {
        return false;
    }

    uint8_t *plain = calloc(1, leaf->block_size);
    if (!plain) {
        return false;
    }

    if (leaf->leaf_token_len > 0) {
        memcpy(plain, leaf->leaf_token, leaf->leaf_token_len);
    }

    content_transform(leaf->encrypted_content, plain, leaf, false);

    bool ok = compute_tag(leaf, leaf->tag);
    if (ok) {
        leaf->content_ready = true;
    }

    secure_wipe(plain, leaf->block_size);
    free(plain);

    if (ok && leaf->leaf_token) {
        secure_wipe(leaf->leaf_token, leaf->leaf_token_len);
        free(leaf->leaf_token);
        leaf->leaf_token = NULL;
    }

    return ok;
}

bool decrypt_leaf(const CryptoNode *leaf, char **out_token, size_t *out_len)
{
    if (!leaf || !leaf->is_leaf || !leaf->content_ready ||
        !out_token || !out_len) {
        return false;
    }

    *out_token = NULL;
    *out_len = 0;

    uint8_t expected[TAG_SIZE];
    if (!compute_tag(leaf, expected)) {
        return false;
    }
    if (!ct_equal(expected, leaf->tag, TAG_SIZE)) {
        return false;
    }

    uint8_t *plain = calloc(1, leaf->block_size);
    if (!plain) {
        return false;
    }

    content_transform(plain, leaf->encrypted_content, leaf, true);

    char *token = malloc(leaf->leaf_token_len + 1);
    if (!token) {
        secure_wipe(plain, leaf->block_size);
        free(plain);
        return false;
    }

    if (leaf->leaf_token_len > 0) {
        memcpy(token, plain, leaf->leaf_token_len);
    }
    token[leaf->leaf_token_len] = '\0';

    *out_token = token;
    *out_len = leaf->leaf_token_len;

    secure_wipe(plain, leaf->block_size);
    free(plain);
    return true;
}

bool aggregate_node(CryptoNode *node)
{
    if (!node || node->is_leaf) {
        return false;
    }

    uint8_t *fold = calloc(1, node->block_size);
    if (!fold) {
        return false;
    }

    for (size_t i = 0; i < node->children_count; ++i) {
        const CryptoNode *child = node->children[i];

        if (!child->content_ready ||
            child->block_size != node->block_size) {
            secure_wipe(fold, node->block_size);
            free(fold);
            return false;
        }

        for (size_t j = 0; j < node->block_size; ++j) {
            fold[j] ^= child->encrypted_content[j];
        }
    }

    content_transform(node->encrypted_content, fold, node, false);

    bool ok = compute_tag(node, node->tag);
    if (ok) {
        node->content_ready = true;
    }

    secure_wipe(fold, node->block_size);
    free(fold);
    return ok;
}

bool validate_node(const CryptoNode *node)
{
    if (!node || !node->content_ready) {
        return false;
    }

    uint8_t expected[TAG_SIZE];
    if (!compute_tag(node, expected)) {
        return false;
    }
    if (!ct_equal(expected, node->tag, TAG_SIZE)) {
        return false;
    }

    if (node->is_leaf) {
        return true;
    }

    uint8_t *decrypted = calloc(1, node->block_size);
    uint8_t *fold = calloc(1, node->block_size);
    if (!decrypted || !fold) {
        free(decrypted);
        free(fold);
        return false;
    }

    content_transform(decrypted, node->encrypted_content, node, true);

    for (size_t i = 0; i < node->children_count; ++i) {
        const CryptoNode *child = node->children[i];

        if (!child->content_ready ||
            child->block_size != node->block_size) {
            secure_wipe(decrypted, node->block_size);
            secure_wipe(fold, node->block_size);
            free(decrypted);
            free(fold);
            return false;
        }

        for (size_t j = 0; j < node->block_size; ++j) {
            fold[j] ^= child->encrypted_content[j];
        }
    }

    bool ok = ct_equal(decrypted, fold, node->block_size);

    secure_wipe(decrypted, node->block_size);
    secure_wipe(fold, node->block_size);
    free(decrypted);
    free(fold);
    return ok;
}

bool validate_tree(const CryptoNode *node)
{
    if (!node) {
        return false;
    }
    if (!validate_node(node)) {
        return false;
    }
    if (node->is_leaf) {
        return true;
    }

    for (size_t i = 0; i < node->children_count; ++i) {
        if (!validate_tree(node->children[i])) {
            return false;
        }
    }
    return true;
}

void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s:", label);
    for (size_t i = 0; i < len; ++i) {
        if (i % 16 == 0) {
            printf("\n  ");
        }
        printf("%02X ", (unsigned int)data[i]);
    }
    printf("\n");
}
