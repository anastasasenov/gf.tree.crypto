/** Unit tests for the Dynamic N-Tree impl */

#define _XOPEN_SOURCE 500
#include "gf_crypto_tree.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>



static int hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static void hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    for (size_t i = 0; i < out_len; ++i) {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);
        assert(hi >= 0 && lo >= 0);
        out[i] = (uint8_t)((hi << 4) | lo);
    }
}

static void test_gf_vectors(void)
{
    assert(gf_mul(0x57, 0x13) == 0xFE);
    assert(gf_mul(0x00, 0xAB) == 0x00);
    assert(gf_mul(0xAB, 0x00) == 0x00);
    assert(gf_mul(0x01, 0xAB) == 0xAB);
    assert(gf_mul(0x02, 0x80) == 0x1B);
    assert(gf_mul(0xFF, 0x01) == 0xFF);

    assert(gf_inv(0) == 0);
    for (unsigned int a = 1; a <= 255; ++a) {
        assert(gf_mul((uint8_t)a, gf_inv((uint8_t)a)) == 0x01);
    }
}

static void test_gf_block(void)
{
    uint8_t key[KEY_SIZE] = {
        0x00, 0x01, 0x00, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    uint8_t input[64];
    uint8_t encrypted[64];
    uint8_t decrypted[64];

    for (size_t i = 0; i < sizeof input; ++i) {
        input[i] = (uint8_t)(i * 7 + 3);
    }

    gf_mul_block_enc(encrypted, input, key, sizeof input);
    gf_mul_block_dec(decrypted, encrypted, key, sizeof input);

    assert(memcmp(input, decrypted, sizeof input) == 0);
    assert(memcmp(input, encrypted, sizeof input) != 0);

    for (size_t i = 0; i < sizeof key; ++i) {
        if (key[i] == 0) {
            key[i] = 0x01;
        }
    }
    uint8_t expected[64];
    gf_mul_block_enc(expected, input, key, sizeof input);
    assert(memcmp(expected, encrypted, sizeof input) == 0);
}

static void test_rotl_key(void)
{
    uint8_t original[KEY_SIZE];

    for (size_t i = 0; i < KEY_SIZE; ++i) {
        original[i] = (uint8_t)(i * 0x11);
    }

    uint8_t key[KEY_SIZE];

    memcpy(key, original, KEY_SIZE);
    rotl_key(key, 0);
    assert(memcmp(key, original, KEY_SIZE) == 0);

    memcpy(key, original, KEY_SIZE);
    rotl_key(key, 128);
    assert(memcmp(key, original, KEY_SIZE) == 0);

    uint8_t sequence[KEY_SIZE];
    uint8_t expected_byte_shift[KEY_SIZE];
    for (size_t i = 0; i < KEY_SIZE; ++i) {
        sequence[i] = (uint8_t)i;
        expected_byte_shift[i] = (uint8_t)((i + 1) % KEY_SIZE);
    }
    rotl_key(sequence, 8);
    assert(memcmp(sequence, expected_byte_shift, KEY_SIZE) == 0);

    uint8_t bit_rotated[KEY_SIZE];
    memcpy(key, original, KEY_SIZE);
    rotl_key(key, 4);
    for (size_t i = 0; i < KEY_SIZE; ++i) {
        bit_rotated[i] = (uint8_t)((original[i] << 4) |
                                   (original[(i + 1) % KEY_SIZE] >> 4));
    }
    assert(memcmp(key, bit_rotated, KEY_SIZE) == 0);

    for (unsigned int shift = 1; shift < 128; ++shift) {
        memcpy(key, original, KEY_SIZE);
        rotl_key(key, shift);
        rotl_key(key, 128 - shift);
        assert(memcmp(key, original, KEY_SIZE) == 0);
    }
}

static void test_sha256_vectors(void)
{
    uint8_t digest[SHA256_DIGEST_SIZE];
    uint8_t expected[SHA256_DIGEST_SIZE];

    sha256("", 0, digest);
    hex_to_bytes("e3b0c44298fc1c149afbf4c8996fb924"
                 "27ae41e4649b934ca495991b7852b855",
                 expected, sizeof expected);
    assert(memcmp(digest, expected, sizeof expected) == 0);

    sha256("abc", 3, digest);
    hex_to_bytes("ba7816bf8f01cfea414140de5dae2223"
                 "b00361a396177a9cb410ff61f20015ad",
                 expected, sizeof expected);
    assert(memcmp(digest, expected, sizeof expected) == 0);
}

static void test_hmac_sha256_vector(void)
{
    uint8_t digest[SHA256_DIGEST_SIZE];
    uint8_t expected[SHA256_DIGEST_SIZE];
    const uint8_t key[] = { 'J', 'e', 'f', 'e' };
    const char *data = "what do ya want for nothing?";

    hmac_sha256(key, sizeof key, data, strlen(data), digest);
    hex_to_bytes("5bdcc146bf60754e6a042426089575c7"
                 "5a003f089d2739839dec58b964ec3843",
                 expected, sizeof expected);
    assert(memcmp(digest, expected, sizeof expected) == 0);
}

static void test_key_derivation(void)
{
    uint8_t parent[KEY_SIZE];
    uint8_t a[KEY_SIZE];
    uint8_t b[KEY_SIZE];
    uint8_t c[KEY_SIZE];
    uint8_t again[KEY_SIZE];

    for (size_t i = 0; i < KEY_SIZE; ++i) {
        parent[i] = (uint8_t)(i + 1);
    }

    derive_child_key(parent, a, 1, 0);
    derive_child_key(parent, b, 1, 1);
    derive_child_key(parent, c, 2, 0);
    derive_child_key(parent, again, 1, 0);

    assert(memcmp(a, parent, KEY_SIZE) != 0);
    assert(memcmp(a, b, KEY_SIZE) != 0);
    assert(memcmp(a, c, KEY_SIZE) != 0);
    assert(memcmp(a, again, KEY_SIZE) == 0);
}

static void test_api_errors(void)
{
    assert(create_node(0, false, 0) == NULL);
    assert(create_node(0, false, MAX_BLOCK_SIZE + 1) == NULL);
    assert(!node_set_key(NULL, NULL));
    assert(!node_set_nonce(NULL, NULL));
    assert(!leaf_set_token(NULL, "x", 1));
    assert(!add_child(NULL, NULL));

    CryptoNode *parent = create_node(0, false, 32);
    CryptoNode *wrong_size = create_node(1, true, 64);
    CryptoNode *leaf = create_node(2, true, 32);

    assert(parent && wrong_size && leaf);
    assert(!add_child(parent, wrong_size));
    assert(!leaf_set_token(leaf, "this token is far too long", 33));

    assert(leaf_set_token(leaf, "", 0));
    assert(!leaf_set_token(wrong_size, "wrong size", 65));
    assert(!validate_tree(parent));
    assert(!decrypt_leaf(leaf, NULL, NULL));

    free_node(parent);
    free_node(wrong_size);
    free_node(leaf);
}

static void test_tree_pipeline(void)
{
    const size_t block_size = 64;
    char long_token[65];
    memset(long_token, 'x', 64);
    long_token[64] = '\0';

    const char *tokens[4] = { "", "A", "hello world", long_token };

    CryptoNode *root = create_node(0, false, block_size);
    CryptoNode *inter0 = create_node(1, false, block_size);
    CryptoNode *inter1 = create_node(2, false, block_size);
    CryptoNode *leaves[4] = { NULL, NULL, NULL, NULL };

    assert(root && inter0 && inter1);

    uint8_t root_key[KEY_SIZE];
    for (size_t i = 0; i < KEY_SIZE; ++i) {
        root_key[i] = (uint8_t)(i * 0x11 + 0xA5);
    }
    assert(node_set_key(root, root_key));

    uint8_t child_key[KEY_SIZE];
    derive_child_key(root_key, child_key, (uint32_t)root->id, 0);
    assert(node_set_key(inter0, child_key));
    derive_child_key(root_key, child_key, (uint32_t)root->id, 1);
    assert(node_set_key(inter1, child_key));

    assert(add_child(root, inter0));
    assert(add_child(root, inter1));

    for (int i = 0; i < 4; ++i) {
        CryptoNode *parent = (i < 2) ? inter0 : inter1;

        leaves[i] = create_node(3 + i, true, block_size);
        assert(leaves[i]);

        derive_child_key(parent->node_key, child_key,
                         (uint32_t)parent->id, (uint32_t)(i % 2));
        assert(node_set_key(leaves[i], child_key));
        assert(add_child(parent, leaves[i]));
        assert(leaf_set_token(leaves[i], tokens[i], strlen(tokens[i])));
    }

    for (int i = 0; i < 4; ++i) {
        assert(encrypt_leaf(leaves[i]));
        assert(leaves[i]->leaf_token == NULL);
        assert(leaves[i]->content_ready);
    }

    assert(aggregate_node(inter0));
    assert(aggregate_node(inter1));
    assert(aggregate_node(root));

    assert(validate_node(root));
    assert(validate_node(inter0));
    assert(validate_node(inter1));
    assert(validate_tree(root));

    for (int i = 0; i < 4; ++i) {
        char *recovered = NULL;
        size_t recovered_len = 0;

        assert(decrypt_leaf(leaves[i], &recovered, &recovered_len));
        assert(recovered_len == strlen(tokens[i]));
        assert(memcmp(recovered, tokens[i], recovered_len) == 0);
        free(recovered);
    }

    uint8_t saved = leaves[0]->encrypted_content[0];
    leaves[0]->encrypted_content[0] = (uint8_t)(saved ^ 0xFFu);
    assert(!validate_tree(root));
    leaves[0]->encrypted_content[0] = saved;
    assert(validate_tree(root));

    uint8_t saved_tag = inter1->tag[0];
    inter1->tag[0] = (uint8_t)(saved_tag ^ 0x01u);
    assert(!validate_tree(root));
    inter1->tag[0] = saved_tag;
    assert(validate_tree(root));

    uint8_t saved_root = root->encrypted_content[0];
    root->encrypted_content[0] = (uint8_t)(saved_root ^ 0x80u);
    assert(!validate_tree(root));
    root->encrypted_content[0] = saved_root;
    assert(validate_tree(root));

    leaves[2]->encrypted_content[0] ^= 0xFFu;
    char *recovered = NULL;
    size_t recovered_len = 0;
    assert(!decrypt_leaf(leaves[2], &recovered, &recovered_len));
    leaves[2]->encrypted_content[0] ^= 0xFFu;
    assert(decrypt_leaf(leaves[2], &recovered, &recovered_len));
    free(recovered);

    free_node(root);
}

int main(void)
{
    test_gf_vectors();
    test_gf_block();
    test_rotl_key();
    test_sha256_vectors();
    test_hmac_sha256_vector();
    test_key_derivation();
    test_api_errors();
    test_tree_pipeline();

    printf("All GaloisTreeCrypto tests passed.\n");
    return 0;
}
