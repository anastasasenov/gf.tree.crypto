/** gf_tree_crypto: demo Dynamic Cryptographic Tree */

#include "gf_crypto_tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifndef UNIT_TEST

static void demo_nonce(CryptoNode *node)
{
    uint8_t nonce[NONCE_SIZE];

    for (size_t i = 0; i < NONCE_SIZE; ++i) {
        nonce[i] = (uint8_t)((node->id * 31 + (int)i * 7 + 1) & 0xFF);
    }
    (void)node_set_nonce(node, nonce);
}

static bool set_leaf(CryptoNode *leaf, const char *token)
{
    return leaf_set_token(leaf, token, strlen(token));
}

int main(void)
{
    const size_t block_size = DEFAULT_BLOCK_SIZE;
    const char *tokens[4] = { "Leaf0", "Leaf1", "Leaf2", "Leaf3" };
    CryptoNode *leaves[4] = { NULL, NULL, NULL, NULL };
    bool ok = true;

    CryptoNode *root = create_node(0, false, block_size);
    CryptoNode *inter0 = create_node(1, false, block_size);
    CryptoNode *inter1 = create_node(2, false, block_size);

    if (!root || !inter0 || !inter1) {
        fprintf(stderr, "Failed to allocate nodes\n");
        free_node(root);
        free_node(inter0);
        free_node(inter1);
        return EXIT_FAILURE;
    }

    demo_nonce(root);
    demo_nonce(inter0);
    demo_nonce(inter1);

    uint8_t root_key[KEY_SIZE];
    for (size_t i = 0; i < KEY_SIZE; ++i) {
        root_key[i] = (uint8_t)(i * 0x11 + 0xA5);
    }
    ok &= node_set_key(root, root_key);

    uint8_t child_key[KEY_SIZE];
    derive_child_key(root_key, child_key, (uint32_t)root->id, 0);
    ok &= node_set_key(inter0, child_key);
    derive_child_key(root_key, child_key, (uint32_t)root->id, 1);
    ok &= node_set_key(inter1, child_key);

    ok &= add_child(root, inter0);
    ok &= add_child(root, inter1);

    for (int i = 0; i < 4; ++i) {
        CryptoNode *parent = (i < 2) ? inter0 : inter1;
        leaves[i] = create_node(3 + i, true, block_size);
        if (!leaves[i]) {
            fprintf(stderr, "Failed to allocate leaf %d\n", i);
            free_node(root);
            return EXIT_FAILURE;
        }

        demo_nonce(leaves[i]);

        derive_child_key(parent->node_key, child_key,
                         (uint32_t)parent->id, (uint32_t)(i % 2));
        ok &= node_set_key(leaves[i], child_key);
        ok &= add_child(parent, leaves[i]);
        ok &= set_leaf(leaves[i], tokens[i]);
    }

    if (!ok) {
        fprintf(stderr, "Tree setup failed\n");
        free_node(root);
        return EXIT_FAILURE;
    }

    printf("=== Leaf encryption ===\n");
    for (int i = 0; i < 4; ++i) {
        if (!encrypt_leaf(leaves[i])) {
            fprintf(stderr, "Failed to encrypt leaf %d\n", i);
            free_node(root);
            return EXIT_FAILURE;
        }
        printf("\nleaf %d (\"%s\") plaintext wiped: %s\n",
               i, tokens[i], leaves[i]->leaf_token == NULL ? "yes" : "no");
        print_hex("  ciphertext", leaves[i]->encrypted_content, block_size);
        print_hex("  tag", leaves[i]->tag, TAG_SIZE);
    }

    printf("\n=== Bottom-up aggregation ===\n");
    if (!aggregate_node(inter0) ||
        !aggregate_node(inter1) ||
        !aggregate_node(root)) {
        fprintf(stderr, "Aggregation failed\n");
        free_node(root);
        return EXIT_FAILURE;
    }
    print_hex("inter0", inter0->encrypted_content, block_size);
    print_hex("inter1", inter1->encrypted_content, block_size);
    print_hex("root  ", root->encrypted_content, block_size);

    printf("\n=== Top-down validation ===\n");
    bool valid = validate_tree(root);
    printf("validate_tree: %s\n", valid ? "SUCCESS" : "FAILURE");

    printf("\n=== Leaf decryption ===\n");
    bool decrypt_ok = true;
    for (int i = 0; i < 4; ++i) {
        char *recovered = NULL;
        size_t recovered_len = 0;

        if (!decrypt_leaf(leaves[i], &recovered, &recovered_len)) {
            printf("leaf %d: decryption FAILED\n", i);
            decrypt_ok = false;
            continue;
        }

        bool matches = recovered_len == strlen(tokens[i]) &&
                       memcmp(recovered, tokens[i], recovered_len) == 0;
        printf("leaf %d: \"%s\" (%s)\n", i, recovered,
               matches ? "matches" : "MISMATCH");
        decrypt_ok &= matches;
        free(recovered);
    }

    printf("\n=== Tamper detection ===\n");
    uint8_t saved = leaves[0]->encrypted_content[0];
    leaves[0]->encrypted_content[0] = (uint8_t)(saved ^ 0xFFu);
    bool tampered = validate_tree(root);
    leaves[0]->encrypted_content[0] = saved;
    bool restored = validate_tree(root);

    printf("modified leaf detected: %s\n", tampered ? "NO (bad)" : "yes");
    printf("original restored:      %s\n", restored ? "yes" : "NO (bad)");

    bool all_ok = valid && decrypt_ok && !tampered && restored;
    printf("\nOverall: %s\n", all_ok ? "SUCCESS" : "FAILURE");

    free_node(root);

    return all_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

#endif /** ifndef UNIT_TEST */
