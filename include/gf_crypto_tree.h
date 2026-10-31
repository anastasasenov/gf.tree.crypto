#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define DEFAULT_BLOCK_SIZE  (32u)
#define MAX_BLOCK_SIZE      (1024u * 1024u)
#define NONCE_SIZE          (8u)
#define TAG_SIZE            (32u)
#define KEY_SIZE            (16u)
#define SHA256_DIGEST_SIZE  (32u)

/** representation of a node in dynamic tree */
typedef struct CryptoNode {

    int id;                         /** unique identifier */
    uint8_t node_key[KEY_SIZE];     /** per node key */
    uint8_t nonce[NONCE_SIZE];
    uint8_t *encrypted_content;     /* exactly block_size bytes */
    uint8_t tag[TAG_SIZE];          /* authentication tag for this node */
    size_t block_size;
    bool is_leaf;                   /** true when it is a leaf node */
    bool content_ready;             /* ciphertext + tag have been produced */
    char *leaf_token;               /* plaintext staging area (leaves only) */
    size_t leaf_token_len;
    struct CryptoNode **children;   /** array of child pointers */
    size_t children_count;          /** number of children */
    size_t children_capacity;

} CryptoNode;


/** primitive operations GF/AES */
uint8_t gf_mul(uint8_t a, uint8_t b);
uint8_t gf_inv(uint8_t a);
void gf_mul_block_enc(uint8_t *out,
                      const uint8_t *in,
                      const uint8_t *key,
                      size_t len);
void gf_mul_block_dec(uint8_t *out,
                      const uint8_t *in,
                      const uint8_t *key,
                      size_t len);
uint8_t gf_key_byte(const uint8_t *key, size_t index);
void rotl_key(uint8_t key[KEY_SIZE], unsigned int shift);
uint8_t gf_mul(uint8_t a, uint8_t b);
void gf_mul_block(uint8_t *out,
                   const uint8_t *in,
                   const uint8_t *key,
                   size_t len);
void rotl_key(uint8_t *key, unsigned int shift);
void derive_child_key(const uint8_t parent_key[KEY_SIZE],
                      uint8_t child_key[KEY_SIZE],
                      uint32_t parent_id,
                      uint32_t child_index);

/** SHA-256 */
void sha256(const void *data, size_t len,
            uint8_t out[SHA256_DIGEST_SIZE]);
void hmac_sha256(const uint8_t *key, size_t keylen,
                 const void *data, size_t datalen,
                 uint8_t out[SHA256_DIGEST_SIZE]);

/** tree management */
CryptoNode *create_node(int id, bool is_leaf, size_t block_size);
void free_node(CryptoNode *node);
bool node_set_key(CryptoNode *node, const uint8_t key[KEY_SIZE]);
bool node_set_nonce(CryptoNode *node, const uint8_t nonce[NONCE_SIZE]);
bool leaf_set_token(CryptoNode *leaf, const char *token, size_t len);
bool add_child(CryptoNode *parent, CryptoNode *child);
void derive_child_key(const uint8_t parent_key[KEY_SIZE],
                      uint8_t child_key[KEY_SIZE],
                      uint32_t parent_id,
                      uint32_t child_index);

/** cryptographic pipeline */
bool encrypt_leaf(CryptoNode *leaf);
bool decrypt_leaf(const CryptoNode *leaf, char **out_token, size_t *out_len);
bool aggregate_node(CryptoNode *node);
bool validate_node(const CryptoNode *node);
bool validate_tree(const CryptoNode *node);

/** debug/trace */
void print_hex(const char *label, const uint8_t *data, size_t len);



