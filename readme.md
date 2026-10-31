## GaloisTreeCrypto

An experimental C11 implementation of an alternative symmetric key cryptosystem
that combines a dynamically allocated Nary tree with algebraic diffusion
performed over the Galois Field ( GF(2^8), AES polynomial 0x11B ).

The program demonstrates:
    . key derivation
    . leaf encryption
    . hierarchical aggregation
    . zero-trust top down validation

### Architecture

The system models data as a dynamic Nary tree where each node holds a
cryptographic key derived from its parent:

    . Leaf nodes contain plaintext tokens. They are encrypted by multiplying each
    byte of the token with the corresponding byte of the node's key in GF(2**8).

    . Intermediate nodes XOR the ciphertexts of all direct children and then
    encrypt the resulting block with their own key.

    . Zero-trust validation is performed top down: a node decrypts its own
    ciphertext, recomputes the XOR of its children, and compares the two buffers.


### Build

```bash

git clone ::https://github/xxx/gf_tree_crypto.git
mkdir  build && cd build
cmake gf_tree_crypto
make

./gf_tree_crypto # demo
./test_crypto_tree # unit tests
```

### Security

    . key isolation: child keys are derived via a non linear operation
      (GF multiplication + XOR + rotation)
    . block-size flexibility - larger blocks increase diffusion ( high mem.usage )
    . zero-trust model - validation occurs before any plaintext
    . No external dependencies - only the C std.lib is used


### License

Distributed under the MIT License.

