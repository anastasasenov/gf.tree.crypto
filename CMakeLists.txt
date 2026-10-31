cmake_minimum_required(VERSION 3.16)
project(GaloisTreeCrypto C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -O3 -fstack-protector-strong -D_FORTIFY_SOURCE=2)
elseif(MSVC)
    add_compile_options(/W4 /O2 /GS)
endif()

include_directories(${PROJECT_SOURCE_DIR}/include)

add_executable(gf_tree_crypto
    src/gf_crypto_tree_impl.c
    src/main.c
)

# Unit tests
enable_testing()

# UNIT_TEST
add_executable(test_crypto_tree
    tests/test_crypto_tree.c
    src/gf_crypto_tree_impl.c
)
target_compile_definitions(test_crypto_tree PRIVATE UNIT_TEST)

add_test(NAME crypto_tree_test COMMAND test_crypto_tree)
