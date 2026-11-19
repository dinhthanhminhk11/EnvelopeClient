/*
 * Two Rust static libraries in one executable (tools/c-abi-smoke.sh, step 5): DoodleArtCore as build-ios.sh ships it
 * (prelinked: only doodleart_* global, its Rust runtime local) next to tests/c-abi/other_rust.rs, an ordinary Rust
 * staticlib whose std and runtime symbols are global. include/doodleart_core.h ("Linking") promises that this links
 * without duplicate symbols (the script checks the link) and that each library keeps its own runtime and panic hook:
 *   1. the other library installs its counting panic hook first;
 *   2. doodleart_init answers OK: its first call installed DoodleArtCore's silent panic hook, in DoodleArtCore's own runtime;
 *   3. a panic in the other library is caught there (-1) AND its own hook saw it: with a shared runtime DoodleArtCore's
 *      set_hook would have replaced that hook (count 0);
 *   4. the other library still works (other_rust_call(1) == 2), and so does DoodleArtCore after that panic
 *      (doodleart_ios_device_hash of the vector, its length check).
 * A panic inside a doodleart_* function cannot be caused from C in a shipped library; its INTERNAL reply and its silent
 * hook are covered by the unit tests of src/ffi/tests.rs. expect.h and vectors.h are written by the script. Exit
 * status 0 when every check passed.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "expect.h"
#include "doodleart_core.h"
#include "vectors.h"

void other_rust_install_hook(void);
uint32_t other_rust_hook_calls(void);
int32_t other_rust_call(int32_t x);

static int failures = 0;

#define CHECK(condition, what)                            \
    do {                                                  \
        if (!(condition)) {                               \
            failures++;                                   \
            fprintf(stderr, "FAIL two-rust: %s\n", what); \
        }                                                 \
    } while (0)

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(void) {
    uint8_t secret[64];
    size_t secret_len = strlen(V_IOS_SECRET_HEX) / 2;
    DoodleArtBuf buf;
    size_t i;

    other_rust_install_hook();

    buf = doodleart_init();
    CHECK(buf.ptr != NULL && buf.len > 1 && buf.ptr[0] == DOODLEART_STATUS_OK, "doodleart_init answers OK");
    doodleart_buf_free(buf);

    CHECK(other_rust_call(42) == -1, "the other library catches its own panic");
    CHECK(other_rust_hook_calls() == 1, "the other library's hook still runs after doodleart_init installed its own");
    CHECK(other_rust_call(1) == 2, "the other library works after its panic");

    CHECK(secret_len <= sizeof secret, "vector secret size");
    for (i = 0; i < secret_len && i < sizeof secret; i++) {
        secret[i] = (uint8_t)(hex_value(V_IOS_SECRET_HEX[2 * i]) << 4 | hex_value(V_IOS_SECRET_HEX[2 * i + 1]));
    }
    buf = doodleart_ios_device_hash(secret, secret_len);
    CHECK(buf.ptr != NULL && buf.len == 1 + strlen(V_IOS_HASH) && buf.ptr[0] == DOODLEART_STATUS_OK &&
              memcmp(buf.ptr + 1, V_IOS_HASH, strlen(V_IOS_HASH)) == 0,
          "doodleart_ios_device_hash gives the vector after the other library's panic");
    doodleart_buf_free(buf);
    buf = doodleart_ios_device_hash(secret, secret_len - 1);
    CHECK(buf.ptr != NULL && buf.len == 1 && buf.ptr[0] == DOODLEART_STATUS_INVALID_ARGUMENT,
          "doodleart_ios_device_hash refuses 31 bytes");
    doodleart_buf_free(buf);

    if (failures == 0) {
        printf("two Rust libraries (%s): ok\n", EXPECT_BUILD_TYPE);
    }
    return failures == 0 ? 0 : 1;
}
