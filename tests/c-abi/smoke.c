/*
 * C ABI smoke test (tools/c-abi-smoke.sh): calls the static library through include/doodleart_core.h exactly as a C or
 * Swift caller does, on the shared vectors (vectors.h, generated from tests/fixtures by gen_vectors.py). expect.h,
 * written by the script, gives EXPECT_BUILD_TYPE, EXPECT_PROJECT_ID and EXPECT_DEBUG_HOOKS of the library under test.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "expect.h"
#include "doodleart_core.h"
#include "vectors.h"

static int checks = 0;
static int failures = 0;

#define CHECK(condition, ...)                                                                                        \
    do {                                                                                                             \
        checks++;                                                                                                    \
        if (!(condition)) {                                                                                          \
            failures++;                                                                                              \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);                                                     \
            fprintf(stderr, __VA_ARGS__);                                                                            \
            fputc('\n', stderr);                                                                                     \
        }                                                                                                            \
    } while (0)

/* A C string as a (ptr, len) pair. */
#define TEXT(value) (const uint8_t *)(value), strlen(value)

/* A reply copied out of its DoodleArtBuf, which is released at once (the caller's side of the ownership rule). */
typedef struct {
    uint8_t *bytes;
    size_t len;
} Reply;

static Reply take(DoodleArtBuf buf) {
    Reply reply = {NULL, 0};
    if (buf.ptr == NULL || buf.len == 0) {
        fprintf(stderr, "FAIL: NULL or empty reply\n");
        exit(2);
    }
    reply.bytes = malloc(buf.len);
    if (reply.bytes == NULL) {
        exit(2);
    }
    memcpy(reply.bytes, buf.ptr, buf.len);
    reply.len = buf.len;
    doodleart_buf_free(buf);
    return reply;
}

static int status_of(DoodleArtBuf buf) {
    Reply reply = take(buf);
    int status = reply.bytes[0];
    free(reply.bytes);
    return status;
}

#define MAX_FIELDS 8

typedef struct {
    Reply reply;
    size_t count;
    const uint8_t *ptr[MAX_FIELDS];
    size_t len[MAX_FIELDS];
} Fields;

/* Splits the frame after the status byte; count = 0 when it does not parse. */
static Fields fields_of(Reply reply) {
    Fields fields;
    size_t at = 1;
    memset(&fields, 0, sizeof fields);
    fields.reply = reply;
    while (at < reply.len) {
        size_t length;
        if (reply.len - at < 4 || fields.count == MAX_FIELDS) {
            fields.count = 0;
            return fields;
        }
        length = ((size_t)reply.bytes[at] << 24) | ((size_t)reply.bytes[at + 1] << 16) |
                 ((size_t)reply.bytes[at + 2] << 8) | (size_t)reply.bytes[at + 3];
        at += 4;
        if (reply.len - at < length) {
            fields.count = 0;
            return fields;
        }
        fields.ptr[fields.count] = reply.bytes + at;
        fields.len[fields.count] = length;
        fields.count++;
        at += length;
    }
    return fields;
}

static uint64_t u64_of(const uint8_t *bytes) {
    uint64_t value = 0;
    int index;
    for (index = 0; index < 8; index++) {
        value = (value << 8) | bytes[index];
    }
    return value;
}

/* Lowercase hex → malloc'd bytes. */
static uint8_t *unhex(const char *text, size_t *len) {
    size_t count = strlen(text) / 2;
    size_t index;
    uint8_t *out = malloc(count + 1);
    if (out == NULL) {
        exit(2);
    }
    for (index = 0; index < count; index++) {
        unsigned int byte;
        if (sscanf(text + 2 * index, "%2x", &byte) != 1) {
            exit(2);
        }
        out[index] = (uint8_t)byte;
    }
    *len = count;
    return out;
}

static int same(const uint8_t *bytes, size_t len, const uint8_t *expected, size_t expected_len) {
    return len == expected_len && (len == 0 || memcmp(bytes, expected, len) == 0);
}

static int same_text(const uint8_t *bytes, size_t len, const char *expected) {
    return same(bytes, len, (const uint8_t *)expected, strlen(expected));
}

static int same_hex(const uint8_t *bytes, size_t len, const char *expected_hex) {
    size_t expected_len;
    uint8_t *expected = unhex(expected_hex, &expected_len);
    int result = same(bytes, len, expected, expected_len);
    free(expected);
    return result;
}

static void check_init(void) {
    Fields init = fields_of(take(doodleart_init()));
    CHECK(init.reply.bytes[0] == DOODLEART_STATUS_OK, "init status %d", init.reply.bytes[0]);
    CHECK(init.count == 5, "init has %zu fields", init.count);
    if (init.count == 5) {
        CHECK(same_text(init.ptr[0], init.len[0], EXPECT_BUILD_TYPE), "buildType");
        CHECK(init.len[1] > 0 && init.len[2] > 0, "crateVersion and kidsCsv");
        CHECK(init.len[3] == 8 && u64_of(init.ptr[3]) == DOODLEART_ABI_VERSION, "abiVersion");
        CHECK(same_text(init.ptr[4], init.len[4], EXPECT_PROJECT_ID), "projectId");
    }
    free(init.reply.bytes);
}

static void check_device_key_id(void) {
    size_t spki_len;
    uint8_t *spki = unhex(V_SPKI_HEX, &spki_len);
    Reply reply = take(doodleart_device_key_id(spki, spki_len));
    CHECK(reply.bytes[0] == DOODLEART_STATUS_OK && same_text(reply.bytes + 1, reply.len - 1, V_DEVICE_KEY_ID),
          "deviceKeyId of the vector SPKI");
    free(reply.bytes);
    CHECK(status_of(doodleart_device_key_id(spki, spki_len - 1)) == DOODLEART_STATUS_INVALID_ARGUMENT, "90-byte SPKI");
    CHECK(status_of(doodleart_device_key_id(NULL, 0)) == DOODLEART_STATUS_INVALID_ARGUMENT, "absent SPKI");
    CHECK(status_of(doodleart_device_key_id(NULL, spki_len)) == DOODLEART_STATUS_INVALID_ARGUMENT, "NULL with a length");
    free(spki);
}

static void check_integrity_hash(void) {
    int index;
    Fields generated;
    for (index = 0; index < V_DAPI1_COUNT; index++) {
        const char *const *row = V_DAPI1[index];
        size_t body_len;
        uint8_t *body = unhex(row[4], &body_len);
        Fields reply = fields_of(take(doodleart_integrity_hash(TEXT(row[0]), TEXT(row[1]), TEXT(row[2]), TEXT(row[3]),
                                                            body, body_len)));
        CHECK(reply.reply.bytes[0] == DOODLEART_STATUS_OK && reply.count == 3, "DAPI1 case %d status/fields", index);
        if (reply.count == 3) {
            CHECK(same_text(reply.ptr[0], reply.len[0], row[2]), "DAPI1 case %d requestId", index);
            CHECK(same_text(reply.ptr[1], reply.len[1], row[5]), "DAPI1 case %d requestHash", index);
            CHECK(same_hex(reply.ptr[2], reply.len[2], row[6]), "DAPI1 case %d raw requestHash", index);
        }
        free(reply.reply.bytes);
        free(body);
    }
    /* An absent requestId is generated (UUID, 36 characters); an absent sid is "". */
    generated = fields_of(take(doodleart_integrity_hash(TEXT("POST"), TEXT("/api/v1/devices/register"), NULL, 0, NULL, 0,
                                                     TEXT("{}"))));
    CHECK(generated.reply.bytes[0] == DOODLEART_STATUS_OK && generated.count == 3 && generated.len[0] == 36 &&
              generated.len[2] == 32,
          "generated requestId");
    free(generated.reply.bytes);
    CHECK(status_of(doodleart_integrity_hash(TEXT("post"), TEXT("/api/v1/x"), NULL, 0, NULL, 0, NULL, 0)) ==
              DOODLEART_STATUS_INVALID_ARGUMENT,
          "lower-case method");
}

static void check_register_message(void) {
    Fields reply = fields_of(take(doodleart_register_message(TEXT(V_REG_0), TEXT(V_REG_1), TEXT(V_REG_2), TEXT(V_REG_3))));
    CHECK(reply.reply.bytes[0] == DOODLEART_STATUS_OK && reply.count == 2, "register message status/fields");
    if (reply.count == 2) {
        CHECK(same_hex(reply.ptr[0], reply.len[0], V_REG_MESSAGE_HEX), "register message");
        CHECK(same_hex(reply.ptr[1], reply.len[1], V_REG_HASH_HEX), "register clientDataHash");
    }
    free(reply.reply.bytes);
    CHECK(status_of(doodleart_register_message(TEXT(V_REG_0), TEXT(V_REG_1), TEXT(V_REG_2), TEXT("web"))) ==
              DOODLEART_STATUS_INVALID_ARGUMENT,
          "unknown platform");
    CHECK(status_of(doodleart_register_message(NULL, 0, TEXT(V_REG_1), TEXT(V_REG_2), TEXT(V_REG_3))) ==
              DOODLEART_STATUS_INVALID_ARGUMENT,
          "absent nonce");
}

static void check_ios_device_hash(void) {
    int index;
    for (index = 0; index < V_IOS_COUNT; index++) {
        size_t secret_len;
        uint8_t *secret = unhex(V_IOS[index][0], &secret_len);
        Reply reply = take(doodleart_ios_device_hash(secret, secret_len));
        CHECK(reply.bytes[0] == DOODLEART_STATUS_OK && same_text(reply.bytes + 1, reply.len - 1, V_IOS[index][1]),
              "iosDeviceHash case %d", index);
        free(reply.bytes);
        CHECK(status_of(doodleart_ios_device_hash(secret, secret_len - 1)) == DOODLEART_STATUS_INVALID_ARGUMENT,
              "31-byte secret");
        free(secret);
    }
    CHECK(status_of(doodleart_ios_device_hash(NULL, 32)) == DOODLEART_STATUS_INVALID_ARGUMENT, "NULL with a length");
}

static void check_session_assert_hash(void) {
    size_t message_len;
    uint8_t *message = unhex(V_DAAS1_MESSAGE_HEX, &message_len);
    Reply reply = take(doodleart_session_assert_hash(message, message_len));
    CHECK(reply.bytes[0] == DOODLEART_STATUS_OK && same_hex(reply.bytes + 1, reply.len - 1, V_DAAS1_HASH_HEX),
          "DAAS1 vector");
    free(reply.bytes);
    CHECK(status_of(doodleart_session_assert_hash(message, message_len - 1)) == DOODLEART_STATUS_INVALID_ARGUMENT,
          "truncated signature message");
    free(message);
}

static void check_handshake_and_handles(void) {
    Fields begin = fields_of(take(doodleart_handshake_begin(TEXT("8b0e5d1c-3f7a-4c2e-9a61-2d4b7c9e1f30"),
                                                         TEXT(V_DEVICE_KEY_ID), TEXT("2.0.0"))));
    CHECK(begin.reply.bytes[0] == DOODLEART_STATUS_OK && begin.count == 3 && begin.len[0] == 8, "handshake_begin");
    if (begin.count == 3) {
        int64_t handshake = (int64_t)u64_of(begin.ptr[0]);
        Reply by_handle = take(doodleart_handshake_assert_hash(handshake));
        Reply by_message = take(doodleart_session_assert_hash(begin.ptr[1], begin.len[1]));
        CHECK(by_handle.bytes[0] == DOODLEART_STATUS_OK && by_handle.len == 33, "DAAS1 by handle");
        CHECK(same(by_handle.bytes, by_handle.len, by_message.bytes, by_message.len), "DAAS1 by handle = by message");
        free(by_handle.bytes);
        free(by_message.bytes);
        CHECK(handshake > 0, "positive handle");
        CHECK(doodleart_handshake_abort(handshake) == DOODLEART_STATUS_OK, "abort");
        CHECK(doodleart_handshake_abort(handshake) == DOODLEART_STATUS_UNKNOWN_HANDLE, "second abort");
        CHECK(status_of(doodleart_handshake_assert_hash(handshake)) == DOODLEART_STATUS_UNKNOWN_HANDLE, "aborted handle");
    }
    free(begin.reply.bytes);
    CHECK(doodleart_session_close(42) == DOODLEART_STATUS_UNKNOWN_HANDLE, "unknown session");
    CHECK(status_of(doodleart_session_seal(42, TEXT("GET"), TEXT("/api/v1/x"), NULL, 0)) == DOODLEART_STATUS_UNKNOWN_HANDLE,
          "seal on an unknown session");
}

static void check_risk_scan_and_buffers(void) {
    Fields scan = fields_of(take(doodleart_risk_scan()));
    DoodleArtBuf buf;
    DoodleArtBuf none = {NULL, 0};
    CHECK(scan.reply.bytes[0] == DOODLEART_STATUS_OK && scan.count == 2, "risk scan frame(csv, details)");
    if (scan.count == 2) {
        /* The Apple scan (risk/apple.rs) runs: the macOS library skips its file probes and its first detail says so,
         * a detail the Android scan never gives (details exist in debug libraries only). */
        static const char unchecked[] = "root.unchecked";
        const char *details = (const char *)scan.ptr[1];
        if (strcmp(EXPECT_BUILD_TYPE, "debug") == 0) {
            CHECK(scan.len[1] >= sizeof unchecked - 1 && memcmp(details, unchecked, sizeof unchecked - 1) == 0 &&
                      (scan.len[1] == sizeof unchecked - 1 || details[sizeof unchecked - 1] == ','),
                  "risk scan details start with root.unchecked: %.*s", (int)scan.len[1], details);
        } else {
            CHECK(scan.len[1] == 0, "no risk scan details in a %s library", EXPECT_BUILD_TYPE);
        }
    }
    free(scan.reply.bytes);

    /* {NULL, 0} is ignored (reaching the end without a crash is the check). Every reply is released exactly once:
     * a second release is the caller's bug (the allocator may already have given its address to another reply). */
    doodleart_buf_free(none);
    buf = doodleart_init();
    doodleart_buf_free(buf);
}

/* Whether the comma-separated list csv[0..len) holds token. */
static int has_token(const uint8_t *csv, size_t len, const char *token) {
    size_t token_len = strlen(token);
    size_t at = 0;
    while (at <= len) {
        size_t end = at;
        while (end < len && csv[end] != ',') {
            end++;
        }
        if (end - at == token_len && memcmp(csv + at, token, token_len) == 0) {
            return 1;
        }
        at = end + 1;
    }
    return 0;
}

/* The Apple scan reads P_TRACED (src/risk/apple.rs): this process, not traced, reports no debugger; a forked child
 * that declares itself traced by its parent (PT_TRACE_ME, which sets P_TRACED) reports the flag, and in a debug
 * library the detail debugger.traced. Exit status of the child: 0 ok, 1 wrong, 3 ptrace refused (skipped). */
static void check_traced_risk_scan(void) {
    Fields scan = fields_of(take(doodleart_risk_scan()));
    int status = 0;
    pid_t child;
    CHECK(scan.count == 2 && !has_token(scan.ptr[0], scan.len[0], "debugger"), "untraced: no debugger flag");
    free(scan.reply.bytes);

    fflush(stdout);
    fflush(stderr);
    child = fork();
    if (child == 0) {
        Fields traced;
        int ok;
        if (ptrace(PT_TRACE_ME, 0, NULL, 0) != 0) {
            _exit(3);
        }
        traced = fields_of(take(doodleart_risk_scan()));
        ok = traced.count == 2 && has_token(traced.ptr[0], traced.len[0], "debugger");
        if (strcmp(EXPECT_BUILD_TYPE, "debug") == 0) {
            ok = ok && has_token(traced.ptr[1], traced.len[1], "debugger.traced");
        } else {
            ok = ok && traced.len[1] == 0;
        }
        _exit(ok ? 0 : 1);
    }
    CHECK(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status), "traced child exited");
    if (WIFEXITED(status) && WEXITSTATUS(status) == 3) {
        printf("traced risk scan skipped: ptrace(PT_TRACE_ME) refused\n");
        return;
    }
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "traced child: debugger flag (exit %d)", WEXITSTATUS(status));
}

static void check_debug_hooks(void) {
#if EXPECT_DEBUG_HOOKS
    CHECK(doodleart_debug_clock_advance_ms(0) == DOODLEART_STATUS_OK, "debug clock advance 0");
    CHECK(doodleart_debug_clock_advance_ms(-1) == DOODLEART_STATUS_INVALID_ARGUMENT, "debug clock advance -1");
    CHECK(doodleart_debug_clock_advance_ms(604800001) == DOODLEART_STATUS_INVALID_ARGUMENT, "debug clock advance > week");
#endif
}

int main(void) {
    check_init();
    check_device_key_id();
    check_integrity_hash();
    check_register_message();
    check_ios_device_hash();
    check_session_assert_hash();
    check_handshake_and_handles();
    check_risk_scan_and_buffers();
    check_traced_risk_scan();
    check_debug_hooks();
    printf("c-abi smoke (C, %s): %d checks, %d failures\n", EXPECT_BUILD_TYPE, checks, failures);
    return failures == 0 ? 0 : 1;
}
