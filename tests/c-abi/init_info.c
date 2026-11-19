/*
 * Prints the doodleart_init reply of a static library as `key=value` lines (buildType, crateVersion, kidsCsv,
 * abiVersion, projectId). build-ios.sh links it against the prelinked macOS slice it has just built: this proves the
 * shipped slice links and runs, and the manifest is checked against what the library itself reports.
 * Exit status: 0 on success, 1 on any unexpected reply.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "doodleart_core.h"

#define FIELDS 5

static uint64_t u64_of(const uint8_t *bytes) {
    uint64_t value = 0;
    int index;
    for (index = 0; index < 8; index++) {
        value = (value << 8) | bytes[index];
    }
    return value;
}

/* A text field is printed as is; it must not contain a line break or a NUL (the caller parses lines). */
static int print_text(const char *key, const uint8_t *bytes, size_t len) {
    size_t index;
    for (index = 0; index < len; index++) {
        if (bytes[index] == '\n' || bytes[index] == '\r' || bytes[index] == 0) {
            fprintf(stderr, "init_info: %s contains a control character\n", key);
            return 0;
        }
    }
    printf("%s=%.*s\n", key, (int)len, (const char *)bytes);
    return 1;
}

int main(void) {
    static const char *const keys[FIELDS] = {"buildType", "crateVersion", "kidsCsv", "abiVersion", "projectId"};
    const uint8_t *ptr[FIELDS];
    size_t len[FIELDS];
    size_t count = 0;
    size_t at = 1;
    int ok = 1;
    size_t index;
    DoodleArtBuf buf = doodleart_init();

    if (buf.ptr == NULL || buf.len < 1 || buf.ptr[0] != DOODLEART_STATUS_OK) {
        int status = buf.ptr != NULL && buf.len > 0 ? buf.ptr[0] : -1;
        fprintf(stderr, "init_info: doodleart_init failed (status %d)\n", status);
        doodleart_buf_free(buf);
        return 1;
    }
    /* frame(buildType, crateVersion, kidsCsv, u64(abiVersion), projectId); fields appended later are ignored. */
    while (at < buf.len && count < FIELDS) {
        size_t length;
        if (buf.len - at < 4) {
            ok = 0;
            break;
        }
        length = ((size_t)buf.ptr[at] << 24) | ((size_t)buf.ptr[at + 1] << 16) | ((size_t)buf.ptr[at + 2] << 8) |
                 (size_t)buf.ptr[at + 3];
        at += 4;
        if (buf.len - at < length) {
            ok = 0;
            break;
        }
        ptr[count] = buf.ptr + at;
        len[count] = length;
        count++;
        at += length;
    }
    if (!ok || count != FIELDS || len[3] != 8) {
        fprintf(stderr, "init_info: unexpected init reply layout (%zu fields)\n", count);
        doodleart_buf_free(buf);
        return 1;
    }
    for (index = 0; index < FIELDS && ok; index++) {
        if (index == 3) {
            printf("%s=%llu\n", keys[index], (unsigned long long)u64_of(ptr[index]));
        } else {
            ok = print_text(keys[index], ptr[index], len[index]);
        }
    }
    doodleart_buf_free(buf);
    return ok ? 0 : 1;
}
