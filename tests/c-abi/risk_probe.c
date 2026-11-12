/*
 * The Apple risk scan wired into the library as built (tools/c-abi-smoke.sh, on the macOS slice; prelinked with
 * --prebuilt): the imports check of tools/check-macho.sh cannot tell the scan's _dyld_* / getenv calls from Rust std's
 * own, so this runs them. Through doodleart_risk_scan:
 *   1. nothing set: no hook, no frida flag;
 *   2. DYLD_INSERT_LIBRARIES set in this process: hook (hook.dyld_env);
 *   3. argv[1] loaded with dlopen, a library whose path names a tweak (libhooker): hook (hook.dyld_image);
 *   4. a listener on 127.0.0.1:27042, frida-server's default port: frida (frida.port), and no frida once it is closed
 *      (skipped, with a message, when something else holds the port);
 *   5. argv[2] loaded, a library whose path names Frida's gadget: frida (frida.dyld_image).
 * Debug libraries must also name the check in detailsCsv; release libraries report no details. expect.h (written by
 * the script) gives EXPECT_BUILD_TYPE. Exit status 0 when every check passed.
 */

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "expect.h"
#include "doodleart_core.h"

static int failures = 0;

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

static uint32_t u32_of(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | bytes[3];
}

/* Runs the scan; expects flag (and, in a debug library, detail) to be present or absent. */
static void expect_scan(const char *step, const char *flag, const char *detail, int present) {
    DoodleArtBuf buf = doodleart_risk_scan();
    const uint8_t *flags, *details;
    uint32_t flags_len, details_len;
    int debug = strcmp(EXPECT_BUILD_TYPE, "debug") == 0;
    if (buf.ptr == NULL || buf.len < 9 || buf.ptr[0] != DOODLEART_STATUS_OK) {
        fprintf(stderr, "FAIL %s: doodleart_risk_scan did not answer OK\n", step);
        exit(2);
    }
    flags_len = u32_of(buf.ptr + 1);
    flags = buf.ptr + 5;
    details_len = u32_of(flags + flags_len);
    details = flags + flags_len + 4;
    if (has_token(flags, flags_len, flag) != present) {
        failures++;
        fprintf(stderr, "FAIL %s: flag %s %s in \"%.*s\"\n", step, flag, present ? "missing" : "present", (int)flags_len,
                (const char *)flags);
    }
    if (debug && present && !has_token(details, details_len, detail)) {
        failures++;
        fprintf(stderr, "FAIL %s: detail %s missing in \"%.*s\"\n", step, detail, (int)details_len,
                (const char *)details);
    }
    if (!debug && details_len != 0) {
        failures++;
        fprintf(stderr, "FAIL %s: details in a %s library\n", step, EXPECT_BUILD_TYPE);
    }
    doodleart_buf_free(buf);
}

/* A listening TCP socket on 127.0.0.1:port, or -1 (errno set) when the port cannot be bound. */
static int listen_loopback(uint16_t port) {
    struct sockaddr_in address;
    int one = 1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (const struct sockaddr *)&address, sizeof address) != 0 || listen(fd, 8) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

int main(int argc, char **argv) {
    int listener;
    const char *port_result = "frida.port";
    if (argc != 3) {
        fprintf(stderr, "usage: %s <libhooker-named dylib> <frida-gadget-named dylib>\n", argv[0]);
        return 2;
    }
    unsetenv("DYLD_INSERT_LIBRARIES");
    expect_scan("clean process", "hook", "", 0);
    expect_scan("clean process", "frida", "", 0);

    setenv("DYLD_INSERT_LIBRARIES", "/nonexistent/probe.dylib", 1);
    expect_scan("DYLD_INSERT_LIBRARIES set", "hook", "hook.dyld_env", 1);
    unsetenv("DYLD_INSERT_LIBRARIES");
    expect_scan("DYLD_INSERT_LIBRARIES unset again", "hook", "", 0);

    if (dlopen(argv[1], RTLD_NOW) == NULL) {
        fprintf(stderr, "FAIL: dlopen %s: %s\n", argv[1], dlerror());
        return 2;
    }
    expect_scan("tweak library loaded", "hook", "hook.dyld_image", 1);
    expect_scan("tweak library loaded", "frida", "", 0);

    /* Before the gadget: once it is loaded, frida stays set whatever the port does. */
    listener = listen_loopback(27042);
    if (listener < 0) {
        fprintf(stderr, "skipped frida.port: 127.0.0.1:27042 cannot be bound (%s)\n", strerror(errno));
        port_result = "frida.port skipped";
    } else {
        expect_scan("frida-server port listening", "frida", "frida.port", 1);
        close(listener);
        expect_scan("frida-server port closed", "frida", "", 0);
    }

    if (dlopen(argv[2], RTLD_NOW) == NULL) {
        fprintf(stderr, "FAIL: dlopen %s: %s\n", argv[2], dlerror());
        return 2;
    }
    expect_scan("Frida gadget loaded", "frida", "frida.dyld_image", 1);

    printf("c-abi risk probe (%s): hook.dyld_env, hook.dyld_image, %s, frida.dyld_image %s\n", EXPECT_BUILD_TYPE,
           port_result, failures == 0 ? "ok" : "FAILED");
    return failures == 0 ? 0 : 1;
}
