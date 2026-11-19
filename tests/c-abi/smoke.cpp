// C++ side of the C ABI smoke test (tools/c-abi-smoke.sh): the header compiles as C++ and its extern "C" guard gives
// the unmangled names of the static library (a missing guard is a link error here).
#include <cstdio>

#include "doodleart_core.h"

int main() {
    DoodleArtBuf reply = doodleart_init();
    bool ok = reply.ptr != nullptr && reply.len > 1 && reply.ptr[0] == DOODLEART_STATUS_OK;
    doodleart_buf_free(reply);
    ok = ok && doodleart_session_close(1) == DOODLEART_STATUS_UNKNOWN_HANDLE;
    std::printf("c-abi smoke (C++): %s\n", ok ? "ok" : "FAILED");
    return ok ? 0 : 1;
}
