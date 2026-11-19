// Clang module side of the C ABI smoke test (tools/c-abi-smoke.sh): include/module.modulemap makes the header
// importable as the module DoodleArtCore, the name Swift imports.
@import DoodleArtCore;

int main(void) {
    DoodleArtBuf reply = doodleart_init();
    int ok = reply.ptr != 0 && reply.len > 1 && reply.ptr[0] == DOODLEART_STATUS_OK;
    doodleart_buf_free(reply);
    return ok ? 0 : 1;
}
