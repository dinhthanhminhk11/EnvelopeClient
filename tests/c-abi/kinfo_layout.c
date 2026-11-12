/*
 * Prints the layout of struct kinfo_proc and the sysctl constants the Apple debugger check uses (src/risk/apple.rs),
 * as tests/fixtures/kinfo-proc-macos-sdk.txt holds them. tools/c-abi-smoke.sh compiles it against the host SDK and
 * compares the output with that file (Apple does not guarantee this layout: QA1361).
 */

#include <stddef.h>
#include <stdio.h>
#include <sys/proc.h>
#include <sys/sysctl.h>

int main(void) {
    printf("sizeof_kinfo_proc=%zu\n", sizeof(struct kinfo_proc));
    printf("offsetof_p_flag=%zu\n", offsetof(struct kinfo_proc, kp_proc.p_flag));
    printf("offsetof_p_pid=%zu\n", offsetof(struct kinfo_proc, kp_proc.p_pid));
    printf("P_TRACED=%d\n", P_TRACED);
    printf("CTL_KERN=%d\n", CTL_KERN);
    printf("KERN_PROC=%d\n", KERN_PROC);
    printf("KERN_PROC_PID=%d\n", KERN_PROC_PID);
    return 0;
}
