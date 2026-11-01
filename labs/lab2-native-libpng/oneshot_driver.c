/* Minimal replacement for libFuzzer's driver: feed one input file to the
 * fuzz target's entrypoint once, under ASan/UBSan. This lets us reproduce a
 * proof-of-vulnerability without a clang/libFuzzer build -- the sanitizer is
 * the judge, the driver is just plumbing. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <input-file>\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 2; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc(n ? n : 1);
    if (fread(buf, 1, n, f) != (size_t)n) { perror("fread"); return 2; }
    fclose(f);
    LLVMFuzzerTestOneInput(buf, (size_t)n);
    free(buf);
    fprintf(stderr, "[oneshot] returned cleanly (no sanitizer abort)\n");
    return 0;
}
