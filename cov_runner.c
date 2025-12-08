// cov_runner.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s file1 [file2 ...]\n", argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        const char *path = argv[i];
        FILE *f = fopen(path, "rb");
        if (!f) {
            perror(path);
            continue;
        }

        if (fseek(f, 0, SEEK_END) != 0) {
            perror("fseek");
            fclose(f);
            continue;
        }

        long sz = ftell(f);
        if (sz < 0) {
            perror("ftell");
            fclose(f);
            continue;
        }
        rewind(f);

        uint8_t *buf = malloc((size_t)sz);
        if (!buf) {
            fprintf(stderr, "malloc failed for %s\n", path);
            fclose(f);
            continue;
        }

        size_t rd = fread(buf, 1, (size_t)sz, f);
        fclose(f);

        // вызываем твой фазз-callback
        LLVMFuzzerTestOneInput(buf, rd);

        free(buf);
    }

    return 0;
}
