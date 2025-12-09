//afl_driver.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int main(void) {
    static uint8_t buf[1024*1024]; // до 1 МБ на одно выполнение
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    if (n>0) {
        LLVMFuzzerTestOneInput(buf, n);
    }
    return 0;
}