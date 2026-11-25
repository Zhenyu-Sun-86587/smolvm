#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

int main(void)
{
    const size_t length = 4 * 1024 * 1024;
    volatile uint8_t *ram = mmap(NULL, length, PROT_READ | PROT_WRITE,
                                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (ram == MAP_FAILED)
        return 1;
    ram[length - 1] = 0xa7;
    uint32_t tick = 0;
    for (;;) {
        printf("RESOURCE_GUEST tick=%u cold=%02x private=%u pid=%ld\n",
               tick, tick < 8 ? 0 : ram[length - 1], ram[0], (long)getpid());
        fflush(stdout);
        ram[0] = ++tick;
        nanosleep(&(struct timespec){.tv_nsec = 150000000}, NULL);
    }
}
