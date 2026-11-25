#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int main(void)
{
    const int observer = getenv("WORKER_BLOCK_OBSERVE") != NULL;
    const char *paths[] = {"/dev/vda", "/dev/vdb"};
    unsigned char sector[512] = {0};
    for (size_t index = 0; index < 2; ++index) {
        const unsigned char marker = 0xb1 + index;
        int fd = open(paths[index], observer ? O_RDONLY : O_RDWR);
        if (fd < 0) {
            perror(paths[index]);
            return 1;
        }
        if (pread(fd, sector, sizeof(sector), 0) != sizeof(sector) || sector[0] != 0xa7) {
            fprintf(stderr, "missing immutable base marker on %s: %02x\n", paths[index], sector[0]);
            return 2;
        }
        if (observer) {
            if (pread(fd, sector, sizeof(sector), 4096) != sizeof(sector) || sector[0] != marker) {
                fprintf(stderr, "missing durable volume marker on %s: %02x\n", paths[index], sector[0]);
                return 3;
            }
        } else {
            memset(sector, marker, sizeof(sector));
            if (pwrite(fd, sector, sizeof(sector), 4096) != sizeof(sector) || fsync(fd) != 0) {
                perror("write and flush volume");
                return 4;
            }
        }
        close(fd);
    }
    puts(observer ? "BLOCK_OBSERVED_BOTH" : "BLOCK_FLUSHED_BOTH");
    fflush(stdout);
    if (getenv("WORKER_BLOCK_PIVOT") != NULL) {
        unsigned int tick = 0;
        int writers[] = {open(paths[0], O_RDWR), open(paths[1], O_RDWR)};
        if (writers[0] < 0 || writers[1] < 0)
            return 5;
        for (;;) {
            ++tick;
            for (size_t index = 0; index < 2; ++index) {
                memset(sector, (int)(tick + index), sizeof(sector));
                if (pwrite(writers[index], sector, sizeof(sector), 8192) != sizeof(sector)
                    || fsync(writers[index]) != 0)
                    return 6;
            }
            printf("BLOCK_RUNNING tick=%u\n", tick);
            fflush(stdout);
            nanosleep(&(struct timespec){.tv_nsec = 150000000}, NULL);
        }
    }
    for (;;)
        pause();
}
