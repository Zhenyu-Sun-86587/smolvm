// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

int main(void)
{
    static const char source_id[] = "0102030405060708090a0b0c0d0e0f10\n";
    static const uint64_t salt = UINT64_C(0xbeef12349876);
    uint64_t previous[2] = {0};
    unsigned char sector[512] = {0};
    char hostname[65] = {0}, identity[34] = {0};
    if (mount("tmpfs", "/etc", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755") ||
        sethostname("capture-source", 14))
        return 1;
    int identity_fd = open("/etc/machine-id", O_WRONLY | O_CREAT | O_EXCL, 0444);
    if (identity_fd < 0 || write(identity_fd, source_id, 33) != 33 || close(identity_fd))
        return 2;
    int disks[] = {open("/dev/vdb", O_RDWR | O_CLOEXEC), open("/dev/vdc", O_RDWR | O_CLOEXEC)};
    if (disks[0] < 0 || disks[1] < 0)
        return 3;
    for (uint64_t tick = 1;; ++tick) {
        identity_fd = open("/etc/machine-id", O_RDONLY | O_CLOEXEC);
        if (identity_fd < 0 || read(identity_fd, identity, 32) != 32 ||
            close(identity_fd) || gethostname(hostname, sizeof(hostname)))
            return 4;
        uint64_t branch = strcmp(hostname, "capture-source") ? (uint64_t)hostname[0] << 48 : 0;
        for (size_t disk = 0; disk < 2; ++disk) {
            if (pread(disks[disk], sector, sizeof(sector), 4096) != sizeof(sector))
                return 5;
            memcpy(&previous[disk], sector, sizeof(previous[disk]));
            const uint64_t marker = tick ^ branch ^ (disk ? salt : 0);
            memset(sector, 0, sizeof(sector));
            memcpy(sector, &marker, sizeof(marker));
            if (pwrite(disks[disk], sector, sizeof(sector), 4096) != sizeof(sector) || fsync(disks[disk]))
                return 6;
        }
        dprintf(1, "PARKED_BLOCK_TICK %llu %d %s %.32s %llu %llu\n",
                (unsigned long long)tick, getpid(), hostname, identity,
                (unsigned long long)previous[0], (unsigned long long)previous[1]);
        usleep(320000);
    }
}
