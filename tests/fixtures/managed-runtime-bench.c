// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef BENCH_COMPILE
#include <elf.h>
#include <libtcc.h>
#endif

#ifndef DIRTY_MIB
#define DIRTY_MIB 0
#endif

#define READERS 4
#define READS 256
#define BLOCK_BYTES 4096

static uint64_t monotonic_ns(void)
{
    struct timespec tp;
    if (clock_gettime(CLOCK_MONOTONIC, &tp))
        abort();
    return (uint64_t)tp.tv_sec * 1000000000 + tp.tv_nsec;
}

static int read_workload(unsigned index)
{
    int fd = open(index % 2 ? "/dev/vdb" : "/dev/vdc", O_RDONLY | O_DIRECT);
    void *data;
    if (fd < 0 || posix_memalign(&data, BLOCK_BYTES, BLOCK_BYTES))
        return 1;
    unsigned char empty[BLOCK_BYTES] = {0};
    uint32_t seed = index + 1;
    for (unsigned i = 0; i < READS; i++) {
        seed = seed * 1664525 + 1013904223;
        off_t offset = (2 + seed % 2046) * BLOCK_BYTES;
        if (pread(fd, data, BLOCK_BYTES, offset) != BLOCK_BYTES ||
            memcmp(data, empty, sizeof(empty)))
            return 2;
    }
    free(data);
    return close(fd) != 0;
}

static int run_workers(int (*work)(unsigned), unsigned count)
{
    pid_t workers[count];
    for (unsigned i = 0; i < count; i++) {
        workers[i] = fork();
        if (workers[i] < 0)
            return 1;
        if (!workers[i])
            _exit(work(i));
    }
    for (unsigned i = 0; i < count; i++) {
        int status;
        if (waitpid(workers[i], &status, 0) != workers[i] ||
            !WIFEXITED(status) || WEXITSTATUS(status))
            return 2;
    }
    return 0;
}

#ifdef BENCH_COMPILE
enum { COMPILE_JOBS = 2, UNITS_PER_JOB = 16 };

static int compile_workload(unsigned job)
{
    char object[48];
    snprintf(object, sizeof(object), "/etc/bench-job-%u.o", job);
    for (unsigned unit = 0; unit < UNITS_PER_JOB; unit++) {
        char variant[16];
        snprintf(variant, sizeof(variant), "%u", job * UNITS_PER_JOB + unit);
        TCCState *compiler = tcc_new();
        if (!compiler)
            return 1;
        tcc_set_options(compiler, "-nostdinc -nostdlib");
        tcc_define_symbol(compiler, "BENCH_VARIANT", variant);
        int failed = tcc_set_output_type(compiler, TCC_OUTPUT_OBJ) ||
                     tcc_add_file(compiler, "/bench-arithmetic.c") ||
                     tcc_output_file(compiler, object);
        tcc_delete(compiler);
        if (failed)
            return 2;
        int fd = open(object, O_RDONLY);
        Elf64_Ehdr header;
        if (fd < 0 || read(fd, &header, sizeof(header)) != sizeof(header) ||
            memcmp(header.e_ident, ELFMAG, SELFMAG) || header.e_type != ET_REL ||
            header.e_machine != EM_X86_64 || header.e_shnum < 3 || close(fd) || unlink(object))
            return 3;
    }
    return 0;
}
#endif

static int first_task(const char *host)
{
    const uint64_t start = monotonic_ns();
    if (run_workers(read_workload, READERS))
        return 1;
    uint64_t read_ns = monotonic_ns() - start;
#ifdef BENCH_COMPILE
    const uint64_t compile_start = monotonic_ns();
    if (run_workers(compile_workload, COMPILE_JOBS))
        return 2;
    dprintf(1, "BENCH_COMPILE %s %llu %u\n", host,
            (unsigned long long)(monotonic_ns() - compile_start), COMPILE_JOBS * UNITS_PER_JOB);
#endif
    dprintf(1, "BENCH_TASK %s %llu %u\n", host,
            (unsigned long long)read_ns, READERS * READS * BLOCK_BYTES);
    return 0;
}

int main(void)
{
    static const char source_id[] = "0102030405060708090a0b0c0d0e0f10\n";
    static const uint64_t salt = UINT64_C(0xbeef12349876);
    static volatile unsigned char pages[16 * 1024 * 1024];
    if (mount("tmpfs", "/etc", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755") ||
        sethostname("capture-source", 14))
        return 1;
    int identity = open("/etc/machine-id", O_WRONLY | O_CREAT | O_EXCL, 0444);
    if (identity < 0 || write(identity, source_id, 33) != 33 || close(identity))
        return 2;
    int disks[] = {open("/dev/vdb", O_RDWR), open("/dev/vdc", O_RDWR)};
    if (disks[0] < 0 || disks[1] < 0)
        return 3;
    for (size_t i = 0; i < sizeof(pages); i += BLOCK_BYTES)
        pages[i] = 1;
    char prior_host[65] = {0};
    for (uint64_t tick = 1;; tick++) {
        char host[65] = {0};
        if (gethostname(host, sizeof(host)))
            return 4;
        if (strcmp(host, prior_host)) {
            if (first_task(host))
                return 5;
            memcpy(prior_host, host, sizeof(host));
        }
#if DIRTY_MIB > 0
        for (size_t i = 0; i < DIRTY_MIB * 1024 * 1024; i += BLOCK_BYTES)
            pages[i]++;
#endif
        for (unsigned disk = 0; disk < 2; disk++) {
            unsigned char sector[512] = {0};
            uint64_t previous;
            if (pread(disks[disk], sector, sizeof(sector), 4096) != sizeof(sector))
                return 6;
            memcpy(&previous, sector, sizeof(previous));
            uint64_t mask = disk ? salt : 0;
            if (previous != (tick == 1 ? 0 : (tick - 1) ^ mask))
                return 7;
            uint64_t next = tick ^ mask;
            memcpy(sector, &next, sizeof(next));
            if (pwrite(disks[disk], sector, sizeof(sector), 4096) != sizeof(sector) || fsync(disks[disk]))
                return 8;
        }
        dprintf(1, "PARKED_BLOCK_TICK %llu %d %s %llu\n",
                (unsigned long long)tick, getpid(), host,
                (unsigned long long)monotonic_ns());
        usleep(20000);
    }
}
