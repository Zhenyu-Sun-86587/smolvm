#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

// Fail one read-only reopen of a sealed RAM descriptor in the fixture VMM.
static int open_for_fixture(int directory, const char *path, int flags, va_list args)
{
    const char prefix[] = "/proc/self/fd/";
    const char *armed = getenv("SMOLVM_TEST_CAPTURE_OPEN_FAULT");
    if (armed && (flags & O_ACCMODE) == O_RDONLY && !strncmp(path, prefix, sizeof(prefix) - 1)) {
        const char *number = path + sizeof(prefix) - 1;
        char *end = NULL;
        long fd = strtol(number, &end, 10);
        if (*number && !*end && fd >= 0 && fd <= INT_MAX) {
            int seals = fcntl((int)fd, F_GET_SEALS);
            if (seals >= 0 && (seals & F_SEAL_WRITE) && unlink(armed) == 0) {
                errno = EMFILE;
                return -1;
            }
        }
    }
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE)
        mode = (mode_t)va_arg(args, int);
    return (int)syscall(SYS_openat, directory, path, flags, mode);
}

int open(const char *path, int flags, ...)
{
    va_list args;
    va_start(args, flags);
    int result = open_for_fixture(AT_FDCWD, path, flags, args);
    va_end(args);
    return result;
}

int openat(int directory, const char *path, int flags, ...)
{
    va_list args;
    va_start(args, flags);
    int result = open_for_fixture(directory, path, flags, args);
    va_end(args);
    return result;
}

extern __typeof(open) open64 __attribute__((alias("open")));
extern __typeof(openat) openat64 __attribute__((alias("openat")));
