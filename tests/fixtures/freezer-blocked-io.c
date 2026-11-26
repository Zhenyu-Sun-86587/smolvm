// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "fuse.h"

static void fail(const char *op)
{
    perror(op);
    exit(1);
}

static void notify(const char *path, const char *message)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0 || dprintf(fd, "%s\n", message) < 0 || close(fd))
        fail(path);
}

static void await_file(const char *path)
{
    for (unsigned i = 0; i < 4500; i++) {
        if (!access(path, F_OK))
            return;
        usleep(20000);
    }
    errno = ETIMEDOUT;
    fail(path);
}

static void exercise_ext4(void)
{
    if (mount("/dev/vda", "/blocked-fs", "ext4", MS_NOSUID | MS_NODEV, NULL))
        fail("mount disposable ext4");
    int dir = open("/blocked-fs", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int file = open("/blocked-fs/marker", O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (dir < 0 || file < 0 || ioctl(dir, FIFREEZE, 0))
        fail("freeze disposable ext4");
    pid_t writer = fork();
    if (!writer)
        _exit(write(file, "D", 1) == 1 && !fsync(file) ? 0 : 1);
    if (writer < 0)
        fail("fork writer");
    char path[64], line[1024];
    snprintf(path, sizeof(path), "/proc/%d/stat", writer);
    int blocked = 0;
    for (unsigned i = 0; i < 200 && !blocked; i++) {
        FILE *status = fopen(path, "r");
        if (!status || !fgets(line, sizeof(line), status) || fclose(status))
            fail("read writer state");
        char *end = strrchr(line, ')');
        blocked = end && end[1] == ' ' && end[2] == 'D';
        if (!blocked)
            usleep(10000);
    }
    if (!blocked) {
        errno = ETIMEDOUT;
        fail("observe D-state writer");
    }
    snprintf(line, sizeof(line), "writer %d state D", writer);
    notify("/ext4-blocked", line);
    await_file("/release-ext4");
    if (ioctl(dir, FITHAW, 0))
        fail("thaw disposable ext4");
    int status;
    char marker;
    if (waitpid(writer, &status, 0) != writer || !WIFEXITED(status) || WEXITSTATUS(status) ||
        pread(file, &marker, 1, 0) != 1 || marker != 'D')
        fail("complete original write");
    close(file);
    close(dir);
    if (umount("/blocked-fs"))
        fail("umount disposable ext4");
    notify("/ext4-completed", "original write completed");
}

static void report_fuse_tasks(pid_t counters)
{
    char path[96], line[1024], summary[128] = "";
    snprintf(path, sizeof(path), "/proc/self/task/%d/children", getpid());
    FILE *children = fopen(path, "r");
    if (!children)
        fail("read FUSE children");
    int child, observed = 0;
    while (fscanf(children, "%d", &child) == 1) {
        if (child == counters)
            continue;
        snprintf(path, sizeof(path), "/proc/%d/stat", child);
        FILE *status = fopen(path, "r");
        if (!status || !fgets(line, sizeof(line), status) || fclose(status))
            fail("read FUSE task state");
        char *end = strrchr(line, ')');
        if (!end || end[1] != ' ' || observed == 2)
            fail("unexpected FUSE task");
        size_t used = strlen(summary);
        snprintf(summary + used, sizeof(summary) - used, "%s%d=%c", used ? ", " : "FUSE tasks ", child, end[2]);
        observed++;
    }
    if (fclose(children) || observed != 2)
        fail("missing FUSE tasks");
    notify("/fuse-tasks", summary);
}

int main(void)
{
    pid_t counters = fork();
    if (!counters) {
        execl("/tickers", "tickers", NULL);
        _exit(127);
    }
    if (counters < 0)
        fail("fork counters");
    exercise_ext4();
    await_file("/start-fuse");
    if (start_fuse_request())
        fail("start FUSE lookup");
    notify("/fuse-blocked", "FUSE server received LOOKUP");
    await_file("/inspect-fuse");
    report_fuse_tasks(counters);
    await_file("/release-fuse");
    if (finish_fuse_request())
        fail("complete original FUSE lookup");
    notify("/fuse-completed", "server replied and client completed");
    int status;
    return waitpid(counters, &status, 0) == counters && WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
