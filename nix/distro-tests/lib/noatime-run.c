// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later
//
// noatime-run PROGRAM [ARG...]
//
// Runs PROGRAM in a mount namespace of its own in which every mount is
// noatime, so nothing it reads, the program file, its loader and libraries,
// the files it opens, the directories it lists and the links it follows,
// changes an access time. The access-time scenario
// (nix/distro-tests/tests/access-times.nix) runs every guest command whose
// reads must not count through it. It is linked statically and shared in on
// the /run tmpfs, so starting it reads nothing of the decoy disk either.
//
// The namespace's mounts are made private before their atime mode changes,
// so the change reaches no other namespace. A step that fails ends it with
// status 97 before PROGRAM starts: a command that would read with access
// times on never runs.

#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_mount_setattr
#define SYS_mount_setattr 442
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif
#ifndef MOUNT_ATTR__ATIME
#define MOUNT_ATTR__ATIME 0x00000070
#endif
#ifndef MOUNT_ATTR_NOATIME
#define MOUNT_ATTR_NOATIME 0x00000010
#endif

struct mount_attr_arg {
  uint64_t attr_set;
  uint64_t attr_clr;
  uint64_t propagation;
  uint64_t userns_fd;
};

int main(int argc, char **argv) {
  if (argc < 2) {
    fputs("usage: noatime-run PROGRAM [ARG...]\n", stderr);
    return 2;
  }
  if (unshare(CLONE_NEWNS) != 0) {
    perror("noatime-run: unshare");
    return 97;
  }
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
    perror("noatime-run: make the mounts private");
    return 97;
  }
  struct mount_attr_arg attr = {
      .attr_set = MOUNT_ATTR_NOATIME,
      .attr_clr = MOUNT_ATTR__ATIME,
  };
  if (syscall(SYS_mount_setattr, AT_FDCWD, "/", AT_RECURSIVE, &attr,
              sizeof attr) != 0) {
    perror("noatime-run: set every mount noatime");
    return 97;
  }
  execv(argv[1], argv + 1);
  perror("noatime-run: exec");
  return 127;
}
