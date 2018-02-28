/*
 * seccomp example with syscall reporting
 *
 * Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Authors:
 *  Kees Cook <keescook@chromium.org>
 *  Will Drewry <wad@chromium.org>
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */
#define _GNU_SOURCE 1
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "convert-w-sb.h"
#include "seccomp-bpf.h"
#include "syscall-reporter.h"

static int install_syscall_filter(void) {
  struct sock_filter filter[] = {
      /* Validate architecture. */
      VALIDATE_ARCHITECTURE,
      /* Grab the system call number. */
      EXAMINE_SYSCALL,
      /* List allowed syscalls. */
      ALLOW_SYSCALL(rt_sigreturn),
#ifdef __NR_sigreturn
      ALLOW_SYSCALL(sigreturn),
#endif
      ALLOW_SYSCALL(exit_group),
      ALLOW_SYSCALL(exit),
      ALLOW_SYSCALL(read),
      ALLOW_SYSCALL(write),
      /* Add more syscalls here. */
      ALLOW_SYSCALL(openat),
      ALLOW_SYSCALL(lseek),
      ALLOW_SYSCALL(munmap),
      ALLOW_SYSCALL(close),
      ALLOW_SYSCALL(times),
      ALLOW_SYSCALL(getcwd),
      ALLOW_SYSCALL(getpid),
      ALLOW_SYSCALL(readlink),
      ALLOW_SYSCALL(stat),
      ALLOW_SYSCALL(access),
      ALLOW_SYSCALL(sysinfo),
      ALLOW_SYSCALL(prlimit64),
      ALLOW_SYSCALL(lstat),
      ALLOW_SYSCALL(futex),
      ALLOW_SYSCALL(mprotect),
      ALLOW_SYSCALL(mmap),
      ALLOW_SYSCALL(brk),
      ALLOW_SYSCALL(open),
      ALLOW_SYSCALL(clone),
      ALLOW_SYSCALL(set_robust_list),

      ALLOW_SYSCALL(fstat),
      KILL_PROCESS,
  };
  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("prctl(NO_NEW_PRIVS)");
    goto failed;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
    perror("prctl(SECCOMP)");
    goto failed;
  }
  return 0;

failed:
  if (errno == EINVAL) fprintf(stderr, "SECCOMP_FILTER is not available. :(\n");
  return 1;
}

int main(int argc, char *argv[]) {
  if (install_syscall_reporter()) return 1;
  if (install_syscall_filter()) return 1;
  printf("running\n");
  convert_image("../diaper.jpg", "../tiny_diaper.jpg");
  printf("done\n");
  return 0;
}
