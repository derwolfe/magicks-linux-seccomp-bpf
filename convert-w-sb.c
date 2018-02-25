#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

#include <ImageMagick-6/wand/MagickWand.h>

#define ArchField offsetof(struct seccomp_data, arch)

#define Allow(syscall) \
  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##syscall, 0, 1),  \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

struct sock_filter filter[] = {
  /* validate arch */
  BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ArchField),
  BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
  BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

  /* load syscall */
  BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

  /* list of allowed syscalls, "the policy" */
  Allow(exit_group),  /* exits a processs */
  Allow(brk),         /* for malloc(), inside libc */
  Allow(mmap),        /* also for malloc() */
  Allow(munmap),      /* for free(), inside libc */
  Allow(write),       /* called by printf */
  Allow(fstat),       /* called by printf */

  /* and if we don't match above, die */
  BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
};

struct sock_fprog filterprog = {
  .len = sizeof(filter)/sizeof(filter[0]),
  .filter = filter
};

int main(int argc, char **argv) {
  // setup the env
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("Could not start seccomp:");
    exit(1);
  }
  // setup seccomp-bpf
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filterprog) == -1) {
    perror("Could not start seccomp:");
    exit(1);
  }

  // there is a way to inspect was system calls are actually needed. Kees
  // discusses it at https://outflux.net/teach-seccomp/
  ConvertImageCommand(NULL, 1, NULL, NULL, NULL);
}

// mostly taken from https://eigenstate.org/notes/seccomp
