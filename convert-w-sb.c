#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <linux/audit.h>
#include <linux/filter.h>

#include <seccomp.h>

#include <ImageMagick-6/wand/MagickWand.h>

int install_seccomp() {
  int rc = -1;

  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
  // reject all by default
  rc = seccomp_arch_add(ctx, SCMP_ARCH_X86);
  if (rc != 0) {
    goto out;
  };

  // simple rules, break printf
  rc = seccomp_load(ctx);
  if (rc != 0) {
    goto out;
  };

  return 0;

 out:
  seccomp_release(ctx);
  return -1;
}

int main(int argc, char **argv) {
  // setup the env
  //if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
  //  perror("Could not start seccomp:");
  //  exit(1);
  //}
  //// setup seccomp-bpf
  //if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, NULL) == -1) {
  //  perror("Could not start seccomp:");
  //  exit(1);
  //}

  int ret = install_seccomp();
  if (ret != 0) {
    printf("failed\n");
    exit(1);
  }

  // there is a way to inspect was system calls are actually needed. Kees
  // discusses it at https://outflux.net/teach-seccomp/
  ConvertImageCommand(NULL, 1, NULL, NULL, NULL);
}

// mostly taken from https://eigenstate.org/notes/seccomp
