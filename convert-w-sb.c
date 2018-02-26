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
  if (rc != 0) { goto out; };

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  if (rc != 0) { goto out; };
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
  if (rc != 0) { goto out; };
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
  if (rc != 0) { goto out; };
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
  if (rc != 0) { goto out; };
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  if (rc != 0) { goto out; };
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  if (rc != 0) { goto out; };
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  if (rc != 0) { goto out; };

  rc = seccomp_load(ctx);
  if (rc != 0) { goto out; };

  return 0;

 out:
  seccomp_release(ctx);
  return -1;
}

int main(int argc, char **argv) {

  int ret = install_seccomp();
  if (ret != 0) {
    printf("failed\n");
    exit(1);
  }
  ConvertImageCommand(NULL, 1, NULL, NULL, NULL);
}

// mostly taken from https://eigenstate.org/notes/seccomp
