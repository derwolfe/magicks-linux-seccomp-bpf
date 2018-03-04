#include <errno.h>
#include <fcntl.h>
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

int install_seccomp(char *path_a, char *path_b) {
  int rc = -1;
  //char export_file[] = "/tmp/seccomp_filter.pfc";

  prctl(PR_SET_NO_NEW_PRIVS, 1);
  prctl(PR_SET_DUMPABLE, 0);

  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
  if (ctx == NULL) {
    perror("initializing context failed");
    return -1;
  }

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigreturn), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);

  // you can constrain what it writes to
  // rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
  //                       SCMP_CMP(0, SCMP_CMP_EQ, (intptr_t) path_a),
  //                       SCMP_CMP(0, SCMP_CMP_EQ, (intptr_t) path_b));
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(times), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sysinfo), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
  // needed for export, nt convert
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
  rc = seccomp_load(ctx);
  if (rc < 0) {
    goto out;
  };

  // int filter_fd = open(export_file, O_WRONLY | O_TRUNC | O_CREAT);
  // if (filter_fd == -1) {
  //   rc = -errno;
  //   goto out;
  // }

  // rc = seccomp_export_pfc(ctx, filter_fd);
  // if (rc < 0) {
  //   close(filter_fd);
  //   goto out;
  // }
  // close(filter_fd);

  return 0;

out:
  seccomp_release(ctx);
  perror("failed to build rules");
  return -1;
}

void convert_image(char *infile, char *outfile) {
  // proxy this for ConvertImageCommand
  MagickWand *image = NULL;
  PixelWand *target = NULL;
  PixelWand *fill = NULL;

  // Convert 40% to double
  const double fuzz = 40 * QuantumRange / 100;

  MagickWandGenesis();

  target = NewPixelWand();
  fill = NewPixelWand();
  image = NewMagickWand();

  // Load image
  MagickReadImage(image, infile);

  // Set Colors
  PixelSetColor(target, "rgb(65535, 65535, 65535)");
  PixelSetColor(fill, "rgb(53456, 35209, 30583)");

  // Apply effect(wand,0.40);
  MagickOpaquePaintImage(image, target, fill, fuzz, MagickFalse);

  // Save image
  MagickWriteImages(image, outfile, MagickTrue);

  // Clean up
  image = DestroyMagickWand(image);
  MagickWandTerminus();
}

int main(int argc, char **argv) {
  char *from = "diaper.jpg";
  char *to = "tiny_diaper.jpg";

  printf("before\n");
  int sc = install_seccomp(to, from);
  if (sc != 0) {
    exit(1);
  }
  convert_image(from, to);
  printf("done!\n");
}
