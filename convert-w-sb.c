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

  // reject all by default
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
  rc = seccomp_arch_add(ctx, SCMP_ARCH_X86);
  if (rc != 0) {
    goto out;
  };

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  if (rc != 0) {
    goto out;
  };
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
  if (rc != 0) {
    goto out;
  };
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
  if (rc != 0) {
    goto out;
  };
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
  if (rc != 0) {
    goto out;
  };
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  if (rc != 0) {
    goto out;
  };
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  if (rc != 0) {
    goto out;
  };
  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  if (rc != 0) {
    goto out;
  };

  rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
                        SCMP_A0(SCMP_CMP_EQ, STDERR_FILENO));
  if (rc != 0) {
    goto out;
  };
  rc = seccomp_load(ctx);
  if (rc != 0) {
    goto out;
  };

  return 0;

out:
  seccomp_release(ctx);
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
  // The idea behind working with wand this way is that it allows us to test
  // running all convert operations without requiring one to modify/rebuild
  // magickwand on changes. After a policy is verified as being good enough, it
  // could be pulled in.

  int sc = install_seccomp();
  if (sc != 0) {
    printf("failed\n");
    exit(1);
  }
  convert_image("diaper.jpg", "tiny_diaper.jpg");
}
