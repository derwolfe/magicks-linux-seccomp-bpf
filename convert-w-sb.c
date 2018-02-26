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
#include <linux/seccomp.h>

#include <ImageMagick-6/wand/MagickWand.h>

#define syscall_arg(_n) (offsetof(struct seccomp_data, args[_n]))
#define syscall_nr (offsetof(struct seccomp_data, nr))

int start_sb(char *path_a, char *path_b) {
  struct sock_filter filter[] = {
    //BPF_STMT(BPF_LD + BPF_W + BPF_ABS, syscall_nr),
    //BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_rt_sigreturn, 0, 1),
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
  };

  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
    perror("prctl");
    return 1;
  }
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("prctl(NO_NEW_PRIVS)");
    return 1;
  }
  return 0;
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

  int sc = start_sb(to, from);
  if (sc != 0) {
    printf("failed\n");
    exit(1);
  }
  convert_image(to, from);
}
