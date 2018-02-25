gcc --std=c99 $(pkg-config --cflags ImageMagick) convert-w-sb.c -o convert-w-sb $(pkg-config --libs MagickWand)
