#!/bin/bash

gcc -Wall --std=c99 $(pkg-config --cflags MagickWand libseccomp) convert-w-sb.c -o convert-w-sb $(pkg-config --libs MagickWand libseccomp) && ./convert-w-sb || true
echo 'removing convert-w-sb'
rm ./convert-w-sb
