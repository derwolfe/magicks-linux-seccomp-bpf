#!/bin/bash

gcc -Wall --std=c99 $(pkg-config --cflags MagickWand) convert-w-sb.c -o convert-w-sb $(pkg-config --libs MagickWand) && ./convert-w-sb || true
echo 'removing convert-w-sb'
rm ./convert-w-sb
