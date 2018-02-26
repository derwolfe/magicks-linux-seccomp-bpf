#!/bin/bash

gcc -Wall --std=c99 -g \
    $(pkg-config --cflags MagickWand libseccomp) \
	  convert-w-sb.c -o convert-w-sb $(pkg-config --libs MagickWand libseccomp) 
