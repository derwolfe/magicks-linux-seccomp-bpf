CC=gcc
CFLAGS=-Wall

CFLAGS += `pkg-config --cflags MagickWand`
LDFLAGS += `pkg-config --libs MagickWand`

all: example

include syscall-reporter.mk

example: example.o syscall-reporter.o convert-w-sb.o

.PHONY: clean
clean:
	rm -f example *.o 
