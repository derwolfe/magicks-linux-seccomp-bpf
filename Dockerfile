from debian:unstable

RUN apt update && apt install -y \
    gcc vim libseccomp-dev seccomp \
    sudo git automake autoconf \
    make pkg-config man \
    libmagickwand-dev imagemagick
RUN apt install -y gdb strace

WORKDIR magick-sb
