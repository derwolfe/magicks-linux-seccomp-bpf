from ubuntu:latest

RUN apt update && apt install -y \
    gcc vim libseccomp-dev \
    sudo git automake autoconf \
    make pkg-config man \
    libmagickwand-dev imagemagick

WORKDIR magick-sb