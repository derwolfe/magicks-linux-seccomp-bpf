from ubuntu:latest

RUN apt update && apt install -y \
    gcc vim libseccomp-dev \
    sudo git automake autoconf \
    make
   # libmagickwand-dev imagemagick

RUN git clone --depth 1 https://github.com/ImageMagick/ImageMagick /tmp/ImageMagick
RUN cd /tmp/ImageMagick && ./configure --enable-shared && make -j$(nproc) && make install && cd /

WORKDIR sb-fun