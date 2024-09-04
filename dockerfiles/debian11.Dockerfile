FROM debian:bullseye

RUN apt update && apt install -y \
    build-essential git tree software-properties-common dirmngr apt-transport-https ufw libpcre2-dev zlib1g-dev

COPY configure /tmp
COPY config /tmp
COPY Makefile /tmp
COPY phantom_token.c /tmp
ARG NGINX_VERSION
ENV NGINX_VERSION=$NGINX_VERSION
ADD nginx-$NGINX_VERSION.tar.gz /tmp/

WORKDIR /tmp
RUN ./configure && make
