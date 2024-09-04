FROM alpine:3

RUN apk add --no-cache --virtual .build-deps \
    gcc libc-dev make pcre2-dev zlib-dev linux-headers libxslt-dev \
    gd-dev geoip-dev perl-dev libedit-dev mercurial alpine-sdk findutils bash

COPY configure /tmp
COPY config /tmp
COPY Makefile /tmp
COPY phantom_token.c /tmp
ARG NGINX_VERSION
ENV NGINX_VERSION=$NGINX_VERSION
ADD nginx-$NGINX_VERSION.tar.gz /tmp/

WORKDIR /tmp
RUN ./configure && make
