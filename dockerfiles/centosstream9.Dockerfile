FROM quay.io/centos/centos:stream9 as centos-stream9-builder

RUN yum install -y \
     gcc pcre-devel zlib-devel make

COPY configure /tmp
COPY config /tmp
COPY Makefile /tmp
COPY phantom_token.c /tmp
ARG NGINX_VERSION
ENV NGINX_VERSION=$NGINX_VERSION
ADD nginx-$NGINX_VERSION.tar.gz /tmp/

WORKDIR /tmp
RUN ./configure && make