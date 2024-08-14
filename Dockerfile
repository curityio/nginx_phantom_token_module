######
# FROM ubuntu:18.04 as ubuntu18-builder

# RUN apt-get update && \
#     apt-get install -y build-essential libxslt1-dev

# COPY configure /tmp
# COPY config /tmp
# COPY Makefile /tmp
# COPY phantom_token.c /tmp
# ARG NGINX_VERSION
# ENV NGINX_VERSION=$NGINX_VERSION
# ADD nginx-$NGINX_VERSION.tar.gz /tmp/

# WORKDIR /tmp
# RUN ./configure && make

# ######
# FROM ubuntu:20.04 as ubuntu20-builder

# RUN apt-get update && \
#     apt-get install -y build-essential wget

# COPY configure /tmp
# COPY config /tmp
# COPY Makefile /tmp
# COPY phantom_token.c /tmp
# ARG NGINX_VERSION
# ENV NGINX_VERSION=$NGINX_VERSION
# ADD nginx-$NGINX_VERSION.tar.gz /tmp/

# WORKDIR /tmp
# RUN wget https://sourceforge.net/projects/pcre/files/pcre/8.45/pcre-8.45.tar.gz && mkdir -p pcre && tar -xz -C pcre -f pcre-8.45.tar.gz --strip-components=1
# RUN wget https://www.zlib.net/zlib-1.3.1.tar.gz && mkdir -p zlib && tar -xz -C zlib -f zlib-1.3.1.tar.gz --strip-components=1
# RUN CONFIG_OPTS="--with-pcre=../pcre --with-zlib=../zlib" ./configure && make

# ######
# FROM ubuntu:22.04 as ubuntu22-builder

# RUN apt-get update && \
#     apt-get install -y build-essential wget

# COPY configure /tmp
# COPY config /tmp
# COPY Makefile /tmp
# COPY phantom_token.c /tmp
# ARG NGINX_VERSION
# ENV NGINX_VERSION=$NGINX_VERSION
# ADD nginx-$NGINX_VERSION.tar.gz /tmp/

# WORKDIR /tmp
# RUN wget https://sourceforge.net/projects/pcre/files/pcre/8.45/pcre-8.45.tar.gz && mkdir -p pcre && tar -xz -C pcre -f pcre-8.45.tar.gz --strip-components=1
# RUN wget https://www.zlib.net/zlib-1.3.1.tar.gz && mkdir -p zlib && tar -xz -C zlib -f zlib-1.3.1.tar.gz --strip-components=1
# RUN CONFIG_OPTS="--with-pcre=../pcre --with-zlib=../zlib" ./configure && make

# ######
# # FROM centos:7 as centos7-builder

# # RUN yum install -y \
# #      gcc pcre-devel zlib-devel make

# # COPY configure /tmp
# # COPY config /tmp
# # COPY Makefile /tmp
# # COPY phantom_token.c /tmp
# # ARG NGINX_VERSION
# # ENV NGINX_VERSION=$NGINX_VERSION
# # ADD nginx-$NGINX_VERSION.tar.gz /tmp/

# # WORKDIR /tmp
# # RUN ./configure && make

# # ######
# # FROM quay.io/centos/centos:stream9 as centos-stream9-builder

# # RUN yum install -y \
# #      gcc pcre-devel zlib-devel make

# # COPY configure /tmp
# # COPY config /tmp
# # COPY Makefile /tmp
# # COPY phantom_token.c /tmp
# # ARG NGINX_VERSION
# # ENV NGINX_VERSION=$NGINX_VERSION
# # ADD nginx-$NGINX_VERSION.tar.gz /tmp/

# # WORKDIR /tmp
# # RUN ./configure && make

# ######
# FROM debian:buster as debian10-builder

# RUN apt update && apt install -y \
#     wget build-essential git tree software-properties-common dirmngr apt-transport-https ufw

# COPY configure /tmp
# COPY config /tmp
# COPY Makefile /tmp
# COPY phantom_token.c /tmp
# ARG NGINX_VERSION
# ENV NGINX_VERSION=$NGINX_VERSION
# ADD nginx-$NGINX_VERSION.tar.gz /tmp/

# WORKDIR /tmp
# RUN wget https://sourceforge.net/projects/pcre/files/pcre/8.45/pcre-8.45.tar.gz && mkdir -p pcre && tar -xz -C pcre -f pcre-8.45.tar.gz --strip-components=1
# RUN wget https://www.zlib.net/zlib-1.3.1.tar.gz && mkdir -p zlib && tar -xz -C zlib -f zlib-1.3.1.tar.gz --strip-components=1
# RUN CONFIG_OPTS="--with-pcre=../pcre --with-zlib=../zlib" ./configure && make

# ######
# FROM debian:bullseye as debian11-builder

# RUN apt update && apt install -y \
#     wget build-essential git tree software-properties-common dirmngr apt-transport-https ufw

# COPY configure /tmp
# COPY config /tmp
# COPY Makefile /tmp
# COPY phantom_token.c /tmp
# ARG NGINX_VERSION
# ENV NGINX_VERSION=$NGINX_VERSION
# ADD nginx-$NGINX_VERSION.tar.gz /tmp/

# WORKDIR /tmp
# RUN wget https://sourceforge.net/projects/pcre/files/pcre/8.45/pcre-8.45.tar.gz && mkdir -p pcre && tar -xz -C pcre -f pcre-8.45.tar.gz --strip-components=1
# RUN wget https://www.zlib.net/zlib-1.3.1.tar.gz && mkdir -p zlib && tar -xz -C zlib -f zlib-1.3.1.tar.gz --strip-components=1
# RUN CONFIG_OPTS="--with-pcre=../pcre --with-zlib=../zlib" ./configure && make

# ######
# FROM debian:bookworm as debian12-builder

# RUN apt update && apt install -y \
#     wget build-essential git tree software-properties-common dirmngr apt-transport-https ufw

# COPY configure /tmp
# COPY config /tmp
# COPY Makefile /tmp
# COPY phantom_token.c /tmp
# ARG NGINX_VERSION
# ENV NGINX_VERSION=$NGINX_VERSION
# ADD nginx-$NGINX_VERSION.tar.gz /tmp/

# WORKDIR /tmp
# RUN wget https://sourceforge.net/projects/pcre/files/pcre/8.45/pcre-8.45.tar.gz && mkdir -p pcre && tar -xz -C pcre -f pcre-8.45.tar.gz --strip-components=1
# RUN wget https://www.zlib.net/zlib-1.3.1.tar.gz && mkdir -p zlib && tar -xz -C zlib -f zlib-1.3.1.tar.gz --strip-components=1
# RUN CONFIG_OPTS="--with-pcre=../pcre --with-zlib=../zlib" ./configure && make

# ######
# FROM amazonlinux:2 as amzn2-builder

# RUN yum install -y \
#  gcc pcre-devel zlib-devel make

# COPY configure /tmp
# COPY config /tmp
# COPY Makefile /tmp
# COPY phantom_token.c /tmp
# ARG NGINX_VERSION
# ENV NGINX_VERSION=$NGINX_VERSION
# ADD nginx-$NGINX_VERSION.tar.gz /tmp/

# WORKDIR /tmp
# RUN ./configure && make

# ######
# FROM amazonlinux:2023 as amzn2023-builder

# RUN yum install -y \
#  gcc pcre-devel zlib-devel make

# COPY configure /tmp
# COPY config /tmp
# COPY Makefile /tmp
# COPY phantom_token.c /tmp
# ARG NGINX_VERSION
# ENV NGINX_VERSION=$NGINX_VERSION
# ADD nginx-$NGINX_VERSION.tar.gz /tmp/

# WORKDIR /tmp
# RUN ./configure && make

######
FROM alpine as alpine-builder

RUN apk add --no-cache --virtual .build-deps \
    gcc libc-dev make openssl-dev pcre-dev zlib-dev linux-headers libxslt-dev \
    gd-dev geoip-dev perl-dev libedit-dev mercurial bash alpine-sdk findutils bash

COPY configure /tmp
COPY config /tmp
COPY Makefile /tmp
COPY phantom_token.c /tmp
ARG NGINX_VERSION
ENV NGINX_VERSION=$NGINX_VERSION
ADD nginx-$NGINX_VERSION.tar.gz /tmp/

WORKDIR /tmp
RUN ./configure && make

######
FROM alpine

ARG NGINX_VERSION
ENV NGINX_VERSION=$NGINX_VERSION
# COPY --from=ubuntu18-builder /tmp/nginx-$NGINX_VERSION/objs/ngx_curity_http_phantom_token_module.so /build/ubuntu.18.04.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so
# COPY --from=ubuntu20-builder /tmp/nginx-$NGINX_VERSION/objs/ngx_curity_http_phantom_token_module.so /build/ubuntu.20.04.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so
# COPY --from=ubuntu22-builder /tmp/nginx-$NGINX_VERSION/objs/ngx_curity_http_phantom_token_module.so /build/ubuntu.22.04.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so
# COPY --from=centos7-builder /tmp/nginx-$NGINX_VERSION/objs/ngx_curity_http_phantom_token_module.so /build/centos.7.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so
# COPY --from=centos-stream9-builder /tmp/nginx-$NGINX_VERSION/objs/ngx_curity_http_phantom_token_module.so /build/centos.stream.9.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so
# COPY --from=debian10-builder /tmp/nginx-$NGINX_VERSION/objs/ngx_curity_http_phantom_token_module.so /build/debian.buster.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so
# COPY --from=debian11-builder /tmp/nginx-$NGINX_VERSION/objs/ngx_curity_http_phantom_token_module.so /build/debian.bullseye.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so
# COPY --from=debian12-builder /tmp/nginx-$NGINX_VERSION/objs/ngx_curity_http_phantom_token_module.so /build/debian.bookworm.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so
# COPY --from=amzn2-builder /tmp/nginx-$NGINX_VERSION/objs/ngx_curity_http_phantom_token_module.so /build/amzn2.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so
# COPY --from=amzn2023-builder /tmp/nginx-$NGINX_VERSION/objs/ngx_curity_http_phantom_token_module.so /build/amzn2023.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so
COPY --from=alpine-builder /tmp/nginx-$NGINX_VERSION/objs/ngx_curity_http_phantom_token_module.so /build/alpine.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so

ENTRYPOINT ["sleep"]

CMD ["300"]
