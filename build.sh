#!/bin/bash

NGINX_VERSION=${NGINX_VERSION:-1.19.0}
NGINX_TARBALL=nginx-${NGINX_VERSION}.tar.gz

if [[ ! -r $NGINX_TARBALL ]]; then
    wget https://nginx.org/download/nginx-"${NGINX_VERSION}".tar.gz
fi

docker build -t nginx-module-builder \
  --build-arg NGINX_SRC_DIR=/tmp/nginx-"$NGINX_VERSION" \
  --build-arg NGINX_VERSION="$NGINX_VERSION" \
  --build-arg NGINX_DEBUG=n \
  --build-arg DYNAMIC_MODULE=Y \
  -f Dockerfile .

docker run --name nginx-modules -d nginx-module-builder 300
docker cp nginx-modules:/build/ .
docker stop -t 0 nginx-modules
docker rm nginx-modules