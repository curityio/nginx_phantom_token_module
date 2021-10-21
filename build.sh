#!/bin/bash

NGINX_VERSION=${NGINX_VERSION:-1.21.3}
NGINX_TARBALL=nginx-${NGINX_VERSION}.tar.gz

if [[ ! -r $NGINX_TARBALL ]]; then
  if [ -z "$DOWNLOAD_PROGRAM" ]; then
      if hash curl &>/dev/null; then
        DOWNLOAD_PROGRAM="curl -O"
      elif hash wget &>/dev/null; then
        DOWNLOAD_PROGRAM="wget"
      else
        echo "Couldn't find curl or wget, please install either of these programs."
        exit 1
      fi
  fi
    $DOWNLOAD_PROGRAM https://nginx.org/download/nginx-"${NGINX_VERSION}".tar.gz
fi

docker build --no-cache -t nginx-module-builder \
  --build-arg NGINX_SRC_DIR=/tmp/nginx-"$NGINX_VERSION" \
  --build-arg NGINX_VERSION="$NGINX_VERSION" \
  --build-arg NGINX_DEBUG=n \
  --build-arg DYNAMIC_MODULE=Y \
  -f Dockerfile .

docker run --name nginx-modules -d nginx-module-builder 300
docker cp nginx-modules:/build/ .
docker stop -t 0 nginx-modules
docker rm nginx-modules
docker rmi nginx-module-builder
