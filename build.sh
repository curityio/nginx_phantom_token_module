#!/bin/bash

#########################################################################
# Builds a particular NGINX version for a particular Linux OS and version
#########################################################################

NGINX_VERSION=${NGINX_VERSION:-1.25.5}
NGINX_TARBALL=nginx-${NGINX_VERSION}.tar.gz
LINUX_DISTRO=${LINUX_DISTRO:-alpine}

if [ "$LINUX_DISTRO" != 'alpine' ] &&
   [ "$LINUX_DISTRO" != 'debian11' ] &&
   [ "$LINUX_DISTRO" != 'debian12' ] &&
   [ "$LINUX_DISTRO" != 'ubuntu20' ] &&
   [ "$LINUX_DISTRO" != 'ubuntu22' ] &&
   [ "$LINUX_DISTRO" != 'ubuntu24' ] &&
   [ "$LINUX_DISTRO" != 'amazon2' ] &&
   [ "$LINUX_DISTRO" != 'amazon2023' ] &&
   [ "$LINUX_DISTRO" != 'centosstream9' ]; then
  echo "$LINUX_DISTRO is not a supported Linux distribution"
  exit 1
fi

function getLibraryPrefix() {
  if [ "$LINUX_DISTRO" == 'alpine' ]; then
    echo 'alpine'
  elif [ "$LINUX_DISTRO" == 'debian11' ]; then
    echo 'debian.bullseye'
  elif [ "$LINUX_DISTRO" == 'debian12' ]; then
    echo 'debian.bookworm'
  elif [ "$LINUX_DISTRO" == 'ubuntu20' ]; then
    echo 'ubuntu.20.04'
  elif [ "$LINUX_DISTRO" == 'ubuntu22' ]; then
    echo 'ubuntu.22.04'
  elif [ "$LINUX_DISTRO" == 'ubuntu24' ]; then
    echo 'ubuntu.24.04'
  elif [ "$LINUX_DISTRO" == 'amazon2' ]; then
    echo 'amzn2'
  elif [ "$LINUX_DISTRO" == 'amazon2023' ]; then
    echo 'amzn2023'
  elif [ "$LINUX_DISTRO" == 'centosstream9' ]; then
    echo 'centos.stream.9'
  fi
}

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
  --build-arg NGINX_VERSION="$NGINX_VERSION" \
  -f builders/$LINUX_DISTRO.Dockerfile .
if [ $? -ne 0 ]; then
  echo "Docker build problem encountered for OS $LINUX_DISTRO and NGINX $NGINX_VERSION"
  exit 1
fi

mkdir -p build
LIBRARY_PREFIX=$(getLibraryPrefix)
docker run --name nginx-modules nginx-module-builder
docker cp nginx-modules:/tmp/nginx-$NGINX_VERSION/objs/ngx_curity_http_phantom_token_module.so ./build/$LIBRARY_PREFIX.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so
docker rm nginx-modules
docker rmi nginx-module-builder
