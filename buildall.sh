#!/bin/bash

##################################################################################
# Builds an entire release with all supported NGINX versions and Linux OS versions
##################################################################################

NGINX_VERSIONS=('1.25.5' '1.25.3' '1.25.1' '1.23.4' '1.23.2')
LINUX_DISTROS=('alpine' 'debian11' 'debian12' 'ubuntu20' 'ubuntu22' 'ubuntu24' 'amazon2' 'amazon2023' 'centosstream9')
rm log.txt 2>/dev/null

#
# Avoid building modules for platforms NGINX does not support
#
function isValidBuild() {
    local LINUX_DISTRO_PARAM=$1
    local NGINX_VERSION_PARAM=$2

    if [ "$LINUX_DISTRO_PARAM" == 'ubuntu24' ] && [[ '1.25.5' > "$NGINX_VERSION_PARAM" ]]; then
      echo 'false'
    elif [ "$LINUX_DISTRO_PARAM" == 'debian12' ] && [[ '1.25.1' > "$NGINX_VERSION_PARAM" ]]; then
      echo 'false'
    else
      echo 'true'
    fi
}

#
# Build modules for all supported environments and versions
#
for LINUX_DISTRO in ${LINUX_DISTROS[@]}
do
  for NGINX_VERSION in ${NGINX_VERSIONS[@]}
  do
    if [ "$(isValidBuild $LINUX_DISTRO $NGINX_VERSION)" == 'true' ]; then
      
      echo "Building the NGINX $NGINX_VERSION phantom token module for $LINUX_DISTRO ..."
      export NGINX_VERSION=$NGINX_VERSION
      export LINUX_DISTRO=$LINUX_DISTRO
      ./build.sh 1>>./log.txt 2>&1
      if [ $? -ne 0 ]; then
        exit 1
      fi

    else
      echo "Skipping unsupported build for NGINX $NGINX_VERSION and $LINUX_DISTRO ..."
    fi
  done
done
