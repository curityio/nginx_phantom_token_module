#!/bin/bash

######################################################
# Tear down after testing and report on memory results
######################################################

cd "$(dirname "${BASH_SOURCE[0]}")"

#
# Calculate parameters
#
case $LINUX_DISTRO in

  'alpine')
    MODULE_FILE="alpine.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so"
    MODULE_FOLDER='/usr/lib/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;

  'debian11')
    MODULE_FILE="debian.bullseye.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so"
    MODULE_FOLDER='/usr/lib/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;

  'debian12')
    MODULE_FILE="debian.bookworm.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so"
    MODULE_FOLDER='/usr/lib/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;

  'ubuntu20')
    MODULE_FILE="ubuntu.20.04.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so"
    MODULE_FOLDER='/usr/lib/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;

  'ubuntu22')
    MODULE_FILE="ubuntu.22.04.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so"
    MODULE_FOLDER='/usr/lib/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;

  'ubuntu24')
    MODULE_FILE="ubuntu.24.04.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so"
    MODULE_FOLDER='/usr/lib/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;

  'amazon2')
    MODULE_FILE="amzn2.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so"
    MODULE_FOLDER='/etc/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;

  'amazon2023')
    MODULE_FILE="amzn2023.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so"
    MODULE_FOLDER='/etc/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;

  'centosstream9')
    MODULE_FILE="centos.stream.9.ngx_curity_http_phantom_token_module_$NGINX_VERSION.so"
    MODULE_FOLDER='/etc/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;
esac

#
# Check for valid input
#
if [ "$MODULE_FILE" == '' ]; then
  >&2 echo 'Please enter a supported Linux distribution as a command line argument'
  exit 1
fi

#
# Output valgrind results
#
echo
echo 'Retrieving valgrind memory results ...'
DOCKER_CONTAINER_ID=$(docker container ls | grep "nginx_$LINUX_DISTRO" | awk '{print $1}')
docker cp "$DOCKER_CONTAINER_ID:/valgrind-results.txt" .
cat valgrind-results.txt

#
# Free resources
#
export LICENSE_KEY=''
export ADMIN_PASSWORD=''
export LINUX_DISTRO
export NGINX_VERSION
export MODULE_FILE
export MODULE_FOLDER
export NGINX_PATH
export CONF_PATH
docker compose down
