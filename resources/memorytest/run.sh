#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

#
# Manage getting a license file for the Curity Identity Server
#
if [ "$LICENSE_FILE_PATH" == '' ]; then
  read -t 10 -p 'Enter the path to the license file for the Curity Identity Server: ' LICENSE_FILE_PATH || :
fi
LICENSE_FILE_PATH=$(eval echo "$LICENSE_FILE_PATH")
if [ ! -f "$LICENSE_FILE_PATH" ]; then
  >&2 echo 'A valid LICENSE_FILE_PATH parameter was not supplied'
  exit 1
fi
LICENSE_KEY=$(cat "$LICENSE_FILE_PATH" | jq -r .License)
if [ "$LICENSE_KEY" == '' ]; then
  >&2 echo 'A valid license key was not found'
  exit 1
fi

#
# Default other input values
#
if [ "$ADMIN_PASSWORD" == '' ]; then
  ADMIN_PASSWORD=Password1
fi
if [ "$DISTRO" == '' ]; then
  DISTRO='alpine'
fi
if [ "$NGINX_DEPLOY_VERSION" == '' ]; then
  NGINX_DEPLOY_VERSION='1.25.5'
fi
echo "Deploying for $DISTRO with NGINX version $NGINX_DEPLOY_VERSION ..."

#
# Validate input to ensure that we have a supported Linux distribution
#
case $DISTRO in

  'alpine')
    MODULE_FILE="alpine.ngx_curity_http_phantom_token_module_$NGINX_DEPLOY_VERSION.so"
    MODULE_FOLDER='/usr/lib/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;

  'debian11')
    MODULE_FILE="debian.bullseye.ngx_curity_http_phantom_token_module_$NGINX_DEPLOY_VERSION.so"
    MODULE_FOLDER='/usr/lib/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;

  'debian12')
    MODULE_FILE="debian.bookworm.ngx_curity_http_phantom_token_module_$NGINX_DEPLOY_VERSION.so"
    MODULE_FOLDER='/usr/lib/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;

  'ubuntu20')
    MODULE_FILE="ubuntu.20.04.ngx_curity_http_phantom_token_module_$NGINX_DEPLOY_VERSION.so"
    MODULE_FOLDER='/usr/lib/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;

  'ubuntu22')
    MODULE_FILE="ubuntu.22.04.ngx_curity_http_phantom_token_module_$NGINX_DEPLOY_VERSION.so"
    MODULE_FOLDER='/usr/lib/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;

  'ubuntu24')
    MODULE_FILE="ubuntu.24.04.ngx_curity_http_phantom_token_module_$NGINX_DEPLOY_VERSION.so"
    MODULE_FOLDER='/usr/lib/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;

  'amazon2')
    MODULE_FILE="amzn2.ngx_curity_http_phantom_token_module_$NGINX_DEPLOY_VERSION.so"
    MODULE_FOLDER='/etc/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;

  'amazon2023')
    MODULE_FILE="amzn2023.ngx_curity_http_phantom_token_module_$NGINX_DEPLOY_VERSION.so"
    MODULE_FOLDER='/etc/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;

  'centosstream9')
    MODULE_FILE="centos.stream.9.ngx_curity_http_phantom_token_module_$NGINX_DEPLOY_VERSION.so"
    MODULE_FOLDER='/etc/nginx/modules'
    NGINX_PATH='/usr/sbin/nginx'
    CONF_PATH='/etc/nginx/nginx.conf'
    ;;
esac

#
# Check for a valid distro
#
if [ "$MODULE_FILE" == '' ]; then
  >&2 echo 'Please enter a supported Linux distribution as a command line argument'
  exit 1
fi

#
# Check that the image has been built
#
if [ ! -f "../../build/${MODULE_FILE}" ]; then
  >&2 echo "The Phantom Token plugin for $DISTRO version $NGINX_DEPLOY_VERSION has not been built"
  exit 1
fi

#
# Build the valgrind image
#
echo 'Building the NGINX and valgrind Docker image ...'
docker build --no-cache -f "$DISTRO/Dockerfile" --build-arg NGINX_DEPLOY_VERSION="$NGINX_DEPLOY_VERSION" -t "nginx_$DISTRO:$NGINX_DEPLOY_VERSION" .
if [ $? -ne 0 ]; then
  >&2 echo "Problem encountered building the NGINX $DISTRO docker image"
  exit 1
fi

#
# Deploy the system
#
export LICENSE_KEY
export ADMIN_PASSWORD
export DISTRO
export NGINX_DEPLOY_VERSION
export MODULE_FILE
export MODULE_FOLDER
export NGINX_PATH
export CONF_PATH
docker compose up -d
if [ $? -ne 0 ]; then
  >&2 echo 'Problem encountered running the Docker Compose deployment'
  exit 1
fi

#
# Wait for the Identity Server to come up
#
echo 'Waiting for the Curity Identity Server to start ...'
c=0; while [[ $c -lt 25 && "$(curl -fs -w ''%{http_code}'' localhost:8443)" != "404" ]]; do ((c++)); echo -n "."; sleep 1; done

#
# Test parameters
#
CLIENT_ID='test-client'
CLIENT_SECRET='secret1'
RESPONSE_FILE=response.txt

#
# Run curl tests to call the API via the reverse proxy
#
echo
echo 'Running API tests ...'
for TOKEN in 1 2 3 4 5
do
  #
  # Act as a client to get a token
  #
  echo -n "."
  HTTP_STATUS=$(curl -s -X POST http://localhost:8443/oauth/v2/oauth-token \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "grant_type=client_credentials" \
    -o $RESPONSE_FILE -w '%{http_code}')
  if [ "$HTTP_STATUS" != '200' ]; then
    echo "Unexpected status authenticating: $HTTP_STATUS"
  fi
  JSON=$(cat $RESPONSE_FILE)
  ACCESS_TOKEN=$(jq -r .access_token <<< "$JSON")

  #
  # Make 4 valid API calls to test the success path, the first of which will cause the module to make an introspection request
  #
  for CALL in 1 2 3 4
  do
    echo -n "."
    HTTP_STATUS=$(curl -s -X GET 'http://localhost:8080/api' -H "Authorization: Bearer $ACCESS_TOKEN" -o $RESPONSE_FILE -w '%{http_code}')
    if [ "$HTTP_STATUS" != '200' ]; then
      >&2 echo "Unexpected status during API call: $HTTP_STATUS"
    fi
  done

  #
  # Make 1 invalid API call to test the error path, where the module returns a 401 to the caller
  #
  echo -n "."
  HTTP_STATUS=$(curl -s -X GET 'http://localhost:8080/api' -H "Authorization: Bearer xxx" -o $RESPONSE_FILE -w '%{http_code}')
  if [ "$HTTP_STATUS" != '401' ]; then
    >&2 echo "Unexpected status during API call: $HTTP_STATUS"
  fi
done

#
# Output valgrind results
#
echo
echo 'Retrieving valgrind memory results ...'
DOCKER_CONTAINER_ID=$(docker container ls | grep "nginx_$DISTRO" | awk '{print $1}')
docker cp "$DOCKER_CONTAINER_ID:/valgrind-results.txt" .
cat valgrind-results.txt

#
# Free resources
#
docker-compose down
