#!/bin/bash

#############################################
# Build and deploy a Docker image for testing
#############################################

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
if [ "$LINUX_DISTRO" == '' ]; then
  LINUX_DISTRO='alpine'
fi
if [ "$NGINX_VERSION" == '' ]; then
  NGINX_VERSION='1.25.5'
fi
echo "Deploying for $LINUX_DISTRO with NGINX version $NGINX_VERSION ..."

#
# Validate input to ensure that we have a supported Linux distribution
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
# Check for a valid Linux distribution
#
if [ "$MODULE_FILE" == '' ]; then
  >&2 echo 'Please enter a supported Linux distribution as a command line argument'
  exit 1
fi

#
# Check that the image has been built
#
if [ ! -f "../../build/${MODULE_FILE}" ]; then
  >&2 echo "The Phantom Token plugin for $LINUX_DISTRO version $NGINX_VERSION has not been built"
  exit 1
fi

#
# Build the valgrind image
#
echo 'Building the NGINX and valgrind Docker image ...'
docker build --no-cache -f "$LINUX_DISTRO/Dockerfile" --build-arg NGINX_VERSION="$NGINX_VERSION" -t "nginx_$LINUX_DISTRO:$NGINX_VERSION" .
if [ $? -ne 0 ]; then
  >&2 echo "Problem encountered building the NGINX $LINUX_DISTRO docker image"
  exit 1
fi

#
# Deploy the system
#
export LICENSE_KEY
export ADMIN_PASSWORD
export LINUX_DISTRO
export NGINX_VERSION
export MODULE_FILE
export MODULE_FOLDER
export NGINX_PATH
export CONF_PATH
docker compose down 2>/dev/null
docker compose up -d
if [ $? -ne 0 ]; then
  >&2 echo 'Problem encountered running the Docker Compose deployment'
  exit 1
fi

#
# Wait for the Identity Server to come up
#
echo 'Waiting for the Curity Identity Server to start ...'
c=0; while [[ $c -lt 50 && "$(curl -fs -w ''%{http_code}'' localhost:8443)" != "404" ]]; do ((c++)); echo -n "."; sleep 1; done

#
# Look at logs if you need to investigate startup errors
#
# docker compose logs

#
# Define test parameters
#
CLIENT_ID='test-client'
CLIENT_SECRET='secret1'
RESPONSE_FILE=response.txt

#
# Run curl tests to call the API via the reverse proxy
#
echo
echo 'Running API tests ...'
for TOKEN in $(seq 1 20)
do
  #
  # Act as a client to get a token
  #
  echo "Getting token $TOKEN" 
  HTTP_STATUS=$(curl -s -X POST http://localhost:8443/oauth/v2/oauth-token \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "grant_type=client_credentials" \
    -d "scope=example" \
    -o $RESPONSE_FILE -w '%{http_code}')
  if [ "$HTTP_STATUS" != '200' ]; then
    echo "Unexpected status authenticating: $HTTP_STATUS"
  fi
  JSON=$(cat $RESPONSE_FILE)
  ACCESS_TOKEN=$(jq -r .access_token <<< "$JSON")

  #
  # Make valid and invalid API calls
  #
  for CALL in $(seq 1 2)
  do
    echo "Calling API $CALL"
    HTTP_STATUS=$(curl -s -X GET 'http://localhost:8080/api' -H "Authorization: Bearer $ACCESS_TOKEN" -o $RESPONSE_FILE -w '%{http_code}')
    if [ "$HTTP_STATUS" != '200' ]; then
      >&2 echo "Unexpected status during API call: $HTTP_STATUS"
    fi
  done

  echo "Calling API 3" 
  HTTP_STATUS=$(curl -s -X GET 'http://localhost:8080/api' -H "Authorization: Bearer xxx" -o $RESPONSE_FILE -w '%{http_code}')
  if [ "$HTTP_STATUS" != '401' ]; then
    >&2 echo "Unexpected status during API call: $HTTP_STATUS"
  fi

  for CALL in $(seq 4 5)
  do
    echo "Calling API $CALL"
    HTTP_STATUS=$(curl -s -X GET 'http://localhost:8080/api' -H "Authorization: Bearer $ACCESS_TOKEN" -o $RESPONSE_FILE -w '%{http_code}')
    if [ "$HTTP_STATUS" != '200' ]; then
      >&2 echo "Unexpected status during API call: $HTTP_STATUS"
    fi
  done
done

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
docker compose down
