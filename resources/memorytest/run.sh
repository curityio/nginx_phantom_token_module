#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"
RESPONSE_FILE=response.txt

#
# The user must set these to valid values
#
LICENSE_FILE_PATH=~/.curity/license.json
ADMIN_PASSWORD=Password1
if [ ! -f "$LICENSE_FILE_PATH" ]; then
  echo 'Please supply the LICENSE_FILE_PATH parameter'
  exit
fi

#
# Build the valgrind image
#
echo 'Building the NGINX and valgrind Docker image ...'
docker build --no-cache -t nginx_custom:v1 .
if [ "$?" != '0' ]; then
  echo "Problem encountered building the NGINX $DISTRO docker image"
  exit
fi

#
# Deploy the system
#
LICENSE_KEY=$(cat $LICENSE_FILE_PATH | jq -r .License)
export LICENSE_KEY && export ADMIN_PASSWORD && docker compose up -d

#
# Wait for the Identity Server to come up
#
echo 'Waiting for the Curity Identity Server to start ...'
c=0; while [[ $c -lt 25 && "$(curl -fs -w ''%{http_code}'' localhost:8443)" != "404" ]]; do ((c++)); echo -n "."; sleep 1; done

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
    -d "client_id=test-client" \
    -d "client_secret=secret1" \
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
      echo "Unexpected status during API call: $HTTP_STATUS"
    fi
  done

  #
  # Make 1 invalid API call to test the error path, where the module returns a 401 to the caller
  #
  echo -n "."
  HTTP_STATUS=$(curl -s -X GET 'http://localhost:8080/api' -H "Authorization: Bearer xxx" -o $RESPONSE_FILE -w '%{http_code}')
  if [ "$HTTP_STATUS" != '401' ]; then
    echo "Unexpected status during API call: $HTTP_STATUS"
  fi
done

#
# Output valgrind results
#
echo 'Retrieving valgrind memory results ...'
DOCKER_CONTAINER_ID=$(docker container ls | grep "nginx_custom" | awk '{print $1}')
docker cp "$DOCKER_CONTAINER_ID:/valgrind-results.txt" .
cat valgrind-results.txt

#
# Free resources
#
cd resources/memorytest
docker-compose down
