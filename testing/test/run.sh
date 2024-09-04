#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

#
# Input parameters
#
ADMIN_PASSWORD=Password1

#
# Prompt if required, and expand relative paths such as those containing ~
#
if [ "$LICENSE_FILE_PATH" == '' ]; then
  read -t 10 -p 'Enter the path to the license file for the Curity Identity Server: ' LICENSE_FILE_PATH || :
fi
LICENSE_FILE_PATH=$(eval echo "$LICENSE_FILE_PATH")

#
# Check we have valid data before proceeding
#
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
# Deploy the system
#
export LICENSE_KEY && export ADMIN_PASSWORD && docker compose up -d

#
# Wait for the Identity Server to come up
#
echo 'Waiting for the Curity Identity Server to start...'
c=0; while [[ $c -lt 25 && "$(curl -fs -w ''%{http_code}'' localhost:8443)" != "404" ]]; do ((c++)); echo -n "."; sleep 1; done

#
# Run integration tests
#
PATH="$NGINX_SRC_DIR/objs:$PATH" prove -v -f t/

#
# Free resources
#
docker-compose down
