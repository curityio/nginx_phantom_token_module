#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

#
# Set these to valid values
#
LICENSE_FILE_PATH=~/.curity/license.json
ADMIN_PASSWORD=Password1
if [ ! -f "$LICENSE_FILE_PATH" ]; then
  echo 'Please supply the LICENSE_FILE_PATH parameter'
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
echo 'Waiting for the Curity Identity Server to start...'
c=0; while [[ $c -lt 25 && "$(curl -fs -w ''%{http_code}'' localhost:8443)" != "404" ]]; do ((c++)); echo -n "."; sleep 1; done

#
# Run integration tests
#
cd ../..
PATH="$NGINX_SRC_DIR/objs:$PATH" prove -v -f t/

#
# Free resources
#
cd resources/test
docker-compose down
