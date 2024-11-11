#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

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
