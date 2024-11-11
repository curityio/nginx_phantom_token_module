#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

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
docker compose down
