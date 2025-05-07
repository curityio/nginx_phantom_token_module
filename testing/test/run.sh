#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

#
# To run tests multiple times without needing to redeploy the Curity Identity Server, use commands like these:
#
# export LICENSE_FILE_PATH=~/Desktop/license.json
# ./testing/test/deploy.sh
# make test
# make test
# make test
# ./testing/test/teardown.sh
#
IS_DEPLOYED="$(docker ps | grep curity)"
if [ "$IS_DEPLOYED" == '' ]; then
   ./deploy.sh
fi

#
# To focus on a particular test, first filter on its source file:
# - prove -v -f t/large_requests.t
#
# Then add the '--- ONLY' directive to limit the test run to the particular test
#
# Them use debug statements and look in the 'testing/test/t/servroot/logs/error.log' file for NGINX details
#
# Read more in the wiki:
# - https://github.com/curityio/nginx_phantom_token_module/wiki/2.-Running-Tests
#
echo 'Running tests ...'
PATH="$NGINX_SRC_DIR/objs:$PATH" prove -v -f t/

if [ "$IS_DEPLOYED" == '' ]; then
  ./teardown.sh
fi
