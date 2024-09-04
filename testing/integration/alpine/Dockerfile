#
# Alpine has an up to date NGINX image so use that
#

ARG NGINX_DEPLOY_VERSION
FROM nginx:$NGINX_DEPLOY_VERSION-alpine
RUN apk add --no-cache valgrind
