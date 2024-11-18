#
# For Ubuntu we need to install some dependencies and then install nginx
# http://nginx.org/en/linux_packages.html#Ubuntu
#

FROM ubuntu:20.04
ARG NGINX_VERSION

RUN apt update
RUN apt install -y curl gnupg2 ca-certificates lsb-release ubuntu-keyring

RUN curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
| tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null

RUN echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
http://nginx.org/packages/mainline/ubuntu `lsb_release -cs` nginx" \
| tee /etc/apt/sources.list.d/nginx.list

# 'apt list -a nginx' shows versions available
RUN apt update
RUN apt list -a nginx
RUN apt install -y nginx=$NGINX_VERSION-1~focal valgrind
