#
# For Amazon Linux we need to install some dependencies and then install nginx
# http://nginx.org/en/linux_packages.html#Amazon-Linux
#

FROM amazonlinux:2023
ARG NGINX_VERSION

RUN yum install -y yum-utils

COPY amazon2023/nginx.repo /etc/yum.repos.d/nginx.repo

RUN yum-config-manager --enable nginx-mainline

# 'yum list available nginx --showduplicates' shows versions available
RUN yum install -y nginx-$NGINX_VERSION-1.amzn2023.ngx.x86_64 valgrind
