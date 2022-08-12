#
# For CentOS we need to install some dependencies and then install nginx
# http://nginx.org/en/linux_packages.html#CentOS
#

FROM centos:7
ARG NGINX_DEPLOY_VERSION

RUN yum install -y yum-utils

COPY centos7/nginx.repo /etc/yum.repos.d/nginx.repo

RUN yum-config-manager --enable nginx-mainline

# 'yum list available nginx --showduplicates' shows versions available
RUN yum install -y nginx-1:$NGINX_DEPLOY_VERSION-1.el7.ngx.x86_64 valgrind
