-include .build.info

# There is no `all` target in the NGINX Makefile, but it's a common default, so we add it. When this is used though,
# we always pass on `default` since `all` is unknown to the NGINX Makefile
default all: .build.info
	cd $(NGINX_SRC_DIR) && $(MAKE) -e default

module modules: .build.info $(NGINX_SRC_DIR)/Makefile
ifneq (, $(filter y yes Y YES Yes, $(DYNAMIC_MODULE)))
	cd $(NGINX_SRC_DIR) && $(MAKE) -f Makefile modules
else
	$(error Rerun the configure script and indicate that a dynamic module should be built)	
endif	

build install upgrade: .build.info $(NGINX_SRC_DIR)/Makefile
	cd $(NGINX_SRC_DIR) && $(MAKE) -e $@

clean:
	test -d "$(NGINX_SRC_DIR)" && $(MAKE) -C $(NGINX_SRC_DIR) $@ || true
	rm -rf .build.info nginx-$(NGINX_VERSION) nginx-$(NGINX_VERSION).tar.gz* t/servroot

test: all
	@bash -c 'NGINX_SRC_DIR="$(NGINX_SRC_DIR)" ./testing/test/run.sh'

integration:
	@bash -c './testing/integration/run.sh'

.build.info $(NGINX_SRC_DIR)/Makefile:
	$(error You need to run the configure script in the root of this directory before building the source)
