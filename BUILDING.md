To build this module, do the following:

1. Download and unpack [PCRE](http://www.pcre.org/), OpenSSL, and zlib if you intend to use these optional dependencies. 
2. [Download NGINX](http://nginx.org/en/download.html)
3. Run `./configure`. Be sure to pass the following options:
    - `--add-dynamic-module` with a path argument pointing to this module's source code root directory (being careful not to use shell patterns like `~`)
    - `--with-debug` (if you want to log messages at the debug level) 
    - Any [additional parameters](http://nginx.org/en/docs/configure.html) (e.g., `--prefix`) that you may need.
4. Run `make && make install` 
5. Open the file `$NGINX_HOME/conf/nginx.conf` and make the following changes for easier development:
    - Load this module, for example, by adding `load_module modules/ngx_http_access_token_to_jwt_module.so;` to top of the config file.
    - Change the `http` `server` `port` to some higher port, for example, `8080`
    - Add the top level directive `daemon off`, so that NGINX will not fork into the background
    - Set the log file of the `error_log` and `access_log` to standard out (e.g., with `access_log /dev/stdout;` in the `server` directive)
    - Set the [log level](nginx.org/en/docs/ngx_core_module.html#error_log) in the `error_log` directive as needed, e.g., `error_log /dev/stdout debug;`
    - Enable this module, e.g., by adding `access_token_to_jwt on` to the `locaiton /` directive.
6.     