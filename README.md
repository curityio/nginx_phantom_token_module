# nginx_introspect
NGINX module that introspects access tokens according to RFC 7662

## About
This module, when enabled, filters incoming requests, denying access to those which do NOT have a valid `Authorization: Bearer` header. From this header, the `access_token` is exctracted and introspected using the configured endpoint. Curity replies to this request according to RFC 7662. For an active _access_token_, the body of Curity's response is a JSON which contains the JWT that replaces the _access_token_ in the header of the request forwarded to the backend. In case of a not active _access_token_, 401 Unauthorized is returned.

## Configuration directives
access_token_to_jwt
-------------------
* **syntax**: `access_token_to_jwt on|off`
* **default**: `off`
* **context**: `location`

Enable or disable the module.

access_token_to_jwt_client_id
-------------------
* **syntax**: `access_token_to_jwt_client_id <string>`
* **default**: 	`—`
* **context**: `location`

The `client_id` of the OAuth client which will be used for introspection.

access_token_to_jwt_client_secret
-------------------
* **syntax**: `access_token_to_jwt_client_secret <string>`
* **default**: 	`—`
* **context**: `location`

The `client_secret` of the OAuth client which will be used for introspection.

access_token_to_jwt_introspection_endpoint
-------------------
* **syntax**: `access_token_to_jwt_introspection_endpoint <string>`
* **default**: 	`—`
* **context**: `location`
 
The name of the location that proxies requests to Curity. Note that this location needs to be in the same server as the one refering to it using this directive.



## Sample configuration


### Simple configuration (same server)

        server {
            location /api {
                proxy_pass         https://example.com/api;
                access_token_to_jwt on;
                access_token_to_jwt_client_id "client_id";
                access_token_to_jwt_client_secret "client_secret";
                access_token_to_jwt_introspection_endpoint curity;
            }
            
            location curity {
                proxy_pass "https://curity.example.com/oauth/v2/introspection";
                proxy_set_header content-type "application/x-www-form-urlencoded";
            }
        }
### Complex configuration (separate servers)
        server {
            server_name server1.example.com;n
            location /api {
                proxy_pass         https://example.com/api;
                access_token_to_jwt on;
                access_token_to_jwt_client_id "client_id";
                access_token_to_jwt_client_secret "client_secret";
                access_token_to_jwt_introspection_endpoint curity;
            }
            
            location curity {
                proxy_pass "https://server2.example.com:8443/oauth/v2/introspection";
                proxy_set_header content-type "application/x-www-form-urlencoded";
            }
        }
        
        server {
            listen 8443;
            server_name server2.example.com;
            location / {
                proxy_pass "https://curity.example.com";
            }
        }
        
### Advanced configuration (separate servers + cache)
This module takes advantage of NGINX built-in _proxy_cache_ directive. In order to be able to cache the requests made to the introspection endpoint, except of the `proxy_cache_path` in http context and `proxy_cache` in location context, you have to add the following 3 directives in the location context of the introspection endpoint.

- `proxy_cache_methods POST;` POST requests are not cached by default.
- `proxy_cache_key $request_body;` The key of the cache is related to the _access_token_ sent in the original request. Different requests using the same _access_token_ reach the same cache.
- `proxy_ignore_headers Set-Cookie;` NGINX will not cache the response if `Set-Cookie` header is not ignored.


    http {
        proxy_cache_path /path/to/cache/cache levels=1:2 keys_zone=my_cache:10m max_size=10g
                         inactive=60m use_temp_path=off;
       server {
            server_name server1.example.com;
            location /api {
                proxy_pass         https://example.com/api;
                access_token_to_jwt on;
                access_token_to_jwt_client_id "client_id";
                access_token_to_jwt_client_secret "client_secret";
                access_token_to_jwt_introspection_endpoint curity;
            }
            
            location curity {
                proxy_pass "https://server2.example.com:8443/oauth/v2/introspection";
                proxy_set_header content-type "application/x-www-form-urlencoded";
                
                proxy_cache_methods POST;
                proxy_cache my_cache;
                proxy_cache_key $request_body;
                proxy_ignore_headers Set-Cookie;
            }
        }
        
        server {
            listen 8443;
            server_name server2.example.com;
            location / {
                proxy_pass "https://curity.example.com";
            }
        }
        
    }   

## Build    
Download the NGINX source code from [nginx.org](<http://nginx.org/>) and then build with this module:

        wget 'http://nginx.org/download/nginx-1.x.x.tar.gz'
        tar -xzvf nginx-1.x.x.tar.gz
        cd nginx-1.x.x/
        ./configure --add-module=/path/to/ngx_http_access_token_to_jwt_module

        make
        make install


## Testing and compatibility
TBD
## Status
 This module is still in development. Use it at your own risk!

## More Information
For more information, please contact [Curity](http://curity.io).
Copyright (C) 2017 Curity AB. All rights reserved