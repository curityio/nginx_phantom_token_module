# nginx_introspect
NGINX module that introspects access tokens according to [RFC 7662](https://tools.ietf.org/html/rfc7662).

This module, when enabled, filters incoming requests, denying access to those which do *not* have a valid `Authorization: Bearer` header. From this header, the access_token is extracted and introspected using the configured endpoint. Curity replies to this request according to the standard. For an active access token, the body of Curity's response contains the JWT that replaces the access token in the header of the request that is forwarded to the back-end. If the token is not valid or absent, no request to the back-end is made and the caller is given a 401, unauthorized, error.

## Configuration Directives

### Required Configuration Directives

All the directives in this subsection are required; if any of these are omitted, the module will be disabled.

#### access_token_to_jwt_base64encoded_client_credentials

> **Syntax**: **`access_token_to_jwt_base64encoded_client_credentials`** _`string`_ 
> 
> **Default**: *`—`*                                                                
> 
> **Context**: `location`                                                           
 
The base-64 encoded string `client_id:client_secret` of the OAuth client which will be used for introspection.

#### access_token_to_jwt_introspection_endpoint

> **Syntax**: **`access_token_to_jwt_introspection_endpoint`** _`string`_
>
> **Default**: *`—`*
>
> **Context**: `location`

The name of the location that proxies requests to Curity. Note that this location needs to be in the same server as the one referring to it using this directive.

Example configuraiton:

```nginx
server {
    location /api {
        ...
        access_token_to_jwt_introspection_endpoint my_good_location_name_for_curity;
    }
    
    location my_good_location_name_for_curity {
        ...
    }
}
```

### Optional Configuration Directives

The following directives are optional and do not need to be configured.

#### access_token_to_jwt_realm

> **Syntax**: **`access_token_to_jwt_realm`** _`string`_
> 
> **Default**: *`—`*
> 
> **Context**: `location`

The name of the protected realm or scope of protection that should be used when a client does not provide an access token.

Example configuration:

```nginx
location / {
   ...
   access_token_to_jwt_realm "myGoodRealm";
}   
```

#### access_token_to_jwt_scopes

> **Syntax**: **`access_token_to_jwt_scopes`** _`string`_
>
> **Default**: *`—`*
>
> **Context**: `location`

The space-separated list of scopes that the server should inform the client are required when it does not provide an access token.

Example configuration:

```nginx
location / {
   ...
   access_token_to_jwt_scopes "scope_a scope_b scope_c";
}
```

#### access_token_to_jwt_scope

> **Syntax**: **`access_token_to_jwt_scope`** _`string`_
>
> **Default**: *`—`*
>
> **Context**: `location`

An array of scopes that the server should inform the client are required when it does not provide an access token. If `access_token_to_jwt_scopes` is also configured, that value will supersede these.
 
Example configuration:
 
```nginx
location / {
   ...
   access_token_to_jwt_scope "scope_a";
   access_token_to_jwt_scope "scope_b";
   access_token_to_jwt_scope "scope_c";
}
```

## Sample Configuration

### Simple Configuration
The following is a simple configuration that might be used in demo or development environments where the NGINX reverse proxy is on the same host as the Curity Identity Server:

```nginx
server {
    location /api {
        proxy_pass         https://example.com/api;
        access_token_to_jwt_base64encoded_client_credentials "Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=";
        access_token_to_jwt_introspection_endpoint curity;
    }
    
    location curity {
        proxy_pass "https://curity.example.com/oauth/v2/introspection";
        proxy_set_header content-type "application/x-www-form-urlencoded";
    }
}
```

### Complex Configuration
The following is a more complex configuration where the NGINX reverse proxy is on a seperate host then the Curity Identity Server:

```nginx
server {
    server_name server1.example.com;n
    location /api {
        proxy_pass         https://example.com/api;
        access_token_to_jwt_base64encoded_client_credentials "Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=";
        access_token_to_jwt_introspection_endpoint curity;
        
        access_token_to_jwt_realm "myGoodAPI";
        access_token_to_jwt_scopes "scope_a scope_b scope_c";
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
```
        
### More Advanced Configuration (separate servers + cache)
This module takes advantage of NGINX built-in _proxy_cache_ directive. In order to be able to cache the requests made to the introspection endpoint, except of the `proxy_cache_path` in http context and `proxy_cache` in location context, you have to add the following 3 directives in the location context of the introspection endpoint.

- `proxy_cache_methods POST;` POST requests are not cached by default.
- `proxy_cache_key $request_body;` The key of the cache is related to the _access_token_ sent in the original request. Different requests using the same _access_token_ reach the same cache.
- `proxy_ignore_headers Set-Cookie;` NGINX will not cache the response if `Set-Cookie` header is not ignored.

```nginx
http {
    proxy_cache_path /path/to/cache/cache levels=1:2 keys_zone=my_cache:10m max_size=10g
                     inactive=60m use_temp_path=off;
    server {
        server_name server1.example.com;
        location /api {
            proxy_pass         https://example.com/api;
            access_token_to_jwt_base64encoded_client_credentials "Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=";
            access_token_to_jwt_introspection_endpoint curity;
            access_token_to_jwt_scopes "scope_a scope_b scope_c";
            access_token_to_jwt_realm "myGoodAPI";
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
```

## Installing    
Download the NGINX source code from [nginx.org](<http://nginx.org/>) and then build with this module:

        wget 'http://nginx.org/download/nginx-1.x.x.tar.gz'
        tar -xzvf nginx-1.x.x.tar.gz
        cd nginx-1.x.x/
        ./configure --add-module=/path/to/ngx_http_access_token_to_jwt_module

        make
        make install


## Testing and Compatibility
TBD

## Status
 This module is still in development. Use it at your own risk!

## More Information
For more information, please contact [Curity](http://curity.io).
Copyright (C) 2017 Curity AB. All rights reserved
