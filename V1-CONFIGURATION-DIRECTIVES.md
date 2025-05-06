## Version 1 Configuration Directives

If you use a release before 2.0, use the following older configuration directives.

### Required Configuration Directives

All the directives in this subsection are required; if any of these are omitted, the module will be disabled.

#### phantom_token

> **Syntax**: **`phantom_token`** `on` | `off`
>
> **Default**: *`off`*
>
> **Context**: `location`

#### phantom_token_client_credential

> **Syntax**: **`phantom_token_client_credential`** _`string`_ _`string`_ 
> 
> **Default**: *`—`*                                                                
> 
> **Context**: `location`                                                           
 
The client ID and secret of the OAuth client which will be used for introspection. The first argument to this directive is the client ID and the second is the secret. The maximum total length of the two arguments must be less than 255 characters. Both should be printable ASCII values; non-ASCII values _may_ work but are untested. If this directive is not configured, then the module will be disabled.

#### phantom_token_introspection_endpoint

> **Syntax**: **`phantom_token_introspection_endpoint`** _`string`_
>
> **Default**: *`—`*
>
> **Context**: `location`

The name of the location that proxies requests to the Curity Identity Server. Note that this location needs to be in the same server as the one referring to it using this directive.

Example configuration:

```nginx
server {
    location /api {
        ...
        phantom_token_introspection_endpoint my_good_location_name_for_curity;
    }
    
    location my_good_location_name_for_curity {
        ...
    }
}
```

### Optional Configuration Directives

The following directives are optional and do not need to be configured.

#### phantom_token_realm

> **Syntax**: **`phantom_token_realm`** _`string`_
> 
> **Default**: *`api`*
> 
> **Context**: `location`

The name of the protected realm or scope of protection that should be used when a client does not provide an access token.

Example configuration:

```nginx
location / {
   ...
   phantom_token_realm "myGoodRealm";
}   
```

#### phantom_token_scopes

> **Syntax**: **`phantom_token_scopes`** _`string`_
>
> **Default**: *`—`*
>
> **Context**: `location`

The space-separated list of scopes that the server should inform the client are required when it does not provide an access token.

Example configuration:

```nginx
location / {
   ...
   phantom_token_scopes "scope_a scope_b scope_c";
}
```

#### phantom_token_scope

> **Syntax**: **`phantom_token_scope`** _`string`_
>
> **Default**: *`—`*
>
> **Context**: `location`

An array of scopes that the server should inform the client are required when it does not provide an access token. If `phantom_token_scopes` is also configured, that value will supersede these.
 
Example configuration:
 
```nginx
location / {
   ...
   phantom_token_scope "scope_a";
   phantom_token_scope "scope_b";
   phantom_token_scope "scope_c";
}
```

## Sample Configuration

### Versions

If you use version 2.0+ of the module you must include the Accept and Content-Type headers as shown here.\
If you use version 1.x of the module you must omit the Accept and Content-Type headers from the configuration.

```nginx
location curity {
    proxy_pass "https://login.example.com/oauth/v2/oauth-introspect";
    proxy_set_header Accept "application/jwt";
    proxy_set_header Content-Type "application/x-www-form-urlencoded";
}
```

### Loading the Module

If the module is downloaded from GitHub or compiled as a shared library (the default) and not explicitly compiled into NGINX, it will need to be loaded using the [load_module](http://nginx.org/en/docs/ngx_core_module.html#load_module) directive. This needs to be done in the _main_ part of the NGINX configuration:

```nginx
load_module modules/ngx_curity_http_phantom_token_module.so;
```

The file can be an absolute or relative path. If it is not absolute, it should be relative to the NGINX root directory.

### Simple Configuration

The following is a simple configuration that might be used in demo or development environments where the NGINX reverse proxy is on the same host as the Curity Identity Server:

```nginx
server {
    location /api {
        proxy_pass         https://example.com/api;

        phantom_token on;
        phantom_token_client_credential "client_id" "client_secret";
        phantom_token_introspection_endpoint curity;
    }
    
    location curity {
        proxy_pass "https://curity.example.com/oauth/v2/introspection";
    }
}
```

### Complex Configuration

The following is a more complex configuration where the NGINX reverse proxy is on a separate host to the Curity Identity Server:

```nginx
server {
    server_name server1.example.com;n
    location /api {
        proxy_pass         https://example.com/api;

        phantom_token on;
        phantom_token_client_credential "client_id" "client_secret";
        phantom_token_introspection_endpoint curity;
        
        phantom_token_realm "myGoodAPI";
        phantom_token_scopes "scope_a scope_b scope_c";
    }
    
    location curity {
        proxy_pass "https://server2.example.com:8443/oauth/v2/introspection";
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
        
### More Advanced Configuration with Separate Servers and Caching

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

            phantom_token on;
            phantom_token_introspection_endpoint curity;
            phantom_token_scopes "scope_a scope_b scope_c";
            phantom_token_realm "myGoodAPI";
        }
        
        location curity {
            proxy_pass "https://server2.example.com:8443/oauth/v2/introspection";
            
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

## Cacheless Configuration

It is recommended to cache the results of the call to the Curity Identity Server so that you avoid triggering an introspection request for every API request. If you wish to disable caching you should extend the default [proxy_buffer_size](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#directives) to ensure that the module can read large JWTs. Do so by updating the configuration of the introspection request as in the following example.

```nginx
http {
    server {
        server_name server1.example.com;
        location /api {
            proxy_pass         https://example.com/api;

            phantom_token on;
            phantom_token_client_credential "client_id" "client_secret";
            phantom_token_introspection_endpoint curity;
            phantom_token_scopes "scope_a scope_b scope_c";
            phantom_token_realm "myGoodAPI";
        }
        
        location curity {
            proxy_pass "https://server2.example.com:8443/oauth/v2/introspection";
            proxy_ignore_headers Set-Cookie;
            proxy_buffer_size 16k;
            proxy_buffers 4 16k;
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
