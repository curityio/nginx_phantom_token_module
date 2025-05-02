# Breaking Changes

## Version 2.0

In version 1.x we dynamically added the Accept and Content-Type headers for the introspection subrequest in code.\

```nginx
location curity {
    proxy_pass "https://login.example.com/oauth/v2/oauth-introspect";
}
```

However, doing so [adds complexity](https://mailman.nginx.org/pipermail/nginx-devel/2020-November/013659.html) that could affect headers received by upstream APIs.\
To fix an issue for version 2.0 we therefore made a breaking change that simplifies code and improves stability.\
Starting in version 2.0 you must now configure the fixed headers used by the introspection request:

```nginx
location curity {
    proxy_pass "https://login.example.com/oauth/v2/oauth-introspect";
    proxy_set_header Accept "application/jwt";
    proxy_set_header Content-Type "application/x-www-form-urlencoded";
}
```
