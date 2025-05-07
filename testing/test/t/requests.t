#!/usr/bin/perl

#####################################################
# Tests to ensure that basic request logic is correct
#####################################################

use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Nginx::Socket 'no_plan';

SKIP: {
      our $token  = &get_token_from_idsvr();

      if ($token) {
          run_tests();
      }
      else {
          fail("Could not get tokens from idsvr");
      }
}

#
# Get an opaque access token
#
sub get_token_from_idsvr {
    use LWP::UserAgent;
 
    my $ua = LWP::UserAgent->new();

    my $response = $ua->post("http://localhost:8443/oauth/v2/oauth-token", {
        "client_id" => "test-client",
        "client_secret" => "secret1",
        "grant_type" => "client_credentials"
    });
    my $content = $response->decoded_content();

    my ($result) = $content =~ /access_token":"([^"]+)/;

    return $result;
}

#
# Read the JWT access token from the introspection response
#
sub process_json_from_backend {
    return sub {
        my ($response) = @_;
        
        # Uncomment to see the introspection response data
        # print("$response\n");

        if ($response =~ /Authorization": "[Bb]earer ey/) {
            return "GOOD"; # A JWT (which starts with "ey") was forwarded to the back-end
        }
        else {
            return $response;
        }
    }
}

__DATA__

=== TEST REQUEST_1: A REF token can be introspected for a phantom token

--- config
location tt {
    internal;
    proxy_pass_request_headers off;
    proxy_set_header Accept "application/jwt";
    proxy_set_header Content-Type "application/x-www-form-urlencoded";
    proxy_set_header Authorization "Basic dGVzdC1uZ2lueDpzZWNyZXQy"; # test-nginx:secret2"
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    phantom_token on;
    phantom_token_introspection_endpoint tt;
    proxy_pass "http://localhost:8080/anything";
}

--- error_code: 200

--- request
GET /t

--- more_headers eval
"Authorization: bearer " . $main::token

--- response_body_filters eval
main::process_json_from_backend()

--- response_body: GOOD

=== Test REQUEST_2: An invalid or expired token results in an access denied error

--- config
location tt {
    internal;
    proxy_pass_request_headers off;
    proxy_set_header Accept "application/jwt";
    proxy_set_header Content-Type "application/x-www-form-urlencoded";
    proxy_set_header Authorization "Basic dGVzdC1uZ2lueDpzZWNyZXQy"; # test-nginx:secret2"
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    phantom_token on;
    phantom_token_introspection_endpoint tt;
    proxy_pass "http://localhost:8080/anything";
}

--- more_headers 
Authorization: bearer zort

--- request
GET /t

--- error_code: 401

--- response_headers
content-type: application/json
WWW-Authenticate: Bearer realm="api"

--- response_body_like chomp
{"code":"unauthorized_request","message":"Access denied due to missing, invalid or expired credentials"}

=== Test REQUEST_3: The wrong kind of HTTP authorization method is used results in an access denied error

--- config
location tt {
    internal;
    proxy_pass_request_headers off;
    proxy_set_header Accept "application/jwt";
    proxy_set_header Content-Type "application/x-www-form-urlencoded";
    proxy_set_header Authorization "Basic dGVzdC1uZ2lueDpzZWNyZXQy"; # test-nginx:secret2"
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    phantom_token on;
    phantom_token_introspection_endpoint tt;
    proxy_pass "http://localhost:8080/anything";
}

--- more_headers 
Authorization: basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==

--- request
GET /t

--- error_code: 401

--- error_log
Authorization header does not contain a bearer token

=== Test REQUEST_4: A request with no authorization request header results in an access denied error

--- config
location tt {
    internal;
    proxy_pass_request_headers off;
    proxy_set_header Accept "application/jwt";
    proxy_set_header Content-Type "application/x-www-form-urlencoded";
    proxy_set_header Authorization "Basic dGVzdC1uZ2lueDpzZWNyZXQy"; # test-nginx:secret2"
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    phantom_token on;
    phantom_token_introspection_endpoint tt;
    proxy_pass "http://localhost:8080/anything";
}

--- request
GET /t

--- error_code: 401

--- response_headers
content-type: application/json
WWW-Authenticate: Bearer realm="api"

--- response_body_like chomp
{"code":"unauthorized_request","message":"Access denied due to missing, invalid or expired credentials"}

--- error_log
Authorization header not present

=== Test REQUEST_5: A valid token with trash after results in an access denied error

--- config
location tt {
    internal;
    proxy_pass_request_headers off;
    proxy_set_header Accept "application/jwt";
    proxy_set_header Content-Type "application/x-www-form-urlencoded";
    proxy_set_header Authorization "Basic dGVzdC1uZ2lueDpzZWNyZXQy"; # test-nginx:secret2"
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    phantom_token on;
    phantom_token_introspection_endpoint tt;
    proxy_pass "http://localhost:8080/anything";
}

--- request
GET /t

--- more_headers eval
"Authorization: bearer " . $main::token . "z"

--- error_code: 401

--- response_headers
content-type: application/json
WWW-Authenticate: Bearer realm="api"

=== Test REQUEST_6: The bearer HTTP method can be in upper case

--- config
location tt {
    internal;
    proxy_pass_request_headers off;
    proxy_set_header Accept "application/jwt";
    proxy_set_header Content-Type "application/x-www-form-urlencoded";
    proxy_set_header Authorization "Basic dGVzdC1uZ2lueDpzZWNyZXQy"; # test-nginx:secret2"
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    phantom_token on;
    phantom_token_introspection_endpoint tt;
    proxy_pass "http://localhost:8080/anything";
}

--- error_code: 200

--- request
GET /t

--- more_headers eval
"Authorization: BEARER " . $main::token

--- response_body_filters eval
main::process_json_from_backend()

--- response_body: GOOD

=== Test REQUEST_7: The bearer HTTP method can be in mixed case

--- config
location tt {
    internal;
    proxy_pass_request_headers off;
    proxy_set_header Accept "application/jwt";
    proxy_set_header Content-Type "application/x-www-form-urlencoded";
    proxy_set_header Authorization "Basic dGVzdC1uZ2lueDpzZWNyZXQy"; # test-nginx:secret2"
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    phantom_token on;
    phantom_token_introspection_endpoint tt;    
    proxy_pass "http://localhost:8080/anything";
}

--- error_code: 200

--- request
GET /t

--- more_headers eval
"Authorization: bEaReR " . $main::token

--- response_body_filters eval
main::process_json_from_backend()

--- response_body: GOOD

=== Test REQUEST_8: The bearer HTTP method can have > 1 space before it

--- config
location tt {
    internal;
    proxy_pass_request_headers off;
    proxy_set_header Accept "application/jwt";
    proxy_set_header Content-Type "application/x-www-form-urlencoded";
    proxy_set_header Authorization "Basic dGVzdC1uZ2lueDpzZWNyZXQy"; # test-nginx:secret2"
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    phantom_token on;
    phantom_token_introspection_endpoint tt;    
    proxy_pass "http://localhost:8080/anything";
}

--- error_code: 200

--- request
GET /t

--- more_headers eval
"Authorization: bearer               " . $main::token

--- response_body_filters eval
main::process_json_from_backend()

--- response_body: GOOD

=== Test REQUEST_9: A misconfigured client secret results in a 502 error

--- config
location tt {
    internal;
    proxy_pass_request_headers off;
    proxy_set_header Accept "application/jwt";
    proxy_set_header Content-Type "application/x-www-form-urlencoded";
    proxy_set_header Authorization "Basic dGVzdC1uZ2lueDpzZWNyZXQz"; # test-nginx:secret3"
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    phantom_token on;
    phantom_token_introspection_endpoint tt;
    proxy_pass "http://localhost:8080/anything";
}

--- error_code: 502

--- request
GET /t

--- more_headers eval
"Authorization: bearer               " . $main::token

--- response_headers
content-type: application/json

--- response_body_like chomp
{"code":"server_error","message":"Problem encountered processing the request"}

--- error_log
Introspection subrequest returned response code: 401

=== Test REQUEST_10: An unreachable authorization server results in a 502 error

--- config
location tt {
    internal;
    proxy_pass_request_headers off;
    proxy_set_header Accept "application/jwt";
    proxy_set_header Content-Type "application/x-www-form-urlencoded";
    proxy_set_header Authorization "Basic dGVzdC1uZ2lueDpzZWNyZXQy"; # test-nginx:secret2"
    proxy_pass "http://localhost:9443/oauth/v2/oauth-introspect";
}

location /t {
    phantom_token on;
    phantom_token_introspection_endpoint tt;
    proxy_pass "http://localhost:8080/anything";
}

--- error_code: 502

--- request
GET /t

--- more_headers eval
"Authorization: bearer               " . $main::token

--- response_headers
content-type: application/json

--- response_body_like chomp
{"code":"server_error","message":"Problem encountered processing the request"}

--- error_log
Introspection subrequest returned response code: 502
