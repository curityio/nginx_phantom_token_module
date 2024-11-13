#!/usr/bin/perl

use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Nginx::Socket 'no_plan';

SKIP: {
      our $token  = &get_token_from_idsvr();
      our $token2 = &get_token2_from_idsvr();

      if ($token && $token2) {
          run_tests();
      }
      else {
          fail("Could not get tokens from idsvr");
      }
}

# Most tests use a small JWT access token
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

# The example scope instead issues a large claim so that the JWT is around 6KB
sub get_token2_from_idsvr {
    use LWP::UserAgent;
 
    my $ua = LWP::UserAgent->new();

    my $response = $ua->post("http://localhost:8443/oauth/v2/oauth-token", {
        "client_id" => "test-client",
        "client_secret" => "secret1",
        "grant_type" => "client_credentials",
        "scope" => "example"
    });
    my $content = $response->decoded_content();

    my ($result) = $content =~ /access_token":"([^"]+)/;

    return $result;
}

sub process_json_from_backend {
    return sub {
        my ($response) = @_;
        
        if ($response =~ /Authorization": "[Bb]earer ey/) {
            return "GOOD"; # A JWT (which starts with "ey") was forwarded to the back-end
        }
        else {
            return $response;
        }
    }
}

__DATA__

=== TEST 1: A REF token can be introspected for a phantom token

--- config
location tt {
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    proxy_pass         "http://localhost:8080/anything";

    phantom_token on;
    phantom_token_client_credential "test-nginx" "secret2";
    phantom_token_introspection_endpoint tt;
}

--- error_code: 200

--- request
GET /t

--- more_headers eval
"Authorization: bearer " . $main::token

--- response_body_filters eval
main::process_json_from_backend()

--- response_body: GOOD

=== Test 2: An unknown token results in an access denied error

--- config
location tt {
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    proxy_pass         "http://localhost:8080/anything";

    phantom_token on;
    phantom_token_client_credential "test-nginx" "secret2";
    phantom_token_introspection_endpoint tt;    
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

=== Test 3: The wrong kind of HTTP method is used results in an access denied error

--- config
location tt {
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    proxy_pass         "http://localhost:8080/anything";

    phantom_token on;
    phantom_token_client_credential "test-nginx" "secret2";
    phantom_token_introspection_endpoint tt;    
}

--- more_headers 
Authorization: basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==

--- request
GET /t

--- error_code: 401

=== Test 4: A request with no authorization request header results in an access denied error

--- config
location tt {
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    proxy_pass         "http://localhost:8080/anything";

    phantom_token on;
    phantom_token_client_credential "test-nginx" "secret2";
    phantom_token_introspection_endpoint tt;    
}

--- request
GET /t

--- error_code: 401

--- response_headers
content-type: application/json
WWW-Authenticate: Bearer realm="api"

--- response_body_like chomp
{"code":"unauthorized_request","message":"Access denied due to missing, invalid or expired credentials"}

=== Test 5: A valid token with trash after results in an access denied error

--- config
location tt {
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    proxy_pass         "http://localhost:8080/anything";

    phantom_token on;
    phantom_token_client_credential "test-nginx" "secret2";
    phantom_token_introspection_endpoint tt;    
}

--- request
GET /t

--- more_headers eval
"Authorization: bearer " . $main::token . "z"

--- error_code: 401

--- response_headers
content-type: application/json
WWW-Authenticate: Bearer realm="api"

=== Test 6: The bearer HTTP method can be in upper case

--- config
location tt {
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    proxy_pass         "http://localhost:8080/anything";

    phantom_token on;
    phantom_token_client_credential "test-nginx" "secret2";
    phantom_token_introspection_endpoint tt;    
}

--- error_code: 200

--- request
GET /t

--- more_headers eval
"Authorization: BEARER " . $main::token

--- response_body_filters eval
main::process_json_from_backend()

--- response_body: GOOD

=== Test 7: The bearer HTTP method can be in mixed case

--- config
location tt {
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    proxy_pass         "http://localhost:8080/anything";

    phantom_token on;
    phantom_token_client_credential "test-nginx" "secret2";
    phantom_token_introspection_endpoint tt;    
}

--- error_code: 200

--- request
GET /t

--- more_headers eval
"Authorization: bEaReR " . $main::token

--- response_body_filters eval
main::process_json_from_backend()

--- response_body: GOOD

=== Test 8: The bearer HTTP method can have > 1 space before it

--- config
location tt {
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    proxy_pass         "http://localhost:8080/anything";

    phantom_token on;
    phantom_token_client_credential "test-nginx" "secret2";
    phantom_token_introspection_endpoint tt;    
}

--- error_code: 200

--- request
GET /t

--- more_headers eval
"Authorization: bearer               " . $main::token

--- response_body_filters eval
main::process_json_from_backend()

--- response_body: GOOD

=== Test 9: A misconfigured client secret results in a 502 error

--- config
location tt {
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    proxy_pass         "http://localhost:8080/anything";

    phantom_token on;
    phantom_token_client_credential "test-nginx" "incorrect_secret";
    phantom_token_introspection_endpoint tt;
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

=== Test 10: An unreachable authorization server results in a 502 error

--- config
location tt {
    proxy_pass "http://localhost:9443/oauth/v2/oauth-introspect";
}

location /t {
    proxy_pass         "http://localhost:8080/anything";

    phantom_token on;
    phantom_token_client_credential "test-nginx" "secret2";
    phantom_token_introspection_endpoint tt;
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

=== TEST 11: A large JWT can be processed with the correct proxy buffer configuration

--- config
location tt {
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
    proxy_buffer_size 16k;
    proxy_buffers 4 16k;
}

location /t {
    proxy_pass         "http://localhost:8080/anything";

    phantom_token on;
    phantom_token_client_credential "test-nginx" "secret2";
    phantom_token_introspection_endpoint tt;
}

--- error_code: 200

--- request
GET /t

--- more_headers eval
"Authorization: bearer " . $main::token2

--- response_body_filters eval
main::process_json_from_backend()

--- response_body: GOOD

=== TEST 12: A large JWT cannot cause an end of buffer read and returns an error instead

--- config
location tt {
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    proxy_pass         "http://localhost:8080/anything";

    phantom_token on;
    phantom_token_client_credential "test-nginx" "secret2";
    phantom_token_introspection_endpoint tt;
}

--- error_code: 502

--- request
GET /t

--- more_headers eval
"Authorization: bearer " . $main::token2

--- response_headers
content-type: application/json

--- response_body_like chomp
{"code":"server_error","message":"Problem encountered processing the request"}
