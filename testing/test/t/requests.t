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

=== Test REQUEST_2: An unknown token results in an access denied error

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

=== Test REQUEST_3: The wrong kind of HTTP method is used results in an access denied error

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

=== Test REQUEST_4: A request with no authorization request header results in an access denied error

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

=== Test REQUEST_5: A valid token with trash after results in an access denied error

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

=== Test REQUEST_6: The bearer HTTP method can be in upper case

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

=== Test REQUEST_7: The bearer HTTP method can be in mixed case

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

=== Test REQUEST_8: The bearer HTTP method can have > 1 space before it

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

=== Test REQUEST_9: A misconfigured client secret results in a 502 error

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

=== Test REQUEST_10: An unreachable authorization server results in a 502 error

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

=== TEST REQUEST_11: Upstream receives browser headers correctly

--- config
location tt {
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    proxy_pass http://localhost:1984/target;

    phantom_token on;
    phantom_token_client_credential "test-nginx" "secret2";
    phantom_token_introspection_endpoint tt;
}

location /target {
    add_header 'accept' $http_accept;
    add_header 'accept-language' $http_accept_language;
    add_header 'cache-control' $http_cache_control;
    add_header 'dnt' $http_dnt;
    add_header 'origin' $http_origin;
    add_header 'pragma' $http_pragma;
    add_header 'priority' $http_priority;
    add_header 'referer' $http_referer;
    add_header 'sec-fetch-dest' $http_sec_fetch_dest;
    add_header 'sec-fetch-mode' $http_sec_fetch_mode;
    add_header 'sec-fetch-site' $http_sec_fetch_site;
    add_header 'user-agent' $http_user_agent;
    add_header 'x-custom-1' $http_x_custom_1;
    add_header 'x-custom-2' $http_x_custom_2;
    return 200;
}

--- error_code: 200

--- request
GET /t

--- more_headers eval
my $request;
$request .= "accept: */*\n";
$request .= "accept-language: en-GB,en-US;q=0.9,en;q=0.8\n";
$request .= "authorization: Bearer $main::token\n";
$request .= "cache-control: no-cache\n";
$request .= "dnt: 1\n";
$request .= "origin: https://random.example.com\n";
$request .= "pragma: no-cache\n";
$request .= "priority: u=1, i\n";
$request .= "referer: https://random.example.com/\n";
$request .= "sec-fetch-dest: empty\n";
$request .= "sec-fetch-mode: cors\n";
$request .= "sec-fetch-site: same-site\n";
$request .= "user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36\n";
$request .= "x-custom-1: custom header 1\n";
$request .= "x-custom-2: custom header 2\n";
$request;

--- response_headers eval
my $response;
$response .= "accept: */*\n";
$response .= "accept-language: en-GB,en-US;q=0.9,en;q=0.8\n";
$response .= "cache-control: no-cache\n";
$response .= "dnt: 1\n";
$response .= "origin: https://random.example.com\n";
$response .= "pragma: no-cache\n";
$response .= "priority: u=1, i\n";
$response .= "referer: https://random.example.com/\n";
$response .= "sec-fetch-dest: empty\n";
$response .= "sec-fetch-mode: cors\n";
$response .= "sec-fetch-site: same-site\n";
$response .= "user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36\n";
$response .= "x-custom-1: custom header 1\n";
$response .= "x-custom-2: custom header 2\n";
$response;
