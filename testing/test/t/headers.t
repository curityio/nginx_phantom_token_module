#!/usr/bin/perl

#################################################################################
# Tests to ensure that header update logic is correct.
# A subrequest is a new request within the context of the main request.
# The subrequest inherits the main request's headers.
# Therefore, when introspection changes headers they must be restored afterwards.
#################################################################################

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

__DATA__

=== TEST HEADER_1: Upstream receives more than 20 browser headers correctly, to use 2 buffers

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
    add_header 'x-custom-0' $http_x_custom_0;
    add_header 'x-custom-1' $http_x_custom_1;
    add_header 'x-custom-2' $http_x_custom_2;
    add_header 'x-custom-3' $http_x_custom_3;
    add_header 'x-custom-4' $http_x_custom_4;
    add_header 'x-custom-5' $http_x_custom_5;
    add_header 'x-custom-6' $http_x_custom_6;
    add_header 'x-custom-7' $http_x_custom_7;
    add_header 'x-custom-8' $http_x_custom_8;
    add_header 'x-custom-9' $http_x_custom_9;
    return 200;
}

--- request
GET /t

--- more_headers eval
my $request_headers;
$request_headers .= "accept-language: en-GB,en-US;q=0.9,en;q=0.8\n";
$request_headers .= "authorization: Bearer $main::token\n";
$request_headers .= "cache-control: no-cache\n";
$request_headers .= "dnt: 1\n";
$request_headers .= "origin: https://random.example.com\n";
$request_headers .= "pragma: no-cache\n";
$request_headers .= "priority: u=1, i\n";
$request_headers .= "referer: https://random.example.com/\n";
$request_headers .= "sec-fetch-dest: empty\n";
$request_headers .= "sec-fetch-mode: cors\n";
$request_headers .= "sec-fetch-site: same-site\n";
$request_headers .= "user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36\n";
$request_headers .= "x-custom-0: custom header 0\n";
$request_headers .= "x-custom-1: custom header 1\n";
$request_headers .= "x-custom-2: custom header 2\n";
$request_headers .= "x-custom-3: custom header 3\n";
$request_headers .= "x-custom-4: custom header 4\n";
$request_headers .= "x-custom-5: custom header 5\n";
$request_headers .= "x-custom-6: custom header 6\n";
$request_headers .= "x-custom-7: custom header 7\n";
$request_headers .= "x-custom-8: custom header 8\n";
$request_headers .= "x-custom-9: custom header 9\n";
$request_headers;

--- error_code: 200

--- response_headers eval
my $response_headers;
$response_headers .= "accept-language: en-GB,en-US;q=0.9,en;q=0.8\n";
$response_headers .= "cache-control: no-cache\n";
$response_headers .= "dnt: 1\n";
$response_headers .= "origin: https://random.example.com\n";
$response_headers .= "pragma: no-cache\n";
$response_headers .= "priority: u=1, i\n";
$response_headers .= "referer: https://random.example.com/\n";
$response_headers .= "sec-fetch-dest: empty\n";
$response_headers .= "sec-fetch-mode: cors\n";
$response_headers .= "sec-fetch-site: same-site\n";
$response_headers .= "user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36\n";
$response_headers .= "x-custom-0: custom header 0\n";
$response_headers .= "x-custom-1: custom header 1\n";
$response_headers .= "x-custom-2: custom header 2\n";
$response_headers .= "x-custom-3: custom header 3\n";
$response_headers .= "x-custom-4: custom header 4\n";
$response_headers .= "x-custom-5: custom header 5\n";
$response_headers .= "x-custom-6: custom header 6\n";
$response_headers .= "x-custom-7: custom header 7\n";
$response_headers .= "x-custom-8: custom header 8\n";
$response_headers .= "x-custom-9: custom header 9\n";
$response_headers;

=== TEST HEADER_2: Upstream receives more than 40 browser headers correctly, to use 3 buffers

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
    add_header 'x-custom-00' $http_x_custom_00;
    add_header 'x-custom-01' $http_x_custom_01;
    add_header 'x-custom-02' $http_x_custom_02;
    add_header 'x-custom-03' $http_x_custom_03;
    add_header 'x-custom-04' $http_x_custom_04;
    add_header 'x-custom-05' $http_x_custom_05;
    add_header 'x-custom-06' $http_x_custom_06;
    add_header 'x-custom-07' $http_x_custom_07;
    add_header 'x-custom-08' $http_x_custom_08;
    add_header 'x-custom-09' $http_x_custom_09;
    add_header 'x-custom-10' $http_x_custom_10;
    add_header 'x-custom-11' $http_x_custom_11;
    add_header 'x-custom-12' $http_x_custom_12;
    add_header 'x-custom-13' $http_x_custom_13;
    add_header 'x-custom-14' $http_x_custom_14;
    add_header 'x-custom-15' $http_x_custom_15;
    add_header 'x-custom-16' $http_x_custom_16;
    add_header 'x-custom-17' $http_x_custom_17;
    add_header 'x-custom-18' $http_x_custom_18;
    add_header 'x-custom-19' $http_x_custom_19;
    add_header 'x-custom-20' $http_x_custom_20;
    add_header 'x-custom-21' $http_x_custom_21;
    add_header 'x-custom-22' $http_x_custom_22;
    add_header 'x-custom-23' $http_x_custom_23;
    add_header 'x-custom-24' $http_x_custom_24;
    add_header 'x-custom-25' $http_x_custom_25;
    add_header 'x-custom-26' $http_x_custom_26;
    add_header 'x-custom-27' $http_x_custom_27;
    add_header 'x-custom-28' $http_x_custom_28;
    add_header 'x-custom-29' $http_x_custom_29;
    return 200;
}

--- request
GET /t

--- more_headers eval
my $request_headers;
$request_headers .= "accept-language: en-GB,en-US;q=0.9,en;q=0.8\n";
$request_headers .= "authorization: Bearer $main::token\n";
$request_headers .= "cache-control: no-cache\n";
$request_headers .= "dnt: 1\n";
$request_headers .= "origin: https://random.example.com\n";
$request_headers .= "pragma: no-cache\n";
$request_headers .= "priority: u=1, i\n";
$request_headers .= "referer: https://random.example.com/\n";
$request_headers .= "sec-fetch-dest: empty\n";
$request_headers .= "sec-fetch-mode: cors\n";
$request_headers .= "sec-fetch-site: same-site\n";
$request_headers .= "user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36\n";
$request_headers .= "x-custom-00: custom header 00\n";
$request_headers .= "x-custom-01: custom header 01\n";
$request_headers .= "x-custom-02: custom header 02\n";
$request_headers .= "x-custom-03: custom header 03\n";
$request_headers .= "x-custom-04: custom header 04\n";
$request_headers .= "x-custom-05: custom header 05\n";
$request_headers .= "x-custom-06: custom header 06\n";
$request_headers .= "x-custom-07: custom header 07\n";
$request_headers .= "x-custom-08: custom header 08\n";
$request_headers .= "x-custom-09: custom header 09\n";
$request_headers .= "x-custom-10: custom header 10\n";
$request_headers .= "x-custom-11: custom header 11\n";
$request_headers .= "x-custom-12: custom header 12\n";
$request_headers .= "x-custom-13: custom header 13\n";
$request_headers .= "x-custom-14: custom header 14\n";
$request_headers .= "x-custom-15: custom header 15\n";
$request_headers .= "x-custom-16: custom header 16\n";
$request_headers .= "x-custom-17: custom header 17\n";
$request_headers .= "x-custom-18: custom header 18\n";
$request_headers .= "x-custom-19: custom header 19\n";
$request_headers .= "x-custom-20: custom header 20\n";
$request_headers .= "x-custom-21: custom header 21\n";
$request_headers .= "x-custom-22: custom header 22\n";
$request_headers .= "x-custom-23: custom header 23\n";
$request_headers .= "x-custom-24: custom header 24\n";
$request_headers .= "x-custom-25: custom header 25\n";
$request_headers .= "x-custom-26: custom header 26\n";
$request_headers .= "x-custom-27: custom header 27\n";
$request_headers .= "x-custom-28: custom header 28\n";
$request_headers .= "x-custom-29: custom header 29\n";
$request_headers;

--- error_code: 200

--- response_headers eval
my $response_headers;
$response_headers .= "accept-language: en-GB,en-US;q=0.9,en;q=0.8\n";
$response_headers .= "cache-control: no-cache\n";
$response_headers .= "dnt: 1\n";
$response_headers .= "origin: https://random.example.com\n";
$response_headers .= "pragma: no-cache\n";
$response_headers .= "priority: u=1, i\n";
$response_headers .= "referer: https://random.example.com/\n";
$response_headers .= "sec-fetch-dest: empty\n";
$response_headers .= "sec-fetch-mode: cors\n";
$response_headers .= "sec-fetch-site: same-site\n";
$response_headers .= "user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36\n";
$response_headers .= "x-custom-00: custom header 00\n";
$response_headers .= "x-custom-01: custom header 01\n";
$response_headers .= "x-custom-02: custom header 02\n";
$response_headers .= "x-custom-03: custom header 03\n";
$response_headers .= "x-custom-04: custom header 04\n";
$response_headers .= "x-custom-05: custom header 05\n";
$response_headers .= "x-custom-06: custom header 06\n";
$response_headers .= "x-custom-07: custom header 07\n";
$response_headers .= "x-custom-08: custom header 08\n";
$response_headers .= "x-custom-09: custom header 09\n";
$response_headers .= "x-custom-10: custom header 10\n";
$response_headers .= "x-custom-11: custom header 11\n";
$response_headers .= "x-custom-12: custom header 12\n";
$response_headers .= "x-custom-13: custom header 13\n";
$response_headers .= "x-custom-14: custom header 14\n";
$response_headers .= "x-custom-15: custom header 15\n";
$response_headers .= "x-custom-16: custom header 16\n";
$response_headers .= "x-custom-17: custom header 17\n";
$response_headers .= "x-custom-18: custom header 18\n";
$response_headers .= "x-custom-19: custom header 19\n";
$response_headers .= "x-custom-20: custom header 20\n";
$response_headers .= "x-custom-21: custom header 21\n";
$response_headers .= "x-custom-22: custom header 22\n";
$response_headers .= "x-custom-23: custom header 23\n";
$response_headers .= "x-custom-24: custom header 24\n";
$response_headers .= "x-custom-25: custom header 25\n";
$response_headers .= "x-custom-26: custom header 26\n";
$response_headers .= "x-custom-27: custom header 27\n";
$response_headers .= "x-custom-28: custom header 28\n";
$response_headers .= "x-custom-29: custom header 29\n";
$response_headers;

=== TEST HEADER_3: For a missing accept header the upstream receives a default value

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
    return 200;
}

--- request
GET /t

--- more_headers eval
my $request_headers;
$request_headers .= "authorization: Bearer $main::token\n";
$request_headers;

--- error_code: 200

--- response_headers
accept: */*

=== TEST HEADER_4: When the client sends an accept header the upstream receives the correct value

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
    return 200;
}

--- request
GET /t

--- more_headers eval
my $request_headers;
$request_headers .= "accept: application/json\n";
$request_headers .= "authorization: Bearer $main::token\n";
$request_headers;

--- error_code: 200

--- response_headers
accept: application/json

=== TEST HEADER_5: For a missing content-type header the upstream receives no value

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
    add_header 'content-type-received' $http_content_type;
    return 200;
}

--- request
GET /t

--- more_headers eval
my $request_headers;
$request_headers .= "authorization: Bearer $main::token\n";
$request_headers;

--- error_code: 200

--- response_headers
content-type-received:

=== TEST HEADER_6: When the client sends a content-type header the upstream receives the correct value

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
    add_header 'content-type-received' $http_content_type;
    return 200;
}

--- request
GET /t

--- more_headers eval
my $request_headers;
$request_headers .= "authorization: Bearer $main::token\n";
$request_headers .= "content-type: application/json\n";
$request_headers;

--- error_code: 200

--- response_headers
content-type-received: application/json
