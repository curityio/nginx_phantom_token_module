#!/usr/bin/perl

#####################################################
# Tests to ensure that large requests works correctly
#####################################################

use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Nginx::Socket 'no_plan';

SKIP: {
      our $token = &get_token_from_idsvr();

      if ($token) {
          run_tests();
      }
      else {
          fail("Could not get tokens from idsvr");
      }
}

#
# Get an opaque access token with a scope that produces a large JWT of around 6KB
#
sub get_token_from_idsvr {
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

#
# Read the JWT access token from the introspection response
#
sub process_json_from_backend {
    return sub {
        my ($response) = @_;
        
        # Uncomment to see the introspection response data
        #print("$response\n");

        if ($response =~ /Authorization": "[Bb]earer ey/) {
            return "GOOD"; # A JWT (which starts with "ey") was forwarded to the back-end
        }
        else {
            return $response;
        }
    }
}

__DATA__

=== TEST L1: A large JWT can be processed with the correct proxy buffer configuration

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
"Authorization: bearer " . $main::token

--- response_body_filters eval
main::process_json_from_backend()

--- response_body: GOOD

=== TEST L2: A large JWT cannot cause an end of buffer read and returns an error instead

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
"Authorization: bearer " . $main::token

--- response_headers
content-type: application/json

--- response_body_like chomp
{"code":"server_error","message":"Problem encountered processing the request"}

=== TEST L3: Upstream receives a large JWT and many custom headers correctly

--- config
location tt {
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
    proxy_buffer_size 16k;
    proxy_buffers 4 16k;
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
    add_header 'x-fixture-a' $http_x_fixture_a;
    add_header 'x-fixture-b' $http_x_fixture_b;
    add_header 'x-fixture-c' $http_x_fixture_c;
    add_header 'x-fixture-d' $http_x_fixture_d;
    add_header 'x-fixture-e' $http_x_fixture_e;
    add_header 'x-fixture-f' $http_x_fixture_f;
    add_header 'x-fixture-g' $http_x_fixture_g;
    return 200;
}

--- error_code: 200

--- request
GET /t

--- more_headers eval
my $data;
$data .= "accept: */*\n";
$data .= "accept-language: en-GB,en-US;q=0.9,en;q=0.8\n";
$data .= "authorization: Bearer $main::token\n";
$data .= "cache-control: no-cache\n";
$data .= "dnt: 1\n";
$data .= "origin: https://random.example.com\n";
$data .= "pragma: no-cache\n";
$data .= "priority: u=1, i\n";
$data .= "referer: https://random.example.com/\n";
$data .= "sec-fetch-dest: empty\n";
$data .= "sec-fetch-mode: cors\n";
$data .= "sec-fetch-site: same-site\n";
$data .= "user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36\n";
$data .= "x-fixture-a: a\n";
$data .= "x-fixture-b: b\n";
$data .= "x-fixture-c: c\n";
$data .= "x-fixture-d: d\n";
$data .= "x-fixture-e: e\n";
$data .= "x-fixture-f: f\n";
$data .= "x-fixture-g: g\n";
$data;

--- response_headers
accept: */*
accept-language: en-GB,en-US;q=0.9,en;q=0.8
cache-control: no-cache
dnt: 1
origin: https://random.example.com
pragma: no-cache
priority: u=1, i
referer: https://random.example.com/
sec-fetch-dest: empty
sec-fetch-mode: cors
sec-fetch-site: same-site
user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
x-fixture-a: a
x-fixture-b: b
x-fixture-c: c
x-fixture-d: d
x-fixture-e: e
x-fixture-f: f
x-fixture-g: g
