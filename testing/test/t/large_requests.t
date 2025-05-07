#!/usr/bin/perl

####################################################
# Tests to ensure that large requests work correctly
####################################################

use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Nginx::Socket 'no_plan';

SKIP: {
      our $token = &get_token_from_idsvr();
      our $long_header_value = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

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

=== TEST LARGE_DATA_1: A large JWT can be processed with the correct proxy buffer configuration

--- config
location tt {
    internal;
    proxy_pass_request_headers off;
    proxy_set_header Accept "application/jwt";
    proxy_set_header Content-Type "application/x-www-form-urlencoded";
    proxy_set_header Authorization "Basic dGVzdC1uZ2lueDpzZWNyZXQy"; # test-nginx:secret2"
    proxy_buffer_size 16k;
    proxy_buffers 4 16k;
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
"Authorization: bearer " . $main::token

--- error_code: 200

--- response_body_filters eval
main::process_json_from_backend()

--- response_body: GOOD

=== TEST LARGE_DATA_2: A large JWT cannot cause an end of buffer read and returns an error instead

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

--- error_code: 502

--- request
GET /t

--- more_headers eval
"Authorization: bearer " . $main::token

--- response_headers
content-type: application/json

--- response_body_like chomp
{"code":"server_error","message":"Problem encountered processing the request"}

--- error_log
The introspection response buffer is too small to contain the JWT: increase the proxy_buffer_size configuration setting

=== TEST LARGE_DATA_3: Upstream receives a large JWT and many custom headers correctly

--- config
location tt {
    internal;
    proxy_pass_request_headers off;
    proxy_set_header Accept "application/jwt";
    proxy_set_header Content-Type "application/x-www-form-urlencoded";
    proxy_set_header Authorization "Basic dGVzdC1uZ2lueDpzZWNyZXQy"; # test-nginx:secret2"
    proxy_buffer_size 16k;
    proxy_buffers 4 16k;
    proxy_pass "http://localhost:8443/oauth/v2/oauth-introspect";
}

location /t {
    proxy_buffer_size 16k;
    proxy_buffers 4 16k;
    phantom_token on;
    phantom_token_introspection_endpoint tt;
    proxy_pass http://localhost:1984/target;
}

location /target {

    add_header 'accept' $http_accept;
    add_header 'accept-language' $http_accept_language;
    add_header 'cache-control' $http_cache_control;
    add_header 'content-type-received' $http_content_type;
    add_header 'dnt' $http_dnt;
    add_header 'origin' $http_origin;
    add_header 'pragma' $http_pragma;
    add_header 'priority' $http_priority;
    add_header 'referer' $http_referer;
    add_header 'sec-fetch-dest' $http_sec_fetch_dest;
    add_header 'sec-fetch-mode' $http_sec_fetch_mode;
    add_header 'sec-fetch-site' $http_sec_fetch_site;
    add_header 'user-agent' $http_user_agent;
    add_header 'x-fixture-0' $http_x_fixture_0;
    add_header 'x-fixture-1' $http_x_fixture_1;
    add_header 'x-fixture-2' $http_x_fixture_2;
    add_header 'x-fixture-3' $http_x_fixture_3;
    add_header 'x-fixture-4' $http_x_fixture_4;
    add_header 'x-fixture-5' $http_x_fixture_5;
    add_header 'x-fixture-6' $http_x_fixture_6;
    add_header 'x-fixture-7' $http_x_fixture_7;
    add_header 'x-fixture-8' $http_x_fixture_8;
    add_header 'x-fixture-9' $http_x_fixture_9;
    return 200;
}

--- error_code: 200

--- request
GET /t

--- more_headers eval
my $request_headers;
$request_headers .= "x-fixture-0: 0$main::long_header_value\n";
$request_headers .= "x-fixture-1: 1$main::long_header_value\n";
$request_headers .= "x-fixture-2: 2$main::long_header_value\n";
$request_headers .= "x-fixture-3: 3$main::long_header_value\n";
$request_headers .= "x-fixture-4: 4$main::long_header_value\n";
$request_headers .= "accept: application/json\n";
$request_headers .= "accept-language: en-GB,en-US;q=0.9,en;q=0.8\n";
$request_headers .= "authorization: Bearer $main::token\n";
$request_headers .= "cache-control: no-cache\n";
$request_headers .= "content-type: application/json\n";
$request_headers .= "dnt: 1\n";
$request_headers .= "origin: https://random.example.com\n";
$request_headers .= "pragma: no-cache\n";
$request_headers .= "priority: u=1, i\n";
$request_headers .= "referer: https://random.example.com/\n";
$request_headers .= "sec-fetch-dest: empty\n";
$request_headers .= "sec-fetch-mode: cors\n";
$request_headers .= "sec-fetch-site: same-site\n";
$request_headers .= "user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36\n";
$request_headers .= "x-fixture-5: 5$main::long_header_value\n";
$request_headers .= "x-fixture-6: 6$main::long_header_value\n";
$request_headers .= "x-fixture-7: 7$main::long_header_value\n";
$request_headers .= "x-fixture-8: 8$main::long_header_value\n";
$request_headers .= "x-fixture-9: 9$main::long_header_value\n";
$request_headers;

--- response_headers eval
my $response_headers;
$response_headers .= "x-fixture-0: 0$main::long_header_value\n";
$response_headers .= "x-fixture-1: 1$main::long_header_value\n";
$response_headers .= "x-fixture-2: 2$main::long_header_value\n";
$response_headers .= "x-fixture-3: 3$main::long_header_value\n";
$response_headers .= "x-fixture-4: 4$main::long_header_value\n";
$response_headers .= "accept: application/json\n";
$response_headers .= "accept-language: en-GB,en-US;q=0.9,en;q=0.8\n";
$response_headers .= "cache-control: no-cache\n";
$response_headers .= "content-type-received: application/json\n";
$response_headers .= "dnt: 1\n";
$response_headers .= "origin: https://random.example.com\n";
$response_headers .= "pragma: no-cache\n";
$response_headers .= "priority: u=1, i\n";
$response_headers .= "referer: https://random.example.com/\n";
$response_headers .= "sec-fetch-dest: empty\n";
$response_headers .= "sec-fetch-mode: cors\n";
$response_headers .= "sec-fetch-site: same-site\n";
$response_headers .= "user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36\n";
$response_headers .= "x-fixture-5: 5$main::long_header_value\n";
$response_headers .= "x-fixture-6: 6$main::long_header_value\n";
$response_headers .= "x-fixture-7: 7$main::long_header_value\n";
$response_headers .= "x-fixture-8: 8$main::long_header_value\n";
$response_headers .= "x-fixture-9: 9$main::long_header_value\n";
$response_headers;
