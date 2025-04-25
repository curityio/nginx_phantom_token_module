#!/usr/bin/perl

#####################################################
# Tests to ensure that header update logic is correct
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

=== TEST HEADER_1: Upstream receives browser headers correctly

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
