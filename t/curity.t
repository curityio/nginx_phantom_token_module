#!/usr/bin/perl

use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use Test::Nginx::Socket 'no_plan';
use Idsh;

SKIP: {
    my $exit_code = 0;

    eval { 
        my $message = <<'EOF';
configure
commit

# Switch test server to HTTP
set environments environment services service TestServer1 protocol http

EOF

        $exit_code = system("echo '$message' | idsh -s");
    };

    if ($@ or $exit_code != 0) {
        skip("could not configure idsvr; server probably isn't running or idsh isn't in path");
    }
    else {
        our $token = &get_token_from_idsvr();

        if ($token) {
            run_tests();
        }
        else {
            fail("Could not get token from idsvr");
        }

        # Revert the config changes
        system("echo 'configure\nrollback 0\ncommit\n' | idsh -s");
    }
}

sub get_token_from_idsvr {
    use LWP::UserAgent;
 
    my $ua = LWP::UserAgent->new();

    my $response = $ua->post("http://localhost:8443/dev/oauth/token", { 
        "client_id" => "client-one",
        "client_secret" => "0ne!Secret",
        "grant_type" => "client_credentials"
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
    proxy_pass "http://localhost:8443/introspection";   
}

location /t {
    proxy_pass         "http://httpbin.org/get";

    phantom_token on;
    phantom_token_client_credential "test_gateway_client" "Password1";
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
    proxy_pass "http://localhost:8443/introspection";   
}

location /t {
    proxy_pass         "http://httpbin.org/get";

    phantom_token on;
    phantom_token_client_credential "test_gateway_client" "Password1";
    phantom_token_introspection_endpoint tt;    
}

--- more_headers 
Authorization: bearer zort

--- request
GET /t

--- error_code: 401

=== Test 3: The wrong kind of HTTP method is used results in an access denied error

--- config
location tt {
    proxy_pass "http://localhost:8443/introspection";   
}

location /t {
    proxy_pass         "http://httpbin.org/get";

    phantom_token on;
    phantom_token_client_credential "test_gateway_client" "Password1";
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
    proxy_pass "http://localhost:8443/introspection";   
}

location /t {
    proxy_pass         "http://httpbin.org/get";

    phantom_token on;
    phantom_token_client_credential "test_gateway_client" "Password1";
    phantom_token_introspection_endpoint tt;    
}

--- request
GET /t

--- error_code: 401

=== Test 4: A valid token with trash after results in an access denied error

--- config
location tt {
    proxy_pass "http://localhost:8443/introspection";   
}

location /t {
    proxy_pass         "http://httpbin.org/get";

    phantom_token on;
    phantom_token_client_credential "test_gateway_client" "Password1";
    phantom_token_introspection_endpoint tt;    
}

--- request
GET /t

--- more_headers eval
"Authorization: bearer " . $main::token . "z"

--- error_code: 401

=== Test 5: The bearer HTTP method can be in upper case

--- config
location tt {
    proxy_pass "http://localhost:8443/introspection";   
}

location /t {
    proxy_pass         "http://httpbin.org/get";

    phantom_token on;
    phantom_token_client_credential "test_gateway_client" "Password1";
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

=== Test 6: The bearer HTTP method can be in mixed case

--- config
location tt {
    proxy_pass "http://localhost:8443/introspection";   
}

location /t {
    proxy_pass         "http://httpbin.org/get";

    phantom_token on;
    phantom_token_client_credential "test_gateway_client" "Password1";
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

=== Test 6: The bearer HTTP method can have > 1 space before it

--- config
location tt {
    proxy_pass "http://localhost:8443/introspection";   
}

location /t {
    proxy_pass         "http://httpbin.org/get";

    phantom_token on;
    phantom_token_client_credential "test_gateway_client" "Password1";
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
