#!/usr/bin/perl

use FindBin;
use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: Client ID configured without secret fails

--- config
location = /t {
    phantom_token on;
    phantom_token_client_credential "client_id"; # Missing secret as 2nd arg
}

--- must_die

--- error_log
invalid number of arguments in "phantom_token_client_credential" directive

=== TEST 2: All required settings are configured correctly

--- config
location tt {

}

location /t {
    phantom_token off;
    phantom_token_client_credential "client_id" "some_secret";
    phantom_token_introspection_endpoint tt;
}

--- request
GET /

=== TEST 3: Curity endpoint not configured fails

--- config

location /t {
    phantom_token on;
    phantom_token_client_credential "client_id" "some_secret";
}

--- request
GET /t

--- ignore_response

--- error_log
Module not configured properly: missing introspection endpoint

=== TEST 4: Curity endpoint not configured doesn't fail when module is disabled

--- config

location /t {
    phantom_token off;
    phantom_token_client_credential "client_id" "some_secret";
}

--- request
GET /t

--- ignore_response

--- no_error_log
Module not configured properly: missing introspection endpoint

=== TEST 5: Module can be disabled at the HTTP level

--- http_config

phantom_token off;

--- config

--- request
GET /t

--- ignore_response

--- error_log
Module disabled

--- skip_eval: 1: open(FH, "<", "$FindBin::Bin/../.build.info"); my $skip=0; while (<FH>) { $skip = 1 if ($_ =~ /DEBUG=n/) } $skip

=== TEST 6: HTTP level config is overridden by location directive

--- http_config

phantom_token off;

--- config

location tt {

}

location /t {
    phantom_token on;
    phantom_token_client_credential "client_id" "some_secret";
    phantom_token_introspection_endpoint tt;
}

--- request
GET /t

--- error_code: 401

--- no_error_log
Module disabled

