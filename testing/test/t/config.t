#!/usr/bin/perl

####################################################
# Tests to ensure that configuration works correctly
####################################################

use FindBin;
use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST CONFIG_1: Introspection endpoint not configured fails

--- config

location /t {
    phantom_token on;
}

--- request
GET /t

--- ignore_response

--- error_log
Module not configured properly: missing introspection endpoint

=== TEST CONFIG_2: Introspection endpoint not configured doesn't fail when module is disabled

--- config

location /t {
    phantom_token off;
}

--- request
GET /t

--- ignore_response

--- no_error_log
Module not configured properly: missing introspection endpoint

=== TEST CONFIG_3: Module can be disabled at the HTTP level

--- http_config

phantom_token off;

--- config

--- request
GET /t

--- ignore_response

--- error_log
Module disabled

--- skip_eval: 1: open(FH, "<", "$FindBin::Bin/../.build.info"); my $skip=0; while (<FH>) { $skip = 1 if ($_ =~ /DEBUG=n/) } $skip

=== TEST CONFIG_4: HTTP level config is overridden by location directive

--- http_config

phantom_token off;

--- config

location tt {

}

location /t {
    phantom_token on;
    phantom_token_introspection_endpoint tt;
}

--- request
GET /t

--- error_code: 401

--- no_error_log
Module disabled
