#ifndef PHANTOM_TOKEN_UTILS
#define PHANTOM_TOKEN_UTILS

static const char BEARER[] = "Bearer ";
static const size_t BEARER_SIZE = sizeof(BEARER) - 1;

void utils_set_memory_allocation_error(ngx_http_request_t *request, const char *operation);
void utils_log_upstream_set_header_error(ngx_http_request_t *request, ngx_str_t header_name);
void utils_log_subrequest_set_header_error(ngx_http_request_t *request, ngx_str_t header_name);
ngx_int_t utils_set_www_authenticate_header(ngx_http_request_t *request, phantom_token_configuration_t *module_location_config, char *error_code);
ngx_int_t utils_write_error_response(ngx_http_request_t *request, ngx_int_t status, phantom_token_configuration_t *module_location_config);

#endif
