#ifndef PHANTOM_TOKEN
#define PHANTOM_TOKEN

typedef struct
{
    ngx_str_t base64encoded_client_credential;
    ngx_str_t introspection_endpoint;
    ngx_str_t realm;
    ngx_array_t *scopes;
    ngx_str_t space_separated_scopes;
    ngx_flag_t enable;
} phantom_token_configuration_t;

#endif