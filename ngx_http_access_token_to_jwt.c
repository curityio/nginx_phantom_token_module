#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define ACCESS_TOKEN_BUF_LEN 45

typedef struct
{
    ngx_flag_t enable;
    ngx_str_t base64encoded_client_credentials;
    ngx_str_t introspection_endpoint;
    ngx_array_t *vars;
} ngx_http_access_token_to_jwt_conf_t;

typedef struct
{
    ngx_uint_t done;
    ngx_uint_t status;
    ngx_str_t jwt;
    ngx_http_request_t *subrequest;
} ngx_http_access_token_to_jwt_ctx_t;

static ngx_int_t ngx_http_access_token_to_jwt_postconfig(ngx_conf_t *config);

static ngx_int_t ngx_http_access_token_to_jwt_handler(ngx_http_request_t *request);

static void *ngx_http_access_token_to_jwt_create_loc_conf(ngx_conf_t *config);

static char *ngx_http_access_token_to_jwt_merge_loc_conf(ngx_conf_t *config, void *parent, void *child);

static ngx_int_t ngx_http_access_token_to_jwt_request_done(ngx_http_request_t *request, void *data, ngx_int_t rc);

static char BEARER[] = "Bearer ";
const size_t BEARER_SIZE = sizeof(BEARER) - 1;

/**
 * This module provided directive: access_token_to_jwt.
 */
static ngx_command_t ngx_http_access_token_to_jwt_commands[] =
{
    {
        ngx_string("access_token_to_jwt"),
        NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_access_token_to_jwt_conf_t, enable),
        NULL
    },
    {
        ngx_string("access_token_to_jwt_base64encoded_client_credentials"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_access_token_to_jwt_conf_t, base64encoded_client_credentials),
        NULL
    },
    {
        ngx_string("access_token_to_jwt_introspection_endpoint"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_access_token_to_jwt_conf_t, introspection_endpoint),
        NULL
    },
    ngx_null_command /* command termination */
};

/* The module context. */
static ngx_http_module_t ngx_http_access_token_to_jwt_module_ctx =
{
    NULL, /* preconfiguration */
    ngx_http_access_token_to_jwt_postconfig, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_access_token_to_jwt_create_loc_conf, /* create location configuration */
    ngx_http_access_token_to_jwt_merge_loc_conf /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_access_token_to_jwt_module =
{
    NGX_MODULE_V1,
    &ngx_http_access_token_to_jwt_module_ctx, /* module context */
    ngx_http_access_token_to_jwt_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_access_token_to_jwt_handler(ngx_http_request_t *request)
{
    ngx_http_access_token_to_jwt_conf_t *module_location_config = ngx_http_get_module_loc_conf(
            request, ngx_http_access_token_to_jwt_module);

    // Return OK if the module is not active or properly configured
    if (!module_location_config->enable)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "Module disabled");

        return NGX_DECLINED;
    }

    ngx_str_t encoded_client_credentials = module_location_config->base64encoded_client_credentials;

    if (encoded_client_credentials.len == 0)
    {
        //ngx_conf_log_error(NGX_LOG_WARN, )
        // TODO: use ngx_conf_log_error instead?
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
                      "Module not configured properly: missing client credential");

        return NGX_ABORT;
    }

    if (module_location_config->introspection_endpoint.len == 0)
    {
        ngx_log_debug0(NGX_LOG_WARN, request->connection->log, 0,
                       "Module not configured properly: missing introspection endpoint");

        return NGX_ABORT;
    }

    ngx_http_access_token_to_jwt_ctx_t *module_context = ngx_http_get_module_ctx(request, ngx_http_access_token_to_jwt_module);

    if (module_context != NULL)
    {
        if (module_context->done)
        {
            // return appropriate status
            if (module_context->status >= NGX_HTTP_OK && module_context->status < NGX_HTTP_SPECIAL_RESPONSE)
            {
                // Introspection was successful. Replace the incoming Authorization header with one that has the JWT.
                // todo add Bearer
                request->headers_in.authorization->value.len = module_context->jwt.len;
                request->headers_in.authorization->value.data = module_context->jwt.data;

                return NGX_OK;
            }

            // should handle other HTTP codes accordingly. Till then return 401 for any request that was not legal
            return NGX_HTTP_UNAUTHORIZED;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0,
                       "Called again without having received the response from Curity");

        return NGX_AGAIN;
    }

    // return unauthorized when no Authorization header is present
    if (!request->headers_in.authorization || request->headers_in.authorization->value.len <= 0)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "Authorization header not present");

        // TODO: Add WWW-Authenticate response header

        return NGX_HTTP_UNAUTHORIZED;
    }

    u_char *bearer_token_pos;

    //if ((bearer_token_pos = ngx_strstrn(request->headers_in.authorization->value.data, BEARER, BEARER_SIZE)) == NULL)
    if ((bearer_token_pos = (u_char *)strcasestr((char*)request->headers_in.authorization->value.data, BEARER)) == NULL)
    {
        // return unauthorized when Authorization header is not Bearer

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0,
                       "Authorization header does not contain a bearer token");

        return NGX_HTTP_UNAUTHORIZED;
    }

    bearer_token_pos += BEARER_SIZE;

    // Remove any extra whitespace after the "Bearer " part of the authorization request header
    while (isspace(*bearer_token_pos))
    {
        bearer_token_pos++;
    }

    module_context = ngx_pcalloc(request->pool, sizeof(ngx_http_access_token_to_jwt_ctx_t));

    if (module_context == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_post_subrequest_t *introspection_request_callback = ngx_palloc(request->pool, sizeof(ngx_http_post_subrequest_t));

    if (introspection_request_callback == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    introspection_request_callback->handler = ngx_http_access_token_to_jwt_request_done;
    introspection_request_callback->data = module_context;
    ngx_http_request_t *introspection_request;

    if (ngx_http_subrequest(request, &module_location_config->introspection_endpoint, NULL, &introspection_request,
                            introspection_request_callback, NGX_HTTP_SUBREQUEST_WAITED) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // extract access token from header
    u_char *introspect_body_data = ngx_palloc(request->pool, ACCESS_TOKEN_BUF_LEN);

    if (introspect_body_data == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_t *introspection_body = ngx_palloc(request->pool, sizeof(ngx_str_t));

    if (introspection_body == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_snprintf(introspect_body_data, ACCESS_TOKEN_BUF_LEN, "token=%s", bearer_token_pos);

    introspection_body->data = introspect_body_data;
    introspection_body->len = ngx_strlen(introspection_body->data);

    // todo check cache, if access_token association is there just set

    introspection_request->request_body = ngx_pcalloc(request->pool, sizeof(ngx_http_request_body_t));

    if (introspection_request->request_body == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_request_body_t *introspection_request_body = ngx_pcalloc(request->pool, sizeof(ngx_http_request_body_t));

    if (introspection_request_body == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_buf_t *introspection_request_body_buffer = ngx_calloc_buf(request->pool);

    if (introspection_request_body_buffer == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    introspection_request_body_buffer->start = introspection_request_body_buffer->pos = introspection_body->data;
    introspection_request_body_buffer->end = introspection_request_body_buffer->last = introspection_body->data +
            introspection_body->len;

    introspection_request_body_buffer->temporary = TRUE;

    introspection_request_body->bufs = ngx_alloc_chain_link(request->pool);

    if (introspection_request_body->bufs == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    introspection_request_body->bufs->buf = introspection_request_body_buffer;
    introspection_request_body->bufs->next = NULL;
    introspection_request_body->buf = introspection_request_body_buffer;
    introspection_request->request_body = introspection_request_body;
    introspection_request->headers_in.content_length_n = introspection_body->len;

    introspection_request->header_only = FALSE;
    module_context->subrequest = introspection_request;

    // Change subrequest method to POST
    introspection_request->method = NGX_HTTP_POST;
    ngx_str_set(&introspection_request->method_name, "POST");

    // set authorization credentials header to Basic base64encoded_client_credentials
    size_t authorization_header_data_len = encoded_client_credentials.len + sizeof("Basic ") - 1;
    u_char *authorization_header_data = ngx_palloc(request->pool, authorization_header_data_len);

    if (authorization_header_data == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_snprintf(authorization_header_data, authorization_header_data_len, "Basic %V", &encoded_client_credentials);

    introspection_request->headers_in.authorization->value.data = authorization_header_data;
    introspection_request->headers_in.authorization->value.len = authorization_header_data_len;

    ngx_http_set_ctx(request, module_context, ngx_http_access_token_to_jwt_module);

    return NGX_AGAIN;
}

static ngx_int_t ngx_http_access_token_to_jwt_request_done(ngx_http_request_t *request, void *data, ngx_int_t rc)
{
    ngx_http_access_token_to_jwt_ctx_t *module_context = (ngx_http_access_token_to_jwt_ctx_t*)data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "auth request done s:%d", request->headers_out.status);

    module_context->status = request->headers_out.status;

    // fail early for not 200 response
    if (request->headers_out.status != NGX_HTTP_OK)
    {
        module_context->done = 1;

        return rc;
    }

    // body parsing
    char *jwt_start = ngx_strstr(request->upstream->buffer.start, "\"jwt\":\"");

    if (jwt_start == NULL)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "Failed to parse JSON response\n");
        module_context->done = 1;
        module_context->status = NGX_HTTP_UNAUTHORIZED;

        return NGX_ERROR;
    }

    jwt_start += sizeof("\"jwt\":\"") - 1;

    char *jwt_end = ngx_strchr(jwt_start, '"');

    if (jwt_end == NULL)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "Failed to parse JSON response\n");
        module_context->done = 1;
        module_context->status = NGX_HTTP_UNAUTHORIZED;

        return NGX_ERROR;
    }

    module_context->jwt.len = jwt_end - jwt_start;

    module_context->jwt.data = ngx_pcalloc(request->pool, module_context->jwt.len);

    if (module_context->jwt.data == NULL)
    {
        return NGX_ERROR;
    }

    ngx_copy(module_context->jwt.data, jwt_start, module_context->jwt.len);

    module_context->done = 1;

    return rc;
}

static ngx_int_t ngx_http_access_token_to_jwt_postconfig(ngx_conf_t *config)
{
    ngx_http_core_main_conf_t *cmcf = ngx_http_conf_get_module_main_conf(config, ngx_http_core_module);
    ngx_http_handler_pt *h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

    if (h == NULL)
    {
        return NGX_ERROR;
    }

    *h = ngx_http_access_token_to_jwt_handler;

    return NGX_OK;
}

static void *ngx_http_access_token_to_jwt_create_loc_conf(ngx_conf_t *config)
{
    ngx_http_access_token_to_jwt_conf_t *conf = ngx_pcalloc(config->pool, sizeof(ngx_http_access_token_to_jwt_conf_t));

    if (conf == NULL)
    {
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}

static char *ngx_http_access_token_to_jwt_merge_loc_conf(ngx_conf_t *config, void *parent, void *child)
{
    ngx_http_access_token_to_jwt_conf_t *prev = parent, *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->base64encoded_client_credentials, prev->base64encoded_client_credentials, "");
    ngx_conf_merge_str_value(conf->introspection_endpoint, prev->introspection_endpoint, "");

    return NGX_CONF_OK;
}
