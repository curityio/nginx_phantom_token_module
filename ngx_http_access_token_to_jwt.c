/*
 * Copyright (C) 2017 Curity AB
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define ACCESS_TOKEN_BUF_LEN 45

typedef struct
{
    ngx_flag_t enable;
    ngx_str_t base64encoded_client_credentials;
    ngx_str_t client_id;
    ngx_str_t client_secret;
    ngx_str_t introspection_endpoint;
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
static char JWT_KEY[] = "\"jwt\":\"";
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
        ngx_string("access_token_to_jwt_client_id"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_access_token_to_jwt_conf_t, client_id),
        NULL
    },
    {
        ngx_string("access_token_to_jwt_client_secret"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_access_token_to_jwt_conf_t, client_secret),
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

    if (module_location_config->client_secret.len == 0)
    {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
            "Module not configured properly: missing client secret");
        return NGX_DECLINED;
    }

    if (module_location_config->client_id.len == 0)
    {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0,
                           "Module not configured properly: missing client id");
        return NGX_DECLINED;
    }

    ngx_str_t encoded_client_credentials = module_location_config->base64encoded_client_credentials;


    if (module_location_config->introspection_endpoint.len == 0)
    {
        ngx_log_debug0(NGX_LOG_WARN, request->connection->log, 0,
                       "Module not configured properly: missing introspection endpoint");

        return NGX_DECLINED;
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

    ngx_http_post_subrequest_t *introspection_request_callback = ngx_pcalloc(request->pool, sizeof(ngx_http_post_subrequest_t));

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
    u_char *introspect_body_data = ngx_pcalloc(request->pool, ACCESS_TOKEN_BUF_LEN);

    if (introspect_body_data == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_t *introspection_body = ngx_pcalloc(request->pool, sizeof(ngx_str_t));

    if (introspection_body == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_snprintf(introspect_body_data, ACCESS_TOKEN_BUF_LEN, "token=%s", bearer_token_pos);

    introspection_body->data = introspect_body_data;
    introspection_body->len = ngx_strlen(introspection_body->data);

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

    introspection_request->header_only = TRUE;
    module_context->subrequest = introspection_request;

    // Change subrequest method to POST
    introspection_request->method = NGX_HTTP_POST;
    ngx_str_set(&introspection_request->method_name, "POST");

    // set authorization credentials header to Basic base64encoded_client_credentials
    size_t authorization_header_data_len = encoded_client_credentials.len + sizeof("Basic ") - 1;
    u_char *authorization_header_data = ngx_pcalloc(request->pool, authorization_header_data_len);

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
    char *jwt_start = ngx_strstr(request->header_start, JWT_KEY);

    if (jwt_start == NULL && request->cache && request->cache->buf && request->cache->valid_sec > 0)
    {
        ngx_read_file(&request->cache->file, request->cache->buf->pos, request->cache->length, 0);
        jwt_start = ngx_strstr(request->cache->buf->start + request->cache->body_start, JWT_KEY);
    }

    if (jwt_start == NULL)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "Failed to parse JSON response\n");
        module_context->done = 1;
        module_context->status = NGX_HTTP_UNAUTHORIZED;

        return rc;
    }

    jwt_start += sizeof(JWT_KEY) - 1;

    char *jwt_end = ngx_strchr(jwt_start, '"');

    if (jwt_end == NULL)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "Failed to parse JSON response\n");
        module_context->done = 1;
        module_context->status = NGX_HTTP_UNAUTHORIZED;

        return rc;
    }

    module_context->jwt.len = jwt_end - jwt_start + BEARER_SIZE;

    module_context->jwt.data = ngx_pcalloc(request->pool, module_context->jwt.len);

    if (module_context->jwt.data == NULL)
    {
        return rc;
    }

    void * jwt_pointer = ngx_copy(module_context->jwt.data, BEARER, BEARER_SIZE);
    ngx_copy(jwt_pointer, jwt_start, module_context->jwt.len);

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

    ngx_conf_merge_str_value(conf->client_id, prev->client_id, "");
    ngx_conf_merge_str_value(conf->client_secret, prev->client_secret, "");
    ngx_conf_merge_str_value(conf->introspection_endpoint, prev->introspection_endpoint, "");


    ngx_str_t  *concat_credentials =  ngx_pcalloc(config->pool, sizeof(ngx_str_t));

    if (concat_credentials == NULL)
    {
        return NGX_CONF_ERROR;
    }

    int concat_credentials_size = conf->client_id.len + conf->client_secret.len + 1; // client_id:client_secret

    u_char *concat_credentials_data = ngx_pcalloc(config->pool, concat_credentials_size);

    if (concat_credentials_data == NULL)
    {
        return NGX_CONF_ERROR;
    }

    concat_credentials->data = concat_credentials_data;
    concat_credentials->len = concat_credentials_size;

    ngx_snprintf(concat_credentials_data, concat_credentials_size, "%s:%s", conf->client_id.data, conf->client_secret.data);

    conf->base64encoded_client_credentials.data = ngx_pcalloc(config->pool, ngx_base64_encoded_length(concat_credentials_size));

    if (conf->base64encoded_client_credentials.data == NULL)
    {
        return NGX_CONF_ERROR;
    }

    ngx_encode_base64(&conf->base64encoded_client_credentials, concat_credentials);

    ngx_pfree(config->pool, concat_credentials);

    return NGX_CONF_OK;
}
