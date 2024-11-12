/*
 *  Copyright 2017 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>
#include <stdbool.h>
#include <assert.h>

#define UNENCODED_CLIENT_CREDENTIALS_BUF_LEN 255
/* #undef NGX_HTTP_CACHE */

typedef struct
{
    ngx_str_t base64encoded_client_credential;
    ngx_str_t introspection_endpoint;
    ngx_str_t realm;
    ngx_array_t *scopes;
    ngx_str_t space_separated_scopes;
    ngx_flag_t enable;
} phantom_token_configuration_t;

typedef struct
{
    ngx_uint_t done;
    ngx_uint_t status;
    ngx_str_t jwt;
    ngx_str_t original_accept_header;
    ngx_str_t original_content_type_header;
} phantom_token_module_context_t;

static ngx_int_t post_configuration(ngx_conf_t *config);

static ngx_int_t handler(ngx_http_request_t *request);

static void *create_location_configuration(ngx_conf_t *config);

static char *merge_location_configuration(ngx_conf_t *main_config, void *parent, void *child);

static ngx_int_t introspection_response_handler(ngx_http_request_t *request, void *data,
                                                ngx_int_t introspection_subrequest_status_code);

static ngx_int_t write_error_response(ngx_http_request_t *request, ngx_int_t status, phantom_token_configuration_t *module_location_config);

/**
 * Adds a WWW-Authenticate header to the given request's output headers that conforms to <a href="https://tools.ietf.org/html/rfc6750">RFC 6750</>.
 *
 * After calling this method, a WWW-Authenticate header will be added that uses the Bearer scheme. If the realm and or
 * scopes were also configured, then these too will be included. For instance, if scopes are configured, then the
 * following output header will be added: <code> WWW-Authenticate: Bearer scope="scope1 scope2 scope3"</code>. If only
 * realm is configured, then a response header like this one would be added:
 * <code>WWW-Authenticate: Bearer realm="myGoodRealm"</code>. If both are configured, the two will be included and
 * separated by a comma, like this: <code>WWW-Authenticate: Bearer realm="myGoodRealm", scope="scope1 scope2 scope3"</code>.
 *
 * @param request the current request
 * @param realm the configured realm
 * @param space_separated_scopes the space-separated list of configured scopes
 * @param error an error code or NULL if none. Refer to
 * <a href="https://tools.ietf.org/html/rfc6750#section-3.1">RFC 6750 § 3.1</a> for standard values.
 *
 * @return <code>NGX_HTTP_UNAUTHORIZED</code>
 *
 * @example <code>WWW-Authenticate: Bearer realm="myGoodRealm", scope="scope1 scope2 scope3"</code>
 *
 * @see <a href="https://tools.ietf.org/html/rfc6750">RFC 6750</a>
 */
static ngx_int_t set_www_authenticate_header(ngx_http_request_t *request, phantom_token_configuration_t *module_location_config, char *error_code);

/**
 * Sets the base-64-encoded client ID and secret in the module's configuration setting structure.
 *
 * This method assumes the module's command where this setter function (<code>set</code>) is used has a
 * configuration (<code>conf</code>) of <code>NGX_HTTP_LOC_CONF_OFFSET<code> and an <code>offset</code> of
 * <code>base64encoded_client_credential</code>. If this is not the case, the result pointer <em>may</em> point to an
 * unexpected location and the handler may not be able to use the configured values. Also, the command should have a
 * type that includes <code>NGX_CONF_TAKE2</code>.
 *
 * @param config_setting the configuration setting that is being set
 * @param command the module's command where this slot setter function is being used
 * @param result a pointer to the location where the result will be stored; it should be a pointer to a
 * <code>ngx_str_t</code>.
 *
 * @return <code>NGX_CONF_OK</code> upon success; some other character string on failure.
 */
static char* set_client_credential_configuration_slot(ngx_conf_t *config_setting, ngx_command_t *command, void *result);

static const char BEARER[] = "Bearer ";
static const size_t BEARER_SIZE = sizeof(BEARER) - 1;

static ngx_command_t phantom_token_module_directives[] =
{
    {
          ngx_string("phantom_token"),
          NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
          ngx_conf_set_flag_slot,
          NGX_HTTP_LOC_CONF_OFFSET,
          offsetof(phantom_token_configuration_t, enable),
          NULL
    },
    {
        ngx_string("phantom_token_client_credential"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
        set_client_credential_configuration_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t, base64encoded_client_credential),
        NULL
    },
    {
        ngx_string("phantom_token_introspection_endpoint"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t, introspection_endpoint),
        NULL
    },
    {
        ngx_string("phantom_token_realm"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t, realm),
        NULL
    },
    {
        ngx_string("phantom_token_scopes"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t, space_separated_scopes),
        NULL
    },
    {
        ngx_string("phantom_token_scope"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(phantom_token_configuration_t, scopes),
        NULL
    },
    ngx_null_command /* command termination */
};

/* The module context. */
static ngx_http_module_t phantom_token_module_context =
{
    NULL, /* pre-configuration */
    post_configuration,

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    create_location_configuration,
    merge_location_configuration
};

/* Module definition. */
ngx_module_t ngx_curity_http_phantom_token_module =
{
    NGX_MODULE_V1,
    &phantom_token_module_context,
    phantom_token_module_directives,
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

/**
 * Sets the request's Accept header to the given value.
 *
 * @param request the request to which the header value will be set
 * @param value the value to set
 * @return NGX_OK if no error has occurred; NGX_ERROR if an error occurs.
 */
static ngx_int_t set_accept_header_value(ngx_http_request_t *request, const char* value)
{
    ngx_table_elt_t  *accept_header;
    accept_header = ngx_list_push(&request->headers_in.headers);

    if (accept_header == NULL)
    {
        return NGX_ERROR;
    }

    accept_header->hash = 1;
    ngx_str_set(&accept_header->key, "Accept");
    accept_header->value.len = ngx_strlen(value);
    accept_header->value.data = (u_char *)value;
    accept_header->lowcase_key = (u_char *)"accept";

    request->headers_in.accept = accept_header;
    request->headers_in.headers.part.nelts = request->headers_in.headers.last->nelts;

    return NGX_OK;
}

static ngx_int_t handler(ngx_http_request_t *request)
{
    phantom_token_configuration_t *module_location_config = ngx_http_get_module_loc_conf(
            request, ngx_curity_http_phantom_token_module);

    // Return OK if the module is not active
    if (!module_location_config->enable)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "Module disabled");
        return NGX_DECLINED;
    }

    // OPTIONS requests from SPAs can never contain an authorization header so return a standard 204
    if (request->method == NGX_HTTP_OPTIONS)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "Not processing OPTIONS request");
        return NGX_HTTP_NO_CONTENT;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "Handling request to convert token to JWT");

    if (module_location_config->base64encoded_client_credential.len == 0)
    {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0, "Module not configured properly: missing client ID and secret");
        return NGX_DECLINED;
    }

    ngx_str_t encoded_client_credentials = module_location_config->base64encoded_client_credential;

    if (module_location_config->introspection_endpoint.len == 0)
    {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0, "Module not configured properly: missing introspection endpoint");
        return NGX_DECLINED;
    }

    phantom_token_module_context_t *module_context = ngx_http_get_module_ctx(request, ngx_curity_http_phantom_token_module);

    if (module_context != NULL)
    {
        if (module_context->done)
        {
            // return appropriate status
            if (module_context->status == NGX_HTTP_OK)
            {
                // Introspection was successful. Replace the incoming Authorization header with one that has the JWT.
                request->headers_in.authorization->value.len = module_context->jwt.len;
                request->headers_in.authorization->value.data = module_context->jwt.data;

                if (module_context->original_content_type_header.data == NULL)
                {
                    request->headers_in.headers.part.nelts = request->headers_in.headers.last->nelts = request->headers_in.headers.last->nelts - 1;
                }
                else
                {
                    request->headers_in.content_type->value = module_context->original_content_type_header;
                }

                if (request->headers_in.accept == NULL)
                {
                    ngx_int_t result;

                    if ((result = set_accept_header_value(request, "*/*") != NGX_OK))
                    {
                        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Failed to set Accept header value");
                        return result;
                    }
                }
                else
                {
                    request->headers_in.accept->value = module_context->original_accept_header;
                }

                return NGX_OK;
            }
            else if (module_context->status == NGX_HTTP_NO_CONTENT || module_context->status == NGX_HTTP_UNAUTHORIZED)
            {
                return set_www_authenticate_header(request, module_location_config, NULL);
            }
            else if (module_context->status == NGX_HTTP_SERVICE_UNAVAILABLE)
            {
                ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Introspection request failed with service unavailable");
                return write_error_response(request, module_context->status, module_location_config);
            }
            else if (module_context->status >= NGX_HTTP_INTERNAL_SERVER_ERROR)
            {
                ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Introspection request failed with an internal server error");
                return write_error_response(request, module_context->status, module_location_config);
            }
            else if (module_context->status == NGX_HTTP_NOT_FOUND)
            {
                ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Introspection request failed with not found error");
                return write_error_response(request, module_context->status, module_location_config);
            }
            else if (module_context->status == NGX_HTTP_FORBIDDEN)
            {
                ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Introspection request failed with forbidden error");
                return write_error_response(request, module_context->status, module_location_config);
            }

            ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Introspection request failed with an internal server error");
            return write_error_response(request, NGX_HTTP_INTERNAL_SERVER_ERROR, module_location_config);
        }

        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Called again without having received the response from the authorization server");
        return NGX_AGAIN;
    }

    // return unauthorized when no Authorization header is present
    if (!request->headers_in.authorization || request->headers_in.authorization->value.len <= 0)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Authorization header not present");
        return set_www_authenticate_header(request, module_location_config, NULL);
    }

    u_char *bearer_token_pos;

    // return unauthorized when Authorization header is not Bearer
    if ((bearer_token_pos = ngx_strcasestrn((u_char*)request->headers_in.authorization->value.data,
        (char*)BEARER, BEARER_SIZE - 1)) == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Authorization header does not contain a bearer token");
        return set_www_authenticate_header(request, module_location_config, NULL);
    }

    bearer_token_pos += BEARER_SIZE;

    // Remove any extra whitespace after the "Bearer " part of the authorization request header
    while (isspace(*bearer_token_pos))
    {
        bearer_token_pos++;
    }

    module_context = ngx_pcalloc(request->pool, sizeof(phantom_token_module_context_t));
    if (module_context == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Failed to allocate memory for module context");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_post_subrequest_t *introspection_request_callback = ngx_pcalloc(request->pool, sizeof(ngx_http_post_subrequest_t));

    if (introspection_request_callback == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Failed to allocate memory for introspection request callback");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    introspection_request_callback->handler = introspection_response_handler;
    introspection_request_callback->data = module_context;
    ngx_http_request_t *introspection_request;

    if (ngx_http_subrequest(request, &module_location_config->introspection_endpoint, NULL, &introspection_request,
                            introspection_request_callback, NGX_HTTP_SUBREQUEST_WAITED) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Failed to create subrequest to introspection endpoint");
        write_error_response(request, NGX_HTTP_INTERNAL_SERVER_ERROR, module_location_config);
    }

    // extract access token from header
    u_char *introspect_body_data = ngx_pcalloc(request->pool, request->headers_in.authorization->value.len);
    if (introspect_body_data == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Failed to allocate memory for introspection body data");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_t *introspection_body = ngx_pcalloc(request->pool, sizeof(ngx_str_t));
    if (introspection_body == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Failed to allocate memory for introspection body");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_snprintf(introspect_body_data, request->headers_in.authorization->value.len, "token=%s", bearer_token_pos);

    introspection_body->data = introspect_body_data;
    introspection_body->len = ngx_strlen(introspection_body->data);

    introspection_request->request_body = ngx_pcalloc(request->pool, sizeof(ngx_http_request_body_t));

    if (introspection_request->request_body == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Failed to allocate memory for introspection request");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_request_body_t *introspection_request_body = ngx_pcalloc(request->pool, sizeof(ngx_http_request_body_t));
    if (introspection_request_body == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Failed to allocate memory for introspection request body");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_buf_t *introspection_request_body_buffer = ngx_calloc_buf(request->pool);
    if (introspection_request_body_buffer == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Failed to allocate memory for introspection request body buffer");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    introspection_request_body_buffer->start = introspection_request_body_buffer->pos = introspection_body->data;
    introspection_request_body_buffer->end = introspection_request_body_buffer->last = introspection_body->data +
            introspection_body->len;

    introspection_request_body_buffer->temporary = true;

    introspection_request_body->bufs = ngx_alloc_chain_link(request->pool);
    if (introspection_request_body->bufs == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Failed to allocate memory for introspection request body buffers");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    introspection_request_body->bufs->buf = introspection_request_body_buffer;
    introspection_request_body->bufs->next = NULL;
    introspection_request_body->buf = introspection_request_body_buffer;
    introspection_request->request_body = introspection_request_body;
    introspection_request->headers_in.content_length_n = ngx_buf_size(introspection_request_body_buffer);

#if (NGX_HTTP_HEADERS)
    if (request->headers_in.accept == NULL)
    {
        ngx_int_t result;

        if ((result = set_accept_header_value(introspection_request, "application/jwt") != NGX_OK))
        {
            return result;
        }
    }
    else
    {
        module_context->original_accept_header = request->headers_in.accept->value;
    }

    ngx_str_set(&introspection_request->headers_in.accept->value, "application/jwt");
#endif

    if (request->headers_in.content_type == NULL)
    {
        ngx_table_elt_t  *content_type_header;
        content_type_header = ngx_list_push(&introspection_request->headers_in.headers);
        if (content_type_header == NULL)
        {
            return NGX_ERROR;
        }

        content_type_header->hash = 1;
        ngx_str_set(&content_type_header->key, "Content-type");
        ngx_str_set(&content_type_header->value, "application/x-www-form-urlencoded");
        content_type_header->lowcase_key = (u_char *)"content-type";

        introspection_request->headers_in.content_type = content_type_header;
        introspection_request->headers_in.headers.part.nelts = introspection_request->headers_in.headers.last->nelts;
    }
    else
    {
        module_context->original_content_type_header = request->headers_in.content_type->value;
        ngx_str_set(&request->headers_in.content_type->value, "application/x-www-form-urlencoded");
    }

    introspection_request->header_only = true;

    // Change subrequest method to POST
    introspection_request->method = NGX_HTTP_POST;
    ngx_str_set(&introspection_request->method_name, "POST");

    // set authorization credentials header to Basic base64encoded_client_credential
    size_t authorization_header_data_len = encoded_client_credentials.len + sizeof("Basic ") - 1;
    u_char *authorization_header_data = ngx_pcalloc(request->pool, authorization_header_data_len);

    if (authorization_header_data == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Failed to allocate memory for authorization header data");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_snprintf(authorization_header_data, authorization_header_data_len, "Basic %V", &encoded_client_credentials);

    introspection_request->headers_in.authorization->value.data = authorization_header_data;
    introspection_request->headers_in.authorization->value.len = authorization_header_data_len;

    ngx_http_set_ctx(request, module_context, ngx_curity_http_phantom_token_module)

    return NGX_AGAIN;
}

static ngx_int_t introspection_response_handler(ngx_http_request_t *request, void *data,
                                                ngx_int_t introspection_subrequest_status_code)
{
    phantom_token_module_context_t *module_context = (phantom_token_module_context_t*)data;
    ngx_str_t cache_data = ngx_null_string;
    u_char *jwt_start = NULL;
    size_t jwt_len = 0;
    size_t bearer_jwt_len = 0;
    u_char *p = NULL;
    bool use_buffer_response = false;

    ngx_log_error(NGX_LOG_DEBUG, request->connection->log, 0, "Introspection request done status = %d",
                   request->headers_out.status);

    module_context->status = request->headers_out.status;

    // Fail early if the introspection request returned a non 200 response
    if (request->headers_out.status != NGX_HTTP_OK)
    {
        module_context->done = 1;
        return introspection_subrequest_status_code;
    }

#if (NGX_HTTP_CACHE)
    if (request->cache && !request->cache->buf)
    {
        // We have a cache but it's not primed
        ngx_http_file_cache_open(request);
    }

    // When caching is enabled the JWT is always received from the cache, including the initial request from a client with a new opaque access token
    if (request->cache && request->cache->buf && request->cache->valid_sec > 0)
    {
        cache_data.len = request->cache->length;
        cache_data.data = ngx_pnalloc(request->pool, cache_data.len);

        if (cache_data.data == NULL)
        {
            ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Failed to allocate memory for cache data");
        }
        else
        {
            ngx_read_file(&request->cache->file, cache_data.data, cache_data.len, request->cache->body_start);
            jwt_start = cache_data.data;
            jwt_len = request->headers_out.content_length_n;
        }
    }
    else
    {
        use_buffer_response = true;
    }
#else
    use_buffer_response = true;
#endif

    // When caching is disabled the JWT is always read from upstream buffers
    if (use_buffer_response)
    {
        if (request->upstream->buffer.last == request->upstream->buffer.end)
        {
            ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Buffer is maxed out, check the proxy_buffer_size configuration setting");
            module_context->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_ERROR;
        }

        jwt_start = request->upstream->buffer.pos;
        jwt_len = request->upstream->buffer.last - request->upstream->buffer.pos;
    }

    if (jwt_start == NULL || jwt_len == 0)
    {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0, "Failed to obtain JWT from introspection response or cache");
        module_context->done = 1;
        module_context->status = NGX_HTTP_UNAUTHORIZED;
        return introspection_subrequest_status_code;
    }

    bearer_jwt_len = BEARER_SIZE + jwt_len;
    module_context->jwt.len = bearer_jwt_len;
    module_context->jwt.data = ngx_pnalloc(request->pool, bearer_jwt_len);

    if (module_context->jwt.data == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Failed to allocate memory for JWT token");
        module_context->done = 1;
        module_context->status = NGX_HTTP_UNAUTHORIZED;
        return introspection_subrequest_status_code;
    }

    p = ngx_copy(module_context->jwt.data, BEARER, BEARER_SIZE);
    ngx_memcpy(p, jwt_start, jwt_len);

    if (cache_data.len > 0)
    {
        ngx_pfree(request->pool, cache_data.data);
    }

    module_context->done = 1;

    return introspection_subrequest_status_code;
}

static ngx_int_t post_configuration(ngx_conf_t *config)
{
    ngx_http_core_main_conf_t *main_config = ngx_http_conf_get_module_main_conf(config, ngx_http_core_module);
    ngx_http_handler_pt *h = ngx_array_push(&main_config->phases[NGX_HTTP_ACCESS_PHASE].handlers);

    if (h == NULL)
    {
        return NGX_ERROR;
    }

    *h = handler;

    return NGX_OK;
}

static void *create_location_configuration(ngx_conf_t *config)
{
    phantom_token_configuration_t *location_config = ngx_pcalloc(config->pool, sizeof(phantom_token_configuration_t));

    if (location_config == NULL)
    {
        return NGX_CONF_ERROR;
    }

    location_config->enable = NGX_CONF_UNSET_UINT;
    location_config->scopes = NGX_CONF_UNSET_PTR;

    return location_config;
}

static char *merge_location_configuration(ngx_conf_t *main_config, void *parent, void *child)
{
    phantom_token_configuration_t *parent_config = parent, *child_config = child;

    ngx_conf_merge_off_value(child_config->enable, parent_config->enable, 0)
    ngx_conf_merge_str_value(child_config->introspection_endpoint, parent_config->introspection_endpoint, "")
    ngx_conf_merge_str_value(child_config->realm, parent_config->realm, "api")
    ngx_conf_merge_ptr_value(child_config->scopes, parent_config->scopes, NULL)
    ngx_conf_merge_str_value(child_config->space_separated_scopes, parent_config->space_separated_scopes, "")
    ngx_conf_merge_str_value(child_config->base64encoded_client_credential,
                             parent_config->base64encoded_client_credential, "")

    if (child_config->scopes != NULL && child_config->space_separated_scopes.len == 0)
    {
        // Flatten scopes into a space-separated list
        ngx_str_t *scope = child_config->scopes->elts;
        size_t space_separated_scopes_data_size = child_config->scopes->nelts;
        ngx_uint_t i;

        for (i = 0; i < child_config->scopes->nelts; i++)
        {
            space_separated_scopes_data_size += scope[i].len;
        }

        u_char *space_separated_scopes_data = ngx_pcalloc(main_config->pool, space_separated_scopes_data_size);

        if (space_separated_scopes_data == NULL)
        {
            return NGX_CONF_ERROR;
        }

        u_char *p = space_separated_scopes_data;

        for (i = 0; i < child_config->scopes->nelts; i++)
        {
            p = ngx_cpymem(p, scope[i].data, scope[i].len);
            *p = ' ';
            p++;
        }

        *(p - 1) = '\0';

        child_config->space_separated_scopes.data = space_separated_scopes_data;
        child_config->space_separated_scopes.len = ngx_strlen(space_separated_scopes_data);

        assert(child_config->space_separated_scopes.len <= space_separated_scopes_data_size);
    }

    return NGX_CONF_OK;
}

static char* set_client_credential_configuration_slot(ngx_conf_t *config_setting, ngx_command_t *command, void *result)
{
    ngx_str_t *base64encoded_client_credential = result;
    ngx_str_t *args = config_setting->args->elts;
    ngx_str_t client_id = args[1], client_secret = args[2]; // sub 0 is the directive itself

    if (client_id.len > 0 && client_secret.len > 0)
    {
        u_char unencoded_client_credentials_data[UNENCODED_CLIENT_CREDENTIALS_BUF_LEN];
        u_char *p = ngx_snprintf(unencoded_client_credentials_data, sizeof(unencoded_client_credentials_data), "%V:%V",
                                 &client_id, &client_secret);
        ngx_str_t unencoded_client_credentials = { p - unencoded_client_credentials_data,
                                                   unencoded_client_credentials_data };

        base64encoded_client_credential->data = ngx_palloc(
                config_setting->pool, ngx_base64_encoded_length(unencoded_client_credentials.len));

        if (base64encoded_client_credential->data == NULL)
        {
            return NGX_CONF_ERROR;
        }

        ngx_encode_base64(base64encoded_client_credential, &unencoded_client_credentials);

        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, config_setting, 0, "invalid client ID and/or secret");

    return "invalid_client_credential";
}


static ngx_int_t set_www_authenticate_header(ngx_http_request_t *request, phantom_token_configuration_t *module_location_config, char *error_code)
{
    request->headers_out.www_authenticate = ngx_list_push(&request->headers_out.headers);

    if (request->headers_out.www_authenticate == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    static const char REALM_PREFIX[] = "realm=\"";
    static const size_t REALM_PREFIX_SIZE = sizeof(REALM_PREFIX) - 1;

    static const char TOKEN_SUFFIX[] = "\"";
    static const size_t TOKEN_SUFFIX_SIZE = sizeof(TOKEN_SUFFIX) - 1;

    static const char TOKEN_SEPARATER[] = ", ";
    static const size_t TOKEN_SEPARATER_SIZE = sizeof(TOKEN_SEPARATER) - 1;

    static const char SCOPE_PREFIX[] = "scope=\"";
    static const size_t SCOPE_PREFIX_SIZE = sizeof(SCOPE_PREFIX) - 1;

    static const u_char ERROR_CODE_PREFIX[] = "error=\"";
    static const size_t ERROR_CODE_PREFIX_SIZE = sizeof(ERROR_CODE_PREFIX) - 1;

    size_t bearer_data_size = BEARER_SIZE + sizeof('\0'); // Add one for the nul byte
    bool realm_provided = module_location_config->realm.len > 0;
    bool scopes_provided = module_location_config->space_separated_scopes.len > 0;
    bool error_code_provided = error_code != NULL;
    bool append_one_comma = false, append_two_commas = false;
    size_t error_code_len = 0;

    if (realm_provided)
    {
        bearer_data_size += REALM_PREFIX_SIZE + module_location_config->realm.len + TOKEN_SUFFIX_SIZE;
    }

    if (scopes_provided)
    {
        bearer_data_size += SCOPE_PREFIX_SIZE + module_location_config->space_separated_scopes.len + TOKEN_SUFFIX_SIZE;
    }

    if (error_code_provided)
    {
        error_code_len = ngx_strlen(error_code);
        bearer_data_size += ERROR_CODE_PREFIX_SIZE + error_code_len + TOKEN_SUFFIX_SIZE;
    }

    if ((realm_provided && scopes_provided) || (realm_provided && error_code_provided) || (scopes_provided && error_code_provided))
    {
        bearer_data_size += TOKEN_SEPARATER_SIZE;
        append_one_comma = true;

        if (realm_provided && scopes_provided && error_code_provided)
        {
            bearer_data_size += TOKEN_SEPARATER_SIZE;
            append_two_commas = true;
        }
    }

    u_char *bearer_data = ngx_pnalloc(request->pool, bearer_data_size);

    if (bearer_data == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u_char *p = ngx_cpymem(bearer_data, BEARER, BEARER_SIZE);

    if (realm_provided)
    {
        p = ngx_cpymem(p, REALM_PREFIX, REALM_PREFIX_SIZE);
        p = ngx_cpymem(p, module_location_config->realm.data, module_location_config->realm.len);
        p = ngx_cpymem(p, TOKEN_SUFFIX, TOKEN_SUFFIX_SIZE);

        if (append_one_comma)
        {
            p = ngx_cpymem(p, TOKEN_SEPARATER, TOKEN_SEPARATER_SIZE);
        }
    }

    if (scopes_provided)
    {
        p = ngx_cpymem(p, SCOPE_PREFIX, SCOPE_PREFIX_SIZE);
        p = ngx_cpymem(p, module_location_config->space_separated_scopes.data, module_location_config->space_separated_scopes.len);
        p = ngx_cpymem(p, TOKEN_SUFFIX, TOKEN_SUFFIX_SIZE);

        if (append_one_comma || append_two_commas)
        {
            p = ngx_cpymem(p, TOKEN_SEPARATER, TOKEN_SEPARATER_SIZE);
        }
    }

    if (error_code_provided)
    {
        p = ngx_cpymem(p, ERROR_CODE_PREFIX, ERROR_CODE_PREFIX_SIZE);
        p = ngx_cpymem(p, error_code, error_code_len);
        p = ngx_cpymem(p, TOKEN_SUFFIX, TOKEN_SUFFIX_SIZE);
    }

    if (!scopes_provided && !realm_provided && !error_code_provided)
    {
        // Only 'Bearer' is being sent. Replace the space at the end of BEARER with a null byte.
        *(p - 1) = '\0';
    }
    else
    {
        *p = '\0';
    }

    request->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&request->headers_out.www_authenticate->key, "WWW-Authenticate");
    request->headers_out.www_authenticate->value.data = bearer_data;
    request->headers_out.www_authenticate->value.len = ngx_strlen(bearer_data);

    assert(request->headers_out.www_authenticate->value.len <= bearer_data_size);

    return write_error_response(request, NGX_HTTP_UNAUTHORIZED, module_location_config);
}

/*
 * Add the error response as a JSON object that is easier to handle than the default HTML response that NGINX returns
 * http://nginx.org/en/docs/dev/development_guide.html#http_response_body
 */
static ngx_int_t write_error_response(ngx_http_request_t *request, ngx_int_t status, phantom_token_configuration_t *module_location_config)
{
    ngx_int_t rc;
    ngx_str_t code;
    ngx_str_t message;
    u_char json_error_data[256];
    ngx_chain_t output;
    ngx_buf_t *body = NULL;
    const char *error_format = NULL;
    size_t error_len = 0;

    if (request->method == NGX_HTTP_HEAD)
    {
        return status;
    }

    body = ngx_calloc_buf(request->pool);
    if (body == NULL)
    {
        ngx_log_error(NGX_LOG_WARN, request->connection->log, 0, "Failed to allocate memory for error body");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    else
    {
        if (status == NGX_HTTP_UNAUTHORIZED)
        {
            ngx_str_set(&code, "unauthorized_request");
            ngx_str_set(&message, "Access denied due to missing, invalid or expired credentials");
        }
        else
        {
            ngx_str_set(&code, "server_error");
            ngx_str_set(&message, "Problem encountered processing the request");
        }

        /* The string length calculation replaces the two '%V' markers with their actual values */
        error_format = "{\"code\":\"%V\",\"message\":\"%V\"}";
        error_len = ngx_strlen(error_format) + code.len + message.len - 4;
        ngx_snprintf(json_error_data, sizeof(json_error_data) - 1, error_format, &code, &message);
        json_error_data[error_len] = 0;

        request->headers_out.status = status;
        request->headers_out.content_length_n = error_len;
        ngx_str_set(&request->headers_out.content_type, "application/json");

        rc = ngx_http_send_header(request);
        if (rc == NGX_ERROR || rc > NGX_OK || request->header_only) {
            return rc;
        }
        
        body->pos = json_error_data;
        body->last = json_error_data + error_len;
        body->memory = 1;
        body->last_buf = 1;
        body->last_in_chain = 1;
        output.buf = body;
        output.next = NULL;

        /* Return an error result, which also requires finalize_request to be called, to prevent a 'header already sent' warning in logs
           https://forum.nginx.org/read.php?29,280514,280521#msg-280521 */
        rc = ngx_http_output_filter(request, &output);
        ngx_http_finalize_request(request, rc);
        return NGX_DONE;
    }
}