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
#include <assert.h>
#include <stdbool.h>

#define ACCESS_TOKEN_BUF_LEN 45

#define ERROR_CODE_INVALID_REQUEST "invalid_request"
#define ERROR_CODE_INVALID_TOKEN "invalid_token"
#define ERROR_CODE_INSUFFICIENT_SCOPE "insufficient_scope"

/**
 * Calculate the length needed to store a user ID and secret in a nul-terminated string
 *
 * @param id the user/client identifier
 * @param secret the shared secret used to authenticate the user/client
 */
#define basic_credential_length(id, secret) ((id) + (sizeof(":") - 1) + (secret) + (sizeof("\0") - 1))

typedef struct
{
    ngx_str_t base64encoded_client_credentials;
    ngx_str_t client_id;
    ngx_str_t client_secret;
    ngx_str_t introspection_endpoint;
    ngx_str_t realm;
    ngx_array_t *scopes;
    ngx_str_t space_separated_scopes;
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

/**
 * Adds a WWW-Authenticate header to the given request's output headers that conforms to <a href="https://tools.ietf.org/html/rfc6750">RFC 6750</>
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
 * @return NGX_HTTP_UNAUTHORIZED
 *
 * @example WWW-Authenticate: Bearer realm="myGoodRealm", scope="scope1 scope2 scope3"
 *
 * @see <a href="https://tools.ietf.org/html/rfc6750">RFC 6750</a>
 */
static ngx_int_t set_www_authenticate_header(ngx_http_request_t *request, ngx_str_t realm,
                                             ngx_str_t space_separated_scopes, char *error_code);

const static char JWT_KEY[] = "\"jwt\":\"";
const static char BEARER[] = "Bearer ";
const static size_t BEARER_SIZE = sizeof(BEARER) - 1;

/**
 * This module provided directive: access_token_to_jwt.
 */
static ngx_command_t ngx_http_access_token_to_jwt_commands[] =
{
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
    {
        ngx_string("access_token_to_jwt_realm"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_access_token_to_jwt_conf_t, realm),
        NULL
    },
    {
        ngx_string("access_token_to_jwt_scopes"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_access_token_to_jwt_conf_t, space_separated_scopes),
        NULL
    },
    {
        ngx_string("access_token_to_jwt_scope"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_access_token_to_jwt_conf_t, scopes),
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

        return set_www_authenticate_header(request, module_location_config->realm,
                                           module_location_config->space_separated_scopes, NULL);
    }

    u_char *bearer_token_pos;

    if ((bearer_token_pos = (u_char *)strcasestr((char*)request->headers_in.authorization->value.data, BEARER)) == NULL)
    {
        // return unauthorized when Authorization header is not Bearer

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, request->connection->log, 0,
                       "Authorization header does not contain a bearer token");

        return set_www_authenticate_header(request, module_location_config->realm,
                                           module_location_config->space_separated_scopes, NULL);
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

    introspection_request_body_buffer->temporary = true;

    introspection_request_body->bufs = ngx_alloc_chain_link(request->pool);

    if (introspection_request_body->bufs == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    introspection_request_body->bufs->buf = introspection_request_body_buffer;
    introspection_request_body->bufs->next = NULL;
    introspection_request_body->buf = introspection_request_body_buffer;
    introspection_request->request_body = introspection_request_body;
    introspection_request->headers_in.content_length_n = ngx_buf_size(introspection_request_body_buffer);

    introspection_request->header_only = true;
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

static ngx_int_t set_www_authenticate_header(ngx_http_request_t *request, ngx_str_t realm,
                                             ngx_str_t space_separated_scopes, char *error_code)
{
    request->headers_out.www_authenticate = ngx_list_push(&request->headers_out.headers);

    if (request->headers_out.www_authenticate == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    const static char REALM_PREFIX[] = "realm=\"";
    const static size_t REALM_PREFIX_SIZE = sizeof(REALM_PREFIX) - 1;

    const static char TOKEN_SUFFIX[] = "\"";
    const static size_t TOKEN_SUFFIX_SIZE = sizeof(TOKEN_SUFFIX) - 1;

    const static char TOKEN_SEPARATER[] = ", ";
    const static size_t TOKEN_SEPARATER_SIZE = sizeof(TOKEN_SEPARATER) - 1;

    const static char SCOPE_PREFIX[] = "scope=\"";
    const static size_t SCOPE_PREFIX_SIZE = sizeof(SCOPE_PREFIX) - 1;

    const static u_char ERROR_CODE_PREFIX[] = "error=\"";
    const static size_t ERROR_CODE_PREFIX_SIZE = sizeof(ERROR_CODE_PREFIX) - 1;

    size_t bearer_data_size = BEARER_SIZE + sizeof('\0'); // Add one for the nul byte
    bool realm_provided = realm.len > 0;
    bool scopes_provided = space_separated_scopes.len > 0;
    bool error_code_provided = error_code != NULL;
    bool append_one_comma = false, append_two_commas = false;
    size_t error_code_len = 0;

    if (realm_provided)
    {
        bearer_data_size += REALM_PREFIX_SIZE + realm.len + TOKEN_SUFFIX_SIZE;
    }

    if (scopes_provided)
    {
        bearer_data_size += SCOPE_PREFIX_SIZE + space_separated_scopes.len + TOKEN_SUFFIX_SIZE;
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
        p = ngx_cpymem(p, realm.data, realm.len);
        p = ngx_cpymem(p, TOKEN_SUFFIX, TOKEN_SUFFIX_SIZE);

        if (append_one_comma)
        {
            p = ngx_cpymem(p, TOKEN_SEPARATER, TOKEN_SEPARATER_SIZE);
        }
    }

    if (scopes_provided)
    {
        p = ngx_cpymem(p, SCOPE_PREFIX, SCOPE_PREFIX_SIZE);
        p = ngx_cpymem(p, space_separated_scopes.data, space_separated_scopes.len);
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

    return NGX_HTTP_UNAUTHORIZED;
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

    conf->scopes = NGX_CONF_UNSET_PTR;

    return conf;
}

static char *ngx_http_access_token_to_jwt_merge_loc_conf(ngx_conf_t *config, void *parent, void *child)
{
    ngx_http_access_token_to_jwt_conf_t *parent_config = parent, *child_config = child;

    ngx_conf_merge_str_value(child_config->client_id, parent_config->client_id, "");
    ngx_conf_merge_str_value(child_config->client_secret, parent_config->client_secret, "");
    ngx_conf_merge_str_value(child_config->introspection_endpoint, parent_config->introspection_endpoint, "");
    ngx_conf_merge_str_value(child_config->realm, parent_config->realm, "");
    ngx_conf_merge_ptr_value(child_config->scopes, parent_config->scopes, NULL);
    ngx_conf_merge_str_value(child_config->space_separated_scopes, parent_config->space_separated_scopes, "");

    if (child_config->scopes != NULL && child_config->space_separated_scopes.len == 0)
    {
        // Flatten scopes into a space-separated list
        ngx_str_t *scope = child_config->scopes->elts;
        size_t space_separated_scopes_data_size = child_config->scopes->nelts;

        for (ngx_uint_t i = 0; i < child_config->scopes->nelts; i++)
        {
            space_separated_scopes_data_size += scope[i].len;
        }

        u_char *space_separated_scopes_data = ngx_pcalloc(config->pool, space_separated_scopes_data_size);

        if (space_separated_scopes_data == NULL)
        {
            return NGX_CONF_ERROR;
        }

        u_char *p = space_separated_scopes_data;

        for (ngx_uint_t i = 0; i < child_config->scopes->nelts; i++)
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

    //TODO consider moving this logic
    if (child_config->base64encoded_client_credentials.len == 0 && child_config->client_id.len > 0 && child_config->client_secret.len > 0)
    {
        ngx_str_t *unencoded_client_credentials = ngx_pcalloc(config->pool, sizeof(ngx_str_t));

        if (unencoded_client_credentials == NULL)
        {
            return NGX_CONF_ERROR;
        }

        size_t unencoded_client_credentials_data_size = basic_credential_length(child_config->client_id.len, child_config->client_secret.len);

        u_char *unencoded_client_credentials_data = ngx_pcalloc(config->pool, unencoded_client_credentials_data_size);

        if (unencoded_client_credentials_data == NULL)
        {
            return NGX_CONF_ERROR;
        }

        unencoded_client_credentials->data = unencoded_client_credentials_data;
        unencoded_client_credentials->len = unencoded_client_credentials_data_size - 1;

        ngx_snprintf(unencoded_client_credentials_data, unencoded_client_credentials_data_size, "%V:%V",
                     &child_config->client_id, &child_config->client_secret);

        child_config->base64encoded_client_credentials.data = ngx_pcalloc(
                config->pool, ngx_base64_encoded_length(unencoded_client_credentials_data_size - 1));

        if (child_config->base64encoded_client_credentials.data == NULL)
        {
            return NGX_CONF_ERROR;
        }

        ngx_encode_base64(&child_config->base64encoded_client_credentials, unencoded_client_credentials);

        ngx_pfree(config->pool, unencoded_client_credentials);
    }

    return NGX_CONF_OK;
}
