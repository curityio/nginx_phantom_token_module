/*
 *  Copyright 2025 Curity AB
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
#include "phantom_token.h"
#include "phantom_token_utils.h"

extern const char BEARER[];
extern const size_t BEARER_SIZE;

/**
 * Add the error response as a JSON object that is easier to handle than the default HTML response that NGINX returns
 * http://nginx.org/en/docs/dev/development_guide.html#http_response_body
 */
ngx_int_t utils_write_error_response(ngx_http_request_t *request, ngx_int_t status, phantom_token_configuration_t *module_location_config)
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
ngx_int_t utils_set_www_authenticate_header(ngx_http_request_t *request, phantom_token_configuration_t *module_location_config, char *error_code)
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

    return utils_write_error_response(request, NGX_HTTP_UNAUTHORIZED, module_location_config);
}


/**
 * A common routine to attempt to log memory allocation errors
 */
void utils_log_memory_allocation_error(ngx_http_request_t *request, const char *operation)
{
    ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, "Failed to allocate memory for: %s", operation);
}
