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

#ifndef NGX_HTTP_ACCESS_TOKEN_TO_JWT_H
#define NGX_HTTP_ACCESS_TOKEN_TO_JWT_H

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

typedef struct ngx_http_access_token_to_jwt_conf_s
{
    ngx_str_t base64encoded_client_credential;
    ngx_str_t introspection_endpoint;
    ngx_str_t realm;
    ngx_array_t *scopes;
    ngx_str_t space_separated_scopes;
} ngx_http_access_token_to_jwt_conf_t;

typedef struct ngx_http_access_token_to_jwt_ctx_s
{
    ngx_uint_t done;
    ngx_uint_t status;
    ngx_str_t jwt;
    ngx_http_request_t *subrequest;
} ngx_http_access_token_to_jwt_ctx_t;

extern ngx_module_t ngx_http_access_token_to_jwt_module;

#endif // NGX_HTTP_ACCESS_TOKEN_TO_JWT_H
