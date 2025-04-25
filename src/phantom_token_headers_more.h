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

#ifndef PHANTOM_TOKEN_HEADERS_MORE
#define PHANTOM_TOKEN_HEADERS_MORE

ngx_int_t headers_more_set_header_in(ngx_http_request_t *r, ngx_str_t key, ngx_str_t value, ngx_table_elt_t **output_header);
ngx_int_t headers_more_clear_header_in(ngx_http_request_t *r, ngx_str_t key);

#endif
