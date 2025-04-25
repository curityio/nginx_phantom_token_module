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

/********************************************************************************************************************
 * This module manipulates headers using code from the mature headers-more library.
 * The code is based on the 0.38 tag from January 2025 and is slightly adapted to remove headers-more specific types.
 * - https://github.com/openresty/headers-more-nginx-module
 *
 * In NGINX, headers are a linked list of buffers (ngx_list_t).
 * Each buffer (.part) is an array of struct header (ngx_list_part_t *).
 * When a header is set, removed or updated, buffers and nelts values must be updated accurately.
 * This module deals with all low-level processing to keep other module code business-focused.
 ********************************************************************************************************************/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>
#include <assert.h>

static ngx_int_t headers_more_set_header_in_internal(ngx_http_request_t *r, ngx_str_t key, ngx_str_t value, ngx_table_elt_t **output_header);
static ngx_int_t headers_more_remove_header_in(ngx_list_t *l, ngx_list_part_t *cur, ngx_uint_t i);

/**
 * Set the header with the given key from the list
 * See the headers-more function: set_header_helper
 */
ngx_int_t headers_more_set_header_in(
    ngx_http_request_t *r,
    ngx_str_t key,
    ngx_str_t value,
    ngx_table_elt_t **output_header)
{
    ngx_int_t result = headers_more_set_header_in_internal(r, key, value, output_header);
    if (result == NGX_OK) {

        // TODO: Why is this not handled by headers-more?
        if (r->headers_in.headers.part.next == NULL) {
            r->headers_in.headers.part.nelts = r->headers_in.headers.last->nelts;
        }
    }

    return result;
}

/**
 * Clear a header and update buffers
 */
ngx_int_t headers_more_clear_header_in(ngx_http_request_t *r, ngx_str_t key)
{
    ngx_str_t value = ngx_null_string;
    return headers_more_set_header_in_internal(r, key, value, NULL);
}

/**
 * The internal version does not update nelts
 */
ngx_int_t headers_more_set_header_in_internal(
    ngx_http_request_t *r,
    ngx_str_t key,
    ngx_str_t value,
    ngx_table_elt_t **output_header) {

    ngx_list_part_t *part;
    ngx_table_elt_t *h, *matched;
    ngx_uint_t rc;
    ngx_uint_t i;

    matched = NULL;

retry:

    part = &r->headers_in.headers.part;
    h = part->elts;

    // Replace logic
    for (i = 0;; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            // Walk next part
            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].key.len == key.len &&
            ngx_strncasecmp(h[i].key.data, key.data, key.len) == 0) {
            goto matched;
        }

        /* not matched */

        continue;

    matched:

        // If value is 0, remove the header. If there are duplicates, remove
        // them all.
        if (value.len == 0 || (matched && matched != &h[i])) {
            rc = headers_more_remove_header_in(&r->headers_in.headers, part, i);

            assert(
                !(r->headers_in.headers.part.next == NULL &&
                  r->headers_in.headers.last != &r->headers_in.headers.part));

            if (rc == NGX_OK) {
                if (output_header) { // If output_header is set to old header,
                                     // this clears it.
                    *output_header = NULL;
                }
                goto retry; // Make sure to clean all occurrences.
            }

            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "Replacing header with the same key %V", &key);
        h[i].value = value;
        if (output_header) {
            *output_header = &h[i];
        }
        if (matched == NULL) {
            matched = &h[i];
        }
    }

    if (matched) {
        return NGX_OK;
    }

    if (value.len == 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "Removed header %V", &key);
        return NGX_OK;
    }

    if (r->headers_in.headers.last == NULL) {
        /* must be 400 bad request */
        return NGX_OK;
    }

    // Add logic (field was not found)
    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    h->hash = 1;
    h->key = key;
    h->value = value;
#if defined(nginx_version) && nginx_version >= 1023000
    h->next = NULL;
#endif
    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }
    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    if (output_header) {
        *output_header = h;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "Added header "
                   "with key %V",
                   &key);

    return NGX_OK;
}

/**
 * Remove an element from the list and the part that contains it
 * See the headers more function: ngx_http_headers_more_rm_header_helper
 */
ngx_int_t headers_more_remove_header_in(ngx_list_t *l,
                                        ngx_list_part_t *cur,
                                        ngx_uint_t i) {
    ngx_table_elt_t *data;
    ngx_list_part_t *new, *part;

    data = cur->elts;

    if (i == 0) {
        cur->elts = (char *)cur->elts + l->size;
        cur->nelts--;

        if (cur == l->last) {
            if (cur->nelts == 0) {
#if 1
                part = &l->part;

                if (part == cur) {
                    cur->elts = (char *)cur->elts - l->size;
                    /* do nothing */

                } else {
                    while (part->next != cur) {
                        if (part->next == NULL) {
                            return NGX_ERROR;
                        }

                        part = part->next;
                    }

                    l->last = part;
                    part->next = NULL;
                    l->nalloc = part->nelts;
                }
#endif

            } else {
                l->nalloc--;
            }

            return NGX_OK;
        }

        if (cur->nelts == 0) {
            part = &l->part;

            if (part == cur) {
                assert(cur->next != NULL);

                if (l->last == cur->next) {
                    l->part = *(cur->next);
                    l->last = part;
                    l->nalloc = part->nelts;

                } else {
                    l->part = *(cur->next);
                }

            } else {
                while (part->next != cur) {
                    if (part->next == NULL) {
                        return NGX_ERROR;
                    }

                    part = part->next;
                }

                part->next = cur->next;
            }

            return NGX_OK;
        }

        return NGX_OK;
    }

    if (i == cur->nelts - 1) {
        cur->nelts--;

        if (cur == l->last) {
            l->nalloc = cur->nelts;
        }

        return NGX_OK;
    }

    new = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
    if (new == NULL) {
        return NGX_ERROR;
    }

    new->elts = &data[i + 1];
    new->nelts = cur->nelts - i - 1;
    new->next = cur->next;

    cur->nelts = i;
    cur->next = new;
    if (cur == l->last) {
        l->last = new;
        l->nalloc = new->nelts;
    }

    return NGX_OK;
}
