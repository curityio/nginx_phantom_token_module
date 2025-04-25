#ifndef PHANTOM_TOKEN_HEADERS_MORE
#define PHANTOM_TOKEN_HEADERS_MORE

ngx_int_t headers_more_remove_header_in(ngx_list_t *l, ngx_list_part_t *cur, ngx_uint_t i);
ngx_int_t headers_more_set_header_in(ngx_http_request_t *r, ngx_str_t key, ngx_str_t value, ngx_table_elt_t **output_header);
void headers_more_clear_header_in(ngx_http_request_t *r, ngx_str_t key);

#endif
