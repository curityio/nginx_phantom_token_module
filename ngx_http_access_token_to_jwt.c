
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "jsmn.h"



typedef struct {
    ngx_flag_t      enable;
    ngx_str_t       base64encoded_client_credentials;
    ngx_str_t       introspection_endpoint;
    ngx_array_t              *vars;
} ngx_http_access_token_to_jwt_conf_t;

typedef struct {
    ngx_uint_t                done;
    ngx_uint_t                status;
    ngx_str_t                 jwt;
    ngx_http_request_t       *subrequest;
} ngx_http_access_token_to_jwt_ctx_t;


static ngx_int_t ngx_http_access_token_to_jwt_postconfig(ngx_conf_t *cf); 
static ngx_int_t ngx_http_access_token_to_jwt_handler(ngx_http_request_t *r); 
static void *ngx_http_access_token_to_jwt_create_conf(ngx_conf_t *cf);
static char *ngx_http_access_token_to_jwt_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_access_token_to_jwt_request_done(ngx_http_request_t *r, void *data, ngx_int_t rc);
int jsoneq(const char *json, jsmntok_t *tok, const char *s);
/**
 * This module provided directive: access_token_to_jwt.
 *
 */
static ngx_command_t ngx_http_access_token_to_jwt_commands[] = {

    { ngx_string("access_token_to_jwt"), 
        NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, 
        ngx_conf_set_flag_slot, 
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_access_token_to_jwt_conf_t, enable),
        NULL},

      { ngx_string("access_token_to_jwt_base64encoded_client_credentials"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_access_token_to_jwt_conf_t, base64encoded_client_credentials),
        NULL },

      { ngx_string("access_token_to_jwt_introspection_endpoint"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_access_token_to_jwt_conf_t, introspection_endpoint),
        NULL },

        ngx_null_command /* command termination */
};


/* The module context. */
static ngx_http_module_t ngx_http_access_token_to_jwt_module_ctx = {
    NULL, /* preconfiguration */
    ngx_http_access_token_to_jwt_postconfig, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_access_token_to_jwt_create_conf, /* create location configuration */
    ngx_http_access_token_to_jwt_merge_conf /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_access_token_to_jwt_module = {
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



static ngx_int_t ngx_http_access_token_to_jwt_handler(ngx_http_request_t *r) { 

    ngx_http_request_t            *sr;
    ngx_http_post_subrequest_t    *ps;
    ngx_http_access_token_to_jwt_ctx_t   *ctx;
    ngx_http_access_token_to_jwt_conf_t  *arcf;
    ngx_http_request_body_t     *rb = NULL;
    ngx_buf_t                   *b;

    
    

    arcf = ngx_http_get_module_loc_conf(r, ngx_http_access_token_to_jwt_module);
    // return OK if the module is not active or properly configured
    if (!arcf->enable || arcf->base64encoded_client_credentials.len == 0 || arcf->introspection_endpoint.len == 0) {
         ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Module disabled or not configured properly");
         return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_access_token_to_jwt_module);
    
    if (ctx != NULL) {
        if (!ctx->done) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Called again without having received the response from Curity");
            return NGX_AGAIN;
        }

        // return appropriate status 
        if (ctx->status >= NGX_HTTP_OK
            && ctx->status < NGX_HTTP_SPECIAL_RESPONSE)
        {
            // replace the original request's authorization header with the jwt
            // todo add Bearer
            r->headers_in.authorization->value.len = ctx->jwt.len;
            r->headers_in.authorization->value.data = ctx->jwt.data;
            return NGX_OK;
        }
        // should handle other HTTP codes accordingly. Till then return 401 for any request that was not legal
        return NGX_HTTP_UNAUTHORIZED;
    }

     
    // return unauthorized when no Authorization header is present
    if (!r->headers_in.authorization){
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Authorization header not present");
        return NGX_HTTP_UNAUTHORIZED;
    }

    // todo check http spec for bearer spaces before, after and lower-upper case
    int ret;
    char * bearer = "Bearer ";
   
    ret = strncmp(bearer, (char *)r->headers_in.authorization->value.data, 7);

    // return unauthorized when Authorization header is not Bearer
    if (ret != 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Authorization header not formatted properly");
        return NGX_HTTP_UNAUTHORIZED;
    }

    
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_access_token_to_jwt_ctx_t));
    if (ctx == NULL) {
        // could not allocate space for context
        return NGX_ERROR;
    }

    ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (ps == NULL) {
        // could not allocate space for post request
        return NGX_ERROR;
    }

    ps->handler = ngx_http_access_token_to_jwt_request_done;
    ps->data = ctx;


    if (ngx_http_subrequest(r, &arcf->introspection_endpoint, NULL, &sr, ps,
                            NGX_HTTP_SUBREQUEST_WAITED)
        != NGX_OK)
    {
        return NGX_ERROR;
    }


    // extract access token from header
    int header_length = r->headers_in.authorization->value.len;
    char  access_token[header_length-7+1];
    char  original_header[header_length+1];

    strncpy(original_header, (char *) r->headers_in.authorization->value.data,  header_length+1); //
    strncpy(access_token, &original_header[7], header_length-7+1);
    
    char body[sizeof(access_token) + 6-1]; // Token=xyz
    strcpy(body, "token=");
    strcat(body, access_token);

    // todo check cache, if access_token association is there just set 
    // r->header_in.authorization "Bearer jwt" and return NGX_OK

    
    ngx_str_t * body_str = ngx_palloc(r->pool, sizeof(ngx_str_t));
    body_str->len = sizeof(body);
    body_str->data = (u_char *) body;
    
    sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (sr->request_body == NULL) {
        // Cannot allocate for request body
        return NGX_ERROR;
    }

    rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        // Cannot allocate for rb
        return NGX_ERROR;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
            // Cannot allocate for buf
        return NGX_ERROR;
    }

    b->start = b->pos = body_str->data;
    b->end = b->last = body_str->data + body_str->len;
    
    b->temporary = 1;
    // b->memory = 1;
        
    rb->bufs = ngx_alloc_chain_link(r->pool);
    if (rb->bufs == NULL) {
        // Cannot allocate memory for bufs
        return NGX_ERROR;
    }
    rb->bufs->buf = b;
    rb->bufs->next = NULL;
    rb->buf = b;
    sr->request_body = rb;
    sr->headers_in.content_length_n = body_str->len;


    sr->header_only = 1;
    ctx->subrequest = sr;

    // Change subrequest method to POST
    ngx_str_t method_name = ngx_string("POST"); 
    sr->method = NGX_HTTP_POST; 
    sr->method_name = method_name; 

    // set authorization header to Basic base64encoded_client_credentials
    char strbuf[arcf->base64encoded_client_credentials.len+6];

    strcpy(strbuf, "Basic ");
    strcat(strbuf, (char *)arcf->base64encoded_client_credentials.data);
   
    sr->headers_in.authorization->value.len = sizeof(strbuf);
    strncpy((char *)sr->headers_in.authorization->value.data, strbuf, sizeof(strbuf));
    
    ngx_http_set_ctx(r, ctx, ngx_http_access_token_to_jwt_module);
    

    return NGX_AGAIN;
}



static ngx_int_t
ngx_http_access_token_to_jwt_request_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_access_token_to_jwt_ctx_t   *ctx = data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request done s:%d", r->headers_out.status);

    ctx->status = r->headers_out.status;

    // fail early for not 200 response
    if (r->headers_out.status != NGX_HTTP_OK){
        ctx->done = 1;
        return rc;
    }

    // body parsing

    va_list   args;
    u_char * start = r->upstream->buffer.pos-1;
    u_char * end = r->upstream->buffer.last;

    jsmn_parser parser;
    jsmn_init(&parser);
    jsmntok_t t[256];
    const char *JSON_STRING;
    int parse_r, i;

    JSON_STRING = (char *)ngx_vslprintf(start, end, "u", args);
    parse_r = jsmn_parse(&parser, JSON_STRING, strlen(JSON_STRING), t, 256);


    // incorporated from jsmn simple example
    if (parse_r < 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "Failed to parse JSON: %d\n", parse_r);
        ctx->done = 1;
        ctx->status = NGX_HTTP_UNAUTHORIZED;
        return NGX_ERROR;
    }

    /* Assume the top-level element is an object */
    if (parse_r < 1 || t[0].type != JSMN_OBJECT) {
        // Object expected
        ctx->done = 1;
        ctx->status = NGX_HTTP_UNAUTHORIZED;
        return NGX_ERROR;
    }

    for (i = 1; i < parse_r; i++) {
        if (jsoneq(JSON_STRING, &t[i], "jwt") == 0) {
            //todo store the jwt to cache
            /* We may use strndup() to fetch string value */
            char *dest[t[i+1].end-t[i+1].start];
            ngx_memcpy(dest, JSON_STRING + t[i+1].start, t[i+1].end-t[i+1].start);
            ctx->jwt.len = t[i+1].end-t[i+1].start;
            ctx->jwt.data = (u_char *) JSON_STRING + t[i+1].start;
            i++;  
        } 
    }
    // todo  if the jwt is not found, change response to 401

    ctx->done = 1;
    return rc;
}


static ngx_int_t ngx_http_access_token_to_jwt_postconfig(ngx_conf_t *cf)
{ 
    
    ngx_http_handler_pt *h; 
    ngx_http_core_main_conf_t *cmcf; 

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module); 

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers); 
        if (h == NULL) { 
        return NGX_ERROR; 
    } 
    *h = ngx_http_access_token_to_jwt_handler; 

    return NGX_OK; 
}


static void *
ngx_http_access_token_to_jwt_create_conf(ngx_conf_t *cf)
{
    ngx_http_access_token_to_jwt_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_access_token_to_jwt_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET; 

    return conf;
}

static char *
ngx_http_access_token_to_jwt_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{   
    ngx_http_access_token_to_jwt_conf_t *prev = parent;
    ngx_http_access_token_to_jwt_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->base64encoded_client_credentials, prev->base64encoded_client_credentials, "");
    ngx_conf_merge_str_value(conf->introspection_endpoint, prev->introspection_endpoint, "");
    return NGX_CONF_OK;
}

int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
            strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

