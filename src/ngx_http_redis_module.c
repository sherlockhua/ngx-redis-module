
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_ESCAPE_REDIS NGX_ESCAPE_MEMCACHED

typedef struct {
    ngx_http_upstream_conf_t   upstream;
    ngx_int_t                  index;
    ngx_uint_t                 gzip_flag;
} ngx_http_redis_loc_conf_t;

#define NGX_HTTP_REDIS_BUF_CHAIN 1
#define NGX_HTTP_REDIS_BUF_STR   2

typedef struct {
   union {
       ngx_str_t val;
       ngx_chain_t *chain;
   };

   ngx_int_t size;
   ngx_int_t type;
}ngx_http_redis_buf_t;

typedef struct {
    size_t                     rest;
    ngx_http_request_t        *request;
    ngx_str_t                  key;
} ngx_http_redis_ctx_t;

#define NGX_REDIS_METHOD_NONE    -1
#define NGX_REDIS_METHOD_GET      0
#define NGX_REDIS_METHOD_GETBIT   1
#define NGX_REDIS_METHOD_GETSET   2
#define NGX_REDIS_METHOD_GETRANGE 3

static ngx_int_t ngx_http_redis_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_redis_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_redis_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_redis_filter_init(void *data);
static ngx_int_t ngx_http_redis_filter(void *data, ssize_t bytes);
static void ngx_http_redis_abort_request(ngx_http_request_t *r);
static void ngx_http_redis_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static void *ngx_http_redis_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_redis_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_redis_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_redis_pack(ngx_http_request_t *r, 
    ngx_array_t *array, ngx_chain_t **out);


static ngx_conf_bitmask_t  ngx_http_redis_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_response"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("not_found"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_redis_commands[] = {

    { ngx_string("redis_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_redis_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("redis_bind"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_bind_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_redis_loc_conf_t, upstream.local),
      NULL },

    { ngx_string("redis_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_redis_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("redis_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_redis_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("redis_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_redis_loc_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("redis_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_redis_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("redis_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_redis_loc_conf_t, upstream.next_upstream),
      &ngx_http_redis_next_upstream_masks },

    { ngx_string("redis_gzip_flag"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_redis_loc_conf_t, gzip_flag),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_redis_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_redis_create_loc_conf,    /* create location configuration */
    ngx_http_redis_merge_loc_conf      /* merge location configuration */
};


ngx_module_t  ngx_http_redis_module = {
    NGX_MODULE_V1,
    &ngx_http_redis_module_ctx,        /* module context */
    ngx_http_redis_commands,           /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t  ngx_http_redis_key = ngx_string("redis_key");


#define NGX_HTTP_REDIS_END   (sizeof(ngx_http_redis_end) - 1)
static u_char  ngx_http_redis_end[] = CRLF;


static ngx_int_t
ngx_http_redis_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_http_upstream_t            *u;
    ngx_http_redis_ctx_t       *ctx;
    ngx_http_redis_loc_conf_t  *mlcf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;

    ngx_str_set(&u->schema, "redis://");
    u->output.tag = (ngx_buf_tag_t) &ngx_http_redis_module;

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_redis_module);

    u->conf = &mlcf->upstream;

    u->create_request = ngx_http_redis_create_request;
    u->reinit_request = ngx_http_redis_reinit_request;
    u->process_header = ngx_http_redis_process_header;
    u->abort_request = ngx_http_redis_abort_request;
    u->finalize_request = ngx_http_redis_finalize_request;

    ctx = ngx_palloc(r->pool, sizeof(ngx_http_redis_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->rest = NGX_HTTP_REDIS_END;
    ctx->request = r;

    ngx_http_set_ctx(r, ctx, ngx_http_redis_module);

    u->input_filter_init = ngx_http_redis_filter_init;
    u->input_filter = ngx_http_redis_filter;
    u->input_filter_ctx = ctx;

    r->main->count++;

    //ngx_http_upstream_init(r);
    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}

/*
 *创建一个request，用来与后端服务交互。
 *打包格式是ngx_chain_t
 */
/*
static ngx_int_t
ngx_http_redis_create_request(ngx_http_request_t *r)
{
    ngx_http_upstream_t            *u;
    ngx_chain_t                   *body;
    ngx_chain_t                   *cl;
    ngx_buf_t                      *last;
    ngx_buf_t                      *b;
    ngx_int_t                      len;

    u = r->upstream;
    if (!u->request_bufs) {
        return NGX_HTTP_BAD_REQUEST;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->next = NULL;
    body = u->request_bufs;
    if (body) {
        u->request_bufs = cl;
    } 

    while (body) {
        last = body->buf;
        b = ngx_alloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));
        cl->buf = b;

        cl->next = ngx_alloc_chain_link(r->pool);
        if (cl->next == NULL) {
            return NGX_ERROR;
        }

        cl = cl->next;
        cl->next = NULL;

        body = body->next;
        if (last->last_buf) {
            b->last_buf = 0;
            len = 2; 
            b = ngx_create_temp_buf(r->pool, len);
            if (b == NULL) {
                return NGX_ERROR;
            }

            *b->last++ = '\r';
            *b->last++ = '\n';

            cl->buf = b;
            b->last_buf = 1;

            break;
        }
    }

    return NGX_OK;
}
*/

static ngx_int_t
ngx_http_redis_pack_get(ngx_http_request_t *r, u_char* p, u_char* last,
        ngx_variable_value_t *v, ngx_chain_t **cl)
{
    ngx_array_t redis_array;
    ngx_int_t escape = 0;
    ngx_http_redis_buf_t *item;

    if (ngx_array_init(&redis_array, r->pool, 8, sizeof(ngx_http_redis_buf_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    item = ngx_array_push(&redis_array);
    item->type = NGX_HTTP_REDIS_BUF_STR;
    item->val.data = (u_char*)"get";
    item->val.len = sizeof("get") - 1;

    item = ngx_array_push(&redis_array);
    item->type = NGX_HTTP_REDIS_BUF_STR;
    escape = 2 * ngx_escape_uri(NULL, v->data, v->len, NGX_ESCAPE_MEMCACHED);
    if (escape) {
        item->val.data = (u_char*)ngx_palloc(r->pool, escape + v->len);
        u_char *end = (u_char*)ngx_escape_uri(item->val.data, v->data, v->len, NGX_ESCAPE_MEMCACHED);
       
        item->val.len = end - item->val.data;
    } else {
        item->val.data = (u_char*)ngx_palloc(r->pool, v->len);
        u_char* end = ngx_copy(item->val.data, v->data, v->len);
        item->val.len = end - item->val.data;
    }

    return ngx_http_redis_pack(r, &redis_array, cl);
}

static ngx_int_t
ngx_http_redis_pack_getset(ngx_http_request_t *r, u_char* p, u_char* last,
        ngx_variable_value_t *v, ngx_chain_t **cl)
{

    ngx_array_t redis_array;
    ngx_int_t escape = 0;
    ngx_http_redis_buf_t *item;
    ngx_http_upstream_t *u = r->upstream;

    if (!u->request_bufs) {
        return NGX_ERROR;
    }

    if (ngx_array_init(&redis_array, r->pool, 8, sizeof(ngx_http_redis_buf_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    item = ngx_array_push(&redis_array);
    item->type = NGX_HTTP_REDIS_BUF_STR;
    item->val.data = (u_char*)"getset";
    item->val.len = sizeof("getset") - 1;

    item = ngx_array_push(&redis_array);
    item->type = NGX_HTTP_REDIS_BUF_STR;
    escape = 2 * ngx_escape_uri(NULL, v->data, v->len, NGX_ESCAPE_MEMCACHED);
    if (escape) {
        item->val.data = (u_char*)ngx_palloc(r->pool, escape + v->len);
        u_char *end = (u_char*)ngx_escape_uri(item->val.data, v->data, v->len, NGX_ESCAPE_MEMCACHED);
       
        item->val.len = end - item->val.data;
    } else {
        item->val.data = (u_char*)ngx_palloc(r->pool, v->len);
        u_char* end = ngx_copy(item->val.data, v->data, v->len);
        item->val.len = end - item->val.data;
    }

    //value
    item = ngx_array_push(&redis_array);
    item->type = NGX_HTTP_REDIS_BUF_CHAIN;
    item->chain = u->request_bufs;

    return ngx_http_redis_pack(r, &redis_array, cl);
}

static ngx_int_t
ngx_http_redis_pack_getbit(ngx_http_request_t *r, u_char* p, u_char* last,
        ngx_variable_value_t *v, ngx_chain_t **cl)
{
    ngx_array_t redis_array;
    ngx_int_t escape = 0;
    ngx_http_redis_buf_t *item;
    ngx_str_t offset = ngx_null_string;

    if (ngx_array_init(&redis_array, r->pool, 8, sizeof(ngx_http_redis_buf_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    item = ngx_array_push(&redis_array);
    item->type = NGX_HTTP_REDIS_BUF_STR;
    item->val.data = (u_char*)"getbit";
    item->val.len = sizeof("getbit") - 1;

    item = ngx_array_push(&redis_array);
    item->type = NGX_HTTP_REDIS_BUF_STR;
    escape = 2 * ngx_escape_uri(NULL, v->data, v->len, NGX_ESCAPE_MEMCACHED);
    if (escape) {
        item->val.data = (u_char*)ngx_palloc(r->pool, escape + v->len);
        u_char *end = (u_char*)ngx_escape_uri(item->val.data, v->data, v->len, NGX_ESCAPE_MEMCACHED);
       
        item->val.len = end - item->val.data;
    } else {
        item->val.data = (u_char*)ngx_palloc(r->pool, v->len);
        u_char* end = ngx_copy(item->val.data, v->data, v->len);
        item->val.len = end - item->val.data;
    }

    //start
    offset.data = p;
    offset.len = last - p;

    if (offset.len == 0) {
        return NGX_ERROR;
    }

    //start
    item = ngx_array_push(&redis_array);
    item->type = NGX_HTTP_REDIS_BUF_STR;
    item->val = offset;

    return ngx_http_redis_pack(r, &redis_array, cl);
}

static ngx_int_t ngx_http_redis_get_buf_len(ngx_int_t len)
{
    if (len < 10) {
        return 2;
    } else if (len < 100) {
        return 3;
    } else if (len < 1000) {
        return 4;
    } else if (len < 10000) {
        return 5;
    } else if (len < 100000) {
        return 6;
    } else if (len < 1000000) {
        return 7;
    } else if (len < 10000000) {
        return 8;
    } else if (len < 100000000) {
        return 9;
    } else if (len < 1000000000) {
        return 10;
    } 

    return 12;
}

static ngx_int_t ngx_http_redis_pack(ngx_http_request_t *r, ngx_array_t *array, ngx_chain_t **out)
{
    ngx_chain_t **cl;
    ngx_buf_t *buf;
    //ngx_int_t escape = 0;
    ngx_int_t buf_len = 0;
    ngx_uint_t index = 0;

    *out = ngx_alloc_chain_link(r->pool);
    if (*out == NULL) {
        return NGX_ERROR;
    }

    cl = out;
    buf_len = ngx_http_redis_get_buf_len(array->nelts) + sizeof("\r\n") - 1;
    buf = ngx_create_temp_buf(r->pool, buf_len);
    //header(*xx)
    buf->last = ngx_snprintf(buf->last, buf->end - buf->last, "*%d\r\n", array->nelts);
    (*cl)->buf = buf;
    (*cl)->next = NULL; 

    cl = &((*out)->next);
    ngx_http_redis_buf_t *elts = array->elts;
    for (; index < array->nelts; index++) {
        buf_len = 0;
        ngx_http_redis_buf_t redis_buf = elts[index];

        if (*cl == NULL) {
            *cl = ngx_alloc_chain_link(r->pool);
            (*cl)->next = NULL;
        }

        if (redis_buf.type == NGX_HTTP_REDIS_BUF_STR) {
            buf_len += redis_buf.val.len +  sizeof("\r\n") - 1;
            buf_len += ngx_http_redis_get_buf_len(redis_buf.val.len) + sizeof("\r\n") - 1;

            buf = ngx_create_temp_buf(r->pool, buf_len);
            buf->last = ngx_snprintf(buf->last, buf->end - buf->last, "$%d\r\n", redis_buf.val.len);
            buf->last = ngx_copy(buf->last, redis_buf.val.data, redis_buf.val.len);

            *buf->last++ = '\r';
            *buf->last++ = '\n';

            (*cl)->buf = buf;
            cl = &((*cl)->next);
        } else {
            ngx_int_t chain_len = 0;
            ngx_chain_t *p = redis_buf.chain;
            ngx_chain_t **tail = &p;
            while (p) {
                chain_len += ngx_buf_size(p->buf);
                p->buf->last_buf = 0;

                tail = &(p->next);
                p = p->next;

            }

            buf_len = ngx_http_redis_get_buf_len(chain_len) + sizeof("\r\n") - 1;
            buf = ngx_create_temp_buf(r->pool, buf_len);
            buf->last = ngx_snprintf(buf->last, buf->end - buf->last, "$%d\r\n", chain_len);

            (*cl)->buf = buf;
            cl = &((*cl)->next);

            *cl = redis_buf.chain;

            buf_len = sizeof("\r\n") - 1;
            buf = ngx_create_temp_buf(r->pool, buf_len);
            *buf->last++ = '\r';
            *buf->last++ = '\n';

            buf->last_buf = 1;

            *tail =  ngx_alloc_chain_link(r->pool);
            (*tail)->buf = buf;
            (*tail)->next = NULL;
        }
    }
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_redis_pack_getrange(ngx_http_request_t *r, u_char* p, u_char* last,
        ngx_variable_value_t *v, ngx_chain_t **cl)
{
    ngx_array_t redis_array;
    ngx_int_t escape = 0;
    ngx_http_redis_buf_t *item;
    ngx_str_t start = ngx_null_string, end = ngx_null_string;

    if (ngx_array_init(&redis_array, r->pool, 8, sizeof(ngx_http_redis_buf_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    item = ngx_array_push(&redis_array);
    item->type = NGX_HTTP_REDIS_BUF_STR;
    item->val.data = (u_char*)"getrange";
    item->val.len = sizeof("getrange") - 1;

    item = ngx_array_push(&redis_array);
    item->type = NGX_HTTP_REDIS_BUF_STR;
    escape = 2 * ngx_escape_uri(NULL, v->data, v->len, NGX_ESCAPE_MEMCACHED);
    if (escape) {
        item->val.data = (u_char*)ngx_palloc(r->pool, escape + v->len);
        u_char *end = (u_char*)ngx_escape_uri(item->val.data, v->data, v->len, NGX_ESCAPE_MEMCACHED);
       
        item->val.len = end - item->val.data;
    } else {
        item->val.data = (u_char*)ngx_palloc(r->pool, v->len);
        u_char* end = ngx_copy(item->val.data, v->data, v->len);
        item->val.len = end - item->val.data;
    }

    //start
    start.data = p;
    for (; p < last; p++) {
       if (*p == '&') {
           start.len = p - start.data;
           if (p + 1 == last) {
               return NGX_ERROR;
           }

           end.data = p + 1;
           end.len = last - p - 1;
       } 
    }

    if (start.len == 0 || end.len == 0) {
        return NGX_ERROR;
    }

    //start
    item = ngx_array_push(&redis_array);
    item->type = NGX_HTTP_REDIS_BUF_STR;
    item->val = start;

    //end
    item = ngx_array_push(&redis_array);
    item->type = NGX_HTTP_REDIS_BUF_STR;
    item->val = end;

    return ngx_http_redis_pack(r, &redis_array, cl);
 
}

static ngx_int_t
ngx_http_redis_process_get(ngx_http_request_t *r, u_char* p, u_char* last,
        ngx_variable_value_t *v, ngx_chain_t **cl)
{
    u_char                    *start     = p;
    ngx_int_t                 method_len = 0;
    ngx_int_t                 method     = NGX_REDIS_METHOD_NONE;

    for (; p < last; p++) {
        if (*p == '&') {
            p++;
            break;
        }

        method_len++;
    }

    if (method_len < 3) {
        return NGX_HTTP_BAD_REQUEST;
    }
    
    if((start[0] != 'g' && start[0] != 'G') ||
        (start[1] != 'e' && start[1] != 'E') ||
        (start[2] != 't' && start[2] != 'T')) {

        return NGX_HTTP_BAD_REQUEST;
    }

    switch(method_len) {
        case 3:
            method = NGX_REDIS_METHOD_GET;
            break;

        case 6:
            if ((start[3] == 'b' || start[3] == 'B') &&
                    (start[4] == 'i' || start[4] != 'I') &&
                    (start[5] != 't' || start[5] != 'T')) {

                method = NGX_REDIS_METHOD_GETBIT;
                break;
            }

            if ((start[3] == 's' || start[3] == 'S') &&
                    (start[4] == 'e' || start[4] != 'E') &&
                    (start[5] != 't' || start[5] != 'T')) {

                method = NGX_REDIS_METHOD_GETSET;
                break;
            }
            break;

        case 8:
            if ((start[3] == 'r' || start[3] == 'R') &&
                    (start[4] == 'a' || start[4] != 'A') &&
                    (start[5] != 'n' || start[5] != 'N') &&
                    (start[6] != 'g' || start[6] != 'G') &&
                    (start[7] != 'e' || start[7] != 'E')) {

                method = NGX_REDIS_METHOD_GETRANGE;
                break;
            }
            break;

        default:
            return NGX_HTTP_BAD_REQUEST;
    }

    //pack method
    switch (method) {
        case NGX_REDIS_METHOD_GET:
            return ngx_http_redis_pack_get(r, p, last, v, cl);
        case NGX_REDIS_METHOD_GETBIT:
            return ngx_http_redis_pack_getbit(r, p, last, v, cl);
        case NGX_REDIS_METHOD_GETSET:
            return ngx_http_redis_pack_getset(r, p, last, v, cl);
        case NGX_REDIS_METHOD_GETRANGE:
            return ngx_http_redis_pack_getrange(r, p, last, v, cl);
        default:
            break;
    }

    return NGX_HTTP_BAD_REQUEST;
}

static ngx_int_t
ngx_http_redis_create_request(ngx_http_request_t *r)
{
    ngx_int_t                 rc = NGX_ERROR;
    ngx_http_redis_loc_conf_t   *rlcf;
    //ngx_http_redis_ctx_t        *ctx;
    ngx_http_variable_value_t *vv;

    ngx_http_upstream_t            *u = r->upstream;
    ngx_chain_t                   *cl = NULL;
    u_char  *p, *last;

    if (r->args.len == 0) {
        return NGX_ERROR;
    }

    rlcf = ngx_http_get_module_loc_conf(r, ngx_http_redis_module);
    vv = ngx_http_get_indexed_variable(r, rlcf->index);

    if (vv == NULL || vv->not_found || vv->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "the \"$redis_key\" variable is not set");
        return NGX_ERROR;
    }

    p = r->args.data;
    last = p + r->args.len;

    switch (*p) {
        case 'g':
        case 'G':
            rc = ngx_http_redis_process_get(r, p, last, vv, &cl);
            break;
        default:
            break;
    }

    if (rc != NGX_OK) {
        return rc;
    }

    u->request_bufs = cl;
    return NGX_OK;
}


static ngx_int_t
ngx_http_redis_reinit_request(ngx_http_request_t *r)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_redis_process_header(ngx_http_request_t *r)
{
    u_char                         *p;//, *start;
    //ngx_str_t                       line;
    //ngx_uint_t                      flags;
    //ngx_table_elt_t                *h;
    ngx_http_upstream_t            *u;
    //ngx_http_redis_ctx_t       *ctx;
    //ngx_http_redis_loc_conf_t  *mlcf;

    u = r->upstream;

    for (p = u->buffer.pos; p < u->buffer.last; p++) {
        if (*p == LF) {
            goto found;
        }
    }

    return NGX_AGAIN;

found:

    *p = '\0';
    switch (u->buffer.pos[0]) {
        case '+':
        case '-':
        case ':':
            u->headers_in.content_length_n = p - u->buffer.pos - 1;
            u->headers_in.status_n = 200;
            u->state->status = 200;
            return NGX_OK;
        case '$':
            {
                u->headers_in.content_length_n = ngx_atoof(u->buffer.pos + 1, p - u->buffer.pos - 2);
                if (u->headers_in.content_length_n == -1) {
                    u->headers_in.status_n = 404;
                    u->state->status = 404;
                }else {
                    u->headers_in.status_n = 200;
                    u->state->status = 200;
                    u->buffer.pos = p + 1;
                }
            } 
    }

    return NGX_OK;
    /*
no_valid:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "redis sent invalid response: \"%V\"", &line);

    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    */
}


static ngx_int_t
ngx_http_redis_filter_init(void *data)
{
    ngx_http_redis_ctx_t  *ctx = data;

    ngx_http_upstream_t  *u;

    u = ctx->request->upstream;

    u->length += NGX_HTTP_REDIS_END;

    return NGX_OK;
}


static ngx_int_t
ngx_http_redis_filter(void *data, ssize_t bytes)
{
    ngx_http_redis_ctx_t  *ctx = data;

    u_char               *last;
    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;

    u = ctx->request->upstream;
    b = &u->buffer;

    if (u->length == (ssize_t) ctx->rest) {

        if (ngx_strncmp(b->last,
                   ngx_http_redis_end + NGX_HTTP_REDIS_END - ctx->rest,
                   bytes)
            != 0)
        {
            ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                          "redis sent invalid trailer");

            u->length = 0;
            ctx->rest = 0;

            return NGX_OK;
        }

        u->length -= bytes;
        ctx->rest -= bytes;

        if (u->length == 0) {
            u->keepalive = 1;
        }

        return NGX_OK;
    }

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_chain_get_free_buf(ctx->request->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    *ll = cl;

    last = b->last;
    cl->buf->pos = last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "redis filter bytes:%z size:%z length:%z rest:%z",
                   bytes, b->last - b->pos, u->length, ctx->rest);

    if (bytes <= (ssize_t) (u->length - NGX_HTTP_REDIS_END)) {
        u->length -= bytes;
        return NGX_OK;
    }

    last += u->length - NGX_HTTP_REDIS_END;

    if (ngx_strncmp(last, ngx_http_redis_end, b->last - last) != 0) {
        ngx_log_error(NGX_LOG_ERR, ctx->request->connection->log, 0,
                      "redis sent invalid trailer");

        b->last = last;
        cl->buf->last = last;
        u->length = 0;
        ctx->rest = 0;

        return NGX_OK;
    }

    ctx->rest -= b->last - last;
    b->last = last;
    cl->buf->last = last;
    u->length = ctx->rest;

    if (u->length == 0) {
        u->keepalive = 1;
    }

    return NGX_OK;
}


static void
ngx_http_redis_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http redis request");
    return;
}


static void
ngx_http_redis_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http redis request");
    return;
}


static void *
ngx_http_redis_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_redis_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_redis_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.uri = { 0, NULL };
     *     conf->upstream.location = NULL;
     */

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;

    conf->index = NGX_CONF_UNSET;
    conf->gzip_flag = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_redis_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_redis_loc_conf_t *prev = parent;
    ngx_http_redis_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (conf->index == NGX_CONF_UNSET) {
        conf->index = prev->index;
    }

    ngx_conf_merge_uint_value(conf->gzip_flag, prev->gzip_flag, 0);

    return NGX_CONF_OK;
}


static char *
ngx_http_redis_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_redis_loc_conf_t *mlcf = conf;

    ngx_str_t                 *value;
    ngx_url_t                  u;
    ngx_http_core_loc_conf_t  *clcf;

    if (mlcf->upstream.upstream) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    mlcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (mlcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_redis_handler;

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    mlcf->index = ngx_http_get_variable_index(cf, &ngx_http_redis_key);

    if (mlcf->index == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
