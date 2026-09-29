#ifndef NGX_HTTP_AUTO_SSL_FETCH_H
#define NGX_HTTP_AUTO_SSL_FETCH_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_auto_ssl_tar.h"


typedef enum {
    NGX_HTTP_AUTO_SSL_BACKEND_CERTMATE = 0,
    NGX_HTTP_AUTO_SSL_BACKEND_PROVISIONER = 1
} ngx_http_auto_ssl_backend_e;


typedef void (*ngx_http_auto_ssl_fetch_done_pt)(void *data, ngx_int_t status,
    ngx_str_t *cert, ngx_str_t *chain, ngx_str_t *key);


typedef struct ngx_http_auto_ssl_waiter_s  ngx_http_auto_ssl_waiter_t;

struct ngx_http_auto_ssl_waiter_s {
    ngx_http_auto_ssl_waiter_t           *next;
    ngx_http_auto_ssl_fetch_done_pt       handler;
    void                                 *data;
};


typedef struct ngx_http_auto_ssl_inflight_s  ngx_http_auto_ssl_inflight_t;

struct ngx_http_auto_ssl_inflight_s {
    ngx_http_auto_ssl_inflight_t  *next;
    ngx_http_auto_ssl_waiter_t    *waiters;
    ngx_str_t                      key;
    ngx_uint_t                     backend;
};


typedef struct {
    ngx_http_auto_ssl_inflight_t  **buckets;
    ngx_http_auto_ssl_inflight_t   *free;
    ngx_pool_t                     *pool;
    ngx_uint_t                      nbuckets;
} ngx_http_auto_ssl_fetch_table_t;


ngx_http_auto_ssl_fetch_table_t *ngx_http_auto_ssl_fetch_table_create(
    ngx_pool_t *pool, ngx_uint_t nbuckets);

ngx_http_auto_ssl_inflight_t *ngx_http_auto_ssl_fetch_lookup(
    ngx_http_auto_ssl_fetch_table_t *t, ngx_str_t *key, ngx_uint_t backend);

ngx_http_auto_ssl_inflight_t *ngx_http_auto_ssl_fetch_create(
    ngx_http_auto_ssl_fetch_table_t *t, ngx_str_t *key, ngx_uint_t backend,
    ngx_pool_t *key_pool);

ngx_int_t ngx_http_auto_ssl_fetch_attach(ngx_pool_t *pool,
    ngx_http_auto_ssl_inflight_t *inflight,
    ngx_http_auto_ssl_fetch_done_pt handler, void *data);

void ngx_http_auto_ssl_fetch_complete(ngx_http_auto_ssl_fetch_table_t *t,
    ngx_http_auto_ssl_inflight_t *inflight, ngx_int_t status,
    ngx_str_t *cert, ngx_str_t *chain, ngx_str_t *key);

ngx_int_t ngx_http_auto_ssl_extract_bundle(ngx_pool_t *pool, ngx_str_t *body,
    ngx_str_t *prefix, ngx_str_t *cert, ngx_str_t *chain, ngx_str_t *key);

ngx_int_t ngx_http_auto_ssl_decrypt_body(ngx_pool_t *pool,
    u_char node_key[NGX_HTTP_AUTO_SSL_NODE_KEY_LEN], ngx_str_t *in,
    ngx_str_t *out);

ngx_int_t ngx_http_auto_ssl_extract_tar_bundle(ngx_pool_t *pool,
    ngx_str_t *body, ngx_str_t *prefix, ngx_str_t *cert, ngx_str_t *chain,
    ngx_str_t *key);


#endif
