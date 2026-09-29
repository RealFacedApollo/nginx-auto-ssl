#ifndef NGX_HTTP_AUTO_SSL_CURL_H
#define NGX_HTTP_AUTO_SSL_CURL_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <curl/curl.h>

#include "ngx_http_auto_ssl_fetch.h"


typedef struct {
    ngx_str_t   name;
    ngx_str_t   value;
} ngx_http_auto_ssl_header_t;


typedef struct {
    ngx_str_t                   base;
    ngx_http_auto_ssl_header_t  headers[2];
    ngx_uint_t                  nheaders;
    u_char                      node_key[NGX_HTTP_AUTO_SSL_NODE_KEY_LEN];
    ngx_flag_t                  node_key_set;
} ngx_http_auto_ssl_backend_cfg_t;


ngx_int_t ngx_http_auto_ssl_normalize_base(ngx_pool_t *pool, ngx_str_t *url,
    ngx_str_t *out);

ngx_int_t ngx_http_auto_ssl_build_fetch_url(ngx_pool_t *pool,
    ngx_uint_t backend, ngx_str_t *base, ngx_str_t *key, ngx_str_t *out);

ngx_int_t ngx_http_auto_ssl_curl_worker_init(ngx_cycle_t *cycle);

void ngx_http_auto_ssl_curl_worker_exit(ngx_cycle_t *cycle);

ngx_int_t ngx_http_auto_ssl_curl_fetch(
    ngx_http_auto_ssl_backend_cfg_t *cfg, ngx_uint_t backend, ngx_str_t *key,
    ngx_http_auto_ssl_fetch_done_pt handler, void *data);

ngx_int_t ngx_http_auto_ssl_curl_fetch_blocking(
    ngx_http_auto_ssl_backend_cfg_t *cfg, ngx_uint_t backend, ngx_str_t *key,
    ngx_pool_t *pool, ngx_msec_t timeout, ngx_str_t *cert, ngx_str_t *chain,
    ngx_str_t *key_data);

CURLM *ngx_http_auto_ssl_curl_multi_for_test(void);

void ngx_http_auto_ssl_curl_check_for_test(void);

ngx_uint_t ngx_http_auto_ssl_curl_fire_retries_for_test(void);

ngx_uint_t ngx_http_auto_ssl_curl_retryable_for_test(int res, long code);


#endif
