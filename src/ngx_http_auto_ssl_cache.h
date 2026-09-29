#ifndef NGX_HTTP_AUTO_SSL_CACHE_H
#define NGX_HTTP_AUTO_SSL_CACHE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_auto_ssl_fetch.h"
#include "ngx_http_auto_ssl_curl.h"
#include "ngx_http_auto_ssl_ssl.h"


#define NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_TTL               86400000
#define NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_REFRESH_INTERVAL  60000
#define NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_MAX_STALE         604800000
#define NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_NEGATIVE_TTL      60000
#define NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_EXPIRY_INTERVAL   3600000
#define NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_EXPIRY_BEFORE     86400000

/* Bounds that keep one worker from stampeding the backends. */
#define NGX_HTTP_AUTO_SSL_CACHE_MAX_FETCHING              32
#define NGX_HTTP_AUTO_SSL_CACHE_REFRESH_BUDGET            16
#define NGX_HTTP_AUTO_SSL_CACHE_MAX_NEGATIVE              1024


typedef struct ngx_http_auto_ssl_cache_entry_s
    ngx_http_auto_ssl_cache_entry_t;

struct ngx_http_auto_ssl_cache_entry_s {
    ngx_http_auto_ssl_cache_entry_t  *next;
    ngx_pool_t                       *pool;
    ngx_str_t                         key;
    ngx_str_t                         cert;
    ngx_str_t                         chain;
    ngx_str_t                         key_data;
    ngx_http_auto_ssl_parsed_t        parsed;
    ngx_uint_t                        backend;
    time_t                            fetched_at;
};


typedef ngx_int_t (*ngx_http_auto_ssl_cache_fetch_pt)(
    ngx_http_auto_ssl_backend_cfg_t *cfg, ngx_uint_t backend, ngx_str_t *key,
    ngx_http_auto_ssl_fetch_done_pt handler, void *data);


typedef struct ngx_http_auto_ssl_cache_negative_s
    ngx_http_auto_ssl_cache_negative_t;

struct ngx_http_auto_ssl_cache_negative_s {
    ngx_http_auto_ssl_cache_negative_t  *next;
    ngx_uint_t                           backend;
    time_t                               failed_at;
    ngx_str_t                            key;
};


typedef struct {
    ngx_http_auto_ssl_cache_entry_t     **buckets;
    ngx_http_auto_ssl_cache_negative_t  **neg_buckets;
    ngx_uint_t                            nbuckets;
    ngx_uint_t                            neg_count;
    ngx_pool_t                           *pool;
    ngx_log_t                            *log;
    ngx_http_auto_ssl_fetch_table_t      *table;
    ngx_http_auto_ssl_backend_cfg_t      *certmate_cfg;
    ngx_http_auto_ssl_backend_cfg_t      *provisioner_cfg;
    ngx_flag_t                            certmate_ready;
    ngx_flag_t                            provisioner_ready;
    ngx_msec_t                            ttl;
    ngx_msec_t                            refresh_before;
    ngx_msec_t                            refresh_interval;
    ngx_msec_t                            max_stale;
    ngx_msec_t                            negative_ttl;
    ngx_msec_t                            expiry_interval;
    ngx_msec_t                            expiry_before;
    ngx_uint_t                            fetching;
    ngx_uint_t                            refresh_pos;
    ngx_http_auto_ssl_cache_fetch_pt      fetch;
    ngx_event_t                           timer;
    ngx_event_t                           expiry_timer;
} ngx_http_auto_ssl_cache_t;


ngx_http_auto_ssl_cache_t *ngx_http_auto_ssl_cache_create(ngx_pool_t *pool,
    ngx_log_t *log, ngx_uint_t nbuckets);

void ngx_http_auto_ssl_cache_set_backends(ngx_http_auto_ssl_cache_t *cache,
    ngx_http_auto_ssl_backend_cfg_t *certmate_cfg, ngx_flag_t certmate_ready,
    ngx_http_auto_ssl_backend_cfg_t *provisioner_cfg,
    ngx_flag_t provisioner_ready);

void ngx_http_auto_ssl_cache_configure(ngx_http_auto_ssl_cache_t *cache,
    ngx_msec_t ttl, ngx_msec_t refresh_interval, ngx_msec_t max_stale,
    ngx_msec_t negative_ttl, ngx_msec_t expiry_interval,
    ngx_msec_t expiry_before);

ngx_int_t ngx_http_auto_ssl_cache_lookup(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key, ngx_str_t **cert,
    ngx_str_t **chain, ngx_str_t **key_data);

ngx_int_t ngx_http_auto_ssl_cache_lookup_parsed(
    ngx_http_auto_ssl_cache_t *cache, ngx_uint_t backend, ngx_str_t *key,
    ngx_http_auto_ssl_parsed_t **parsed);

ngx_int_t ngx_http_auto_ssl_cache_lookup_stale(
    ngx_http_auto_ssl_cache_t *cache, ngx_uint_t backend, ngx_str_t *key,
    ngx_http_auto_ssl_parsed_t **parsed);

ngx_int_t ngx_http_auto_ssl_cache_prefetch(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key);

ngx_int_t ngx_http_auto_ssl_cache_warm_blocking(
    ngx_http_auto_ssl_cache_t *cache, ngx_uint_t backend, ngx_str_t *key,
    ngx_msec_t timeout);

ngx_int_t ngx_http_auto_ssl_cache_revalidate(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key);

ngx_int_t ngx_http_auto_ssl_cache_store(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key, ngx_str_t *cert,
    ngx_str_t *chain, ngx_str_t *key_data);

void ngx_http_auto_ssl_cache_start_refresh(ngx_http_auto_ssl_cache_t *cache);
void ngx_http_auto_ssl_cache_stop_refresh(ngx_http_auto_ssl_cache_t *cache);

void ngx_http_auto_ssl_cache_start_expiry(ngx_http_auto_ssl_cache_t *cache);
void ngx_http_auto_ssl_cache_stop_expiry(ngx_http_auto_ssl_cache_t *cache);


extern ngx_http_auto_ssl_cache_t  *ngx_http_auto_ssl_worker_cache;


#endif
