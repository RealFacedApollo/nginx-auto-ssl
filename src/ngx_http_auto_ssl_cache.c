#include "ngx_http_auto_ssl_cache.h"


typedef struct {
    ngx_http_auto_ssl_cache_t      *cache;
    ngx_http_auto_ssl_inflight_t   *inflight;
    ngx_pool_t                     *pool;
    ngx_uint_t                      backend;
    ngx_str_t                       key;
} ngx_http_auto_ssl_cache_waiter_ctx_t;


static ngx_uint_t
ngx_http_auto_ssl_cache_bucket(ngx_http_auto_ssl_cache_t *cache,
    ngx_str_t *key, ngx_uint_t backend)
{
    return (ngx_hash_key(key->data, key->len) + backend)
           % cache->nbuckets;
}


static ngx_http_auto_ssl_cache_entry_t *
ngx_http_auto_ssl_cache_find(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key)
{
    ngx_http_auto_ssl_cache_entry_t  *e;

    e = cache->buckets[ngx_http_auto_ssl_cache_bucket(cache, key, backend)];

    while (e != NULL) {
        if (e->backend == backend
            && e->key.len == key->len
            && ngx_memcmp(e->key.data, key->data, key->len) == 0)
        {
            return e;
        }

        e = e->next;
    }

    return NULL;
}


static ngx_http_auto_ssl_cache_negative_t *
ngx_http_auto_ssl_cache_neg_find(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key)
{
    ngx_http_auto_ssl_cache_negative_t  *n;

    n = cache->neg_buckets[ngx_http_auto_ssl_cache_bucket(cache, key,
                                                          backend)];

    while (n != NULL) {
        if (n->backend == backend
            && n->key.len == key->len
            && ngx_memcmp(n->key.data, key->data, key->len) == 0)
        {
            return n;
        }

        n = n->next;
    }

    return NULL;
}


static void
ngx_http_auto_ssl_cache_neg_remove(ngx_http_auto_ssl_cache_t *cache,
    ngx_http_auto_ssl_cache_negative_t *target)
{
    ngx_http_auto_ssl_cache_negative_t  *n, **prev;

    prev = &cache->neg_buckets[ngx_http_auto_ssl_cache_bucket(cache,
                                                             &target->key,
                                                             target->backend)];

    for (n = *prev; n != NULL; n = n->next) {
        if (n == target) {
            *prev = n->next;
            cache->neg_count--;
            ngx_free(n);
            return;
        }

        prev = &n->next;
    }
}


static void
ngx_http_auto_ssl_cache_neg_record(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key, time_t now)
{
    ngx_http_auto_ssl_cache_negative_t  *n;
    u_char                              *data;

    n = ngx_http_auto_ssl_cache_neg_find(cache, backend, key);
    if (n != NULL) {
        n->failed_at = now;
        return;
    }

    if (cache->neg_count >= NGX_HTTP_AUTO_SSL_CACHE_MAX_NEGATIVE) {
        return;
    }

    n = ngx_calloc(sizeof(*n) + key->len, cache->log);
    if (n == NULL) {
        return;
    }

    data = (u_char *) (n + 1);
    ngx_memcpy(data, key->data, key->len);

    n->backend = backend;
    n->failed_at = now;
    n->key.data = data;
    n->key.len = key->len;

    n->next = cache->neg_buckets[ngx_http_auto_ssl_cache_bucket(cache, key,
                                                                backend)];
    cache->neg_buckets[ngx_http_auto_ssl_cache_bucket(cache, key, backend)]
        = n;

    cache->neg_count++;
}


static void
ngx_http_auto_ssl_cache_neg_clear(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key)
{
    ngx_http_auto_ssl_cache_negative_t  *n;

    n = ngx_http_auto_ssl_cache_neg_find(cache, backend, key);
    if (n != NULL) {
        ngx_http_auto_ssl_cache_neg_remove(cache, n);
    }
}


/*
 * Milliseconds since an entry was stored; a backwards clock step reads
 * as zero age (treat as fresh) rather than a huge unsigned value.
 */
static ngx_msec_t
ngx_http_auto_ssl_cache_age_ms(time_t now, time_t then)
{
    if (now < then) {
        return 0;
    }

    return (ngx_msec_t) (now - then) * 1000;
}


static ngx_uint_t
ngx_http_auto_ssl_cache_neg_blocked(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key, time_t now)
{
    ngx_http_auto_ssl_cache_negative_t  *n;

    n = ngx_http_auto_ssl_cache_neg_find(cache, backend, key);
    if (n == NULL) {
        return 0;
    }

    if (ngx_http_auto_ssl_cache_age_ms(now, n->failed_at)
        >= cache->negative_ttl)
    {
        ngx_http_auto_ssl_cache_neg_remove(cache, n);
        return 0;
    }

    return 1;
}


static void
ngx_http_auto_ssl_cache_neg_purge(ngx_http_auto_ssl_cache_t *cache,
    time_t now)
{
    ngx_http_auto_ssl_cache_negative_t  *n, *next, **prev;
    ngx_uint_t                           i;

    for (i = 0; i < cache->nbuckets; i++) {
        prev = &cache->neg_buckets[i];
        n = *prev;

        while (n != NULL) {
            next = n->next;

            if (ngx_http_auto_ssl_cache_age_ms(now, n->failed_at)
                >= cache->negative_ttl)
            {
                *prev = next;
                cache->neg_count--;
                ngx_free(n);
                n = next;
                continue;
            }

            prev = &n->next;
            n = next;
        }
    }
}


static ngx_http_auto_ssl_backend_cfg_t *
ngx_http_auto_ssl_cache_cfg(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend)
{
    if (backend == NGX_HTTP_AUTO_SSL_BACKEND_CERTMATE) {
        return cache->certmate_ready ? cache->certmate_cfg : NULL;
    }

    if (backend == NGX_HTTP_AUTO_SSL_BACKEND_PROVISIONER) {
        return cache->provisioner_ready ? cache->provisioner_cfg : NULL;
    }

    return NULL;
}


ngx_http_auto_ssl_cache_t *
ngx_http_auto_ssl_cache_create(ngx_pool_t *pool, ngx_log_t *log,
    ngx_uint_t nbuckets)
{
    ngx_http_auto_ssl_cache_t  *cache;

    if (nbuckets == 0) {
        nbuckets = 64;
    }

    cache = ngx_pcalloc(pool, sizeof(ngx_http_auto_ssl_cache_t));
    if (cache == NULL) {
        return NULL;
    }

    cache->buckets = ngx_pcalloc(pool, nbuckets * sizeof(void *));
    if (cache->buckets == NULL) {
        return NULL;
    }

    cache->neg_buckets = ngx_pcalloc(pool, nbuckets * sizeof(void *));
    if (cache->neg_buckets == NULL) {
        return NULL;
    }

    cache->table = ngx_http_auto_ssl_fetch_table_create(pool, nbuckets);
    if (cache->table == NULL) {
        return NULL;
    }

    cache->pool = pool;
    cache->log = log;
    cache->nbuckets = nbuckets;
    cache->fetch = ngx_http_auto_ssl_curl_fetch;

    ngx_http_auto_ssl_cache_configure(cache,
        NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_TTL,
        NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_REFRESH_INTERVAL,
        NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_MAX_STALE,
        NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_NEGATIVE_TTL,
        NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_EXPIRY_INTERVAL,
        NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_EXPIRY_BEFORE);

    return cache;
}


void
ngx_http_auto_ssl_cache_set_backends(ngx_http_auto_ssl_cache_t *cache,
    ngx_http_auto_ssl_backend_cfg_t *certmate_cfg, ngx_flag_t certmate_ready,
    ngx_http_auto_ssl_backend_cfg_t *provisioner_cfg,
    ngx_flag_t provisioner_ready)
{
    cache->certmate_cfg = certmate_cfg;
    cache->certmate_ready = certmate_ready;
    cache->provisioner_cfg = provisioner_cfg;
    cache->provisioner_ready = provisioner_ready;
}


void
ngx_http_auto_ssl_cache_configure(ngx_http_auto_ssl_cache_t *cache,
    ngx_msec_t ttl, ngx_msec_t refresh_interval, ngx_msec_t max_stale,
    ngx_msec_t negative_ttl, ngx_msec_t expiry_interval,
    ngx_msec_t expiry_before)
{
    if (ttl <= 0) {
        ttl = NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_TTL;
    }

    if (refresh_interval <= 0) {
        refresh_interval = NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_REFRESH_INTERVAL;
    }

    if (max_stale <= 0) {
        max_stale = NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_MAX_STALE;
    }

    if (negative_ttl <= 0) {
        negative_ttl = NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_NEGATIVE_TTL;
    }

    if (expiry_interval <= 0) {
        expiry_interval = NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_EXPIRY_INTERVAL;
    }

    if (expiry_before <= 0) {
        expiry_before = NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_EXPIRY_BEFORE;
    }

    cache->ttl = ttl;
    cache->refresh_before = ttl / 4;
    cache->refresh_interval = refresh_interval;
    cache->max_stale = max_stale;
    cache->negative_ttl = negative_ttl;
    cache->expiry_interval = expiry_interval;
    cache->expiry_before = expiry_before;
}


/*
 * The entry when still servable (fresh or within max-stale), NULL past
 * that; *fresh reports TTL state.
 */
static ngx_http_auto_ssl_cache_entry_t *
ngx_http_auto_ssl_cache_usable_entry(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key, ngx_uint_t *fresh)
{
    ngx_http_auto_ssl_cache_entry_t  *e;
    ngx_msec_t                        age;
    time_t                            now;

    e = ngx_http_auto_ssl_cache_find(cache, backend, key);
    if (e == NULL) {
        return NULL;
    }

    now = ngx_time();
    age = ngx_http_auto_ssl_cache_age_ms(now, e->fetched_at);

    if (fresh != NULL) {
        *fresh = age < cache->ttl;
    }

    if (age >= cache->ttl + cache->max_stale) {
        return NULL;
    }

    return e;
}


ngx_int_t
ngx_http_auto_ssl_cache_lookup(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key, ngx_str_t **cert,
    ngx_str_t **chain, ngx_str_t **key_data)
{
    ngx_http_auto_ssl_cache_entry_t  *e;
    ngx_uint_t                        fresh;

    e = ngx_http_auto_ssl_cache_usable_entry(cache, backend, key, &fresh);
    if (e == NULL || !fresh) {
        return NGX_DECLINED;
    }

    if (cert != NULL) {
        *cert = &e->cert;
    }

    if (chain != NULL) {
        *chain = &e->chain;
    }

    if (key_data != NULL) {
        *key_data = &e->key_data;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_auto_ssl_cache_lookup_parsed(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key,
    ngx_http_auto_ssl_parsed_t **parsed)
{
    ngx_http_auto_ssl_cache_entry_t  *e;
    ngx_uint_t                        fresh;

    e = ngx_http_auto_ssl_cache_usable_entry(cache, backend, key, &fresh);
    if (e == NULL || !fresh) {
        return NGX_DECLINED;
    }

    *parsed = &e->parsed;

    return NGX_OK;
}


ngx_int_t
ngx_http_auto_ssl_cache_lookup_stale(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key,
    ngx_http_auto_ssl_parsed_t **parsed)
{
    ngx_http_auto_ssl_cache_entry_t  *e;

    e = ngx_http_auto_ssl_cache_usable_entry(cache, backend, key, NULL);
    if (e == NULL) {
        return NGX_DECLINED;
    }

    *parsed = &e->parsed;

    return NGX_OK;
}


static void
ngx_http_auto_ssl_cache_fetch_done(void *data, ngx_int_t status,
    ngx_str_t *cert, ngx_str_t *chain, ngx_str_t *key)
{
    ngx_http_auto_ssl_cache_waiter_ctx_t  *ctx = data;

    /*
     * The fetched body dies with the fetch pool, so copy it here;
     * anything else is recorded negatively so a failing backend is
     * not hammered per handshake.
     */
    if (status == NGX_OK && cert != NULL && key != NULL) {
        if (ngx_http_auto_ssl_cache_store(ctx->cache, ctx->backend, &ctx->key,
                                          cert, chain, key)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, ctx->cache->log, 0,
                          "auto_ssl: cannot store fetched certificate");
            ngx_http_auto_ssl_cache_neg_record(ctx->cache, ctx->backend,
                                               &ctx->key, ngx_time());
        }

    } else {
        ngx_http_auto_ssl_cache_neg_record(ctx->cache, ctx->backend,
                                           &ctx->key, ngx_time());
    }
}


static void
ngx_http_auto_ssl_cache_http_done(void *data, ngx_int_t status,
    ngx_str_t *cert, ngx_str_t *chain, ngx_str_t *key)
{
    ngx_http_auto_ssl_cache_waiter_ctx_t  *ctx = data;
    ngx_http_auto_ssl_cache_t             *cache = ctx->cache;
    ngx_pool_t                            *pool = ctx->pool;

    cache->fetching--;

    ngx_http_auto_ssl_fetch_complete(cache->table, ctx->inflight,
                                     status, cert, chain, key);

    ngx_destroy_pool(pool);
}


static ngx_int_t
ngx_http_auto_ssl_cache_start_fetch(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key)
{
    ngx_http_auto_ssl_backend_cfg_t      *cfg;
    ngx_http_auto_ssl_inflight_t         *inflight;
    ngx_http_auto_ssl_cache_waiter_ctx_t *ctx;
    ngx_pool_t                           *pool;
    u_char                               *key_data;

    cfg = ngx_http_auto_ssl_cache_cfg(cache, backend);
    if (cfg == NULL || cache->fetch == NULL) {
        return NGX_ERROR;
    }

    if (cache->fetching >= NGX_HTTP_AUTO_SSL_CACHE_MAX_FETCHING) {
        return NGX_DECLINED;
    }

    /*
     * The inflight key, waiter, and completion context all live in a
     * dedicated pool that is destroyed when the fetch completes, so a
     * fetch never leaks into the cycle pool.
     */
    pool = ngx_create_pool(1024, cache->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    inflight = ngx_http_auto_ssl_fetch_create(cache->table, key, backend,
                                              pool);
    if (inflight == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    ctx = ngx_pnalloc(pool, sizeof(*ctx) + key->len);
    if (ctx == NULL) {
        goto failed;
    }

    key_data = (u_char *) (ctx + 1);
    ngx_memcpy(key_data, key->data, key->len);

    ctx->cache = cache;
    ctx->inflight = inflight;
    ctx->pool = pool;
    ctx->backend = backend;
    ctx->key.data = key_data;
    ctx->key.len = key->len;

    if (ngx_http_auto_ssl_fetch_attach(pool, inflight,
        ngx_http_auto_ssl_cache_fetch_done, ctx)
        != NGX_OK)
    {
        goto failed;
    }

    cache->fetching++;

    if (cache->fetch(cfg, backend, key, ngx_http_auto_ssl_cache_http_done,
                       ctx)
        != NGX_OK)
    {
        cache->fetching--;
        goto failed;
    }

    return NGX_OK;

failed:

    ngx_http_auto_ssl_fetch_complete(cache->table, inflight,
                                     NGX_ERROR, NULL, NULL, NULL);

    ngx_destroy_pool(pool);

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_auto_ssl_cache_background(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key)
{
    if (ngx_http_auto_ssl_cache_cfg(cache, backend) == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_auto_ssl_fetch_lookup(cache->table, key, backend) != NULL) {
        return NGX_OK;
    }

    if (ngx_http_auto_ssl_cache_neg_blocked(cache, backend, key, ngx_time())) {
        return NGX_DECLINED;
    }

    return ngx_http_auto_ssl_cache_start_fetch(cache, backend, key);
}


ngx_int_t
ngx_http_auto_ssl_cache_prefetch(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key)
{
    if (key->len == 0) {
        return NGX_ERROR;
    }

    if (ngx_http_auto_ssl_cache_lookup(cache, backend, key, NULL, NULL,
                                         NULL)
        == NGX_OK)
    {
        return NGX_DECLINED;
    }

    return ngx_http_auto_ssl_cache_background(cache, backend, key);
}


ngx_int_t
ngx_http_auto_ssl_cache_revalidate(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key)
{
    if (key->len == 0) {
        return NGX_ERROR;
    }

    return ngx_http_auto_ssl_cache_background(cache, backend, key);
}


static ngx_uint_t
ngx_http_auto_ssl_cache_str_equal(ngx_str_t *a, ngx_str_t *b)
{
    ngx_str_t  empty;

    if (a == NULL) {
        empty.data = NULL;
        empty.len = 0;
        a = &empty;
    }

    if (b == NULL) {
        empty.data = NULL;
        empty.len = 0;
        b = &empty;
    }

    return a->len == b->len
           && (a->len == 0 || ngx_memcmp(a->data, b->data, a->len) == 0);
}


ngx_int_t
ngx_http_auto_ssl_cache_store(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key, ngx_str_t *cert,
    ngx_str_t *chain, ngx_str_t *key_data)
{
    ngx_http_auto_ssl_cache_entry_t  *e;
    ngx_pool_t                       *pool;
    ngx_uint_t                        bucket;
    ngx_str_t                         key_copy, cert_copy, chain_copy,
                                      key_data_copy;
    ngx_http_auto_ssl_parsed_t        parsed;
    time_t                            expires_in;

    if (key->len == 0 || cert == NULL || cert->len == 0
        || key_data == NULL || key_data->len == 0)
    {
        return NGX_ERROR;
    }

    e = ngx_http_auto_ssl_cache_find(cache, backend, key);

    /*
     * Unchanged bundle: refresh the timestamp and clear any negative
     * mark — a byte-identical fetch proves the backend is healthy.
     * An expired entry never takes this path; the full store below
     * rejects it on validity dates.
     */
    if (e != NULL
        && ngx_http_auto_ssl_cache_str_equal(&e->cert, cert)
        && ngx_http_auto_ssl_cache_str_equal(&e->chain, chain)
        && ngx_http_auto_ssl_cache_str_equal(&e->key_data, key_data)
        && ngx_http_auto_ssl_expiry(&e->parsed, ngx_time(), &expires_in)
           == NGX_OK
        && expires_in >= 0)
    {
        e->fetched_at = ngx_time();
        ngx_http_auto_ssl_cache_neg_clear(cache, backend, key);
        return NGX_OK;
    }

    chain_copy.data = NULL;
    chain_copy.len = 0;

    pool = ngx_create_pool(4096, cache->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    key_copy.len = key->len;
    key_copy.data = ngx_pstrdup(pool, key);
    cert_copy.len = cert->len;
    cert_copy.data = ngx_pstrdup(pool, cert);
    key_data_copy.len = key_data->len;
    key_data_copy.data = ngx_pstrdup(pool, key_data);

    if (key_copy.data == NULL || cert_copy.data == NULL
        || key_data_copy.data == NULL)
    {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    if (chain != NULL && chain->len != 0) {
        chain_copy.len = chain->len;
        chain_copy.data = ngx_pstrdup(pool, chain);

        if (chain_copy.data == NULL) {
            ngx_destroy_pool(pool);
            return NGX_ERROR;
        }
    }

    /*
     * Parse and validate once here; rejects never reach the data plane.
     */
    if (ngx_http_auto_ssl_parse(&cert_copy, &chain_copy, &key_data_copy,
                                key, ngx_time(), &parsed)
        != NGX_OK)
    {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    if (e != NULL) {
        ngx_destroy_pool(e->pool);
        ngx_http_auto_ssl_parsed_free(&e->parsed);

        e->pool = pool;
        e->key = key_copy;
        e->cert = cert_copy;
        e->chain = chain_copy;
        e->key_data = key_data_copy;
        e->parsed = parsed;
        e->fetched_at = ngx_time();

        ngx_http_auto_ssl_cache_neg_clear(cache, backend, key);

        return NGX_OK;
    }

    e = ngx_pcalloc(cache->pool, sizeof(*e));
    if (e == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    e->pool = pool;
    e->key = key_copy;
    e->cert = cert_copy;
    e->chain = chain_copy;
    e->key_data = key_data_copy;
    e->parsed = parsed;
    e->backend = backend;
    e->fetched_at = ngx_time();

    bucket = ngx_http_auto_ssl_cache_bucket(cache, key, backend);
    e->next = cache->buckets[bucket];
    cache->buckets[bucket] = e;

    ngx_http_auto_ssl_cache_neg_clear(cache, backend, key);

    return NGX_OK;
}


ngx_int_t
ngx_http_auto_ssl_cache_warm_blocking(ngx_http_auto_ssl_cache_t *cache,
    ngx_uint_t backend, ngx_str_t *key, ngx_msec_t timeout)
{
    ngx_http_auto_ssl_backend_cfg_t  *cfg;
    ngx_pool_t                       *pool;
    ngx_str_t                         cert, chain, key_data;
    ngx_int_t                         rc;

    if (key->len == 0) {
        return NGX_ERROR;
    }

    if (ngx_http_auto_ssl_cache_lookup(cache, backend, key, NULL, NULL,
                                       NULL)
        == NGX_OK)
    {
        return NGX_DECLINED;
    }

    cfg = ngx_http_auto_ssl_cache_cfg(cache, backend);
    if (cfg == NULL) {
        return NGX_ERROR;
    }

    pool = ngx_create_pool(4096, cache->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_http_auto_ssl_curl_fetch_blocking(cfg, backend, key, pool,
                                              timeout, &cert, &chain,
                                              &key_data);

    if (rc == NGX_OK) {
        rc = ngx_http_auto_ssl_cache_store(cache, backend, key, &cert,
                                           &chain, &key_data);
    }

    ngx_destroy_pool(pool);

    return rc;
}


static void
ngx_http_auto_ssl_cache_refresh(ngx_event_t *ev)
{
    ngx_http_auto_ssl_cache_t        *cache = ev->data;
    ngx_http_auto_ssl_cache_entry_t  *e;
    ngx_uint_t                        i, k, start, refreshed;
    ngx_msec_t                        age;
    time_t                            now;

    now = ngx_time();

    ngx_http_auto_ssl_cache_neg_purge(cache, now);

    /* Budgeted, rotating refresh spreads backend load across ticks. */
    start = cache->refresh_pos % cache->nbuckets;
    refreshed = 0;

    for (k = 0; k < cache->nbuckets; k++) {
        if (refreshed >= NGX_HTTP_AUTO_SSL_CACHE_REFRESH_BUDGET) {
            break;
        }

        i = (start + k) % cache->nbuckets;

        for (e = cache->buckets[i]; e != NULL; e = e->next) {
            age = ngx_http_auto_ssl_cache_age_ms(now, e->fetched_at);

            if (age + cache->refresh_before < cache->ttl) {
                continue;
            }

            refreshed++;

            if (ngx_http_auto_ssl_cache_background(cache, e->backend, &e->key)
                == NGX_ERROR)
            {
                ngx_log_error(NGX_LOG_ERR, cache->log, 0,
                              "auto_ssl: cannot refresh cached certificate");
            }

            if (refreshed >= NGX_HTTP_AUTO_SSL_CACHE_REFRESH_BUDGET) {
                break;
            }
        }
    }

    cache->refresh_pos = (start + 1) % cache->nbuckets;

    ngx_add_timer(&cache->timer, cache->refresh_interval);
}


static void
ngx_http_auto_ssl_cache_timer_start(ngx_http_auto_ssl_cache_t *cache,
    ngx_event_t *timer, ngx_event_handler_pt handler, ngx_msec_t interval,
    ngx_msec_t offset)
{
    if (timer->timer_set) {
        return;
    }

    timer->handler = handler;
    timer->data = cache;
    timer->log = cache->log;
    timer->cancelable = 1;

    ngx_add_timer(timer, interval + offset);
}


static void
ngx_http_auto_ssl_cache_timer_stop(ngx_event_t *timer)
{
    if (timer->timer_set) {
        ngx_del_timer(timer);
    }
}


void
ngx_http_auto_ssl_cache_start_refresh(ngx_http_auto_ssl_cache_t *cache)
{
    /*
     * Offset the first tick per worker so co-started workers do not fire
     * their refresh scans in lockstep; the address bits differ per
     * process thanks to ASLR.
     */
    ngx_http_auto_ssl_cache_timer_start(cache, &cache->timer,
        ngx_http_auto_ssl_cache_refresh, cache->refresh_interval,
        (ngx_msec_t) ((uintptr_t) cache->buckets % 1000));
}


static void
ngx_http_auto_ssl_cache_expiry(ngx_event_t *ev)
{
    ngx_http_auto_ssl_cache_t        *cache = ev->data;
    ngx_http_auto_ssl_cache_entry_t  *e;
    ngx_uint_t                        i, checked, expiring;
    time_t                            now, seconds;

    now = ngx_time();
    checked = 0;
    expiring = 0;

    for (i = 0; i < cache->nbuckets; i++) {
        for (e = cache->buckets[i]; e != NULL; e = e->next) {
            checked++;

            if (ngx_http_auto_ssl_expiry(&e->parsed, now, &seconds)
                != NGX_OK)
            {
                continue;
            }

            if (seconds < 0) {
                ngx_log_error(NGX_LOG_ERR, cache->log, 0,
                              "auto_ssl: cached certificate is expired, "
                              "refreshing");
                expiring++;

            } else if ((ngx_msec_t) seconds * 1000
                       < cache->expiry_before)
            {
                ngx_log_error(NGX_LOG_WARN, cache->log, 0,
                              "auto_ssl: cached certificate expires soon, "
                              "refreshing");
                expiring++;

            } else {
                continue;
            }

            if (ngx_http_auto_ssl_cache_revalidate(cache, e->backend,
                                                   &e->key)
                == NGX_ERROR)
            {
                ngx_log_error(NGX_LOG_ERR, cache->log, 0,
                              "auto_ssl: cannot refresh expiring "
                              "certificate");
            }
        }
    }

    ngx_log_error(NGX_LOG_INFO, cache->log, 0,
                  "auto_ssl: expiry check: %ui certificates, "
                  "%ui expiring", checked, expiring);

    ngx_add_timer(&cache->expiry_timer, cache->expiry_interval);
}


void
ngx_http_auto_ssl_cache_start_expiry(ngx_http_auto_ssl_cache_t *cache)
{
    ngx_http_auto_ssl_cache_timer_start(cache, &cache->expiry_timer,
        ngx_http_auto_ssl_cache_expiry, cache->expiry_interval,
        (ngx_msec_t) ((uintptr_t) cache->neg_buckets % 1000));
}


void
ngx_http_auto_ssl_cache_stop_expiry(ngx_http_auto_ssl_cache_t *cache)
{
    ngx_http_auto_ssl_cache_timer_stop(&cache->expiry_timer);
}


void
ngx_http_auto_ssl_cache_stop_refresh(ngx_http_auto_ssl_cache_t *cache)
{
    ngx_http_auto_ssl_cache_timer_stop(&cache->timer);
}
