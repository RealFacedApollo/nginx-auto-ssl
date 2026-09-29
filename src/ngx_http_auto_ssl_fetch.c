#include "ngx_http_auto_ssl_fetch.h"

#include <zlib.h>


static ngx_uint_t
ngx_http_auto_ssl_fetch_bucket(ngx_http_auto_ssl_fetch_table_t *t,
    ngx_str_t *key, ngx_uint_t backend)
{
    return (ngx_hash_key(key->data, key->len) + backend) % t->nbuckets;
}


ngx_http_auto_ssl_fetch_table_t *
ngx_http_auto_ssl_fetch_table_create(ngx_pool_t *pool, ngx_uint_t nbuckets)
{
    ngx_http_auto_ssl_fetch_table_t  *t;

    if (nbuckets == 0) {
        nbuckets = 64;
    }

    t = ngx_pcalloc(pool, sizeof(ngx_http_auto_ssl_fetch_table_t));
    if (t == NULL) {
        return NULL;
    }

    t->buckets = ngx_pcalloc(pool, nbuckets * sizeof(void *));
    if (t->buckets == NULL) {
        return NULL;
    }

    t->pool = pool;
    t->nbuckets = nbuckets;
    t->free = NULL;

    return t;
}


ngx_http_auto_ssl_inflight_t *
ngx_http_auto_ssl_fetch_lookup(ngx_http_auto_ssl_fetch_table_t *t,
    ngx_str_t *key, ngx_uint_t backend)
{
    ngx_http_auto_ssl_inflight_t  *e;

    e = t->buckets[ngx_http_auto_ssl_fetch_bucket(t, key, backend)];

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


ngx_http_auto_ssl_inflight_t *
ngx_http_auto_ssl_fetch_create(ngx_http_auto_ssl_fetch_table_t *t,
    ngx_str_t *key, ngx_uint_t backend, ngx_pool_t *key_pool)
{
    ngx_http_auto_ssl_inflight_t  *e;
    u_char                        *data;
    ngx_uint_t                     bucket;

    if (key->len == 0 || key_pool == NULL) {
        return NULL;
    }

    if (t->free != NULL) {
        e = t->free;
        t->free = e->next;

    } else {
        e = ngx_pcalloc(t->pool, sizeof(ngx_http_auto_ssl_inflight_t));
        if (e == NULL) {
            return NULL;
        }
    }

    data = ngx_pnalloc(key_pool, key->len);
    if (data == NULL) {
        e->next = t->free;
        t->free = e;
        return NULL;
    }

    ngx_memcpy(data, key->data, key->len);

    e->key.data = data;
    e->key.len = key->len;
    e->backend = backend;
    e->waiters = NULL;

    bucket = ngx_http_auto_ssl_fetch_bucket(t, key, backend);
    e->next = t->buckets[bucket];
    t->buckets[bucket] = e;

    return e;
}


ngx_int_t
ngx_http_auto_ssl_fetch_attach(ngx_pool_t *pool,
    ngx_http_auto_ssl_inflight_t *inflight,
    ngx_http_auto_ssl_fetch_done_pt handler, void *data)
{
    ngx_http_auto_ssl_waiter_t  *w;

    w = ngx_pnalloc(pool, sizeof(ngx_http_auto_ssl_waiter_t));
    if (w == NULL) {
        return NGX_ERROR;
    }

    w->handler = handler;
    w->data = data;

    w->next = inflight->waiters;
    inflight->waiters = w;

    return NGX_OK;
}


void
ngx_http_auto_ssl_fetch_complete(ngx_http_auto_ssl_fetch_table_t *t,
    ngx_http_auto_ssl_inflight_t *inflight, ngx_int_t status,
    ngx_str_t *cert, ngx_str_t *chain, ngx_str_t *key)
{
    ngx_uint_t                    bucket;
    ngx_uint_t                    found;
    ngx_http_auto_ssl_inflight_t  *e, **prev;
    ngx_http_auto_ssl_waiter_t    *w, *next;

    bucket = ngx_http_auto_ssl_fetch_bucket(t, &inflight->key,
                                            inflight->backend);

    found = 0;

    prev = &t->buckets[bucket];
    for (e = *prev; e != NULL; e = e->next) {
        if (e == inflight) {
            *prev = e->next;
            found = 1;
            break;
        }

        prev = &e->next;
    }

    w = inflight->waiters;
    inflight->waiters = NULL;

    /*
     * The key copy lives in the fetch pool, which the caller destroys
     * after completion; clear it so a recycled node never carries a
     * dangling pointer into its next use.
     */
    inflight->key.data = NULL;
    inflight->key.len = 0;

    /*
     * Recycle only when unlinked: completing the same node twice must
     * not push it onto the free list twice.
     */
    if (found) {
        inflight->next = t->free;
        t->free = inflight;
    }

    while (w != NULL) {
        next = w->next;
        w->handler(w->data, status, cert, chain, key);
        w = next;
    }
}


#define NGX_HTTP_AUTO_SSL_ZIP_EOCD_LEN     22
#define NGX_HTTP_AUTO_SSL_ZIP_CD_LEN       46
#define NGX_HTTP_AUTO_SSL_ZIP_LOCAL_LEN    30
#define NGX_HTTP_AUTO_SSL_ZIP_MAX_ENTRIES  64
#define NGX_HTTP_AUTO_SSL_ZIP_MAX_FILE     (1 * 1024 * 1024)


typedef struct {
    u_char    *comp;
    size_t     comp_len;
    size_t     uncomp_len;
    unsigned   method;
    unsigned   found;
} ngx_http_auto_ssl_zip_entry_t;


static uint16_t
ngx_http_auto_ssl_zip_u16(u_char *p)
{
    return (uint16_t) (p[0] | ((uint16_t) p[1] << 8));
}


static uint32_t
ngx_http_auto_ssl_zip_u32(u_char *p)
{
    return (uint32_t) p[0]
           | ((uint32_t) p[1] << 8)
           | ((uint32_t) p[2] << 16)
           | ((uint32_t) p[3] << 24);
}


static u_char *
ngx_http_auto_ssl_zip_eocd(ngx_str_t *body)
{
    u_char  *p, *start;
    size_t   tail;

    if (body->len < NGX_HTTP_AUTO_SSL_ZIP_EOCD_LEN) {
        return NULL;
    }

    tail = body->len - NGX_HTTP_AUTO_SSL_ZIP_EOCD_LEN;
    if (tail > 65535) {
        tail = 65535;
    }

    start = body->data + body->len - NGX_HTTP_AUTO_SSL_ZIP_EOCD_LEN - tail;

    for (p = body->data + body->len - NGX_HTTP_AUTO_SSL_ZIP_EOCD_LEN;
         p >= start;
         p--)
    {
        if (p[0] == 'P' && p[1] == 'K' && p[2] == 0x05 && p[3] == 0x06
            && (size_t) (body->data + body->len - p)
               == (size_t) NGX_HTTP_AUTO_SSL_ZIP_EOCD_LEN
                 + ngx_http_auto_ssl_zip_u16(p + 20))
        {
            return p;
        }

        if (p == body->data) {
            break;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_auto_ssl_zip_name(u_char *name, size_t name_len, u_char *prefix,
    size_t prefix_len, char *base)
{
    size_t  base_len;

    base_len = strlen(base);

    if (name_len != prefix_len + base_len) {
        return NGX_ERROR;
    }

    if (prefix_len != 0 && ngx_memcmp(name, prefix, prefix_len) != 0) {
        return NGX_ERROR;
    }

    if (ngx_memcmp(name + prefix_len, base, base_len) != 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_auto_ssl_zip_locate(ngx_str_t *body, u_char *prefix,
    size_t prefix_len, ngx_http_auto_ssl_zip_entry_t *cert,
    ngx_http_auto_ssl_zip_entry_t *chain,
    ngx_http_auto_ssl_zip_entry_t *full,
    ngx_http_auto_ssl_zip_entry_t *key)
{
    u_char    *eocd, *p, *end, *name, *l;
    uint32_t   cd_off, cd_size, comp_len, uncomp_len, local_off;
    uint16_t   entries, i, flags, method, name_len, extra_len, comment_len;
    size_t     data_off;

    ngx_http_auto_ssl_zip_entry_t  *dst;

    eocd = ngx_http_auto_ssl_zip_eocd(body);
    if (eocd == NULL) {
        return;
    }

    entries = ngx_http_auto_ssl_zip_u16(eocd + 10);
    cd_size = ngx_http_auto_ssl_zip_u32(eocd + 12);
    cd_off = ngx_http_auto_ssl_zip_u32(eocd + 16);

    if ((size_t) cd_off + (size_t) cd_size > body->len) {
        return;
    }

    p = body->data + cd_off;
    end = p + cd_size;

    for (i = 0; i < entries && i < NGX_HTTP_AUTO_SSL_ZIP_MAX_ENTRIES; i++) {
        if ((size_t) (end - p) < NGX_HTTP_AUTO_SSL_ZIP_CD_LEN) {
            return;
        }

        if (p[0] != 'P' || p[1] != 'K' || p[2] != 0x01 || p[3] != 0x02) {
            return;
        }

        flags = ngx_http_auto_ssl_zip_u16(p + 8);
        method = ngx_http_auto_ssl_zip_u16(p + 10);
        comp_len = ngx_http_auto_ssl_zip_u32(p + 20);
        uncomp_len = ngx_http_auto_ssl_zip_u32(p + 24);
        name_len = ngx_http_auto_ssl_zip_u16(p + 28);
        extra_len = ngx_http_auto_ssl_zip_u16(p + 30);
        comment_len = ngx_http_auto_ssl_zip_u16(p + 32);
        local_off = ngx_http_auto_ssl_zip_u32(p + 42);

        if ((size_t) (end - p)
            < (size_t) (NGX_HTTP_AUTO_SSL_ZIP_CD_LEN + name_len + extra_len
                        + comment_len))
        {
            return;
        }

        name = p + NGX_HTTP_AUTO_SSL_ZIP_CD_LEN;

        dst = NULL;

        if (ngx_http_auto_ssl_zip_name(name, name_len, prefix, prefix_len,
                                       "cert.pem")
            == NGX_OK)
        {
            dst = cert;

        } else if (ngx_http_auto_ssl_zip_name(name, name_len, prefix,
                                              prefix_len, "chain.pem")
                   == NGX_OK)
        {
            dst = chain;

        } else if (ngx_http_auto_ssl_zip_name(name, name_len, prefix,
                                              prefix_len, "fullchain.pem")
                   == NGX_OK)
        {
            dst = full;

        } else if (ngx_http_auto_ssl_zip_name(name, name_len, prefix,
                                              prefix_len, "privkey.pem")
                   == NGX_OK)
        {
            dst = key;
        }

        if (dst == NULL
            || dst->found
            || (flags & 0x09) != 0
            || (method != 0 && method != 8)
            || uncomp_len > NGX_HTTP_AUTO_SSL_ZIP_MAX_FILE
            || (size_t) comp_len > body->len
            || (method == 0 && comp_len != uncomp_len))
        {
            goto next;
        }

        if ((size_t) local_off + NGX_HTTP_AUTO_SSL_ZIP_LOCAL_LEN
            > body->len)
        {
            goto next;
        }

        l = body->data + local_off;

        if (l[0] != 'P' || l[1] != 'K' || l[2] != 0x03 || l[3] != 0x04) {
            goto next;
        }

        data_off = (size_t) local_off + NGX_HTTP_AUTO_SSL_ZIP_LOCAL_LEN
                   + ngx_http_auto_ssl_zip_u16(l + 26)
                   + ngx_http_auto_ssl_zip_u16(l + 28);

        if (data_off + (size_t) comp_len > body->len) {
            goto next;
        }

        dst->comp = body->data + data_off;
        dst->comp_len = comp_len;
        dst->uncomp_len = uncomp_len;
        dst->method = method;
        dst->found = 1;

next:

        p += NGX_HTTP_AUTO_SSL_ZIP_CD_LEN + name_len + extra_len
             + comment_len;
    }
}


static ngx_int_t
ngx_http_auto_ssl_zip_read(ngx_pool_t *pool,
    ngx_http_auto_ssl_zip_entry_t *e, ngx_str_t *out)
{
    z_stream  strm;
    u_char   *data;
    int       rc;

    if (e->uncomp_len == 0) {
        out->data = e->comp;
        out->len = 0;
        return NGX_OK;
    }

    if (e->method == 0) {
        out->data = e->comp;
        out->len = e->uncomp_len;
        return NGX_OK;
    }

    data = ngx_pnalloc(pool, e->uncomp_len);
    if (data == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&strm, sizeof(strm));

    strm.next_in = e->comp;
    strm.avail_in = (uInt) e->comp_len;
    strm.next_out = data;
    strm.avail_out = (uInt) e->uncomp_len;

    if (inflateInit2(&strm, -MAX_WBITS) != Z_OK) {
        return NGX_ERROR;
    }

    rc = inflate(&strm, Z_FINISH);
    inflateEnd(&strm);

    if (rc != Z_STREAM_END || strm.total_out != e->uncomp_len) {
        return NGX_ERROR;
    }

    out->data = data;
    out->len = e->uncomp_len;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auto_ssl_pem_find(ngx_str_t *s, size_t from, char *marker,
    size_t *pos)
{
    size_t  i, mlen;

    mlen = strlen(marker);

    if (mlen == 0 || from >= s->len || mlen > s->len - from) {
        return NGX_ERROR;
    }

    for (i = from; i + mlen <= s->len; i++) {
        if (ngx_memcmp(s->data + i, marker, mlen) == 0) {
            if (pos != NULL) {
                *pos = i;
            }

            return NGX_OK;
        }
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_http_auto_ssl_extract_bundle(ngx_pool_t *pool, ngx_str_t *body,
    ngx_str_t *prefix, ngx_str_t *cert, ngx_str_t *chain, ngx_str_t *key)
{
    ngx_http_auto_ssl_zip_entry_t  cert_e, chain_e, full_e, key_e;
    u_char                        *pfx;
    size_t                         pfx_len, begin, end;
    ngx_str_t                      full;

    if (pool == NULL || body->len == 0) {
        return NGX_ERROR;
    }

    pfx = NULL;
    pfx_len = 0;

    if (prefix != NULL) {
        pfx = prefix->data;
        pfx_len = prefix->len;
    }

    ngx_memzero(&cert_e, sizeof(cert_e));
    ngx_memzero(&chain_e, sizeof(chain_e));
    ngx_memzero(&full_e, sizeof(full_e));
    ngx_memzero(&key_e, sizeof(key_e));

    ngx_http_auto_ssl_zip_locate(body, pfx, pfx_len, &cert_e, &chain_e,
                                 &full_e, &key_e);

    if (!key_e.found || key_e.uncomp_len == 0) {
        return NGX_ERROR;
    }

    if (ngx_http_auto_ssl_zip_read(pool, &key_e, key) != NGX_OK
        || ngx_http_auto_ssl_pem_find(key, 0, "PRIVATE KEY", NULL) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (cert_e.found && cert_e.uncomp_len != 0) {
        if (ngx_http_auto_ssl_zip_read(pool, &cert_e, cert) != NGX_OK
            || ngx_http_auto_ssl_pem_find(cert, 0, "CERTIFICATE", NULL)
               != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (chain_e.found
            && chain_e.uncomp_len != 0
            && ngx_http_auto_ssl_zip_read(pool, &chain_e, chain) == NGX_OK
            && ngx_http_auto_ssl_pem_find(chain, 0, "CERTIFICATE", NULL)
               == NGX_OK)
        {
            return NGX_OK;
        }

        chain->data = NULL;
        chain->len = 0;

        return NGX_OK;
    }

    if (!full_e.found || full_e.uncomp_len == 0) {
        return NGX_ERROR;
    }

    if (ngx_http_auto_ssl_zip_read(pool, &full_e, &full) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_auto_ssl_pem_find(&full, 0, "-----BEGIN CERTIFICATE-----",
                                   &begin)
        != NGX_OK
        || ngx_http_auto_ssl_pem_find(&full, begin,
                                      "-----END CERTIFICATE-----", &end)
           != NGX_OK)
    {
        return NGX_ERROR;
    }

    end += sizeof("-----END CERTIFICATE-----") - 1;

    if (end < full.len && full.data[end] == '\r') {
        end++;
    }

    if (end < full.len && full.data[end] == '\n') {
        end++;
    }

    cert->data = full.data + begin;
    cert->len = end - begin;

    while (end < full.len
           && (full.data[end] == '\r' || full.data[end] == '\n'))
    {
        end++;
    }

    chain->data = full.data + end;
    chain->len = full.len - end;

    if (ngx_http_auto_ssl_pem_find(chain, 0, "CERTIFICATE", NULL) != NGX_OK) {
        chain->data = NULL;
        chain->len = 0;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_auto_ssl_decrypt_body(ngx_pool_t *pool,
    u_char node_key[NGX_HTTP_AUTO_SSL_NODE_KEY_LEN], ngx_str_t *in,
    ngx_str_t *out)
{
    u_char  *plain;
    size_t   plain_len;

    if (pool == NULL || node_key == NULL || in == NULL || in->len == 0
        || out == NULL)
    {
        return NGX_ERROR;
    }

    plain = ngx_pnalloc(pool, in->len);
    if (plain == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_auto_ssl_gcm_decrypt(node_key, in->data, in->len, plain,
                                      &plain_len)
        != 0)
    {
        return NGX_ERROR;
    }

    out->data = plain;
    out->len = plain_len;

    return NGX_OK;
}


ngx_int_t
ngx_http_auto_ssl_extract_tar_bundle(ngx_pool_t *pool, ngx_str_t *body,
    ngx_str_t *prefix, ngx_str_t *cert, ngx_str_t *chain, ngx_str_t *key)
{
    ngx_http_auto_ssl_span_t  c, h, k;
    u_char                   *pfx;
    size_t                    pfx_len;

    (void) pool;

    if (body == NULL || body->len == 0) {
        return NGX_ERROR;
    }

    pfx = NULL;
    pfx_len = 0;

    if (prefix != NULL) {
        pfx = prefix->data;
        pfx_len = prefix->len;
    }

    if (ngx_http_auto_ssl_tar_extract(body->data, body->len, pfx, pfx_len,
                                      &c, &h, &k)
        != 0)
    {
        return NGX_ERROR;
    }

    cert->data = (u_char *) c.data;
    cert->len = c.len;
    chain->data = (u_char *) h.data;
    chain->len = h.len;
    key->data = (u_char *) k.data;
    key->len = k.len;

    return NGX_OK;
}
