#include "ngx_http_auto_ssl_tar.h"

#include <string.h>

#include <openssl/evp.h>


#define NGX_HTTP_AUTO_SSL_TAR_BLK       512
#define NGX_HTTP_AUTO_SSL_TAR_MAX_ENT   64
#define NGX_HTTP_AUTO_SSL_TAR_MAX_FILE  (1 * 1024 * 1024)


static int
ngx_http_auto_ssl_tar_hex(int ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }

    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }

    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }

    return -1;
}


static int
ngx_http_auto_ssl_tar_space(unsigned char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}


int
ngx_http_auto_ssl_node_key_decode(const unsigned char *in, size_t in_len,
    unsigned char out[NGX_HTTP_AUTO_SSL_NODE_KEY_LEN])
{
    size_t  start, len, i;
    int     hi, lo;

    if (in == NULL) {
        return -1;
    }

    start = 0;

    while (start < in_len && ngx_http_auto_ssl_tar_space(in[start])) {
        start++;
    }

    len = in_len;

    while (len > start && ngx_http_auto_ssl_tar_space(in[len - 1])) {
        len--;
    }

    len -= start;

    if (len == NGX_HTTP_AUTO_SSL_NODE_KEY_LEN) {
        memcpy(out, in + start, len);
        return 0;
    }

    if (len != 2 * NGX_HTTP_AUTO_SSL_NODE_KEY_LEN) {
        return -1;
    }

    for (i = 0; i < NGX_HTTP_AUTO_SSL_NODE_KEY_LEN; i++) {
        hi = ngx_http_auto_ssl_tar_hex(in[start + 2 * i]);
        lo = ngx_http_auto_ssl_tar_hex(in[start + 2 * i + 1]);

        if (hi < 0 || lo < 0) {
            memset(out, 0, NGX_HTTP_AUTO_SSL_NODE_KEY_LEN);
            return -1;
        }

        out[i] = (unsigned char) ((hi << 4) | lo);
    }

    return 0;
}


int
ngx_http_auto_ssl_gcm_decrypt(
    const unsigned char key[NGX_HTTP_AUTO_SSL_NODE_KEY_LEN],
    const unsigned char *in, size_t in_len,
    unsigned char *out, size_t *out_len)
{
    EVP_CIPHER_CTX  *ctx;
    unsigned char   *tag;
    size_t           ct_len;
    int              len, ok;

    if (key == NULL || in == NULL || out == NULL || out_len == NULL) {
        return -1;
    }

    *out_len = 0;

    if (in_len <= NGX_HTTP_AUTO_SSL_GCM_NONCE_LEN
                   + NGX_HTTP_AUTO_SSL_GCM_TAG_LEN)
    {
        return -1;
    }

    ct_len = in_len - NGX_HTTP_AUTO_SSL_GCM_NONCE_LEN
                    - NGX_HTTP_AUTO_SSL_GCM_TAG_LEN;

    if (ct_len > (size_t) 0x7fffffff) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    ok = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                               NGX_HTTP_AUTO_SSL_GCM_NONCE_LEN, NULL) != 1
        || EVP_DecryptInit_ex(ctx, NULL, NULL, key, in) != 1
        || EVP_DecryptUpdate(ctx, out, &len, in + NGX_HTTP_AUTO_SSL_GCM_NONCE_LEN,
                             (int) ct_len) != 1)
    {
        goto done;
    }

    *out_len = (size_t) len;

    tag = (unsigned char *) (in + NGX_HTTP_AUTO_SSL_GCM_NONCE_LEN + ct_len);

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            NGX_HTTP_AUTO_SSL_GCM_TAG_LEN, tag)
        != 1
        || EVP_DecryptFinal_ex(ctx, out + *out_len, &len) != 1)
    {
        goto done;
    }

    *out_len += (size_t) len;
    ok = 1;

done:

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        /* Never hand unauthenticated plaintext to the caller. */
        memset(out, 0, ct_len);
        *out_len = 0;
        return -1;
    }

    return 0;
}


static int
ngx_http_auto_ssl_tar_zero(const unsigned char *blk)
{
    size_t  i;

    for (i = 0; i < NGX_HTTP_AUTO_SSL_TAR_BLK; i++) {
        if (blk[i] != '\0') {
            return 0;
        }
    }

    return 1;
}


static int
ngx_http_auto_ssl_tar_size(const unsigned char *p, size_t *size)
{
    size_t  i, v;
    int     digits;

    v = 0;
    digits = 0;
    i = 0;

    while (i < 12 && p[i] == ' ') {
        i++;
    }

    for (; i < 12 && p[i] >= '0' && p[i] <= '7'; i++) {
        digits = 1;

        if (v > ((size_t) -1 - 7) / 8) {
            return -1;
        }

        v = v * 8 + (size_t) (p[i] - '0');
    }

    while (i < 12 && (p[i] == '\0' || p[i] == ' ')) {
        i++;
    }

    if (!digits || i != 12) {
        return -1;
    }

    *size = v;

    return 0;
}


static int
ngx_http_auto_ssl_tar_match(const unsigned char *hdr,
    const unsigned char *prefix, size_t prefix_len, const char *base)
{
    unsigned char  full[155 + 1 + 100];
    size_t         nlen, plen, len, blen;

    nlen = strnlen((const char *) hdr, 100);
    plen = strnlen((const char *) hdr + 345, 155);

    len = 0;

    if (plen != 0) {
        memcpy(full, hdr + 345, plen);
        full[plen] = '/';
        len = plen + 1;
    }

    memcpy(full + len, hdr, nlen);
    len += nlen;

    blen = strlen(base);

    if (len != prefix_len + blen) {
        return 0;
    }

    if (prefix_len != 0 && memcmp(full, prefix, prefix_len) != 0) {
        return 0;
    }

    if (memcmp(full + prefix_len, base, blen) != 0) {
        return 0;
    }

    return 1;
}


static int
ngx_http_auto_ssl_tar_find(const unsigned char *data, size_t len,
    size_t from, const char *marker, size_t *pos)
{
    size_t  i, mlen;

    mlen = strlen(marker);

    if (mlen == 0 || from >= len || mlen > len - from) {
        return -1;
    }

    for (i = from; i + mlen <= len; i++) {
        if (memcmp(data + i, marker, mlen) == 0) {
            if (pos != NULL) {
                *pos = i;
            }

            return 0;
        }
    }

    return -1;
}


int
ngx_http_auto_ssl_tar_extract(const unsigned char *tar, size_t tar_len,
    const unsigned char *prefix, size_t prefix_len,
    ngx_http_auto_ssl_span_t *cert, ngx_http_auto_ssl_span_t *chain,
    ngx_http_auto_ssl_span_t *key)
{
    const unsigned char  *hdr, *data, *full;
    size_t                off, size, blocks, begin, end, full_len;
    unsigned int          n;
    ngx_http_auto_ssl_span_t  c, h, f, k;

    if (tar == NULL || cert == NULL || chain == NULL || key == NULL) {
        return -1;
    }

    if (prefix == NULL) {
        prefix_len = 0;
    }

    memset(&c, 0, sizeof(c));
    memset(&h, 0, sizeof(h));
    memset(&f, 0, sizeof(f));
    memset(&k, 0, sizeof(k));

    off = 0;
    n = 0;

    while (off + NGX_HTTP_AUTO_SSL_TAR_BLK <= tar_len) {
        hdr = tar + off;

        if (ngx_http_auto_ssl_tar_zero(hdr)) {
            break;
        }

        if (memcmp(hdr + 257, "ustar", 5) != 0
            || ngx_http_auto_ssl_tar_size(hdr + 124, &size) != 0
            || size > NGX_HTTP_AUTO_SSL_TAR_MAX_FILE
            || n >= NGX_HTTP_AUTO_SSL_TAR_MAX_ENT)
        {
            return -1;
        }

        n++;

        blocks = (size + NGX_HTTP_AUTO_SSL_TAR_BLK - 1)
                 / NGX_HTTP_AUTO_SSL_TAR_BLK;

        if (blocks > (tar_len - off - NGX_HTTP_AUTO_SSL_TAR_BLK)
                      / NGX_HTTP_AUTO_SSL_TAR_BLK)
        {
            return -1;
        }

        data = tar + off + NGX_HTTP_AUTO_SSL_TAR_BLK;

        if ((hdr[156] == '0' || hdr[156] == '\0') && size != 0) {
            ngx_http_auto_ssl_span_t  *dst = NULL;

            if (ngx_http_auto_ssl_tar_match(hdr, prefix, prefix_len,
                                            "cert.pem"))
            {
                dst = &c;

            } else if (ngx_http_auto_ssl_tar_match(hdr, prefix, prefix_len,
                                                  "chain.pem"))
            {
                dst = &h;

            } else if (ngx_http_auto_ssl_tar_match(hdr, prefix, prefix_len,
                                                  "fullchain.pem"))
            {
                dst = &f;

            } else if (ngx_http_auto_ssl_tar_match(hdr, prefix, prefix_len,
                                                  "privkey.pem"))
            {
                dst = &k;
            }

            if (dst != NULL && dst->data == NULL) {
                dst->data = data;
                dst->len = size;
            }
        }

        off += NGX_HTTP_AUTO_SSL_TAR_BLK
               + blocks * NGX_HTTP_AUTO_SSL_TAR_BLK;
    }

    if (k.data == NULL
        || ngx_http_auto_ssl_tar_find(k.data, k.len, 0, "PRIVATE KEY",
                                      NULL)
           != 0)
    {
        return -1;
    }

    /*
     * A present cert.pem must parse; only a missing one falls back to
     * fullchain.pem. Mirrors the ZIP extractor.
     */
    if (c.data != NULL) {
        if (ngx_http_auto_ssl_tar_find(c.data, c.len, 0, "CERTIFICATE",
                                       NULL)
            != 0)
        {
            return -1;
        }

        *cert = c;
        *key = k;

        if (h.data != NULL
            && ngx_http_auto_ssl_tar_find(h.data, h.len, 0, "CERTIFICATE",
                                          NULL)
               == 0)
        {
            *chain = h;

        } else {
            chain->data = NULL;
            chain->len = 0;
        }

        return 0;
    }

    /* fullchain.pem fallback: split off the first certificate. */
    if (f.data == NULL) {
        return -1;
    }

    full = f.data;
    full_len = f.len;

    if (ngx_http_auto_ssl_tar_find(full, full_len, 0,
                                   "-----BEGIN CERTIFICATE-----", &begin) != 0
        || ngx_http_auto_ssl_tar_find(full, full_len, begin,
                                      "-----END CERTIFICATE-----", &end) != 0)
    {
        return -1;
    }

    end += strlen("-----END CERTIFICATE-----");

    if (end < full_len && full[end] == '\r') {
        end++;
    }

    if (end < full_len && full[end] == '\n') {
        end++;
    }

    cert->data = full + begin;
    cert->len = end - begin;

    while (end < full_len && (full[end] == '\r' || full[end] == '\n')) {
        end++;
    }

    if (ngx_http_auto_ssl_tar_find(full, full_len, end, "CERTIFICATE",
                                   NULL)
        == 0)
    {
        chain->data = full + end;
        chain->len = full_len - end;

    } else {
        chain->data = NULL;
        chain->len = 0;
    }

    *key = k;

    return 0;
}
