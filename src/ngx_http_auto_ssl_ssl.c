#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if !(NGX_HTTP_SSL)
#error "ngx_http_auto_ssl_module requires nginx built with --with-http_ssl_module"
#endif

#include <ngx_http_ssl_module.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <limits.h>

#include "ngx_http_auto_ssl_cache.h"
#include "ngx_http_auto_ssl_ssl.h"


ngx_int_t
ngx_http_auto_ssl_parse(ngx_str_t *cert, ngx_str_t *chain, ngx_str_t *key,
    ngx_str_t *domain, time_t now, ngx_http_auto_ssl_parsed_t *parsed)
{
    BIO            *bio;
    X509           *leaf, *x;
    EVP_PKEY       *pkey;
    STACK_OF(X509) *chainst;

    parsed->leaf = NULL;
    parsed->pkey = NULL;
    parsed->chain = NULL;

    leaf = NULL;
    pkey = NULL;
    chainst = NULL;

    if (cert->len == 0 || cert->len > INT_MAX
        || key->len == 0 || key->len > INT_MAX)
    {
        return NGX_ERROR;
    }

    bio = BIO_new_mem_buf(cert->data, (int) cert->len);
    if (bio == NULL) {
        return NGX_ERROR;
    }

    leaf = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (leaf == NULL) {
        goto failed;
    }

    bio = BIO_new_mem_buf(key->data, (int) key->len);
    if (bio == NULL) {
        goto failed;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (pkey == NULL) {
        goto failed;
    }

    if (chain != NULL && chain->len != 0) {
        if (chain->len > INT_MAX) {
            goto failed;
        }

        chainst = sk_X509_new_null();
        if (chainst == NULL) {
            goto failed;
        }

        bio = BIO_new_mem_buf(chain->data, (int) chain->len);
        if (bio == NULL) {
            goto failed;
        }

        for (;;) {
            x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
            if (x == NULL) {
                break;
            }

            if (sk_X509_push(chainst, x) == 0) {
                X509_free(x);
                BIO_free(bio);
                goto failed;
            }
        }

        BIO_free(bio);

        if (sk_X509_num(chainst) == 0) {
            sk_X509_pop_free(chainst, X509_free);
            chainst = NULL;
        }
    }

    if (X509_check_private_key(leaf, pkey) != 1) {
        goto failed;
    }

    if (domain != NULL && domain->len != 0) {
        if (X509_check_host(leaf, (char *) domain->data, domain->len, 0,
                            NULL)
            != 1)
        {
            goto failed;
        }
    }

    if (X509_cmp_time(X509_get0_notBefore(leaf), &now) > 0
        || X509_cmp_time(X509_get0_notAfter(leaf), &now) < 0)
    {
        goto failed;
    }

    ERR_clear_error();

    parsed->leaf = leaf;
    parsed->pkey = pkey;
    parsed->chain = chainst;

    return NGX_OK;

failed:

    ERR_clear_error();

    if (chainst != NULL) {
        sk_X509_pop_free(chainst, X509_free);
    }

    X509_free(leaf);
    EVP_PKEY_free(pkey);

    return NGX_ERROR;
}


ngx_int_t
ngx_http_auto_ssl_expiry(ngx_http_auto_ssl_parsed_t *parsed, time_t now,
    time_t *seconds)
{
    ASN1_TIME  *t;
    int         days, secs;

    if (parsed->leaf == NULL || seconds == NULL) {
        return NGX_ERROR;
    }

    if (X509_cmp_time(X509_get0_notAfter(parsed->leaf), &now) < 0) {
        *seconds = -1;
        return NGX_OK;
    }

    t = ASN1_TIME_set(NULL, now);
    if (t == NULL) {
        return NGX_ERROR;
    }

    if (ASN1_TIME_diff(&days, &secs, t, X509_get0_notAfter(parsed->leaf))
        != 1)
    {
        ASN1_TIME_free(t);
        return NGX_ERROR;
    }

    ASN1_TIME_free(t);

    if (days > 1000000) {
        days = 1000000;
    }

    *seconds = (time_t) days * 86400 + secs;

    return NGX_OK;
}


void
ngx_http_auto_ssl_parsed_free(ngx_http_auto_ssl_parsed_t *parsed)
{
    if (parsed->chain != NULL) {
        sk_X509_pop_free(parsed->chain, X509_free);
        parsed->chain = NULL;
    }

    X509_free(parsed->leaf);
    parsed->leaf = NULL;

    EVP_PKEY_free(parsed->pkey);
    parsed->pkey = NULL;
}


ngx_int_t
ngx_http_auto_ssl_install_parsed(SSL *ssl,
    ngx_http_auto_ssl_parsed_t *parsed)
{
    STACK_OF(X509)  *chainst;
    X509            *x;
    int              i, n;

    if (parsed->leaf == NULL || parsed->pkey == NULL) {
        return NGX_ERROR;
    }

    chainst = NULL;

    if (parsed->chain != NULL && (n = sk_X509_num(parsed->chain)) > 0) {
        chainst = sk_X509_new_null();
        if (chainst == NULL) {
            return NGX_ERROR;
        }

        /*
         * The cache entry owns its chain, so each handshake takes its own
         * references; the entry may be replaced while the connection that
         * borrowed it is still alive.
         */
        for (i = 0; i < n; i++) {
            x = sk_X509_value(parsed->chain, i);

            if (X509_up_ref(x) != 1) {
                goto failed;
            }

            if (sk_X509_push(chainst, x) == 0) {
                X509_free(x);
                goto failed;
            }
        }
    }

    if (SSL_use_certificate(ssl, parsed->leaf) != 1
        || SSL_use_PrivateKey(ssl, parsed->pkey) != 1
        || (chainst != NULL && SSL_set0_chain(ssl, chainst) != 1))
    {
        goto failed;
    }

    return NGX_OK;

failed:

    if (chainst != NULL) {
        sk_X509_pop_free(chainst, X509_free);
    }

    ERR_clear_error();

    return NGX_ERROR;
}


static time_t  ngx_http_auto_ssl_last_fail_log;


static void
ngx_http_auto_ssl_log_ratelimited(ngx_uint_t level, const char *msg)
{
    time_t  now;

    now = ngx_time();

    if (now == ngx_http_auto_ssl_last_fail_log) {
        return;
    }

    ngx_http_auto_ssl_last_fail_log = now;

    ngx_log_error(level, ngx_cycle->log, 0, "auto_ssl: %s", msg);
}


int
ngx_http_auto_ssl_cert_cb(SSL *ssl, void *arg)
{
    ngx_http_auto_ssl_cert_ctx_t  *cctx = arg;
    ngx_http_auto_ssl_cache_t     *cache;
    ngx_http_auto_ssl_parsed_t    *parsed;

    cache = ngx_http_auto_ssl_worker_cache;

    if (cache == NULL) {
        return 1;
    }

    if (ngx_http_auto_ssl_cache_lookup_parsed(cache, cctx->backend,
                                             &cctx->key, &parsed)
        != NGX_OK)
    {
        if (ngx_http_auto_ssl_cache_lookup_stale(cache, cctx->backend,
                                                &cctx->key, &parsed)
            != NGX_OK)
        {
            ngx_http_auto_ssl_log_ratelimited(NGX_LOG_WARN,
                "no cached certificate, failing handshake");

            ngx_http_auto_ssl_cache_prefetch(cache, cctx->backend,
                                             &cctx->key);

            return 0;
        }

        ngx_http_auto_ssl_cache_prefetch(cache, cctx->backend, &cctx->key);
    }

    if (ngx_http_auto_ssl_install_parsed(ssl, parsed) != NGX_OK) {
        ngx_http_auto_ssl_log_ratelimited(NGX_LOG_ERR,
            "cannot install cached certificate");

        ngx_http_auto_ssl_cache_revalidate(cache, cctx->backend, &cctx->key);

        return 0;
    }

    return 1;
}


/* One server selects at most one backend (merge_srv_conf rejects both). */
ngx_int_t
ngx_http_auto_ssl_srv_binding(ngx_http_auto_ssl_srv_conf_t *conf,
    ngx_uint_t *backend, ngx_str_t **key)
{
    if (conf->certmate_domain.len != 0) {
        *backend = NGX_HTTP_AUTO_SSL_BACKEND_CERTMATE;
        *key = &conf->certmate_domain;
        return NGX_OK;
    }

    if (conf->provisioner_address.len != 0) {
        *backend = NGX_HTTP_AUTO_SSL_BACKEND_PROVISIONER;
        *key = &conf->provisioner_address;
        return NGX_OK;
    }

    return NGX_DECLINED;
}


static ngx_uint_t
ngx_http_auto_ssl_has_ssl_listener(ngx_http_core_main_conf_t *cmcf,
    ngx_http_core_srv_conf_t *cscf)
{
    ngx_http_conf_port_t       *port;
    ngx_http_conf_addr_t       *addr;
    ngx_http_core_srv_conf_t  **cscfp;
    ngx_uint_t                  p, a, s;

    if (cmcf->ports == NULL) {
        return 0;
    }

    port = cmcf->ports->elts;

    for (p = 0; p < cmcf->ports->nelts; p++) {
        addr = port[p].addrs.elts;

        for (a = 0; a < port[p].addrs.nelts; a++) {
            if (!addr[a].opt.ssl) {
                continue;
            }

            cscfp = addr[a].servers.elts;

            for (s = 0; s < addr[a].servers.nelts; s++) {
                if (cscfp[s] == cscf) {
                    return 1;
                }
            }
        }
    }

    return 0;
}


ngx_int_t
ngx_http_auto_ssl_ssl_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t     *cmcf;
    ngx_http_core_srv_conf_t     **cscfp;
    ngx_http_ssl_srv_conf_t       *sscf;
    ngx_http_auto_ssl_srv_conf_t  *ascf;
    ngx_http_auto_ssl_cert_ctx_t  *cctx;
    ngx_str_t                     *key;
    ngx_uint_t                     backend;
    ngx_uint_t                     i;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    cscfp = (ngx_http_core_srv_conf_t **) cmcf->servers.elts;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        ascf = cscfp[i]->ctx->srv_conf[ngx_http_auto_ssl_module.ctx_index];

        if (ngx_http_auto_ssl_srv_binding(ascf, &backend, &key) != NGX_OK) {
            continue;
        }

        sscf = cscfp[i]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];

        if (sscf == NULL || sscf->ssl.ctx == NULL
            || !ngx_http_auto_ssl_has_ssl_listener(cmcf, cscfp[i]))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ssl_certificate_from_certmate and "
                               "ssl_certificate_from_ssl_provisioner require "
                               "a TLS server block: add \"listen ... ssl\" "
                               "to this server block");
            return NGX_ERROR;
        }

        cctx = ngx_pnalloc(cf->pool, sizeof(*cctx));
        if (cctx == NULL) {
            return NGX_ERROR;
        }

        cctx->backend = backend;
        cctx->key = *key;

        SSL_CTX_set_cert_cb(sscf->ssl.ctx, ngx_http_auto_ssl_cert_cb, cctx);
    }

    return NGX_OK;
}
