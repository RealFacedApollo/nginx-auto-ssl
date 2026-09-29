#ifndef NGX_HTTP_AUTO_SSL_SSL_H
#define NGX_HTTP_AUTO_SSL_SSL_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if !(NGX_HTTP_SSL)
#error "ngx_http_auto_ssl_module requires nginx built with --with-http_ssl_module"
#endif

#include <openssl/ssl.h>

#include "ngx_http_auto_ssl_fetch.h"


extern ngx_module_t  ngx_http_auto_ssl_module;


typedef struct {
    ngx_str_t   certmate_domain;
    ngx_str_t   provisioner_address;
} ngx_http_auto_ssl_srv_conf_t;


ngx_int_t ngx_http_auto_ssl_srv_binding(ngx_http_auto_ssl_srv_conf_t *conf,
    ngx_uint_t *backend, ngx_str_t **key);


typedef struct {
    ngx_uint_t  backend;
    ngx_str_t   key;
} ngx_http_auto_ssl_cert_ctx_t;


/* Parsed once at store; handshakes only bump reference counts. */
typedef struct {
    X509            *leaf;
    EVP_PKEY        *pkey;
    STACK_OF(X509)  *chain;
} ngx_http_auto_ssl_parsed_t;


ngx_int_t ngx_http_auto_ssl_parse(ngx_str_t *cert, ngx_str_t *chain,
    ngx_str_t *key, ngx_str_t *domain, time_t now,
    ngx_http_auto_ssl_parsed_t *parsed);

ngx_int_t ngx_http_auto_ssl_expiry(ngx_http_auto_ssl_parsed_t *parsed,
    time_t now, time_t *seconds);

void ngx_http_auto_ssl_parsed_free(ngx_http_auto_ssl_parsed_t *parsed);

ngx_int_t ngx_http_auto_ssl_install_parsed(SSL *ssl,
    ngx_http_auto_ssl_parsed_t *parsed);

int ngx_http_auto_ssl_cert_cb(SSL *ssl, void *arg);

ngx_int_t ngx_http_auto_ssl_ssl_init(ngx_conf_t *cf);


#endif
