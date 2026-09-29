#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_http_ssl_module.h>

#include "ngx_http_auto_ssl_fetch.h"
#include "ngx_http_auto_ssl_curl.h"
#include "ngx_http_auto_ssl_cache.h"
#include "ngx_http_auto_ssl_ssl.h"


typedef struct {
    ngx_str_t   certmate_url;
    ngx_str_t   certmate_api_token;
    ngx_str_t   certmate_api_token_file;
    ngx_str_t   provisioner_url;
    ngx_str_t   provisioner_api_key;
    ngx_str_t   provisioner_api_key_file;
    ngx_str_t   provisioner_node_key_file;
    ngx_http_auto_ssl_backend_cfg_t  certmate;
    ngx_http_auto_ssl_backend_cfg_t  provisioner;
    ngx_flag_t  certmate_ready;
    ngx_flag_t  provisioner_ready;
    ngx_msec_t  cache_ttl;
    ngx_msec_t  cache_refresh_interval;
    ngx_msec_t  cache_max_stale;
    ngx_msec_t  cache_negative_ttl;
    ngx_msec_t  cache_expiry_interval;
    ngx_msec_t  cache_expiry_before;
} ngx_http_auto_ssl_main_conf_t;


#define NGX_HTTP_AUTO_SSL_WARM_TIMEOUT  5000
#define NGX_HTTP_AUTO_SSL_WARM_BUDGET   25

/*
 * Placeholder certificate path planted when a server uses our directives
 * without static certificates. It holds a variable that is never
 * evaluated (our handshake callback supersedes the variable loader),
 * so no dummy files are needed on disk.
 */
#define NGX_HTTP_AUTO_SSL_PLACEHOLDER  "$auto_ssl_placeholder"


static ngx_int_t ngx_http_auto_ssl_preconfiguration(ngx_conf_t *cf);
static char *ngx_http_auto_ssl_set_domain(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_auto_ssl_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_auto_ssl_init_process(ngx_cycle_t *cycle);
static void ngx_http_auto_ssl_exit_process(ngx_cycle_t *cycle);
static void *ngx_http_auto_ssl_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_auto_ssl_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_auto_ssl_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_auto_ssl_read_secret(ngx_conf_t *cf,
    ngx_str_t *path, ngx_str_t *out);


static ngx_int_t
ngx_http_auto_ssl_placeholder_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    (void) data;

    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                  "auto_ssl: placeholder certificate path was evaluated; "
                  "this is a bug");

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auto_ssl_preconfiguration(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;
    ngx_str_t             name = ngx_string("auto_ssl_placeholder");

    var = ngx_http_add_variable(cf, &name, 0);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_auto_ssl_placeholder_variable;

    return NGX_OK;
}


static ngx_command_t ngx_http_auto_ssl_commands[] = {

    { ngx_string("certmate_url"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_auto_ssl_main_conf_t, certmate_url),
      NULL },

    { ngx_string("certmate_api_token"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_auto_ssl_main_conf_t, certmate_api_token),
      NULL },

    { ngx_string("certmate_api_token_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_auto_ssl_main_conf_t, certmate_api_token_file),
      NULL },

    { ngx_string("ssl_provisioner_url"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_auto_ssl_main_conf_t, provisioner_url),
      NULL },

    { ngx_string("ssl_provisioner_api_key"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_auto_ssl_main_conf_t, provisioner_api_key),
      NULL },

    { ngx_string("ssl_provisioner_api_key_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_auto_ssl_main_conf_t, provisioner_api_key_file),
      NULL },

    { ngx_string("ssl_provisioner_node_key_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_auto_ssl_main_conf_t, provisioner_node_key_file),
      NULL },

    { ngx_string("auto_ssl_cache_ttl"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_auto_ssl_main_conf_t, cache_ttl),
      NULL },

    { ngx_string("auto_ssl_cache_refresh_interval"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_auto_ssl_main_conf_t, cache_refresh_interval),
      NULL },

    { ngx_string("auto_ssl_cache_max_stale"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_auto_ssl_main_conf_t, cache_max_stale),
      NULL },

    { ngx_string("auto_ssl_cache_negative_ttl"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_auto_ssl_main_conf_t, cache_negative_ttl),
      NULL },

    { ngx_string("auto_ssl_cache_expiry_interval"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_auto_ssl_main_conf_t, cache_expiry_interval),
      NULL },

    { ngx_string("auto_ssl_cache_expiry_before"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_auto_ssl_main_conf_t, cache_expiry_before),
      NULL },

    { ngx_string("ssl_certificate_from_certmate"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_auto_ssl_set_domain,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_auto_ssl_srv_conf_t, certmate_domain),
      NULL },

    { ngx_string("ssl_certificate_from_ssl_provisioner"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_auto_ssl_set_domain,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_auto_ssl_srv_conf_t, provisioner_address),
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_auto_ssl_module_ctx = {
    ngx_http_auto_ssl_preconfiguration,
    ngx_http_auto_ssl_init,
    ngx_http_auto_ssl_create_main_conf,
    NULL,
    ngx_http_auto_ssl_create_srv_conf,
    ngx_http_auto_ssl_merge_srv_conf,
    NULL,
    NULL
};


ngx_module_t ngx_http_auto_ssl_module = {
    NGX_MODULE_V1,
    &ngx_http_auto_ssl_module_ctx,
    ngx_http_auto_ssl_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    ngx_http_auto_ssl_init_process,
    NULL,
    NULL,
    ngx_http_auto_ssl_exit_process,
    NULL,
    NGX_MODULE_V1_PADDING
};


ngx_http_auto_ssl_cache_t  *ngx_http_auto_ssl_worker_cache;


static void *
ngx_http_auto_ssl_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_auto_ssl_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auto_ssl_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->cache_ttl = NGX_CONF_UNSET_MSEC;
    conf->cache_refresh_interval = NGX_CONF_UNSET_MSEC;
    conf->cache_max_stale = NGX_CONF_UNSET_MSEC;
    conf->cache_negative_ttl = NGX_CONF_UNSET_MSEC;
    conf->cache_expiry_interval = NGX_CONF_UNSET_MSEC;
    conf->cache_expiry_before = NGX_CONF_UNSET_MSEC;

    return conf;
}


static void *
ngx_http_auto_ssl_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_auto_ssl_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auto_ssl_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_auto_ssl_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auto_ssl_srv_conf_t *prev = parent;
    ngx_http_auto_ssl_srv_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->certmate_domain,
                             prev->certmate_domain, "");
    ngx_conf_merge_str_value(conf->provisioner_address,
                             prev->provisioner_address, "");

    if (conf->provisioner_address.len != 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "ssl_certificate_from_ssl_provisioner is deprecated,"
                           " use ssl_certificate_from_certmate instead");
    }

    if (conf->certmate_domain.len != 0
        && conf->provisioner_address.len != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ssl_certificate_from_certmate and "
                           "ssl_certificate_from_ssl_provisioner "
                           "must not be used together");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auto_ssl_read_secret(ngx_conf_t *cf, ngx_str_t *path, ngx_str_t *out)
{
    FILE        *f;
    u_char      *name;
    u_char      *data;
    ngx_str_t    full;
    long         size;
    size_t       n;
    ngx_uint_t   start;

    /* Resolve against the config prefix, like ssl_certificate does. */
    full = *path;

    if (ngx_conf_full_name(cf->cycle, &full, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    name = ngx_pnalloc(cf->pool, full.len + 1);
    if (name == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(name, full.data, full.len);
    name[full.len] = '\0';

    f = fopen((char *) name, "r");
    if (f == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auto_ssl: cannot open secret file");
        return NGX_ERROR;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NGX_ERROR;
    }

    size = ftell(f);
    if (size < 0 || size > 8192) {
        fclose(f);
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auto_ssl: secret file has invalid size");
        return NGX_ERROR;
    }

    rewind(f);

    data = ngx_pnalloc(cf->pool, (size_t) size + 1);
    if (data == NULL) {
        fclose(f);
        return NGX_ERROR;
    }

    n = fread(data, 1, (size_t) size, f);

    if (n != (size_t) size) {
        fclose(f);
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auto_ssl: cannot read secret file");
        return NGX_ERROR;
    }

    fclose(f);

    out->data = data;
    out->len = n;

    start = 0;
    while (start < out->len
           && (data[start] == ' ' || data[start] == '\t'
               || data[start] == '\r' || data[start] == '\n'))
    {
        start++;
    }

    while (out->len > start
           && (data[out->len - 1] == ' ' || data[out->len - 1] == '\t'
               || data[out->len - 1] == '\r' || data[out->len - 1] == '\n'))
    {
        out->len--;
    }

    if (start != 0) {
        out->data = data + start;
        out->len -= start;
    }

    if (out->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auto_ssl: secret file is empty");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static char *
ngx_http_auto_ssl_inject_placeholder(ngx_conf_t *cf, ngx_array_t **which)
{
    ngx_str_t  *s;

    if (*which == NULL || *which == NGX_CONF_UNSET_PTR) {
        *which = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
        if (*which == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    s = ngx_array_push(*which);
    if (s == NULL) {
        return NGX_CONF_ERROR;
    }

    s->len = sizeof(NGX_HTTP_AUTO_SSL_PLACEHOLDER) - 1;
    s->data = (u_char *) NGX_HTTP_AUTO_SSL_PLACEHOLDER;

    return NGX_CONF_OK;
}


static ngx_uint_t
ngx_http_auto_ssl_certs_touched(ngx_http_ssl_srv_conf_t *sscf)
{
    return (sscf->certificates != NULL
            && sscf->certificates != NGX_CONF_UNSET_PTR)
           || (sscf->certificate_keys != NULL
               && sscf->certificate_keys != NGX_CONF_UNSET_PTR);
}


static char *
ngx_http_auto_ssl_set_domain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                     *p = conf;
    ngx_str_t                *field, *value;
    ngx_http_ssl_srv_conf_t  *sscf;

    field = (ngx_str_t *) (p + cmd->offset);

    if (field->data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *field = value[1];

    /*
     * This setter runs while the server block is parsed, before the SSL
     * module merges it, so planted paths flow through nginx's normal
     * context setup. Only the server's own directives are visible here;
     * http-level certificates are shadowed by the placeholder, which is
     * harmless because the fetched certificate takes precedence at
     * runtime anyway.
     */
    sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);

    if (!ngx_http_auto_ssl_certs_touched(sscf)) {
        if (ngx_http_auto_ssl_inject_placeholder(cf, &sscf->certificates)
            != NGX_CONF_OK
            || ngx_http_auto_ssl_inject_placeholder(cf,
                                                   &sscf->certificate_keys)
               != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auto_ssl_init(ngx_conf_t *cf)
{
    ngx_http_auto_ssl_main_conf_t  *main;
    ngx_str_t                       raw;
    u_char                         *value;
    ngx_uint_t                      i, certmate_touched, provisioner_touched;
    size_t                          len;

    main = ngx_http_conf_get_module_main_conf(cf, ngx_http_auto_ssl_module);

    certmate_touched = main->certmate_url.len != 0
                       || main->certmate_api_token.len != 0
                       || main->certmate_api_token_file.len != 0;

    provisioner_touched = main->provisioner_url.len != 0
                          || main->provisioner_api_key.len != 0
                          || main->provisioner_api_key_file.len != 0;

    if (main->certmate_api_token.len != 0
        && main->certmate_api_token_file.len != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "certmate_api_token and certmate_api_token_file "
                           "must not be used together");
        return NGX_ERROR;
    }

    if (main->provisioner_api_key.len != 0
        && main->provisioner_api_key_file.len != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ssl_provisioner_api_key and "
                           "ssl_provisioner_api_key_file "
                           "must not be used together");
        return NGX_ERROR;
    }

    if (main->certmate_api_token_file.len != 0
        && ngx_http_auto_ssl_read_secret(cf, &main->certmate_api_token_file,
                                         &main->certmate_api_token)
           != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (main->provisioner_api_key_file.len != 0
        && ngx_http_auto_ssl_read_secret(cf, &main->provisioner_api_key_file,
                                         &main->provisioner_api_key)
           != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (main->provisioner_node_key_file.len != 0) {
        if (ngx_http_auto_ssl_read_secret(cf,
                                          &main->provisioner_node_key_file,
                                          &raw)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ngx_http_auto_ssl_node_key_decode(raw.data, raw.len,
                                              main->provisioner.node_key)
            != 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ssl_provisioner_node_key_file must hold "
                               "a 32-byte node key "
                               "(64 hex chars or raw 32 bytes)");
            return NGX_ERROR;
        }

        main->provisioner.node_key_set = 1;
    }

    if (certmate_touched) {
        if (main->certmate_url.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "certmate_url is required when "
                               "certmate credentials are configured");
            return NGX_ERROR;
        }

        if (main->certmate_api_token.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "certmate_api_token or "
                               "certmate_api_token_file is required when "
                               "certmate_url is configured");
            return NGX_ERROR;
        }

        for (i = 0; i < main->certmate_api_token.len; i++) {
            if (main->certmate_api_token.data[i] < 0x20
                || main->certmate_api_token.data[i] == 0x7f)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "certmate_api_token must not contain "
                                   "control characters");
                return NGX_ERROR;
            }
        }
    }

    if (provisioner_touched) {
        if (main->provisioner_url.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ssl_provisioner_url is required when "
                               "ssl provisioner credentials are configured");
            return NGX_ERROR;
        }

        if (main->provisioner_api_key.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ssl_provisioner_api_key or "
                               "ssl_provisioner_api_key_file is required when "
                               "ssl_provisioner_url is configured");
            return NGX_ERROR;
        }

        for (i = 0; i < main->provisioner_api_key.len; i++) {
            if (main->provisioner_api_key.data[i] < 0x20
                || main->provisioner_api_key.data[i] == 0x7f)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "ssl_provisioner_api_key must not contain "
                                   "control characters");
                return NGX_ERROR;
            }
        }
    }

    /*
     * Provisioner bundles arrive encrypted, so the local node key is
     * mandatory there; it only decrypts after download and is never
     * sent to the backend.
     */
    if (provisioner_touched && !main->provisioner.node_key_set) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ssl_provisioner_node_key_file is required when "
                           "ssl_provisioner_url is configured");
        return NGX_ERROR;
    }

    if (main->provisioner_node_key_file.len != 0
        && main->provisioner_url.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ssl_provisioner_url is required when "
                           "ssl_provisioner_node_key_file is configured");
        return NGX_ERROR;
    }

    if (certmate_touched) {
        if (ngx_http_auto_ssl_normalize_base(cf->pool, &main->certmate_url,
                                             &main->certmate.base)
            != NGX_OK)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "certmate_url is invalid");
            return NGX_ERROR;
        }

        len = sizeof("Bearer ") - 1 + main->certmate_api_token.len;

        value = ngx_pnalloc(cf->pool, len);
        if (value == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(value, "Bearer ", sizeof("Bearer ") - 1);
        ngx_memcpy(value + sizeof("Bearer ") - 1,
                   main->certmate_api_token.data,
                   main->certmate_api_token.len);

        main->certmate.headers[0].value.data = value;
        main->certmate.headers[0].value.len = len;
        main->certmate.headers[0].name.data = (u_char *) "Authorization";
        main->certmate.headers[0].name.len = sizeof("Authorization") - 1;
        main->certmate.nheaders = 1;
        main->certmate_ready = 1;
    }

    if (provisioner_touched) {
        if (ngx_http_auto_ssl_normalize_base(cf->pool, &main->provisioner_url,
                                             &main->provisioner.base)
            != NGX_OK)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ssl_provisioner_url is invalid");
            return NGX_ERROR;
        }

        main->provisioner.headers[0].name.data = (u_char *) "X-API-Key";
        main->provisioner.headers[0].name.len = sizeof("X-API-Key") - 1;
        main->provisioner.headers[0].value = main->provisioner_api_key;
        main->provisioner.nheaders = 1;
        main->provisioner_ready = 1;
    }

    ngx_conf_init_msec_value(main->cache_ttl,
                               NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_TTL);
    ngx_conf_init_msec_value(main->cache_refresh_interval,
                               NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_REFRESH_INTERVAL);
    ngx_conf_init_msec_value(main->cache_max_stale,
                               NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_MAX_STALE);
    ngx_conf_init_msec_value(main->cache_negative_ttl,
                               NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_NEGATIVE_TTL);
    ngx_conf_init_msec_value(main->cache_expiry_interval,
                               NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_EXPIRY_INTERVAL);
    ngx_conf_init_msec_value(main->cache_expiry_before,
                               NGX_HTTP_AUTO_SSL_CACHE_DEFAULT_EXPIRY_BEFORE);

    if (main->cache_ttl <= 0 || main->cache_refresh_interval <= 0
        || main->cache_max_stale <= 0 || main->cache_negative_ttl <= 0
        || main->cache_expiry_interval <= 0 || main->cache_expiry_before <= 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "auto_ssl_cache_ttl, "
                           "auto_ssl_cache_refresh_interval, "
                           "auto_ssl_cache_max_stale, "
                           "auto_ssl_cache_negative_ttl, "
                           "auto_ssl_cache_expiry_interval, and "
                           "auto_ssl_cache_expiry_before must be positive");
        return NGX_ERROR;
    }

    if (ngx_http_auto_ssl_ssl_init(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_auto_ssl_warm_one(ngx_uint_t backend, ngx_str_t *key)
{
    ngx_int_t  rc;

    rc = ngx_http_auto_ssl_cache_warm_blocking(
             ngx_http_auto_ssl_worker_cache, backend, key,
             NGX_HTTP_AUTO_SSL_WARM_TIMEOUT);

    if (rc == NGX_ERROR) {
        /* The worker must start even when a backend is down. */
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "auto_ssl: blocking warm failed, "
                      "retrying in the background");

        ngx_http_auto_ssl_cache_prefetch(ngx_http_auto_ssl_worker_cache,
                                         backend, key);
    }
}


static void
ngx_http_auto_ssl_warm_cache(ngx_cycle_t *cycle)
{
    ngx_http_core_main_conf_t     *cmcf;
    ngx_http_core_srv_conf_t     **cscfp;
    ngx_http_auto_ssl_srv_conf_t  *conf;
    ngx_str_t                     *key;
    ngx_uint_t                     backend;
    ngx_uint_t                     i;
    time_t                         start;

    cmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_core_module);
    if (cmcf == NULL) {
        return;
    }

    cscfp = (ngx_http_core_srv_conf_t **) cmcf->servers.elts;

    /*
     * Fetch each server's certificate synchronously: old workers keep
     * serving during a reload, so this delays only the new worker's
     * first accept, not the data plane. A budget keeps a big server
     * list from stalling startup.
     */
    start = ngx_time();

    for (i = 0; i < cmcf->servers.nelts; i++) {
        conf = cscfp[i]->ctx->srv_conf[ngx_http_auto_ssl_module.ctx_index];

        if (ngx_http_auto_ssl_srv_binding(conf, &backend, &key) != NGX_OK) {
            continue;
        }

        /*
         * No event loop runs during worker init, so refresh the cached
         * clock here; otherwise it stays frozen and the budget below
         * never trips.
         */
        ngx_time_update();

        if (ngx_time() - start > NGX_HTTP_AUTO_SSL_WARM_BUDGET) {
            ngx_http_auto_ssl_cache_prefetch(ngx_http_auto_ssl_worker_cache,
                                             backend, key);
            continue;
        }

        ngx_http_auto_ssl_warm_one(backend, key);
    }
}


static ngx_int_t
ngx_http_auto_ssl_init_process(ngx_cycle_t *cycle)
{
    ngx_http_auto_ssl_main_conf_t  *main;

    if (ngx_http_auto_ssl_curl_worker_init(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    main = ngx_http_cycle_get_module_main_conf(cycle,
                                              ngx_http_auto_ssl_module);
    if (main == NULL) {
        ngx_http_auto_ssl_curl_worker_exit(cycle);
        return NGX_ERROR;
    }

    ngx_http_auto_ssl_worker_cache =
        ngx_http_auto_ssl_cache_create(cycle->pool, cycle->log, 128);

    if (ngx_http_auto_ssl_worker_cache == NULL) {
        ngx_http_auto_ssl_curl_worker_exit(cycle);
        return NGX_ERROR;
    }

    ngx_http_auto_ssl_cache_set_backends(ngx_http_auto_ssl_worker_cache,
        &main->certmate, main->certmate_ready,
        &main->provisioner, main->provisioner_ready);

    ngx_http_auto_ssl_cache_configure(ngx_http_auto_ssl_worker_cache,
        main->cache_ttl, main->cache_refresh_interval, main->cache_max_stale,
        main->cache_negative_ttl, main->cache_expiry_interval,
        main->cache_expiry_before);

    ngx_http_auto_ssl_cache_start_refresh(ngx_http_auto_ssl_worker_cache);
    ngx_http_auto_ssl_cache_start_expiry(ngx_http_auto_ssl_worker_cache);

    ngx_http_auto_ssl_warm_cache(cycle);

    return NGX_OK;
}


static void
ngx_http_auto_ssl_exit_process(ngx_cycle_t *cycle)
{
    if (ngx_http_auto_ssl_worker_cache != NULL) {
        ngx_http_auto_ssl_cache_stop_refresh(ngx_http_auto_ssl_worker_cache);
        ngx_http_auto_ssl_cache_stop_expiry(ngx_http_auto_ssl_worker_cache);
        ngx_http_auto_ssl_worker_cache = NULL;
    }

    ngx_http_auto_ssl_curl_worker_exit(cycle);
}
