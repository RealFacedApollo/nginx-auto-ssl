#include "ngx_http_auto_ssl_curl.h"

#include <curl/curl.h>


typedef struct ngx_http_auto_ssl_curl_sock_s  ngx_http_auto_ssl_curl_sock_t;

struct ngx_http_auto_ssl_curl_sock_s {
    ngx_http_auto_ssl_curl_sock_t  *next;
    ngx_connection_t               *c;
    curl_socket_t                   fd;
};


typedef struct ngx_http_auto_ssl_curl_op_s  ngx_http_auto_ssl_curl_op_t;

struct ngx_http_auto_ssl_curl_op_s {
    ngx_http_auto_ssl_fetch_done_pt    handler;
    void                              *data;
    struct curl_slist                 *headers;
    ngx_pool_t                        *pool;
    ngx_str_t                          prefix;
    ngx_str_t                          url;
    u_char                            *body;
    size_t                             body_len;
    size_t                             body_cap;
    char                               err[CURL_ERROR_SIZE];
    ngx_uint_t                         backend;
    u_char                             node_key[NGX_HTTP_AUTO_SSL_NODE_KEY_LEN];
    ngx_flag_t                         node_key_set;
    ngx_uint_t                         attempt;
    ngx_event_t                        retry;
    ngx_http_auto_ssl_curl_op_t        *retry_next;
};


typedef struct {
    CURLM                              *multi;
    ngx_pool_t                         *pool;
    ngx_log_t                          *log;
    ngx_event_t                         timer;
    ngx_http_auto_ssl_curl_sock_t      *socks;
    ngx_http_auto_ssl_curl_op_t        *retries;
} ngx_http_auto_ssl_curl_worker_t;


static ngx_http_auto_ssl_curl_worker_t  ngx_http_auto_ssl_curl_worker;


#if LIBCURL_VERSION_NUM >= 0x071507
static int ngx_http_auto_ssl_curl_close_cb(void *clientp,
    curl_socket_t sock_fd);
#endif


/*
 * A certificate bundle is a few kilobytes of PEM; anything past this is
 * either a misbehaving backend or an attack on worker memory.
 */
#define NGX_HTTP_AUTO_SSL_CURL_MAX_BODY  (256 * 1024)

/* Fetch resiliency mirrors the ssl-provisioner script. */
#define NGX_HTTP_AUTO_SSL_CURL_CONNECT_TIMEOUT  15
#define NGX_HTTP_AUTO_SSL_CURL_TIMEOUT          30
#define NGX_HTTP_AUTO_SSL_CURL_RETRY_MAX        2
#define NGX_HTTP_AUTO_SSL_CURL_RETRY_DELAY      2000


static ngx_uint_t
ngx_http_auto_ssl_curl_retryable(CURLcode res, long code)
{
    if (res != CURLE_OK) {
        switch (res) {
        case CURLE_OPERATION_TIMEDOUT:
        case CURLE_COULDNT_RESOLVE_HOST:
        case CURLE_COULDNT_CONNECT:
        case CURLE_GOT_NOTHING:
        case CURLE_SEND_ERROR:
        case CURLE_RECV_ERROR:
        case CURLE_PARTIAL_FILE:
            return 1;

        default:
            return 0;
        }
    }

    return code == 408 || code == 429 || (code >= 500 && code <= 599);
}


static void ngx_http_auto_ssl_curl_retry_event(ngx_event_t *ev);

static size_t ngx_http_auto_ssl_curl_write(char *ptr, size_t size,
    size_t nmemb, void *userdata);


static ngx_uint_t
ngx_http_auto_ssl_curl_scheme_len(u_char *d, size_t len)
{
    if (len >= 7
        && (d[0] == 'h' || d[0] == 'H')
        && (d[1] == 't' || d[1] == 'T')
        && (d[2] == 't' || d[2] == 'T')
        && (d[3] == 'p' || d[3] == 'P')
        && d[4] == ':' && d[5] == '/' && d[6] == '/')
    {
        return 7;
    }

    if (len >= 8
        && (d[0] == 'h' || d[0] == 'H')
        && (d[1] == 't' || d[1] == 'T')
        && (d[2] == 't' || d[2] == 'T')
        && (d[3] == 'p' || d[3] == 'P')
        && (d[4] == 's' || d[4] == 'S')
        && d[5] == ':' && d[6] == '/' && d[7] == '/')
    {
        return 8;
    }

    return 0;
}


ngx_int_t
ngx_http_auto_ssl_normalize_base(ngx_pool_t *pool, ngx_str_t *url,
    ngx_str_t *out)
{
    u_char      *data;
    size_t       len;
    ngx_uint_t   scheme;

    if (url->len == 0) {
        return NGX_ERROR;
    }

    scheme = ngx_http_auto_ssl_curl_scheme_len(url->data, url->len);
    if (scheme == 0) {
        return NGX_ERROR;
    }

    len = url->len;

    while (len > 0 && url->data[len - 1] == '/') {
        len--;
    }

    if (len <= scheme || url->data[scheme] == '/') {
        return NGX_ERROR;
    }

    data = ngx_pnalloc(pool, len);
    if (data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(data, url->data, len);

    out->data = data;
    out->len = len;

    return NGX_OK;
}


static ngx_uint_t
ngx_http_auto_ssl_curl_unreserved(u_char ch)
{
    if ((ch >= 'a' && ch <= 'z')
        || (ch >= 'A' && ch <= 'Z')
        || (ch >= '0' && ch <= '9')
        || ch == '-' || ch == '.' || ch == '_' || ch == '~')
    {
        return 1;
    }

    return 0;
}


ngx_int_t
ngx_http_auto_ssl_build_fetch_url(ngx_pool_t *pool, ngx_uint_t backend,
    ngx_str_t *base, ngx_str_t *key, ngx_str_t *out)
{
    static u_char  hex[] = "0123456789ABCDEF";

    u_char  *b, *mid, *tail;
    size_t   total, i, mid_len, tail_len;

    if (base->len == 0 || key->len == 0) {
        return NGX_ERROR;
    }

    if (backend == NGX_HTTP_AUTO_SSL_BACKEND_CERTMATE) {
        mid = (u_char *) "/api/certificates/";
        mid_len = sizeof("/api/certificates/") - 1;
        tail = (u_char *) "/download";
        tail_len = sizeof("/download") - 1;

    } else if (backend == NGX_HTTP_AUTO_SSL_BACKEND_PROVISIONER) {
        mid = (u_char *) "/cert/";
        mid_len = sizeof("/cert/") - 1;
        tail = (u_char *) "";
        tail_len = 0;

    } else {
        return NGX_ERROR;
    }

    total = base->len + mid_len + tail_len + 1;

    for (i = 0; i < key->len; i++) {
        if (ngx_http_auto_ssl_curl_unreserved(key->data[i])) {
            total += 1;

        } else {
            total += 3;
        }
    }

    b = ngx_pnalloc(pool, total);
    if (b == NULL) {
        return NGX_ERROR;
    }

    out->data = b;
    out->len = total - 1;

    b = ngx_cpymem(b, base->data, base->len);
    b = ngx_cpymem(b, mid, mid_len);

    for (i = 0; i < key->len; i++) {
        if (ngx_http_auto_ssl_curl_unreserved(key->data[i])) {
            *b++ = key->data[i];

        } else {
            *b++ = '%';
            *b++ = hex[key->data[i] >> 4];
            *b++ = hex[key->data[i] & 0x0f];
        }
    }

    b = ngx_cpymem(b, tail, tail_len);
    *b = '\0';

    return NGX_OK;
}


static void
ngx_http_auto_ssl_curl_setopt(CURL *easy, ngx_str_t *url,
    struct curl_slist *headers, ngx_http_auto_ssl_curl_op_t *op)
{
    curl_easy_setopt(easy, CURLOPT_URL, (char *) url->data);
    curl_easy_setopt(easy, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(easy, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION,
                     ngx_http_auto_ssl_curl_write);
    curl_easy_setopt(easy, CURLOPT_WRITEDATA, op);
    curl_easy_setopt(easy, CURLOPT_ERRORBUFFER, op->err);
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 0L);
#if LIBCURL_VERSION_NUM >= 0x071507
    /*
     * Own socket close ordering: libcurl occasionally closes a socket
     * before reporting REMOVE, and deleting kqueue filters against the
     * already-closed fd alerts (ENOENT). Intercepting the close lets us
     * detach first, so deletes always run against a live fd.
     */
    curl_easy_setopt(easy, CURLOPT_CLOSESOCKETFUNCTION,
                     ngx_http_auto_ssl_curl_close_cb);
    curl_easy_setopt(easy, CURLOPT_CLOSESOCKETDATA, NULL);
#endif
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
    curl_easy_setopt(easy, CURLOPT_PROTOCOLS,
                     (long) (CURLPROTO_HTTP | CURLPROTO_HTTPS));
    curl_easy_setopt(easy, CURLOPT_REDIR_PROTOCOLS,
                     (long) (CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
}


static void
ngx_http_auto_ssl_curl_done(ngx_http_auto_ssl_curl_op_t *op,
    ngx_int_t status, ngx_str_t *cert, ngx_str_t *chain, ngx_str_t *key)
{
    ngx_pool_t                       *pool = op->pool;
    ngx_http_auto_ssl_fetch_done_pt   handler = op->handler;
    void                             *data = op->data;

    if (op->headers != NULL) {
        curl_slist_free_all(op->headers);
        op->headers = NULL;
    }

    if (status == NGX_OK) {
        handler(data, NGX_OK, cert, chain, key);

    } else {
        handler(data, NGX_ERROR, NULL, NULL, NULL);
    }

    if (pool != NULL) {
        ngx_destroy_pool(pool);
    }
}


static void
ngx_http_auto_ssl_curl_arm_retry(ngx_http_auto_ssl_curl_worker_t *w,
    ngx_http_auto_ssl_curl_op_t *op)
{
    op->attempt++;
    op->body_len = 0;

    ngx_log_error(NGX_LOG_WARN, w->log, 0,
                  "auto_ssl: fetch failed transiently, retrying in %uis "
                  "(attempt %ui of %ui)",
                  NGX_HTTP_AUTO_SSL_CURL_RETRY_DELAY / 1000, op->attempt,
                  NGX_HTTP_AUTO_SSL_CURL_RETRY_MAX + 1);

    op->retry.handler = ngx_http_auto_ssl_curl_retry_event;
    op->retry.data = op;
    op->retry.log = w->log;
    op->retry.cancelable = 1;

    op->retry_next = w->retries;
    w->retries = op;

    ngx_add_timer(&op->retry, NGX_HTTP_AUTO_SSL_CURL_RETRY_DELAY);
}


static ngx_int_t
ngx_http_auto_ssl_curl_parse(ngx_pool_t *pool, ngx_log_t *log,
    ngx_uint_t backend, u_char *node_key, ngx_flag_t node_key_set,
    ngx_str_t *prefix, ngx_str_t *body,
    ngx_str_t *cert, ngx_str_t *chain, ngx_str_t *key)
{
    ngx_str_t  plain;

    /*
     * A 200 with an unusable body is a backend bug, not a transient
     * failure; retrying the same bytes is pointless.
     */
    if (backend == NGX_HTTP_AUTO_SSL_BACKEND_PROVISIONER) {
        /* The node key only decrypts locally; it is never sent. */
        if (!node_key_set
            || ngx_http_auto_ssl_decrypt_body(pool, node_key, body, &plain)
               != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "auto_ssl: fetch body cannot be decrypted "
                          "with the node key");
            return NGX_ERROR;
        }

        if (ngx_http_auto_ssl_extract_tar_bundle(pool, &plain, prefix,
                                                 cert, chain, key)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "auto_ssl: fetch body is not a usable "
                          "certificate bundle");
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    if (ngx_http_auto_ssl_extract_bundle(pool, body, prefix, cert, chain,
                                         key)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "auto_ssl: fetch body is not a usable "
                      "certificate bundle");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_auto_ssl_curl_check(ngx_http_auto_ssl_curl_worker_t *w)
{
    CURLMsg                      *msg;
    int                           queued;
    CURL                         *easy;
    CURLcode                      res;
    ngx_http_auto_ssl_curl_op_t  *op;
    long                          code;
    ngx_int_t                     status;
    ngx_str_t                     body, cert, chain, key;
    ngx_str_t                    *prefix;

    while ((msg = curl_multi_info_read(w->multi, &queued)) != NULL) {
        if (msg->msg != CURLMSG_DONE) {
            continue;
        }

        easy = msg->easy_handle;
        res = msg->data.result;

        curl_easy_getinfo(easy, CURLINFO_PRIVATE, &op);
        curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &code);

        curl_multi_remove_handle(w->multi, easy);
        curl_easy_cleanup(easy);

        status = NGX_OK;

        if (res != CURLE_OK || code != 200) {
            if (op->attempt <= NGX_HTTP_AUTO_SSL_CURL_RETRY_MAX
                && ngx_http_auto_ssl_curl_retryable(res, code))
            {
                ngx_http_auto_ssl_curl_arm_retry(w, op);
                continue;
            }

            if (res != CURLE_OK) {
                ngx_log_error(NGX_LOG_ERR, w->log, 0,
                              "auto_ssl: fetch failed: %s", op->err);

            } else {
                ngx_log_error(NGX_LOG_ERR, w->log, 0,
                              "auto_ssl: fetch returned status %l", code);
            }

            status = NGX_ERROR;

        } else {
            body.data = op->body;
            body.len = op->body_len;

            prefix = op->prefix.len != 0 ? &op->prefix : NULL;

            if (ngx_http_auto_ssl_curl_parse(op->pool, w->log, op->backend,
                                             op->node_key, op->node_key_set,
                                             prefix, &body, &cert, &chain,
                                             &key)
                != NGX_OK)
            {
                status = NGX_ERROR;
            }
        }

        if (status == NGX_OK) {
            ngx_http_auto_ssl_curl_done(op, NGX_OK, &cert, &chain, &key);

        } else {
            ngx_http_auto_ssl_curl_done(op, NGX_ERROR, NULL, NULL, NULL);
        }
    }
}


static size_t
ngx_http_auto_ssl_curl_write(char *ptr, size_t size, size_t nmemb,
    void *userdata)
{
    ngx_http_auto_ssl_curl_op_t  *op = userdata;
    size_t                        n, cap;
    u_char                       *body;

    n = size * nmemb;

    if (n == 0) {
        return 0;
    }

    if (n > NGX_HTTP_AUTO_SSL_CURL_MAX_BODY
        || op->body_len > NGX_HTTP_AUTO_SSL_CURL_MAX_BODY - n)
    {
        return 0;
    }

    if (op->body_len + n > op->body_cap) {
        cap = op->body_cap ? op->body_cap * 2 : 4096;

        while (cap < op->body_len + n) {
            cap *= 2;
        }

        body = ngx_palloc(op->pool, cap);
        if (body == NULL) {
            return 0;
        }

        if (op->body_len != 0) {
            ngx_memcpy(body, op->body, op->body_len);
        }

        op->body = body;
        op->body_cap = cap;
    }

    ngx_memcpy(op->body + op->body_len, ptr, n);
    op->body_len += n;

    return n;
}


static void
ngx_http_auto_ssl_curl_event(ngx_event_t *ev)
{
    ngx_connection_t                    *c = ev->data;
    ngx_http_auto_ssl_curl_worker_t     *w;
    int                                  action = 0;
    int                                  running;

    w = &ngx_http_auto_ssl_curl_worker;

    if (ev->write) {
        action |= CURL_CSELECT_OUT;
    } else {
        action |= CURL_CSELECT_IN;
    }

    curl_multi_socket_action(w->multi, c->fd, action, &running);

    ngx_http_auto_ssl_curl_check(w);
}


static void
ngx_http_auto_ssl_curl_detach(ngx_connection_t *c)
{
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (c->read->posted) {
        ngx_delete_posted_event(c->read);
    }

    if (c->write->posted) {
        ngx_delete_posted_event(c->write);
    }

    /*
     * Flush deletes synchronously: the close callback detaches before
     * libcurl's close lands, so the fd is live here and a deferred
     * delete would risk hitting it after the close.
     */
    if (c->read->active || c->read->disabled) {
        if (ngx_del_event(c->read, NGX_READ_EVENT, NGX_FLUSH_EVENT)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "auto_ssl: detach READ del failed");
        }
    }

    if (c->write->active || c->write->disabled) {
        if (ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_FLUSH_EVENT)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "auto_ssl: detach WRITE del failed");
        }
    }

    c->read->closed = 1;
    c->write->closed = 1;

    /*
     * The fd belongs to libcurl, which closes it; drop our claim so the
     * worker-exit audit does not see an open socket on this connection.
     */
    c->fd = -1;

    ngx_free_connection(c);
}


#if LIBCURL_VERSION_NUM >= 0x071507
static int
ngx_http_auto_ssl_curl_close_cb(void *clientp, curl_socket_t sock_fd)
{
    ngx_http_auto_ssl_curl_worker_t  *w = &ngx_http_auto_ssl_curl_worker;
    ngx_http_auto_ssl_curl_sock_t    *sock;

    (void) clientp;

    for (sock = w->socks; sock != NULL; sock = sock->next) {
        if (sock->fd == sock_fd) {
            break;
        }
    }

    if (sock != NULL && sock->c != NULL) {
        /*
         * Close arrived before REMOVE: detach now, while the fd is
         * still live, and leave the slot for REMOVE to release.
         */
        ngx_log_error(NGX_LOG_INFO, w->log, 0,
                      "auto_ssl: socket closed before REMOVE, "
                      "detaching early");
        ngx_http_auto_ssl_curl_detach(sock->c);
        sock->c = NULL;
    }

    (void) close((int) sock_fd);

    return 0;
}
#endif


static int
ngx_http_auto_ssl_curl_sock(CURL *easy, curl_socket_t s, int action,
    void *userp, void *socketp)
{
    ngx_http_auto_ssl_curl_worker_t  *w = userp;
    ngx_http_auto_ssl_curl_sock_t    *sock = socketp;
    ngx_connection_t                 *c;

    (void) easy;

    if (action == CURL_POLL_REMOVE) {
        if (sock != NULL) {
            if (sock->c != NULL) {
                ngx_http_auto_ssl_curl_detach(sock->c);
                sock->c = NULL;
            }

            if (w->socks == sock) {
                w->socks = sock->next;

            } else {
                ngx_http_auto_ssl_curl_sock_t  *prev;

                for (prev = w->socks;
                     prev != NULL && prev->next != sock;
                     prev = prev->next)
                {
                }

                if (prev != NULL) {
                    prev->next = sock->next;
                }
            }

            ngx_free(sock);
        }

        curl_multi_assign(w->multi, s, NULL);

        return 0;
    }

    if (sock != NULL && sock->c == NULL) {
        /*
         * The close callback detached this socket early (close arrived
         * before REMOVE). A stray POLL for the now-dead socket must not
         * touch the freed connection; REMOVE still owns slot release.
         */
        ngx_log_error(NGX_LOG_INFO, w->log, 0,
                      "auto_ssl: stray POLL after early detach, ignoring");
        return 0;
    }

    if (sock == NULL) {
        sock = ngx_calloc(sizeof(*sock), w->log);
        if (sock == NULL) {
            return -1;
        }

        c = ngx_get_connection(s, w->log);
        if (c == NULL) {
            ngx_free(sock);
            return -1;
        }

        c->read->handler = ngx_http_auto_ssl_curl_event;
        c->write->handler = ngx_http_auto_ssl_curl_event;
        c->read->data = c;
        c->write->data = c;
        c->read->log = w->log;
        c->write->log = w->log;

        sock->c = c;
        sock->fd = s;

        sock->next = w->socks;
        w->socks = sock;

        curl_multi_assign(w->multi, s, sock);
    }

    c = sock->c;

    if (action == CURL_POLL_IN || action == CURL_POLL_INOUT) {
        if (ngx_add_event(c->read, NGX_READ_EVENT, NGX_LEVEL_EVENT) != NGX_OK) {
            return -1;
        }

    } else if (c->read->active) {
        /* FLUSH: kqueue batches plain dels; a pending DELETE orphaned by a
         * later add + REMOVE in the same turn fires against the closed fd
         * (ENOENT alert). Synchronous delete keeps kernel state exact. */
        ngx_del_event(c->read, NGX_READ_EVENT, NGX_FLUSH_EVENT);
    }

    if (action == CURL_POLL_OUT || action == CURL_POLL_INOUT) {
        if (ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_LEVEL_EVENT)
            != NGX_OK)
        {
            return -1;
        }

    } else if (c->write->active) {
        /* FLUSH for the same reason as above: never leave a DELETE
         * pending across a curl socket-state burst in one event turn. */
        ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_FLUSH_EVENT);
    }

    return 0;
}


static void
ngx_http_auto_ssl_curl_timer_event(ngx_event_t *ev)
{
    ngx_http_auto_ssl_curl_worker_t  *w = ev->data;
    int                               running;

    curl_multi_socket_action(w->multi, CURL_SOCKET_TIMEOUT, 0, &running);

    ngx_http_auto_ssl_curl_check(w);
}


static int
ngx_http_auto_ssl_curl_timer(CURLM *multi, long timeout_ms, void *userp)
{
    ngx_http_auto_ssl_curl_worker_t  *w = userp;

    (void) multi;

    if (timeout_ms < 0) {
        if (w->timer.timer_set) {
            ngx_del_timer(&w->timer);
        }

    } else {
        ngx_add_timer(&w->timer, (ngx_msec_t) timeout_ms);
    }

    return 0;
}


static void
ngx_http_auto_ssl_curl_retry_event(ngx_event_t *ev)
{
    ngx_http_auto_ssl_curl_op_t       *op = ev->data;
    ngx_http_auto_ssl_curl_worker_t   *w;
    ngx_http_auto_ssl_curl_op_t       *o, **prev;
    CURL                              *easy;
    int                                running;

    w = &ngx_http_auto_ssl_curl_worker;

    prev = &w->retries;

    for (o = *prev; o != NULL; o = o->retry_next) {
        if (o == op) {
            *prev = o->retry_next;
            break;
        }

        prev = &o->retry_next;
    }

    op->retry_next = NULL;
    op->err[0] = '\0';

    easy = curl_easy_init();
    if (easy == NULL) {
        ngx_http_auto_ssl_curl_done(op, NGX_ERROR, NULL, NULL, NULL);
        return;
    }

    ngx_http_auto_ssl_curl_setopt(easy, &op->url, op->headers, op);
    curl_easy_setopt(easy, CURLOPT_PRIVATE, op);
    curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT,
                     (long) NGX_HTTP_AUTO_SSL_CURL_CONNECT_TIMEOUT);
    curl_easy_setopt(easy, CURLOPT_TIMEOUT,
                     (long) NGX_HTTP_AUTO_SSL_CURL_TIMEOUT);

    if (curl_multi_add_handle(w->multi, easy) != CURLM_OK) {
        curl_easy_cleanup(easy);
        ngx_http_auto_ssl_curl_done(op, NGX_ERROR, NULL, NULL, NULL);
        return;
    }

    curl_multi_socket_action(w->multi, CURL_SOCKET_TIMEOUT, 0, &running);

    ngx_http_auto_ssl_curl_check(w);
}


static ngx_int_t
ngx_http_auto_ssl_curl_headers(ngx_pool_t *pool,
    ngx_http_auto_ssl_backend_cfg_t *cfg, struct curl_slist **headers)
{
    u_char             *line, *start;
    size_t              line_len;
    ngx_uint_t          i;
    struct curl_slist  *h;

    *headers = NULL;

    for (i = 0; i < cfg->nheaders && i < 2; i++) {
        line_len = cfg->headers[i].name.len + 2 + cfg->headers[i].value.len
                   + 1;

        start = ngx_pnalloc(pool, line_len);
        if (start == NULL) {
            goto failed;
        }

        line = ngx_cpymem(start, cfg->headers[i].name.data,
                          cfg->headers[i].name.len);
        line = ngx_cpymem(line, (u_char *) ": ", 2);
        line = ngx_cpymem(line, cfg->headers[i].value.data,
                          cfg->headers[i].value.len);
        *line = '\0';

        h = curl_slist_append(*headers, (char *) start);
        if (h == NULL) {
            goto failed;
        }

        *headers = h;
    }

    return NGX_OK;

failed:

    if (*headers != NULL) {
        curl_slist_free_all(*headers);
        *headers = NULL;
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_http_auto_ssl_curl_worker_init(ngx_cycle_t *cycle)
{
    ngx_http_auto_ssl_curl_worker_t  *w;
    curl_version_info_data           *info;

    w = &ngx_http_auto_ssl_curl_worker;

    ngx_memzero(w, sizeof(*w));

    w->pool = cycle->pool;
    w->log = cycle->log;

    w->timer.handler = ngx_http_auto_ssl_curl_timer_event;
    w->timer.data = w;
    w->timer.log = w->log;
    w->timer.cancelable = 1;

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        return NGX_ERROR;
    }

    w->multi = curl_multi_init();
    if (w->multi == NULL) {
        curl_global_cleanup();
        return NGX_ERROR;
    }

    curl_multi_setopt(w->multi, CURLMOPT_SOCKETFUNCTION,
                      ngx_http_auto_ssl_curl_sock);
    curl_multi_setopt(w->multi, CURLMOPT_SOCKETDATA, w);
    curl_multi_setopt(w->multi, CURLMOPT_TIMERFUNCTION,
                      ngx_http_auto_ssl_curl_timer);
    curl_multi_setopt(w->multi, CURLMOPT_TIMERDATA, w);

    info = curl_version_info(CURLVERSION_NOW);

#ifdef CURL_VERSION_ASYNCHDNS
    if (info != NULL && !(info->features & CURL_VERSION_ASYNCHDNS)) {
        ngx_log_error(NGX_LOG_WARN, w->log, 0,
                      "auto_ssl: libcurl has no asynchronous resolver; "
                      "backend fetches may stall the worker during DNS");
    }
#else
    (void) info;
#endif

    return NGX_OK;
}


void
ngx_http_auto_ssl_curl_worker_exit(ngx_cycle_t *cycle)
{
    ngx_http_auto_ssl_curl_worker_t  *w;
    ngx_http_auto_ssl_curl_sock_t    *sock;

    (void) cycle;

    w = &ngx_http_auto_ssl_curl_worker;

    /*
     * Detach every bridged connection first: multi_cleanup closes the
     * sockets without REMOVE callbacks, and any wrapper left claiming
     * an fd trips the worker-exit audit.
     */
    while (w->socks != NULL) {
        sock = w->socks;
        w->socks = sock->next;

        if (sock->c != NULL) {
            ngx_http_auto_ssl_curl_detach(sock->c);
            sock->c = NULL;
        }

        ngx_free(sock);
    }

    if (w->multi != NULL) {
        curl_multi_cleanup(w->multi);
        w->multi = NULL;
    }

    curl_global_cleanup();
}


/*
 * Shared fetch setup for both paths; on failure returns NULL with
 * nothing leaked outside pool.
 */
static CURL *
ngx_http_auto_ssl_curl_new_easy(ngx_pool_t *pool,
    ngx_http_auto_ssl_backend_cfg_t *cfg, ngx_uint_t backend, ngx_str_t *key,
    ngx_http_auto_ssl_curl_op_t *op, ngx_str_t *url,
    struct curl_slist **headers)
{
    CURL    *easy;
    u_char  *pfx;

    op->err[0] = '\0';

    if (backend == NGX_HTTP_AUTO_SSL_BACKEND_PROVISIONER) {
        pfx = ngx_pnalloc(pool, key->len + 1);
        if (pfx == NULL) {
            return NULL;
        }

        ngx_memcpy(pfx, key->data, key->len);
        pfx[key->len] = '/';

        op->prefix.data = pfx;
        op->prefix.len = key->len + 1;
    }

    if (ngx_http_auto_ssl_build_fetch_url(pool, backend, &cfg->base, key,
                                          url)
        != NGX_OK)
    {
        return NULL;
    }

    easy = curl_easy_init();
    if (easy == NULL) {
        return NULL;
    }

    if (ngx_http_auto_ssl_curl_headers(pool, cfg, headers) != NGX_OK) {
        curl_easy_cleanup(easy);
        return NULL;
    }

    ngx_http_auto_ssl_curl_setopt(easy, url, *headers, op);

    return easy;
}


ngx_int_t
ngx_http_auto_ssl_curl_fetch(ngx_http_auto_ssl_backend_cfg_t *cfg,
    ngx_uint_t backend, ngx_str_t *key,
    ngx_http_auto_ssl_fetch_done_pt handler, void *data)
{
    ngx_http_auto_ssl_curl_worker_t  *w;
    ngx_http_auto_ssl_curl_op_t      *op;
    ngx_pool_t                       *op_pool;
    CURL                             *easy;
    ngx_str_t                         url;
    int                               running;

    w = &ngx_http_auto_ssl_curl_worker;

    if (w->multi == NULL || cfg == NULL || key->len == 0
        || handler == NULL
        || (backend != NGX_HTTP_AUTO_SSL_BACKEND_CERTMATE
            && backend != NGX_HTTP_AUTO_SSL_BACKEND_PROVISIONER))
    {
        return NGX_ERROR;
    }

    op_pool = ngx_create_pool(4096, w->log);
    if (op_pool == NULL) {
        return NGX_ERROR;
    }

    op = ngx_pcalloc(op_pool, sizeof(*op));
    if (op == NULL) {
        ngx_destroy_pool(op_pool);
        return NGX_ERROR;
    }

    op->handler = handler;
    op->data = data;
    op->pool = op_pool;
    op->attempt = 1;
    op->backend = backend;
    op->node_key_set = cfg->node_key_set;

    if (cfg->node_key_set) {
        ngx_memcpy(op->node_key, cfg->node_key, sizeof(op->node_key));
    }

    easy = ngx_http_auto_ssl_curl_new_easy(op_pool, cfg, backend, key, op,
                                           &url, &op->headers);
    if (easy == NULL) {
        ngx_destroy_pool(op_pool);
        return NGX_ERROR;
    }

    op->url = url;

    curl_easy_setopt(easy, CURLOPT_PRIVATE, op);
    curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT,
                     (long) NGX_HTTP_AUTO_SSL_CURL_CONNECT_TIMEOUT);
    curl_easy_setopt(easy, CURLOPT_TIMEOUT,
                     (long) NGX_HTTP_AUTO_SSL_CURL_TIMEOUT);

    if (curl_multi_add_handle(w->multi, easy) != CURLM_OK) {
        curl_slist_free_all(op->headers);
        op->headers = NULL;
        curl_easy_cleanup(easy);
        ngx_destroy_pool(op_pool);
        return NGX_ERROR;
    }

    curl_multi_socket_action(w->multi, CURL_SOCKET_TIMEOUT, 0, &running);

    ngx_http_auto_ssl_curl_check(w);

    return NGX_OK;
}


/*
 * Synchronous fetch for worker startup only: the worker is not serving
 * yet, so blocking here costs reload time instead of failed handshakes.
 * Must never be called from the event loop.
 */
ngx_int_t
ngx_http_auto_ssl_curl_fetch_blocking(
    ngx_http_auto_ssl_backend_cfg_t *cfg, ngx_uint_t backend, ngx_str_t *key,
    ngx_pool_t *pool, ngx_msec_t timeout, ngx_str_t *cert, ngx_str_t *chain,
    ngx_str_t *key_data)
{
    ngx_http_auto_ssl_curl_worker_t  *w;
    ngx_http_auto_ssl_curl_op_t       op;
    CURL                             *easy;
    CURLcode                          res;
    struct curl_slist                *headers;
    ngx_str_t                         url, body;
    ngx_str_t                        *prefix;
    long                              code;

    w = &ngx_http_auto_ssl_curl_worker;

    if (cfg == NULL || pool == NULL || key->len == 0
        || (backend != NGX_HTTP_AUTO_SSL_BACKEND_CERTMATE
            && backend != NGX_HTTP_AUTO_SSL_BACKEND_PROVISIONER))
    {
        return NGX_ERROR;
    }

    if (timeout <= 0) {
        timeout = 5000;
    }

    ngx_memzero(&op, sizeof(op));

    op.pool = pool;

    easy = ngx_http_auto_ssl_curl_new_easy(pool, cfg, backend, key, &op,
                                           &url, &headers);
    if (easy == NULL) {
        return NGX_ERROR;
    }

    /*
     * Single attempt on purpose: a slow backend must not stall worker
     * startup; the asynchronous fetch (with retries) covers recovery.
     */
    curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, (long) timeout);
    curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, (long) timeout);

    res = curl_easy_perform(easy);

    curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &code);

    curl_easy_cleanup(easy);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        ngx_log_error(NGX_LOG_ERR, w->log, 0,
                      "auto_ssl: blocking fetch failed: %s", op.err);
        return NGX_ERROR;
    }

    if (code != 200) {
        ngx_log_error(NGX_LOG_ERR, w->log, 0,
                      "auto_ssl: blocking fetch returned status %l", code);
        return NGX_ERROR;
    }

    body.data = op.body;
    body.len = op.body_len;

    prefix = op.prefix.len != 0 ? &op.prefix : NULL;

    if (ngx_http_auto_ssl_curl_parse(pool, w->log, backend,
                                     cfg->node_key, cfg->node_key_set,
                                     prefix, &body, cert, chain, key_data)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


CURLM *
ngx_http_auto_ssl_curl_multi_for_test(void)
{
    return ngx_http_auto_ssl_curl_worker.multi;
}


void
ngx_http_auto_ssl_curl_check_for_test(void)
{
    ngx_http_auto_ssl_curl_check(&ngx_http_auto_ssl_curl_worker);
}


ngx_uint_t
ngx_http_auto_ssl_curl_fire_retries_for_test(void)
{
    ngx_http_auto_ssl_curl_worker_t  *w;
    ngx_http_auto_ssl_curl_op_t      *op;
    ngx_uint_t                        n;

    w = &ngx_http_auto_ssl_curl_worker;
    n = 0;

    while (w->retries != NULL) {
        op = w->retries;
        w->retries = op->retry_next;
        op->retry_next = NULL;

        if (op->retry.timer_set) {
            ngx_del_timer(&op->retry);
        }

        n++;

        ngx_http_auto_ssl_curl_retry_event(&op->retry);
    }

    return n;
}


ngx_uint_t
ngx_http_auto_ssl_curl_retryable_for_test(int res, long code)
{
    return ngx_http_auto_ssl_curl_retryable((CURLcode) res, code);
}
