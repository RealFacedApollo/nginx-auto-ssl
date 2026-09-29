/*
 * Provisioner v2 bundle helpers: dependency-free on purpose (libc +
 * libcrypto only, no nginx headers) so the tar/encryption handling the
 * data plane trusts stays unit-testable without an nginx build.
 *
 * Wire format: body = nonce(12) || ciphertext || tag(16), AES-256-GCM.
 * Plaintext = ustar tar holding "<domain>/cert.pem",
 * "<domain>/chain.pem" (or "<domain>/fullchain.pem") and
 * "<domain>/privkey.pem". The node key never leaves the node: it only
 * decrypts locally after download and is never sent to the backend.
 */

#ifndef NGX_HTTP_AUTO_SSL_TAR_H
#define NGX_HTTP_AUTO_SSL_TAR_H


#include <stddef.h>


#define NGX_HTTP_AUTO_SSL_NODE_KEY_LEN  32
#define NGX_HTTP_AUTO_SSL_GCM_NONCE_LEN 12
#define NGX_HTTP_AUTO_SSL_GCM_TAG_LEN   16


/*
 * Decode a node key file's content (surrounding whitespace ignored):
 * 64 hex chars, or raw 32 bytes. Returns 0 on success, -1 otherwise.
 */
int ngx_http_auto_ssl_node_key_decode(const unsigned char *in, size_t in_len,
    unsigned char out[NGX_HTTP_AUTO_SSL_NODE_KEY_LEN]);


/*
 * Decrypt in[0..in_len) into out, which must hold at least in_len bytes;
 * *out_len receives the plaintext length. The output is zeroed when
 * authentication fails. Returns 0 on success, -1 otherwise.
 */
int ngx_http_auto_ssl_gcm_decrypt(
    const unsigned char key[NGX_HTTP_AUTO_SSL_NODE_KEY_LEN],
    const unsigned char *in, size_t in_len,
    unsigned char *out, size_t *out_len);


typedef struct {
    const unsigned char  *data;
    size_t                len;
} ngx_http_auto_ssl_span_t;


/*
 * Extract PEM spans from a tar archive (zero-copy into tar). Members
 * match "<prefix>cert.pem" etc.; an empty prefix matches bare names.
 * fullchain.pem falls back to cert.pem + chain.pem by splitting off
 * the first certificate, like the ZIP extractor. Chain is empty when
 * absent or unusable; cert and key are required. Returns 0 on
 * success, -1 otherwise.
 */
int ngx_http_auto_ssl_tar_extract(const unsigned char *tar, size_t tar_len,
    const unsigned char *prefix, size_t prefix_len,
    ngx_http_auto_ssl_span_t *cert, ngx_http_auto_ssl_span_t *chain,
    ngx_http_auto_ssl_span_t *key);


#endif
