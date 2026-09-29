# nginx-auto-ssl

A dynamic nginx module for automatic SSL certificate configuration and fetching from Certmate or LuckyNetwork's SSL Provisioner. It allows nginx to serve SSL certificates for specified domains without requiring static certificate files on disk, fetching them at runtime from a central management system.

## Why?

Simplify SSL certificate provisioning for services at scale, especially in environments where certificates are managed centrally and need to be distributed to multiple servers dynamically.

### Why not Certbot or Caddy with LetsEncrypt?

We run lots of nginx behind a single outbound IP, so we worry about hitting Let's Encrypt rate limits. Also, the team is already familiar with Nginx, so I don't want to introduce new technology stacks. We also have public facing certificates that are issued by traditional CAs, so we need to keep Certificate Management and Certificate Provisionin separate.

### Why is this module necessary?

This module allow us to have a central certificate management system (Certmate or SSL Provisioner) and have Nginx automatically fetch and serve the correct certificates for each domain without needing to manage static certificate files on disk. It also handles caching, background refreshes, and resiliency against backend failures. Before this, we were manually using scripts to pull certificates to hosts and then reloading Nginx.


## Usage

```nginx
load_module modules/ngx_http_auto_ssl_module.so;

http {
    certmate_url https://certmate.luckynetwork.net;
    certmate_api_token_file /run/secrets/certmate_token;

    server {
        listen 443 ssl;
        ssl_certificate_from_certmate luckynetwork.net;
    }
}
```

```nginx
load_module modules/ngx_http_auto_ssl_module.so;

http {
    ssl_provisioner_url https://provisioner.luckynetwork.net;
    ssl_provisioner_api_key_file /run/secrets/provisioner_api_key;

    server {
        listen 443 ssl;
        ssl_certificate_from_ssl_provisioner luckynet.work;
    }
}
```

Thats all! No need for `ssl_certificate` or `ssl_certificate_key` lines!

*Note: The SSL Provisioner is legacy LuckyNetwork's Certificate Manager, we are migrating to Certmate*

## Short docs of directives:

### SSL Provisoner v Certmate

Each server block can only use EITHER `ssl_certificate_from_certmate` or `ssl_certificate_from_ssl_provisioner`, not both.

### SSL Provisioner
 - `ssl_provisioner_url` - The base URL of the SSL Provisioner API gateway.
 - `ssl_provisioner_api_key` - The Machine Scoped API key for the SSL Provisioner. Can use "LuckyNetwork Global Machine Key" or a scoped key for the node.
 - `ssl_provisioner_api_key_file` - Path to a file containing the API key for the SSL Provisioner. Preferred in production (0600, re-read on reload).
 - `ssl_provisioner_node_key_file` - Path to a "LuckyNetwork Node Key".

You can either use `ssl_provisioner_api_key` or `ssl_provisioner_api_key_file`, but not both. SSL Provisioner encrypts the bundle with the node key, it is recommended to use Global Machine Key to avoid having to manage node keys on each host.

### Certmate
 - `certmate_url` - The base URL of the Certmate API.
 - `certmate_api_token` - The bearer token for Certmate with **Operator** role, as it is required for downloading the private key.
 - `certmate_api_token_file` - Path to a file containing the bearer token for Certmate.


### Caching

Cache behavior can be tuned with the following directives:
 - `auto_ssl_cache_ttl` - How long a fetched certificate is served from cache (default `1d`).
 - `auto_ssl_cache_refresh_interval` - How often the worker scans for entries due for background refresh (default `1m`).
 - `auto_ssl_cache_max_stale` - How long past TTL a stale entry is still served while refreshes fail (default `7d`); past that the handshake fails.
 - `auto_ssl_cache_negative_ttl` - How long a failed fetch suppresses retries for that domain (default `1m`).
 - `auto_ssl_cache_expiry_interval` - How often the worker scans cached certificates for upcoming expiry (default `1h`).
 - `auto_ssl_cache_expiry_before` - Refresh any certificate expiring within this window, regardless of TTL state (default `24h`).

## How to build & use?

### Docker

Docker image is provided for convenience, but you can also build the module from source and load it into your existing Nginx installation.

### Source

```sh
git clone
cd nginx-auto-ssl
./configure --add-dynamic-module=/path/to/nginx-auto-ssl
make modules
```