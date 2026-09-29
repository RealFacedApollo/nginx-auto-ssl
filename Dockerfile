ARG NGINX_VERSION=1.31.1

FROM debian:bookworm-slim AS builder
ARG NGINX_VERSION
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libpcre2-dev zlib1g-dev libssl-dev \
        libcurl4-openssl-dev pkg-config curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" -o nginx.tar.gz \
    && tar xzf nginx.tar.gz
COPY config /src/nginx-auto-ssl/config
COPY src/ /src/nginx-auto-ssl/src/
RUN cd "/src/nginx-${NGINX_VERSION}" \
    && ./configure \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --modules-path=/etc/nginx/modules \
        --with-compat \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-threads \
        --add-dynamic-module=/src/nginx-auto-ssl \
    && make -j"$(nproc)" \
    && make install

FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcre2-8-0 zlib1g libssl3 libcurl4 ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/cache/nginx/client_temp /var/cache/nginx/proxy_temp \
        /var/cache/nginx/fastcgi_temp /var/cache/nginx/uwsgi_temp \
        /var/cache/nginx/scgi_temp /var/log/nginx /etc/nginx/conf.d \
        /run/secrets
COPY --from=builder /usr/sbin/nginx /usr/sbin/nginx
COPY --from=builder /etc/nginx/ /etc/nginx/
COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY docker/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh \
    && nginx -t
EXPOSE 80 443
STOPSIGNAL SIGQUIT
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
