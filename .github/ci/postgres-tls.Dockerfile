FROM postgres:17

RUN set -eux; \
    mkdir -p /etc/postgres-tls; \
    openssl req -new -x509 -days 1 -nodes \
      -subj "/CN=localhost" \
      -keyout /etc/postgres-tls/server.key \
      -out /etc/postgres-tls/server.crt; \
    chown postgres:postgres /etc/postgres-tls/server.key /etc/postgres-tls/server.crt; \
    chmod 0600 /etc/postgres-tls/server.key; \
    chmod 0644 /etc/postgres-tls/server.crt

CMD ["postgres", "-c", "ssl=on", "-c", "ssl_cert_file=/etc/postgres-tls/server.crt", "-c", "ssl_key_file=/etc/postgres-tls/server.key"]

