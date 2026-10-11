# syntax=docker/dockerfile:1
# Certificate manager for the secmail stack. Produces /certs/tls.crt and
# /certs/tls.key (PEM) into a shared volume that secmail (SMTP STARTTLS +
# portal HTTPS) and the Postfix/Dovecot backend (IMAPS + submission TLS) read.
#
#   TLS_MODE=selfsigned  -> openssl self-signed cert (local/internal testing)
#   TLS_MODE=certbot     -> Let's Encrypt via certbot standalone (:80), auto-renew
FROM alpine:3
RUN apk add --no-cache openssl certbot ca-certificates
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
EXPOSE 80
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
