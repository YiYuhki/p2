#!/bin/sh
# Certificate manager for the secmail stack. Writes /certs/tls.crt + /certs/tls.key
# into the shared volume; stays running so a healthcheck can gate dependents and
# (in certbot mode) so certs auto-renew.
set -eu

CERT_DIR=/certs
CRT="$CERT_DIR/tls.crt"
KEY="$CERT_DIR/tls.key"
DOMAIN="${MAIL_DOMAIN:-example.com}"
# Hostnames the cert should cover. Default: the gateway + backend FQDNs.
HOSTS="${TLS_HOSTNAMES:-secmail.$DOMAIN,mail.$DOMAIN}"
FIRST="$(echo "$HOSTS" | cut -d, -f1)"
mkdir -p "$CERT_DIR"

idle() { exec tail -f /dev/null; }

if [ "${TLS_ENABLED:-false}" != "true" ]; then
  echo "[certs] TLS_ENABLED is not 'true'; nothing to do."
  idle
fi

install_pem() {  # $1=fullchain $2=privkey
  cp "$1" "$CRT"
  cp "$2" "$KEY"
  # World-readable so the non-root secmail/dovecot processes in other
  # containers can read them from the shared volume (demo trade-off).
  chmod 644 "$CRT" "$KEY"
}

gen_selfsigned() {
  echo "[certs] generating self-signed certificate for: $HOSTS"
  san="DNS:localhost"
  oifs="$IFS"; IFS=,
  for h in $HOSTS; do san="$san,DNS:$h"; done
  IFS="$oifs"
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout "$KEY" -out "$CRT" -subj "/CN=$FIRST" -addext "subjectAltName=$san" >/dev/null 2>&1
  chmod 644 "$CRT" "$KEY"
  echo "[certs] self-signed certificate ready at $CRT"
}

obtain_certbot() {
  email_opt="--register-unsafely-without-email"
  [ -n "${CERTBOT_EMAIL:-}" ] && email_opt="-m ${CERTBOT_EMAIL}"
  staging_opt=""
  [ "${CERTBOT_STAGING:-false}" = "true" ] && staging_opt="--staging"
  d_opts=""
  oifs="$IFS"; IFS=,
  for h in $HOSTS; do d_opts="$d_opts -d $h"; done
  IFS="$oifs"
  echo "[certs] requesting Let's Encrypt certificate (standalone :80) for: $HOSTS"
  # shellcheck disable=SC2086
  certbot certonly --standalone --non-interactive --agree-tos --keep-until-expiring \
    $email_opt $staging_opt $d_opts || return 1
  install_pem "/etc/letsencrypt/live/$FIRST/fullchain.pem" "/etc/letsencrypt/live/$FIRST/privkey.pem"
  echo "[certs] Let's Encrypt certificate installed at $CRT"
}

case "${TLS_MODE:-selfsigned}" in
  selfsigned)
    if [ -s "$CRT" ] && [ -s "$KEY" ]; then
      echo "[certs] existing certificate found; keeping it."
    else
      gen_selfsigned
    fi
    idle
    ;;
  certbot)
    if ! obtain_certbot; then
      echo "[certs] certbot FAILED. The hostnames in TLS_HOSTNAMES must resolve to" >&2
      echo "[certs] this host and port 80 must be reachable from the Internet." >&2
      echo "[certs] (Use TLS_MODE=selfsigned for local testing.) Leaving container up," >&2
      echo "[certs] no cert written, so dependents stay unhealthy until this is fixed." >&2
      idle
    fi
    # Renew loop: certbot reuses the stored standalone authenticator (needs :80).
    while true; do
      sleep 43200   # 12h
      echo "[certs] renewal check"
      if certbot renew --quiet; then
        cp "/etc/letsencrypt/live/$FIRST/fullchain.pem" "$CRT" 2>/dev/null || true
        cp "/etc/letsencrypt/live/$FIRST/privkey.pem" "$KEY" 2>/dev/null || true
        chmod 644 "$CRT" "$KEY" 2>/dev/null || true
      fi
    done
    ;;
  *)
    echo "[certs] unknown TLS_MODE='${TLS_MODE}' (use selfsigned or certbot)" >&2
    idle
    ;;
esac
