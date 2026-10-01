#!/bin/sh
# Entrypoint for the secmail demo backend (Postfix + Dovecot).
#
# Generates the mailbox list from MAIL_USERS, configures Postfix for virtual
# delivery to Dovecot over LMTP, and runs both daemons. DEMO ONLY.
set -eu

DOMAIN="${MAIL_DOMAIN:-example.com}"
# Space-separated "localpart:password" pairs.
USERS="${MAIL_USERS:-alice:alicepass bob:bobpass security:securitypass}"

# ---- generate mailbox maps (single source of truth: $USERS) ----
: > /etc/postfix/vmailbox
: > /etc/dovecot/users
for pair in $USERS; do
  name="${pair%%:*}"
  pass="${pair#*:}"
  addr="$name@$DOMAIN"
  # Postfix only needs the key to exist to accept the recipient; the value is
  # unused because delivery goes through virtual_transport (LMTP), not virtual(8).
  printf '%s\tOK\n' "$addr" >> /etc/postfix/vmailbox
  # Full passwd-file columns (user:pass:uid:gid:gecos:home:shell:extra) so the
  # userdb lookup resolves uid/gid/home; a 2-column line is not a valid userdb entry.
  printf '%s:%s:5000:5000::/var/mail/vhosts/%s/%s::\n' "$addr" "$pass" "$DOMAIN" "$name" >> /etc/dovecot/users
  install -d -o vmail -g vmail -m 0700 "/var/mail/vhosts/$DOMAIN/$name"
done
postmap /etc/postfix/vmailbox
chown -R vmail:vmail /var/mail/vhosts
# Readable by Dovecot's auth/LMTP processes (they run as the dovecot user/group),
# not world-readable: it holds plaintext demo passwords.
chown root:dovecot /etc/dovecot/users
chmod 640 /etc/dovecot/users

# ---- Postfix main.cf ----
postconf -e \
  "compatibility_level=3.6" \
  "myhostname=mail.$DOMAIN" \
  "mydomain=$DOMAIN" \
  "myorigin=\$mydomain" \
  "mydestination=" \
  "inet_interfaces=all" \
  "inet_protocols=ipv4" \
  "mynetworks=127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16" \
  "virtual_mailbox_domains=$DOMAIN" \
  "virtual_mailbox_maps=hash:/etc/postfix/vmailbox" \
  "virtual_transport=lmtp:inet:127.0.0.1:24" \
  "smtpd_recipient_restrictions=permit_mynetworks,reject_unauth_destination" \
  "message_size_limit=52428800" \
  "smtp_tls_security_level=may" \
  "maillog_file=/dev/stdout"

# ---- Postfix master.cf (submission + DLP re-injection services) ----
# Idempotent: only append once even if the container is restarted on a reused fs.
if ! grep -q "secmail demo" /etc/postfix/master.cf 2>/dev/null; then
  {
    echo ""
    echo "# ---- secmail demo services ----"
    cat /etc/postfix/master.cf.extra
  } >> /etc/postfix/master.cf
fi

# ---- TLS (optional) ----
# When TLS_ENABLED=true and the shared cert is present, turn on Dovecot IMAPS
# (:993) + STARTTLS and Postfix STARTTLS (:25/:587) + implicit-TLS smtps (:465).
CRT=/certs/tls.crt
KEY=/certs/tls.key
if [ "${TLS_ENABLED:-false}" = "true" ] && [ -s "$CRT" ] && [ -s "$KEY" ]; then
  echo "TLS enabled, using $CRT"
  cat >> /etc/dovecot/dovecot.conf <<EOF

# ---- TLS (added by entrypoint) ----
ssl = yes
ssl_cert = <$CRT
ssl_key = <$KEY
service imap-login {
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}
EOF
  postconf -e \
    "smtpd_tls_cert_file=$CRT" \
    "smtpd_tls_key_file=$KEY" \
    "smtpd_tls_security_level=may" \
    "smtp_tls_security_level=may"
  if ! grep -q "smtps-tls demo" /etc/postfix/master.cf; then
    cat >> /etc/postfix/master.cf <<'EOF'

# smtps (465) implicit-TLS submission — secmail demo (smtps-tls demo)
smtps     inet  n       -       n       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
  -o smtpd_sasl_security_options=noanonymous
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o smtpd_reject_unlisted_recipient=no
  -o content_filter=scan:[secmail]:10025
EOF
  fi
else
  # No TLS: Dovecot still needs an explicit ssl setting.
  echo "ssl = no" >> /etc/dovecot/dovecot.conf
  echo "TLS disabled (set TLS_ENABLED=true and attach the certs volume to enable)"
fi

# Dovecot's SASL socket lives under Postfix's private dir; make sure it exists
# and is postfix-owned (master refuses to start otherwise) before Dovecot
# creates the listener.
install -d -o postfix -g postfix -m 0700 /var/spool/postfix/private

# ---- run both daemons ----
# Dovecot in the background; Postfix in the foreground as PID-ish main process.
dovecot
echo "dovecot started (IMAP :143, LMTP :24)"
exec postfix start-fg
