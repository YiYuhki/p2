# syntax=docker/dockerfile:1
#
# Backend mail server for the secmail demo: Postfix (SMTP receive + the DLP
# re-injection hop) and Dovecot (IMAP + LMTP local delivery) in one container.
# This stands in for the "real mail server" (Exchange/Postfix) that lives
# behind the gateway. It is a DEMO image: plaintext IMAP/submission, passwords
# in a file, open re-injection port. Do not ship it to production as-is.
FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive
# Preseed "Local only" so the postfix package generates a complete, valid
# main.cf at install time (entrypoint.sh then overrides the relevant settings).
RUN echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections \
 && echo "postfix postfix/mailname string example.com" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      postfix dovecot-core dovecot-imapd dovecot-lmtpd ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 5000 vmail \
 && useradd -g vmail -u 5000 -d /var/mail/vhosts -m vmail

COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY master.cf.extra /etc/postfix/master.cf.extra
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 25 143 587 10026
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
