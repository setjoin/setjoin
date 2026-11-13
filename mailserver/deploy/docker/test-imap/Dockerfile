FROM alpine:3.24

RUN apk add --no-cache dovecot

COPY dovecot.conf /etc/dovecot/dovecot.conf
COPY setup-maildir.sh /setup-maildir.sh
RUN chmod +x /setup-maildir.sh && /setup-maildir.sh

RUN mkdir -p /run/dovecot

EXPOSE 143

CMD ["dovecot", "-F"]
