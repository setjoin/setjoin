FROM alpine:3.24

RUN apk add --no-cache openldap openldap-clients openldap-back-mdb

COPY seed.ldif /seed.ldif
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 389

CMD ["/start.sh"]
