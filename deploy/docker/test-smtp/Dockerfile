FROM alpine:3.24

RUN apk add --no-cache postfix

COPY main.cf /etc/postfix/main.cf
COPY setup.sh /setup.sh
RUN chmod +x /setup.sh && /setup.sh

EXPOSE 25

CMD ["postfix", "start-fg"]
