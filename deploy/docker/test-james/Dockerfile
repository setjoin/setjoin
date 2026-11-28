FROM apache/james:demo-3.8.0@sha256:e7ac5b29e148b61adf8e9345c5ef011c85c39445b4223d5d75731250dd0a7fd2

# The upstream demo certificate is issued only to james.apache.org. Generate a
# container-local test CA/certificate for localhost so the connector exercises
# verified STARTTLS instead of disabling certificate verification.
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost" \
      -keyout /root/conf/private.key \
      -out /root/conf/private.csr \
    && chmod 0600 /root/conf/private.key \
    && chmod 0644 /root/conf/private.csr
