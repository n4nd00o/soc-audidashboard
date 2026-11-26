# INTENTIONALLY INSECURE demo target: nginx serving an EXPIRED self-signed certificate.
# The certificate (valid 2020-01-01..2020-01-02) is generated at build time.
FROM python:3.12.12-slim AS certgen
RUN pip install --no-cache-dir cryptography==50.0.2
COPY gen_cert.py /gen_cert.py
RUN python /gen_cert.py /out

FROM nginx:1.27.5-alpine
RUN rm -rf /etc/nginx/conf.d /docker-entrypoint.d
COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=certgen --chown=nginx:nginx /out/ /etc/nginx/lab/
USER nginx
EXPOSE 8443
ENTRYPOINT ["nginx", "-g", "daemon off;"]
