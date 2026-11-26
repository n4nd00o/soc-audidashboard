# INTENTIONALLY INSECURE demo target (missing security headers, Server banner with version).
FROM nginx:1.27.5-alpine
RUN rm -rf /etc/nginx/conf.d /docker-entrypoint.d
COPY nginx.conf /etc/nginx/nginx.conf
COPY index.html /usr/share/nginx/lab/index.html
USER nginx
EXPOSE 8080
ENTRYPOINT ["nginx", "-g", "daemon off;"]
