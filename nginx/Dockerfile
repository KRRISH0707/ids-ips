FROM nginx:1.27-alpine

RUN apk add --no-cache openssl

COPY nginx.conf /etc/nginx/nginx.conf
COPY init-ssl.sh /docker-entrypoint.d/init-ssl.sh

RUN chmod +x /docker-entrypoint.d/init-ssl.sh

EXPOSE 80 443

ENTRYPOINT ["/docker-entrypoint.d/init-ssl.sh"]
