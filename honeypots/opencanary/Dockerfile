FROM python:3.11-slim

RUN pip install opencanary cryptography

COPY opencanary.conf /etc/opencanaryd/opencanary.conf

RUN mkdir -p /var/log/opencanary

EXPOSE 80 443

CMD ["sh", "-c", "rm -f /usr/local/bin/opencanaryd.pid && opencanaryd --dev"]