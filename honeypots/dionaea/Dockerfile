FROM python:3.11-slim

WORKDIR /app
COPY ftp_honeypot.py .

RUN mkdir -p /var/log/dionaea

EXPOSE 21

CMD ["python3", "-u", "ftp_honeypot.py"]