FROM python:3.11-slim
WORKDIR /opt/honeypot
COPY scada_honeypot.py .
EXPOSE 502 102
CMD ["python3", "-u", "scada_honeypot.py"]
