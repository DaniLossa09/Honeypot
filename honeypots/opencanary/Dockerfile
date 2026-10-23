FROM python:3.11-slim

RUN pip install opencanary cryptography

RUN mkdir -p /etc/opencanaryd /var/log/opencanary

RUN SKIN_DIR=$(python3 -c "import opencanary; import os; print(os.path.dirname(opencanary.__file__))")/modules/data/http/skin && \
    mkdir -p $SKIN_DIR/nasLogin $SKIN_DIR/basicLogin && \
    echo '<html><body><script>window.location="/";</script></body></html>' > $SKIN_DIR/nasLogin/redirect.html && \
    echo '<html><body><script>window.location="/";</script></body></html>' > $SKIN_DIR/basicLogin/redirect.html

COPY opencanary.conf /etc/opencanaryd/opencanary.conf

COPY hpx.tac /opt/hpx/hpx.tac

EXPOSE 80 443

CMD ["twistd", "--nodaemon", "--pidfile=", "--python=/opt/hpx/hpx.tac"]
