FROM cowrie/cowrie:latest

COPY --chown=cowrie:cowrie cowrie.cfg /cowrie/cowrie-git/etc/cowrie.cfg
COPY --chown=cowrie:cowrie userdb.txt /cowrie/cowrie-git/etc/userdb.txt
USER cowrie

EXPOSE 2222 2223
