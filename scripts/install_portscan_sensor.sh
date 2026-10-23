#!/usr/bin/env bash
# Installa solo il sensore; non modifica firewall, Docker o proprieta dei dati app.
set -euo pipefail
if [ "$(id -u)" != 0 ]; then
    echo 'Eseguire con sudo: installazione servizio host e capability CAP_NET_RAW.' >&2
    exit 1
fi
portscan_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v tcpdump >/dev/null
command -v ip >/dev/null
id cyferwall >/dev/null
# Non sovrascrivere servizi omonimi estranei.
if [ -f /etc/systemd/system/honeypotx-portscan.service ]; then
    if ! cmp -s /etc/systemd/system/honeypotx-portscan.service "$portscan_root/scripts/honeypotx-portscan.service"; then
        echo 'Unita preesistente diversa: verificare manualmente prima di sostituirla.' >&2
        exit 1
    fi
fi
systemd-analyze verify "$portscan_root/scripts/honeypotx-portscan.service"
install -D -o root -g root -m 0755 "$portscan_root/scripts/portscan_sensor.py" /usr/local/libexec/honeypotx-portscan.py
install -o root -g root -m 0644 "$portscan_root/scripts/honeypotx-portscan.service" /etc/systemd/system/honeypotx-portscan.service
systemctl daemon-reload
systemctl enable honeypotx-portscan.service
systemctl restart honeypotx-portscan.service
systemctl --no-pager --full status honeypotx-portscan.service
