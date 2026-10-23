#!/usr/bin/env python3
"""Isolamento nftables dedicato: nessuna modifica alle policy o tabelle altrui.

Uso: sudo python3 scripts/honeypot_isolation.py install
Rollback: sudo /usr/bin/python3 /usr/local/libexec/honeypotx-isolation.py rollback
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

MARKER = 'HoneypotX managed isolation'
TABLE = 'hpx_isolation'
CACHE = Path('/etc/honeypotx-isolation.json')
INSTALLED = Path('/usr/local/libexec/honeypotx-isolation.py')
NFT = '/usr/sbin/nft'
DOCKER = '/usr/bin/docker'
SYSTEMCTL = '/usr/bin/systemctl'


def run(args, *, input=None):
    return subprocess.run(args, input=input, text=True, capture_output=True, check=True).stdout


def config(cached=False):
    if cached:
        result = json.loads(CACHE.read_text())
    else:
        network = json.loads(run([DOCKER, 'network', 'inspect', 'honeypots_honeypot-net']))[0]
        if network['Driver'] != 'bridge':
            raise RuntimeError('La rete honeypot deve essere un bridge Docker')
        result = {'bridge': network.get('Options', {}).get('com.docker.network.bridge.name') or 'br-' + network['Id'][:12]}
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', result['bridge']):
        raise RuntimeError('Nome bridge non valido')
    return result


def existing(family):
    output = json.loads(run([NFT, '-j', 'list', 'tables']))
    if not any(item.get('table', {}).get('family') == family and
               item['table'].get('name') == TABLE for item in output['nftables']):
        return False
    table = json.loads(run([NFT, '-j', 'list', 'table', family, TABLE]))
    info = next(item['table'] for item in table['nftables'] if 'table' in item)
    if info.get('comment') != MARKER:
        raise RuntimeError('Tabella omonima non gestita da HoneypotX: nessuna modifica')
    return True


def rules(bridge, present):
    # Le risposte conservano le regole Docker/host successive: RETURN non le
    # scavalca. Il traffico fra veth viene bloccato nel bridge senza dipendere
    # dal modulo br_netfilter o dalla scelta iptables/nftables di Docker.
    prefix = ''.join(f'delete table {family} {TABLE}\n' for family in ('inet', 'bridge') if present.get(family))
    return prefix + f'''table inet {TABLE} {{
 comment "{MARKER}"
 chain host_input {{
  type filter hook input priority -50; policy accept;
  iifname "{bridge}" ct state established,related return
  iifname "{bridge}" counter reject with icmpx type admin-prohibited
 }}
 chain routed_forward {{
  type filter hook forward priority -50; policy accept;
  iifname "{bridge}" ct state established,related return
  iifname "{bridge}" counter reject with icmpx type admin-prohibited
 }}
}}
table bridge {TABLE} {{
 comment "{MARKER}"
 chain peer_forward {{
  type filter hook forward priority -200; policy accept;
  meta ibrname "{bridge}" counter drop
 }}
}}
'''


def apply(cached=False):
    current = config(cached)
    present = {family: existing(family) for family in ('inet', 'bridge')}
    batch = rules(current['bridge'], present)
    # Check prima di ogni modifica; il batch successivo e una transazione atomica.
    run([NFT, '--check', '-f', '-'], input=batch)
    run([NFT, '-f', '-'], input=batch)
    if not cached:
        CACHE.write_text(json.dumps(current) + '\n')
        CACHE.chmod(0o600)
    print('OK: isolamento IPv4/IPv6 e fra container sul bridge', current['bridge'])


def prepare_logs(repo):
    for source, uid in [('mysql', 10001), ('scada', 10002)]:
        path = repo / 'honeypots/logs' / source
        if path.is_symlink() or not path.is_dir():
            raise RuntimeError('Directory log non valida: ' + str(path))
        # Opera solo sui file regolari dei due bind mount; nessun link seguito,
        # nessuna modifica a data/, config/ o ai log degli altri container.
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            files = []
            for name in os.listdir(fd):
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    raise RuntimeError('File log non regolare: ' + str(path / name))
                files.append(name)
            for name in files:
                log_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    if not stat.S_ISREG(os.fstat(log_fd).st_mode):
                        raise RuntimeError('Tipo file log cambiato')
                    os.fchown(log_fd, uid, uid)
                    os.fchmod(log_fd, 0o644)
                finally:
                    os.close(log_fd)
            os.fchown(fd, uid, uid)
            os.fchmod(fd, 0o755)
        finally:
            os.close(fd)
        print('OK: ownership log', source, uid)


def install(repo):
    # Verifica disponibilita e compatibilita prima di cambiare ownership o unita.
    apply()
    prepare_logs(repo)
    INSTALLED.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(Path(__file__).resolve(), INSTALLED)
    INSTALLED.chmod(0o755)
    os.chown(INSTALLED, 0, 0)
    unit = f'''[Unit]
Description=HoneypotX bridge isolation (cached, before Docker)
Before=docker.service
PartOf=docker.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 {INSTALLED} apply --cached
[Install]
WantedBy=multi-user.target docker.service
'''
    refresh = f'''[Unit]
Description=Refresh HoneypotX isolation after network changes
After=docker.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {INSTALLED} apply
'''
    timer = '''[Unit]
Description=Refresh HoneypotX network isolation
[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
Unit=honeypotx-isolation-refresh.service
[Install]
WantedBy=timers.target
'''
    for name, content in [('honeypotx-isolation.service', unit), ('honeypotx-isolation-refresh.service', refresh), ('honeypotx-isolation-refresh.timer', timer)]:
        path = Path('/etc/systemd/system') / name
        if path.exists() and 'HoneypotX' not in path.read_text():
            raise RuntimeError('Unita omonima estranea: ' + str(path))
        path.write_text(content)
        path.chmod(0o644)
        os.chown(path, 0, 0)
    run([SYSTEMCTL, 'daemon-reload'])
    run([SYSTEMCTL, 'enable', '--now', 'honeypotx-isolation.service', 'honeypotx-isolation-refresh.timer'])
    print('OK: installazione persistente completata; nessuna policy generale modificata')


def rollback():
    # Le unita/file restano disponibili per ispezione; si rimuovono soltanto
    # le due tabelle gestite. Log e volumi non vengono cancellati.
    subprocess.run([SYSTEMCTL, 'disable', '--now', 'honeypotx-isolation-refresh.timer', 'honeypotx-isolation.service'], check=False)
    batch = ''.join(f'delete table {family} {TABLE}\n' for family in ('inet', 'bridge') if existing(family))
    if batch:
        run([NFT, '--check', '-f', '-'], input=batch)
        run([NFT, '-f', '-'], input=batch)
    print('OK: rollback delle sole regole HoneypotX; log e dati conservati')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['plan', 'install', 'apply', 'rollback', 'status'])
    parser.add_argument('--cached', action='store_true')
    args = parser.parse_args()
    if args.action == 'plan':
        print(rules(config()['bridge'], {}))
        return
    if os.geteuid() != 0:
        sys.exit('Richiesto sudo per modificare/ispezionare il firewall host')
    if args.action == 'install':
        install(Path(__file__).resolve().parents[1])
    elif args.action == 'apply':
        apply(args.cached)
    elif args.action == 'rollback':
        rollback()
    else:
        for family in ('inet', 'bridge'):
            if existing(family):
                print(run([NFT, 'list', 'table', family, TABLE]))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        if isinstance(exc, subprocess.CalledProcessError):
            sys.exit('Operazione non completata: ' + exc.stderr.strip())
        sys.exit('Operazione non completata: ' + str(exc))
