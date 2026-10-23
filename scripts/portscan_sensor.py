#!/usr/bin/env python3
"""Sensore passivo TCP host: emette soltanto allarmi aggregati in JSONL."""
import argparse
from collections import OrderedDict
from datetime import datetime, timezone
import ipaddress
import json
import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time


TCP_LINE = re.compile(
    r'^\d+(?:\.\d+)?\s+(?:\S+\s+(?:In|Out)\s+)?IP6?\s+([0-9a-fA-F:.]+)\.(\d+) > '
    r'([0-9a-fA-F:.]+)\.(\d+): Flags \[([^]]+)\]')


def parse_syn(line):
    match = TCP_LINE.match(line)
    if not match:
        return None
    src, sport, dst, dport, flags = match.groups()
    if 'S' not in flags or any(flag in flags for flag in 'ARF.'):
        return None
    try:
        src, dst = str(ipaddress.ip_address(src)), str(ipaddress.ip_address(dst))
        sport, dport = int(sport), int(dport)
        if not (1 <= sport <= 65535 and 1 <= dport <= 65535):
            return None
    except ValueError:
        return None
    return src, dst, sport, dport


class ScanDetector:
    """Finestra mobile per sorgente/destinazione; memoria e frequenza limitate."""
    def __init__(self, threshold=12, window=10.0, cooldown=60.0, max_hosts=4096):
        if threshold < 2 or window <= 0 or cooldown < window or max_hosts < 1:
            raise ValueError('Soglia/finestra/cooldown/capacita non validi')
        self.threshold, self.window = threshold, window
        self.cooldown, self.max_hosts = cooldown, max_hosts
        self.hosts = OrderedDict()
        self.last_sweep = 0.0

    def observe(self, src, dst, port, now):
        if now - self.last_sweep >= self.window:
            for key, state in list(self.hosts.items()):
                if now - state['seen'] > self.cooldown:
                    del self.hosts[key]
            self.last_sweep = now
        key = (src, dst)
        state = self.hosts.pop(key, {'ports': {}, 'alert': float('-inf'), 'seen': now})
        state['seen'] = now
        self.hosts[key] = state
        while len(self.hosts) > self.max_hosts:
            self.hosts.popitem(last=False)
        if now - state['alert'] < self.cooldown:
            return None
        state['ports'] = {p: ts for p, ts in state['ports'].items() if now - ts <= self.window}
        state['ports'][port] = now
        if len(state['ports']) < self.threshold:
            return None
        ports = sorted(state['ports'])
        state['ports'] = {}
        state['alert'] = now
        return ports


def local_addresses():
    rows = json.loads(subprocess.check_output(['/usr/sbin/ip', '-j', 'address', 'show'], text=True))
    # I bridge Docker non sono destinazioni pubblicate del server.
    return {str(ipaddress.ip_address(addr['local']))
            for row in rows if not row['ifname'].startswith(('veth', 'br-', 'docker'))
            for addr in row.get('addr_info', []) if addr.get('family') in {'inet', 'inet6'}}


def scan_event(src, dst, sport, dport, ports, window):
    return {
        'utc_time': datetime.now(timezone.utc).isoformat(),
        'src_host': src, 'src_port': sport, 'dst_host': dst, 'dst_port': dport,
        'logtype': 5001, 'node_id': 'honeypotx-host',
        'logdata': {'SERVICE_NAME': 'portscan', 'SENSOR': 'host-tcp-syn',
                    'PORTS': ports, 'PORT_COUNT': len(ports), 'WINDOW_SECONDS': window},
    }


def run(args):
    addresses = local_addresses()
    if not addresses:
        raise RuntimeError('Nessun indirizzo host disponibile')
    detector = ScanDetector(args.threshold, args.window, args.cooldown)
    handler = RotatingFileHandler(args.output, maxBytes=5 * 1024 * 1024, backupCount=3)
    handler.setFormatter(logging.Formatter('%(message)s'))
    # Gli errori disco devono far ripartire il servizio, non perdere allarmi in silenzio.
    def fail_write(record):
        raise RuntimeError('Scrittura log port scan non riuscita')
    handler.handleError = fail_write
    logger = logging.getLogger('portscan-events')
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    logger.propagate = False
    command = ['/usr/bin/tcpdump', '-i', 'any', '-Q', 'in', '-p', '-nn', '-l', '-tt',
               '-s', '96',
               '(ip and tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn) or (ip6 and tcp)']
    # -p: niente promiscuous; filtro BPF SYN IPv4/TCP IPv6; nessun payload stampato o archiviato.
    process = subprocess.Popen(command, stdout=subprocess.PIPE, bufsize=0)
    running = True
    def stop(signum, frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    refreshed = time.monotonic()
    print('Sensore port scan attivo: TCP, soglia=%d, finestra=%ss' % (args.threshold, args.window), flush=True)
    pending = b''
    try:
        # Lettura binaria: nessuna riga bloccata nei buffer TextIO.
        # Il selector permette anche refresh IP e uscita senza traffico.
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while running:
                now = time.monotonic()
                if now - refreshed >= 30:
                    addresses = local_addresses()
                    refreshed = now
                if not selector.select(timeout=1):
                    if process.poll() is not None:
                        raise RuntimeError('tcpdump terminato')
                    continue
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    raise RuntimeError('Flusso tcpdump terminato')
                pending += chunk
                lines = pending.split(b'\n')
                pending = lines.pop()
                if len(pending) > 4096:
                    raise RuntimeError('Riga tcpdump troppo lunga')
                for line in lines:
                    syn = parse_syn(line.decode('ascii', errors='replace'))
                    if not syn:
                        continue
                    src, dst, sport, dport = syn
                    if dst not in addresses:
                        continue
                    ports = detector.observe(src, dst, dport, time.monotonic())
                    if ports:
                        logger.info(json.dumps(scan_event(src, dst, sport, dport, ports, args.window)))
                        print('Port scan rilevato: %s -> %s, %d porte' % (src, dst, len(ports)), flush=True)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stdout.close()
        handler.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('/var/log/honeypotx-portscan/events.jsonl'))
    parser.add_argument('--threshold', type=int, default=12)
    parser.add_argument('--window', type=float, default=10)
    parser.add_argument('--cooldown', type=float, default=60)
    run(parser.parse_args())


if __name__ == '__main__':
    main()
